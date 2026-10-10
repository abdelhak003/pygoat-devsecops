"""Safe replacements for the dangerous primitives previously used by some PyGoat labs.

Each lab keeps its educational goal (the pages still explain the vulnerability and show
what an attacker would have done), but attacker-controlled input never reaches:
  - an operating-system shell            (command injection, CWE-78)
  - the Python interpreter (eval)        (code injection, CWE-95)
  - an internal network destination      (server-side request forgery, CWE-918)
"""
import ast
import html
import ipaddress
import operator
import re
import socket
import urllib.parse

import certifi
import urllib3

# --------------------------------------------------------------------------------------
# Command injection labs: no shell, no external program, a simulation that explains.
# --------------------------------------------------------------------------------------

SHELL_METACHARACTERS = set(";&|`$<>\\(){}[]*?!'\"\n\r")

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def shell_metacharacters_in(value):
    """Characters a shell would interpret (command chaining, substitution, redirection...)."""
    return sorted({char for char in value if char in SHELL_METACHARACTERS})


def parse_target(value):
    """Returns a valid IP address or hostname, or None.

    A hostname label can never start with '-', so the value can never be mistaken for a
    command-line option either (argument injection).
    """
    value = (value or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value if _HOSTNAME_RE.match(value) else None


def explain_injection(tool, target):
    """Describes, WITHOUT executing anything, how a shell would have read the input."""
    shown = target.replace("\n", "\\n").replace("\r", "\\r")
    return (
        "Command NOT executed (simulation).\n"
        f"Input contains shell metacharacters: {' '.join(repr(c) for c in shell_metacharacters_in(target))}\n"
        f"The vulnerable version passed this string to a shell (shell=True):\n    {tool} {shown}\n"
        "A shell treats these characters as command separators or substitutions, so the text after\n"
        "them would have run as additional commands on the server (CWE-78).\n"
        "The secured version never starts a shell: it only accepts a hostname or an IP address."
    )


def dns_lookup_lab(tool, target):
    """Command injection lab (dig / nslookup): resolves the name in Python, never in a shell."""
    if shell_metacharacters_in(target):
        return explain_injection(tool, target)
    host = parse_target(target)
    if host is None:
        return "Rejected: enter a valid domain name or IP address."
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return f"; {tool} {host} (simulated)\n\nNo address found for {host}."
    addresses = sorted({info[4][0] for info in infos})
    lines = [f"; {tool} {host} (simulated: resolved by the application, no shell, no external program)", ""]
    lines += [f"{host}\t{'AAAA' if ':' in address else 'A'}\t{address}" for address in addresses]
    return "\n".join(lines)


def port_scan_lab(target):
    """MITRE CWE-77 lab (nmap): returns the JSON the page expects, without running nmap.

    Port scanning from the server is disabled: a public port scanner can be abused to map
    the internal network. Lines are HTML-escaped because the page inserts them with innerHTML.
    """
    if shell_metacharacters_in(target):
        lines = explain_injection("nmap", target).splitlines()
    elif parse_target(target) is None:
        lines = ["Rejected: enter a valid IP address or hostname."]
    else:
        host = parse_target(target)
        lines = [
            "Simulation: no scan was run.",
            f"Without a shell, the command would be the argument list ['nmap', '{host}'],",
            "so the input can only ever be ONE argument, never a second command.",
            "Port scanning from the server is disabled in the secured version.",
        ]
    safe_lines = [html.escape(line) for line in lines]
    return {"raw_res": "\n".join(safe_lines), "raw_err": "", "ports": safe_lines}


# --------------------------------------------------------------------------------------
# SSRF lab: strict outbound request policy.
# --------------------------------------------------------------------------------------

ALLOWED_SCHEMES = {"https": 443}
MAX_RESPONSE_BYTES = 500_000
REQUEST_TIMEOUT_SECONDS = 5


class OutboundRequestBlocked(ValueError):
    """The destination is not allowed by the outbound request policy."""


def resolve_public_destination(url):
    """Validates a URL and returns (parts, hostname, port, pinned_ip) or raises OutboundRequestBlocked.

    Policy: https on its default port only (no cleartext http), no credentials in the URL, and EVERY
    address the hostname resolves to must be public (no loopback, private, link-local,
    shared, reserved or multicast range, IPv4-mapped IPv6 addresses included).
    """
    parts = urllib.parse.urlsplit((url or "").strip())
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise OutboundRequestBlocked("only https URLs are allowed")
    if parts.username or parts.password:
        raise OutboundRequestBlocked("credentials in the URL are not allowed")
    host = parts.hostname
    if not host:
        raise OutboundRequestBlocked("the URL has no host")
    try:
        port = parts.port or ALLOWED_SCHEMES[scheme]
    except ValueError:
        raise OutboundRequestBlocked("invalid port")
    if port != ALLOWED_SCHEMES[scheme]:
        raise OutboundRequestBlocked(f"only the default port {ALLOWED_SCHEMES[scheme]} is allowed for {scheme}")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise OutboundRequestBlocked("the host name could not be resolved")
    addresses = []
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global or address.is_multicast:
            raise OutboundRequestBlocked(f"the host resolves to a non-public address ({address})")
        addresses.append(address)
    if not addresses:
        raise OutboundRequestBlocked("the host name could not be resolved")
    return parts, host, port, addresses[0]


def fetch_public_url(url):
    """GET request to a validated public URL. Returns (status, text).

    The connection goes to the address that was VALIDATED (pinned IP), so a second DNS
    answer cannot redirect it to an internal address (DNS rebinding). The TLS certificate
    is still verified against the requested hostname. Redirects are never
    followed automatically, because each new destination would need the same validation.
    """
    parts, host, port, address = resolve_public_destination(url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    options = {
        "port": port,
        "timeout": urllib3.Timeout(connect=REQUEST_TIMEOUT_SECONDS, read=REQUEST_TIMEOUT_SECONDS),
        "retries": False,
        "maxsize": 1,
    }
    pool = urllib3.HTTPSConnectionPool(str(address), server_hostname=host, assert_hostname=host,
                                       cert_reqs="CERT_REQUIRED", ca_certs=certifi.where(), **options)
    host_header = f"[{host}]" if ":" in host else host
    response = pool.urlopen("GET", path, headers={"Host": host_header}, redirect=False,
                            preload_content=False, assert_same_host=False)
    try:
        if 300 <= response.status < 400:
            return response.status, (f"Redirect to {response.headers.get('Location', '?')} not followed: "
                                     "every destination must pass the outbound policy.")
        body = response.read(MAX_RESPONSE_BYTES)
        return response.status, body.decode("utf-8", errors="replace")
    finally:
        response.release_conn()
        pool.close()


# --------------------------------------------------------------------------------------
# Code injection labs (eval): an arithmetic-only calculator built on an AST allowlist.
# --------------------------------------------------------------------------------------

CALC_MAX_LENGTH = 100
CALC_MAX_NODES = 50
CALC_MAX_EXPONENT = 100
CALC_MAX_BASE_FOR_POWER = 10 ** 6
CALC_MAX_INT_BITS = 4096
CALC_HELP = "Only arithmetic is accepted: numbers, + - * / // % **, parentheses."

_CALC_BINARY = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
                ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
                ast.Mod: operator.mod, ast.Pow: operator.pow}
_CALC_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}


class UnsafeExpression(ValueError):
    """The input is not a plain arithmetic expression."""


def explain_eval(expression):
    """What the vulnerable version would have done with the input, without doing it."""
    shown = (expression or "")[:200].replace("\n", "\\n")
    return ("Not evaluated (simulation). The vulnerable version passed this text to Python's eval(), "
            f"which would have executed it as Python code on the server: {shown}  —  {CALC_HELP}")


def safe_calculate(expression):
    """Evaluates +, -, *, /, //, %, ** on int/float literals. Never runs Python code.

    The text is parsed with ast.parse (parsing never executes anything) and the tree is
    computed node by node: names, calls, attributes, subscripts, lambdas, comprehensions...
    are not in the allowlist, so builtins, imports and objects are unreachable.
    Sizes are bounded so that an expression such as 9**9**9 cannot exhaust the server.
    """
    if not isinstance(expression, str) or not expression.strip() or len(expression) > CALC_MAX_LENGTH:
        raise UnsafeExpression(f"the expression must contain 1 to {CALC_MAX_LENGTH} characters")
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except SyntaxError:
        raise UnsafeExpression("not a valid arithmetic expression")
    if sum(1 for _ in ast.walk(tree)) > CALC_MAX_NODES:
        raise UnsafeExpression("the expression is too complex")
    return _calculate(tree.body)


def _calculate(node):
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value
    if isinstance(node, ast.UnaryOp) and type(node.op) in _CALC_UNARY:
        return _CALC_UNARY[type(node.op)](_calculate(node.operand))
    if isinstance(node, ast.BinOp) and type(node.op) in _CALC_BINARY:
        left, right = _calculate(node.left), _calculate(node.right)
        if isinstance(node.op, ast.Pow) and (abs(right) > CALC_MAX_EXPONENT or abs(left) > CALC_MAX_BASE_FOR_POWER):
            raise UnsafeExpression("exponent or base too large")
        result = _CALC_BINARY[type(node.op)](left, right)
        if isinstance(result, complex):
            raise UnsafeExpression("the result is not a real number")
        if isinstance(result, int) and result.bit_length() > CALC_MAX_INT_BITS:
            raise UnsafeExpression("the result is too large")
        return result
    raise UnsafeExpression("not a plain arithmetic expression")


# --------------------------------------------------------------------------------------
# SSTI lab: template syntax is analysed and explained, never given to the template engine.
# --------------------------------------------------------------------------------------

_TEMPLATE_CONSTRUCT = re.compile(r"\{\{(.*?)\}\}|\{%(.*?)%\}", re.S)
_TEMPLATE_RISKS = {
    "load": "loads an extra tag library ({% load log %} exposes the admin action log)",
    "get_admin_log": "reads the Django admin log and the users who performed the actions",
    "debug": "dumps the whole template context",
    "include": "renders another template of the server",
    "extends": "replaces the page layout with another server template",
    "password": "prints password hashes",
    "secret": "prints secret values",
    "settings": "reads the Django settings (SECRET_KEY...)",
    "request": "reads the request (cookies, headers, session)",
    "csrf_token": "prints the CSRF token",
    "user": "reads the logged-in user object",
}


def analyze_template_injection(text, limit=20):
    """Lists the template constructs a vulnerable engine would have interpreted.

    Pure text analysis: nothing is compiled or rendered by Django's template engine.
    """
    findings = []
    for match in _TEMPLATE_CONSTRUCT.finditer(text or ""):
        expression = (match.group(1) if match.group(1) is not None else match.group(2)).strip()
        words = set(re.findall(r"[a-z_]+", expression.lower()))
        findings.append({
            "construct": match.group(0)[:140],
            "kind": "variable" if match.group(1) is not None else "tag",
            "risks": [description for key, description in _TEMPLATE_RISKS.items() if key in words],
        })
        if len(findings) >= limit:
            break
    return findings
