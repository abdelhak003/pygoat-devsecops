"""Static review of learner code for the coding playgrounds (A6, A9, SSRF exercise).

Learner code is DATA. It is parsed with ast.parse() (parsing never executes anything),
inspected, and turned into feedback. It is never written to a .py file, imported,
compiled or executed. The previous design wrote it into modules the application
imports (introduction/playground/...), which allowed persistent code injection (CWE-94).
"""
import ast
import re

MAX_CODE_LENGTH = 20_000
LOG_LEVELS = ("info", "warning", "error")
SENSITIVE_WORDS = ("password", "passwd", "secret", "token", "session", "cookie", "credit")
SAMPLE_VALUES = {"username": "alice", "password": "S3cret!"}
SIMULATED_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH")


class CodeReviewError(ValueError):
    """The learner code cannot be reviewed (empty, too long or invalid syntax)."""


def parse_learner_code(code, label):
    """Parses learner code into a syntax tree. Nothing is compiled to bytecode or executed."""
    if not isinstance(code, str) or not code.strip():
        raise CodeReviewError(f"{label}: no code submitted")
    if len(code) > MAX_CODE_LENGTH:
        raise CodeReviewError(f"{label}: the code is longer than {MAX_CODE_LENGTH} characters")
    try:
        return ast.parse(code)
    except SyntaxError as exc:
        raise CodeReviewError(f"{label}: syntax error line {exc.lineno}: {exc.msg}")
    except (RecursionError, MemoryError, ValueError):
        raise CodeReviewError(f"{label}: the code is too deeply nested to be reviewed")


def _identifiers(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.add(node.value)
    return names


def _is_empty_body(body):
    return all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
               for s in body)


# ------------------------------------------------------------------------------------ A9 logging

def _render_message(node):
    """Text of a log message with sample values, and the sensitive words it exposes."""
    exposed = set()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        text = node.value
    elif isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                inner = ast.unparse(value.value)
                parts.append(SAMPLE_VALUES.get(inner, "{" + inner + "}"))
                exposed |= {w for w in SENSITIVE_WORDS if w in inner.lower()}
        text = "".join(parts)
    else:
        inner = ast.unparse(node)
        text = "{" + inner + "}"
        exposed |= {w for w in SENSITIVE_WORDS if w in inner.lower()}
    return text, exposed


def _method_of(test):
    """'POST' for a test such as: request.method == "POST"."""
    if (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.left, ast.Attribute) and test.left.attr == "method"
            and isinstance(test.comparators[0], ast.Constant) and isinstance(test.comparators[0].value, str)):
        return test.comparators[0].value.upper()
    return None


def review_logging_exercise(log_code, api_code):
    """A9 playground: reviews the Log class and the logging calls of the API view.

    Returns {"passed": bool, "logs": [...]}: simulated log lines (what each HTTP method
    would log, with sample values) followed by review feedback.
    """
    log_tree = parse_learner_code(log_code, "Log.py")
    api_tree = parse_learner_code(api_code, "api.py")
    feedback = []

    log_class = next((n for n in log_tree.body if isinstance(n, ast.ClassDef) and n.name == "Log"), None)
    if log_class is None:
        feedback.append("❌ Log.py: define a class named Log.")
    else:
        methods = {f.name: f for f in log_class.body if isinstance(f, ast.FunctionDef)}
        for level in LOG_LEVELS:
            if level not in methods:
                feedback.append(f"❌ Log.{level}() is missing.")
            elif _is_empty_body(methods[level].body):
                feedback.append(f"❌ Log.{level}() does nothing: the event is lost.")
            else:
                feedback.append(f"✅ Log.{level}() records the event.")
        identifiers = _identifiers(log_class)
        if not identifiers & {"datetime", "now", "utcnow", "time", "isoformat", "strftime"}:
            feedback.append("⚠️ No timestamp: always log when the event happened.")
        if not identifiers & {"REMOTE_ADDR", "META", "user", "username", "get_host"}:
            feedback.append("⚠️ No source IP / user id: log who triggered the event.")
        if not identifiers & {"replace", "escape", "encode", "repr", "\n", "\r"}:
            feedback.append("⚠️ Messages are written as received: neutralise new lines to prevent log injection.")

    simulated = {}
    for node in ast.walk(api_tree):
        if isinstance(node, ast.If) and _method_of(node.test):
            method = _method_of(node.test)
            for call in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and call.func.attr in LOG_LEVELS and call.args):
                    text, exposed = _render_message(call.args[0])
                    simulated.setdefault(method, []).append((call.func.attr.upper(), text, exposed))
    lines = []
    for method in SIMULATED_METHODS:
        entries = simulated.get(method)
        if not entries:
            lines.append(f"(nothing logged for {method})")
            continue
        for level, text, exposed in entries:
            lines.append(f"{level} | {method} request | {text}")
            for word in sorted(exposed):
                feedback.append(f"❌ api.py logs sensitive data ({word}) for {method} requests.")
    if "POST" not in simulated:
        feedback.append("⚠️ Login attempts (POST) are not logged.")

    passed = not any(item.startswith("❌") for item in feedback)
    feedback.append("✅ Secure logging implemented." if passed else "Fix the ❌ items and try again.")
    return {"passed": passed, "logs": lines + ["— review —"] + feedback}


# ------------------------------------------------------------------------------------ A6 dependencies

def review_dependency_checker(code):
    """A6 playground: reviews the learner's check_vul() / check_vuln() function."""
    tree = parse_learner_code(code, "utility.py")
    feedback = []
    function = next((n for n in tree.body if isinstance(n, ast.FunctionDef)
                     and n.name in ("check_vul", "check_vuln")), None)
    if function is None:
        return {"passed": False, "feedback": ["❌ Define a function check_vul(list_of_modules)."]}
    feedback.append("✅ check_vul() defined." if len(function.args.args) == 1
                    else "⚠️ check_vul() should take one argument: the list of 'name==version' modules.")
    calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)]
    http_calls = [c for c in calls if isinstance(c.func, ast.Attribute)
                  and c.func.attr in ("get", "request") and ast.unparse(c.func.value) == "requests"]
    identifiers = _identifiers(function)
    if not http_calls:
        feedback.append("❌ No requests.get() call: query the PyPI JSON API.")
    elif not all(any(k.arg == "timeout" for k in c.keywords) for c in http_calls):
        feedback.append("⚠️ Add a timeout to requests.get(): a slow server must not block the check.")
    else:
        feedback.append("✅ HTTP calls have a timeout.")
    if not any("pypi.org/pypi" in s for s in identifiers if isinstance(s, str)):
        feedback.append("❌ Use the API https://pypi.org/pypi/{module-name}/{module-version}/json")
    if "vulnerabilities" not in identifiers:
        feedback.append("❌ Read the 'vulnerabilities' field of the PyPI response.")
    if not any(isinstance(n, ast.Return) and n.value is not None for n in ast.walk(function)):
        feedback.append("❌ Return the list of vulnerabilities found.")
    passed = not any(item.startswith("❌") for item in feedback)
    return {"passed": passed, "feedback": feedback}


# ------------------------------------------------------------------------------------ SSRF exercise

_REQUEST_SOURCES = {"POST", "GET", "FILES", "COOKIES", "body", "headers", "META"}
_PATH_SINKS = {"open", "join"}


def _is_request_input(node):
    """request.POST["x"], request.GET.get("x"), request.body, ..."""
    target = node.value if isinstance(node, ast.Subscript) else node
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
        target = node.func.value
    return (isinstance(target, ast.Attribute) and target.attr in _REQUEST_SOURCES
            and isinstance(target.value, ast.Name) and target.value.id == "request")


def _uses(node, names):
    return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(node))


def review_ssrf_fix(python_code, html_inputs):
    """SSRF exercise: is the file opened chosen by an allowlist rather than by the user?

    Lightweight taint analysis on the syntax tree: values read from the request are
    "tainted"; a lookup in a mapping (BLOGS[name] / BLOGS.get(name)) produces a clean value;
    a tainted value reaching open() or os.path.join() is accepted only when it was first
    compared against an allowlist (if name in ALLOWED / not in ALLOWED).
    """
    tree = parse_learner_code(python_code, "views.py")
    if len(html_inputs) > 4:
        return {"passed": False, "message": "too many inputs in Html\n Try again"}
    path_like = [v for v in html_inputs if re.search(r"[/\\]|\.\.|\.[A-Za-z0-9]{1,4}$", v)]

    tainted, ever_tainted = set(), set()
    assignments = sorted((n for n in ast.walk(tree) if isinstance(n, ast.Assign)), key=lambda n: n.lineno)
    for node in assignments:
        targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
        value = node.value
        lookup = ((isinstance(value, ast.Subscript) and isinstance(value.value, (ast.Name, ast.Attribute)))
                  or (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                      and value.func.attr == "get" and not _is_request_input(value)))
        if _is_request_input(value) or (_uses(value, tainted) and not lookup):
            tainted |= targets
            ever_tainted |= targets
        else:
            tainted -= targets
    allowlisted = any(isinstance(n, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in n.ops)
                      and _uses(n.left, ever_tainted) for n in ast.walk(tree))
    sinks = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and ((isinstance(n.func, ast.Name) and n.func.id in _PATH_SINKS)
                  or (isinstance(n.func, ast.Attribute) and n.func.attr in _PATH_SINKS))
             and any(_uses(arg, tainted) for arg in n.args)]

    if path_like:
        return {"passed": False, "message": ("The form still sends file paths (" + ", ".join(path_like[:4]) +
                                             "): send an identifier such as blog1 and map it on the server.")}
    opens_a_file = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"
                       for n in ast.walk(tree))
    if not any(isinstance(n, ast.FunctionDef) for n in tree.body) or not opens_a_file:
        return {"passed": False, "message": "Keep the view function: it must still read and return the blog file."}
    if sinks and not allowlisted:
        return {"passed": False, "message": ("Test bench passed but the code is not secure: a value from the "
                                             "request still reaches open()/os.path.join() without an allowlist.")}
    return {"passed": True, "message": "Congratulation, you have written a secure code."}
