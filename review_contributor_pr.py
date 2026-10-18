#!/usr/bin/env python3
"""
Automated PR reviewer harness for musedin-hire-verifier.

Ingests a candidate contribution (job-f78 worker agent_d2eq8gwu3f), restores
the curated baseline verifier + test suite over a copy of it, then runs four
gates:

  GATE 1  attack   -- candidate modules are imported in a network-denied sandbox
                      (runs first: importing untrusted code is the riskiest step)
  GATE 2  lint     -- forbidden imports, dynamic exec, outbound URL literals
  GATE 3  diff     -- protected tests still present, size limits, runner hooks
  GATE 4  tests    -- the baseline unit suite, which the candidate cannot weaken

Scope, stated plainly: this harness reviews the *suite* against a given code
state. Because the baseline test files are restored, a candidate's own edits
to those files are discarded (reported as PROTECTED_FILE_REPLACED warnings) and
never count toward or against the verdict. Candidate source modules outside the
protected list are linted and import-probed.

Emits a structured verdict (APPROVED / REJECTED) as text or JSON.

Safety: read-only on the candidate (copied to a temp dir), never runs the
candidate's runner hooks, and does not itself make outbound requests.
Exit code: 0 APPROVED, 1 REJECTED, 2 usage/infrastructure error.

Usage:
  python3 review_contributor_pr.py --pr-dir /tmp/candidate \
      --baseline-dir /path/to/musedin-hire-verifier [--json]
  python3 review_contributor_pr.py --zip candidate.zip --json
"""

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize
import zipfile
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

APPROVED = "APPROVED"
REJECTED = "REJECTED"

# Files from the baseline that are restored verbatim over the candidate. The
# candidate may not weaken the tests or the verifier under review.
PROTECTED_TESTS = ("test_check_hire_record.py", "test_aer1.py")
PROTECTED_SOURCES = ("check_hire_record.py", "aer1.py")

# Baseline test ids that must still be present (no silent deletions).
BASELINE_TEST_IDS = (
    "test_check_hire_record.TestHireRecordVerifier.test_b64url_decode_padding",
    "test_check_hire_record.TestHireRecordVerifier.test_verify_ed25519_valid",
    "test_check_hire_record.TestHireRecordVerifier.test_verify_ed25519_invalid_signature",
    "test_check_hire_record.TestHireRecordVerifier.test_verify_ed25519_wrong_key",
    "test_check_hire_record.TestHireRecordVerifier.test_check_hire_mock_valid",
)

# Test-runner hooks that could neuter the suite; refused outright.
FORBIDDEN_FILES = ("conftest.py", "sitecustomize.py", "pytest.ini", "tox.ini", "setup.cfg")

NETWORK_MODULES = {
    "socket", "ssl", "http", "urllib", "urllib2", "urllib3", "requests", "httpx",
    "aiohttp", "ftplib", "telnetlib", "smtplib", "xmlrpc", "webbrowser", "asyncio",
    "subprocess", "pty", "shutil", "importlib", "ctypes",
}
FORBIDDEN_DOTTED = ("urllib.request", "http.client", "urllib3", "requests", "httpx",
                    "aiohttp", "os.system", "os.popen", "os.exec", "os.spawn")
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
# Literal URLs are only tolerated for the documented issuer endpoint.
ALLOWED_URL_PREFIXES = ("https://musedin.com/.well-known/musedin-issuer.json",)
URL_REGEX = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>)]+", re.IGNORECASE)
SHELL_TRUE_INJECTION = re.compile(r"#\s*(?:type|py|bash|sh|ruby|node)\s*:\s*", re.IGNORECASE)
MAX_CANDIDATE_BYTES = 512 * 1024


@dataclass
class Finding:
    gate: str
    severity: str  # "block" | "warn"
    code: str
    message: str
    file: Optional[str] = None
    line: Optional[int] = None


@dataclass
class GateResult:
    name: str
    passed: bool
    detail: str = ""
    findings: List[Finding] = field(default_factory=list)


@dataclass
class Verdict:
    verdict: str = REJECTED
    contributor: str = "agent_d2eq8gwu3f"
    job: str = "job-f78"
    gates: List[GateResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "contributor": self.contributor,
            "job": self.job,
            "reason": self.reason,
            "gates": [
                {
                    "name": g.name,
                    "passed": g.passed,
                    "detail": g.detail,
                    "findings": [asdict(f) for f in g.findings],
                }
                for g in self.gates
            ],
            "findings": [asdict(f) for f in self.findings],
        }


# --------------------------------------------------------------------------
# Candidate ingestion
# --------------------------------------------------------------------------

def materialize_candidate(pr_dir: Optional[str], zip_path: Optional[str],
                          workdir: str) -> None:
    """Copy the candidate into workdir (never mutate the original)."""
    if zip_path:
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.infolist():
                name = member.filename
                if name.startswith("/") or ".." in name.split("/"):
                    raise ValueError(f"unsafe zip member path: {name!r}")
                if member.is_dir():
                    continue
                if member.file_size > MAX_CANDIDATE_BYTES:
                    raise ValueError(f"zip member too large: {name!r} ({member.file_size} bytes)")
                target = os.path.join(workdir, name)
                os.makedirs(os.path.dirname(target) or workdir, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        return
    if not pr_dir or not os.path.isdir(pr_dir):
        raise ValueError("candidate directory not found")
    for root, dirs, files in os.walk(pr_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for name in files:
            src = os.path.join(root, name)
            rel = os.path.relpath(src, pr_dir)
            dst = os.path.join(workdir, rel)
            os.makedirs(os.path.dirname(dst) or workdir, exist_ok=True)
            shutil.copyfile(src, dst)


def overlay_baseline(baseline_dir: str, workdir: str) -> List[str]:
    """Restore protected baseline files over the candidate. Returns restored names."""
    restored = []
    for name in PROTECTED_TESTS + PROTECTED_SOURCES:
        src = os.path.join(baseline_dir, name)
        if os.path.isfile(src):
            shutil.copy(src, os.path.join(workdir, name))
            restored.append(name)
    return restored


def candidate_python_files(workdir: str) -> List[str]:
    out = []
    for root, dirs, files in os.walk(workdir):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in files:
            if name.endswith(".py"):
                out.append(os.path.join(root, name))
    return sorted(out)


# --------------------------------------------------------------------------
# GATE 1: tests
# --------------------------------------------------------------------------

def run_tests(workdir: str, python_exe: str, timeout: int = 300) -> GateResult:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Discover mode runs only the restored baseline tests; runner hooks are excluded by GATE 3.
    proc = subprocess.run(
        [python_exe, "-m", "unittest", "discover", "-v"],
        cwd=workdir, env=env, capture_output=True, text=True, timeout=timeout,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    findings: List[Finding] = []
    summary = re.search(r"^Ran (\d+) tests?", output, re.M)
    ran = int(summary.group(1)) if summary else 0
    if proc.returncode != 0 or not re.search(r"^OK\b", output, re.M):
        failures = re.findall(r"^(?:FAIL|ERROR): (\S+)", output, re.M)
        for name in failures:
            findings.append(Finding("tests", "block", "TEST_FAILURE",
                                    f"failing test: {name}"))
        if not failures:
            findings.append(Finding("tests", "block", "TEST_PROCESS",
                                    f"test run exited {proc.returncode}"))
    if ran == 0:
        findings.append(Finding("tests", "block", "NO_TESTS", "test run discovered no tests"))
    passed = not findings
    return GateResult("tests", passed, f"{ran} test(s) run", findings)


# --------------------------------------------------------------------------
# GATE 2: lint for security / network abuse
# --------------------------------------------------------------------------

def _module_root(name: str) -> str:
    return name.split(".", 1)[0]


def lint_file(path: str, rel: str) -> List[Finding]:
    findings: List[Finding] = []
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [Finding("lint", "block", "NON_UTF8", "file is not valid UTF-8", rel)]

    # Shell-injection via a #! line embedded mid-file, or a NUL byte.
    if b"\x00" in raw:
        findings.append(Finding("lint", "block", "NUL_BYTE", "NUL byte in source", rel))
    for lineno, line in enumerate(source.splitlines(), 1):
        if SHELL_TRUE_INJECTION.search(line) and not line.startswith("#!"):
            findings.append(Finding("lint", "block", "SHEBANG_INJECTION",
                                    "embedded '#type:'-style directive", rel, lineno))
        for url in URL_REGEX.findall(line):
            if not url.startswith(ALLOWED_URL_PREFIXES):
                findings.append(Finding("lint", "block", "NETWORK_LITERAL",
                                        f"outbound URL literal not allowlisted: {url}", rel, lineno))

    try:
        tree = ast.parse(source, filename=rel)
    except SyntaxError as exc:
        return findings + [Finding("lint", "block", "SYNTAX", f"cannot parse: {exc.msg}", rel, exc.lineno)]

    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _module_root(a.name) in NETWORK_MODULES:
                    findings.append(Finding("lint", "block", "NETWORK_IMPORT",
                                            f"imports {a.name}", rel, node.lineno))
                aliases[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if _module_root(mod) in NETWORK_MODULES or any(
                    mod == d or mod.startswith(d + ".") for d in FORBIDDEN_DOTTED):
                findings.append(Finding("lint", "block", "NETWORK_IMPORT",
                                        f"from {mod} import ...", rel, node.lineno))
            for a in node.names:
                aliases[a.asname or a.name] = f"{mod}.{a.name}"
        elif isinstance(node, ast.Call):
            func = node.func
            name = ""
            if isinstance(func, ast.Name):
                name = aliases.get(func.id, func.id)
            elif isinstance(func, ast.Attribute):
                base = func.value.id if isinstance(func.value, ast.Name) else ""
                name = f"{aliases.get(base, base)}.{func.attr}".lstrip(".")
            short = name.rsplit(".", 1)[-1]
            if short in FORBIDDEN_CALLS or name in FORBIDDEN_CALLS:
                findings.append(Finding("lint", "block", "DYNAMIC_EXEC",
                                        f"dynamic execution via {short}()", rel, node.lineno))
            if any(name == d or name.startswith(d + ".") for d in FORBIDDEN_DOTTED):
                findings.append(Finding("lint", "block", "NETWORK_OR_EXEC",
                                        f"call to {name}()", rel, node.lineno))
    return findings


def run_lint(workdir: str, candidate_files: List[str]) -> GateResult:
    findings: List[Finding] = []
    for rel in candidate_files:
        full = os.path.join(workdir, rel)
        if os.path.isfile(full):
            findings.extend(lint_file(full, rel))
    return GateResult("lint", not findings, f"{len(candidate_files)} python file(s) scanned", findings)


def run_lint_tokens(workdir: str, candidate_files: List[str]) -> GateResult:
    """Secondary pass: token-level scan catches string-built imports/URLs."""
    findings: List[Finding] = []
    for rel in candidate_files:
        full = os.path.join(workdir, rel)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "rb") as fh:
                for tok in tokenize.tokenize(fh.readline):
                    if tok.type == tokenize.STRING and URL_REGEX.search(tok.string):
                        for url in URL_REGEX.findall(tok.string):
                            if not url.startswith(ALLOWED_URL_PREFIXES):
                                findings.append(Finding("lint", "block", "NETWORK_LITERAL",
                                                        f"URL in string token: {url}", rel, tok.start[0]))
        except (tokenize.TokenError, SyntaxError):
            continue
    return GateResult("lint", not findings, "token scan", findings)


# --------------------------------------------------------------------------
# GATE 3: protected-test diff
# --------------------------------------------------------------------------

def collect_test_ids(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    prefix = os.path.splitext(os.path.basename(path))[0]
    ids: List[str] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                        sub.name.startswith("test_"):
                    ids.append(f"{prefix}.{node.name}.{sub.name}")
    return ids


def run_diff(workdir: str, original_pr: Optional[str]) -> GateResult:
    findings: List[Finding] = []
    test_path = os.path.join(workdir, "test_check_hire_record.py")
    present = set(collect_test_ids(test_path)) if os.path.isfile(test_path) else set()
    for required in BASELINE_TEST_IDS:
        if required not in present:
            findings.append(Finding("diff", "block", "TEST_REMOVED",
                                    f"baseline test missing after overlay: {required}"))
    replaced = []
    if original_pr and os.path.isdir(original_pr):
        for name in sorted(os.listdir(original_pr)):
            path = os.path.join(original_pr, name)
            if os.path.isfile(path) and os.path.getsize(path) > MAX_CANDIDATE_BYTES:
                findings.append(Finding("diff", "block", "SIZE_LIMIT",
                                        f"{name} exceeds {MAX_CANDIDATE_BYTES} bytes", name))
            if name in FORBIDDEN_FILES:
                findings.append(Finding("diff", "block", "RUNNER_HOOK",
                                        f"forbidden test-runner hook file: {name}", name))
            # The overlay silently discards these; surface it so a maintainer
            # knows which proposed changes were not taken as-is.
            if name in PROTECTED_TESTS + PROTECTED_SOURCES:
                replaced.append(name)
                findings.append(Finding("diff", "warn", "PROTECTED_FILE_REPLACED",
                                        f"candidate proposed its own {name}; baseline restored",
                                        name))
    detail = f"{len(present)} baseline test id(s) present"
    if replaced:
        detail += f"; baseline restored over {len(replaced)} proposed file(s)"
    return GateResult("diff", not any(f.severity == "block" for f in findings), detail, findings)


# --------------------------------------------------------------------------
# GATE 4: import attack probe (network denied, subprocess forbidden)
# --------------------------------------------------------------------------

# The probe imports untrusted code, so network access is refused at the OS
# level, not just by Python patching. Strongest mechanism available wins:
#   darwin  -- sandbox-exec profile denying network* (carried by the OS)
#   linux   -- `unshare -rn` (new network namespace) when available, else the
#              preloaded C guard below (LD_PRELOAD)
#   other   -- preloaded C guard when a compiler and preload work
# Whatever is chosen, ISOLATION_SELF_TEST must prove it before any candidate
# code runs; an unproven sandbox is reported as WEAK_SANDBOX, never assumed safe.
NETGUARD_C = r"""
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>

static int guarded(int domain) {
    const char *flag = getenv("NETGUARD_ON");
    if (flag && flag[0] == '1' &&
        (domain == AF_INET || domain == AF_INET6 || domain == AF_UNSPEC)) {
        errno = EPERM;
        return 1;
    }
    return 0;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (guarded(addr ? addr->sa_family : AF_UNSPEC)) {
        errno = EPERM;
        return -1;
    }
    errno = ENETUNREACH;
    return -1;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    if (guarded(AF_UNSPEC)) return EAI_SYSTEM;  /* errno is EPERM */
    return EAI_NONAME;
}
"""

SANDBOX_PROFILE = """(version 1)
(allow default)
(deny network*)
"""


def build_network_guard(tmpdir: str) -> Optional[str]:
    """Compile the C network blocker; return its path or None if unavailable."""
    cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not cc:
        return None
    src = os.path.join(tmpdir, "netguard.c")
    so = os.path.join(tmpdir, "netguard.so")
    with open(src, "w", encoding="utf-8") as fh:
        fh.write(NETGUARD_C)
    try:
        proc = subprocess.run([cc, "-shared", "-fPIC", "-O1", "-o", so, src],
                              capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return so if proc.returncode == 0 and os.path.isfile(so) else None


def isolation_prefix(tmpdir: str) -> Tuple[List[str], Dict[str, str], str]:
    """
    Return (argv prefix, extra env, mechanism) for the isolated subprocesses.
    The caller must still prove the mechanism with ISOLATION_SELF_TEST.

    Candidates are ordered by strength: OS sandbox first, then libc preload.
    """
    if sys.platform == "darwin" and os.path.exists("/usr/bin/sandbox-exec"):
        profile = os.path.join(tmpdir, "nonet.sb")
        with open(profile, "w", encoding="utf-8") as fh:
            fh.write(SANDBOX_PROFILE)
        return ["/usr/bin/sandbox-exec", "-f", profile], {}, "sandbox-exec"

    guard = build_network_guard(tmpdir)
    if guard:
        if sys.platform.startswith("linux") and shutil.which("unshare"):
            # Belt and braces: namespace isolation plus the libc guard.
            return (["unshare", "-rn", "--"], {"LD_PRELOAD": guard, "NETGUARD_ON": "1"},
                    "unshare+LD_PRELOAD")
        if sys.platform.startswith("linux"):
            return [], {"LD_PRELOAD": guard, "NETGUARD_ON": "1"}, "LD_PRELOAD"
        return [], {"DYLD_INSERT_LIBRARIES": guard, "NETGUARD_ON": "1"}, "DYLD_INSERT_LIBRARIES"
    return [], {}, "none"


PROBE = r"""
import json, sys
sys.path.insert(0, ".")
targets = json.loads(sys.argv[1])
blocked = []

def deny(name, *a, **k):
    blocked.append(str(name))
    raise PermissionError("denied by reviewer probe: " + str(name))

import socket
# Keep socket.socket a *class*: ssl subclasses it at import time.
class _DeniedSocket(socket.socket):
    def connect(self, *a, **k):
        deny("socket.connect")
    def connect_ex(self, *a, **k):
        deny("socket.connect_ex")
    def sendto(self, *a, **k):
        deny("socket.sendto")
    def send(self, *a, **k):
        deny("socket.send")
socket.socket = _DeniedSocket
socket.create_connection = lambda *a, **k: deny("socket.create_connection")
socket.getaddrinfo = lambda *a, **k: deny("socket.getaddrinfo")
import subprocess
subprocess.Popen = lambda *a, **k: deny("subprocess.Popen")
subprocess.run = lambda *a, **k: deny("subprocess.run")

results = {}
import importlib
for mod in targets:
    try:
        importlib.import_module(mod)
        results[mod] = "imported"
    except BaseException as exc:
        results[mod] = "error:" + type(exc).__name__ + ":" + str(exc)[:200]
print(json.dumps({"results": results, "blocked": blocked}))
"""


# Runs inside the sandbox before any candidate code: proves the guard is active.
# Only errno EPERM (a policy refusal) counts as proof. A plain OSError could be
# an unreachable host, which would masquerade as a working sandbox.
ISOLATION_SELF_TEST = r"""
import errno, socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("1.1.1.1", 443))
    print("LEAK")
except OSError as exc:
    print("BLOCKED" if exc.errno == errno.EPERM else "INCONCLUSIVE:" + str(exc.errno))
"""


def run_attack_probe(workdir: str, python_exe: str, targets: List[str],
                     timeout: int = 120) -> GateResult:
    """
    Import each candidate module under a network-denied, exec-denied sandbox.

    Isolation is enforced at the OS level where possible, with Python-level
    denials as defence in depth. The mechanism is verified before candidate
    code runs; if it cannot be verified the gate reports WEAK_SANDBOX instead
    of implying containment it does not have.

    An import-time error is BLOCKING here: an artifact that cannot be imported
    cannot have been tested by its author, so it is not reviewable.
    """
    base_env = dict(os.environ)
    base_env["PYTHONDONTWRITEBYTECODE"] = "1"
    if not targets:
        return GateResult("attack", True, "no candidate modules to import", [])

    findings: List[Finding] = []
    with tempfile.TemporaryDirectory(prefix="netguard-") as guarddir:
        prefix, extra_env, mechanism = isolation_prefix(guarddir)
        env = dict(base_env, **extra_env)

        isolated = False
        try:
            check = subprocess.run(prefix + [python_exe, "-c", ISOLATION_SELF_TEST],
                                   cwd=workdir, env=env, capture_output=True,
                                   text=True, timeout=30)
            isolated = check.stdout.strip() == "BLOCKED"
        except subprocess.TimeoutExpired:
            isolated = False  # a hang proves nothing about enforcement
        except OSError:
            isolated = False
        if not isolated:
            findings.append(Finding(
                "attack", "warn", "WEAK_SANDBOX",
                f"network containment unproven (mechanism={mechanism}); "
                "relying on Python-level denials only"))

        try:
            proc = subprocess.run(prefix + [python_exe, "-c", PROBE, json.dumps(targets)],
                                  cwd=workdir, env=env, capture_output=True,
                                  text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            findings.append(Finding("attack", "block", "PROBE_TIMEOUT",
                                    "import probe exceeded its deadline"))
            return GateResult("attack", False, "timeout", findings)

    payload: Dict[str, Any] = {}
    if proc.stdout.strip():
        try:
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
        except json.JSONDecodeError:
            payload = {}
    if payload.get("blocked"):
        findings.append(Finding("attack", "block", "NETWORK_AT_IMPORT",
                                "candidate touched the network while imported: "
                                + ", ".join(sorted(set(payload["blocked"])))))
    results = payload.get("results") or {}
    if not results:
        findings.append(Finding("attack", "block", "PROBE_NO_OUTPUT",
                                f"probe produced no result (exit {proc.returncode})"))
    for mod, status in results.items():
        if status.startswith("error:"):
            findings.append(Finding("attack", "block", "IMPORT_ERROR",
                                    f"{mod} failed to import: {status[6:]}"))
    imported = sum(1 for s in results.values() if s == "imported")
    detail = f"{imported}/{len(targets)} module(s) imported cleanly"
    detail += (f"; network isolation verified ({mechanism})" if isolated
               else f"; WEAK sandbox (mechanism={mechanism} unproven)")
    return GateResult("attack", not any(f.severity == "block" for f in findings), detail, findings)


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def review(pr_dir: Optional[str], zip_path: Optional[str], baseline_dir: str,
           python_exe: str) -> Verdict:
    verdict = Verdict()
    with tempfile.TemporaryDirectory(prefix="pr-review-") as tmp:
        workdir = os.path.join(tmp, "candidate")
        os.makedirs(workdir)
        materialize_candidate(pr_dir, zip_path, workdir)

        original_files = candidate_python_files(pr_dir) if pr_dir else candidate_python_files(workdir)
        before = sorted(os.path.relpath(p, pr_dir or workdir) if pr_dir else os.path.relpath(p, workdir)
                        for p in original_files)

        restored = overlay_baseline(baseline_dir, workdir)
        # Lint the candidate's own bytes, not the restored baseline.
        lint_files = [f for f in before if f not in restored]
        probe_targets = [os.path.splitext(f)[0].replace(os.sep, ".") for f in lint_files]

        # The probe runs first: importing untrusted code is the highest-risk step,
        # and a module that cannot import is not a reviewable artifact.
        gates = [run_attack_probe(workdir, python_exe, probe_targets)]
        lint = run_lint(workdir, lint_files)
        lint.findings.extend(run_lint_tokens(workdir, lint_files).findings)
        lint.passed = not lint.findings
        gates.append(lint)
        gates.append(run_diff(workdir, pr_dir))
        gates.append(run_tests(workdir, python_exe))

        verdict.gates = gates
        verdict.findings = [f for g in gates for f in g.findings]

    blocking = [f for f in verdict.findings if f.severity == "block"]
    if blocking:
        verdict.verdict = REJECTED
        verdict.reason = "; ".join(sorted({f"{f.gate}:{f.code}" for f in blocking}))
    else:
        verdict.verdict = APPROVED
        verdict.reason = "all gates passed"
    return verdict


def render_text(v: Verdict) -> str:
    lines = [
        f"PR REVIEW VERDICT: {v.verdict}",
        f"contributor: {v.contributor}  job: {v.job}",
        f"reason: {v.reason}",
        "",
    ]
    for g in v.gates:
        lines.append(f"  [{'PASS' if g.passed else 'FAIL'}] {g.name:<7} {g.detail}")
        for f in g.findings:
            loc = f" ({f.file}{':' + str(f.line) if f.line else ''})" if f.file else ""
            lines.append(f"       - {f.severity.upper():<5} {f.code}: {f.message}{loc}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Review a candidate PR for musedin-hire-verifier")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--pr-dir", help="directory containing the candidate contribution")
    src.add_argument("--zip", help="zip archive of the candidate contribution")
    parser.add_argument("--baseline-dir", default=os.path.dirname(os.path.abspath(__file__)),
                        help="directory holding the curated baseline (default: this script's dir)")
    parser.add_argument("--python", default=sys.executable, help="interpreter used for gates")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    try:
        verdict = review(args.pr_dir, args.zip, args.baseline_dir, args.python)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        print(f"review harness error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2))
    else:
        print(render_text(verdict))
    return 0 if verdict.verdict == APPROVED else 1


if __name__ == "__main__":
    sys.exit(main())
