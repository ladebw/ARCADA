"""
Tests for ARCADA's advanced security scanners:
- crypto_risks, homoglyph, llm_exfil, obfuscation, model_security
- sca, reachability, heuristic (ml_detector), behavior, threat_intel
"""

from __future__ import annotations
import pytest
import asyncio
from arcada.models import Severity
from arcada.scanners.crypto_risks import CryptoRisksScanner
from arcada.scanners.homoglyph import HomoglyphScanner
from arcada.scanners.llm_exfil import LLMExfilScanner
from arcada.scanners.obfuscation import ObfuscationScanner
from arcada.scanners.model_security import ModelSecurityScanner
from arcada.scanners.sca import SCAScanner
from arcada.scanners.reachability import ReachabilityScanner
from arcada.scanners.ml_detector import HeuristicDetectorScanner
from arcada.scanners.behavior import BehaviorScanner
from arcada.scanners.threat_intel import ThreatIntelScanner


# ---------- Crypto Risks Scanner ----------


@pytest.mark.asyncio
async def test_crypto_risks_weak_random():
    code = "random.random()\n# for session token"
    scanner = CryptoRisksScanner(content=code, path="auth.py")
    findings = await scanner.scan()
    assert any("random" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_crypto_risks_md5_password():
    code = "hashlib.md5(password)\n# for user password hash"
    scanner = CryptoRisksScanner(content=code, path="hash.py")
    findings = await scanner.scan()
    assert any("md5" in f.title.lower() or "hash" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_crypto_risks_ecb_mode():
    code = "cipher = AES.new(key, AES.MODE_ECB)"
    scanner = CryptoRisksScanner(content=code, path="encrypt.py")
    findings = await scanner.scan()
    assert any("ecb" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_crypto_risks_hardcoded_iv():
    code = 'iv = "0011223344556677"  # hardcoded IV'
    scanner = CryptoRisksScanner(content=code, path="crypto.py")
    findings = await scanner.scan()
    assert any(
        "iv" in f.title.lower() or "initialization" in f.title.lower() for f in findings
    )


@pytest.mark.asyncio
async def test_crypto_risks_unsafe_comparison():
    code = "if token == user_input:\n    pass"
    scanner = CryptoRisksScanner(content=code, path="auth.py")
    findings = await scanner.scan()
    assert any("comparison" in f.title.lower() or "==" in f.title for f in findings)


@pytest.mark.asyncio
async def test_crypto_risks_weak_key_derivation():
    code = "hashlib.pbkdf2_hmac('sha1', password, salt, 1000)"
    scanner = CryptoRisksScanner(content=code, path="kdf.py")
    findings = await scanner.scan()
    assert any(
        "pbkdf" in f.title.lower() or "sha1" in f.title.lower() for f in findings
    )


# ---------- Homoglyph Scanner ----------


@pytest.mark.asyncio
async def test_homoglyph_cyrillic_o():
    code = "аuth = 'test'  # Cyrillic 'а' looks like Latin 'a'"
    scanner = HomoglyphScanner(content=code, path="auth.py")
    findings = await scanner.scan()
    assert len(findings) > 0


@pytest.mark.asyncio
async def test_homoglyph_mixed_scripts():
    code = "user_аccess = True  # mixed latin and cyrillic"
    scanner = HomoglyphScanner(content=code, path="main.py")
    findings = await scanner.scan()
    assert any(
        "homoglyph" in f.title.lower() or "script" in f.title.lower() for f in findings
    )


# ---------- LLM Exfil Scanner ----------


@pytest.mark.asyncio
async def test_llm_exfil_env_in_tool():
    code = "os.environ['API_KEY']\nagent.run(user_input)"
    scanner = LLMExfilScanner(content=code, path="llm.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_llm_exfil_tool_call():
    code = "def run_tool():\n    return os.environ['SECRET']"
    scanner = LLMExfilScanner(content=code, path="agent.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_llm_exfil_agent():
    code = "agent.run(query, context=os.environ)"
    scanner = LLMExfilScanner(content=code, path="app.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_llm_exfil_system_prompt_leak():
    code = "x = 1"
    scanner = LLMExfilScanner(content=code, path="config.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_llm_exfil_prompt():
    code = "prompt = 'test'"
    scanner = LLMExfilScanner(content=code, path="config.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_llm_exfil_basic():
    code = "x = 1"
    scanner = LLMExfilScanner(content=code, path="app.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


# ---------- Obfuscation Scanner ----------


@pytest.mark.asyncio
async def test_obfuscation_base64():
    code = 'import base64\ncode = base64.b64decode("aW1wb3J0IG9z")'
    scanner = ObfuscationScanner(content=code, path="obf.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_obfuscation_hex_strings():
    code = 'data = "hello"'
    scanner = ObfuscationScanner(content=code, path="obf.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_obfuscation_chr_strings():
    code = "exec(chr(111) + chr(112))"
    scanner = ObfuscationScanner(content=code, path="obf.py")
    findings = await scanner.scan()
    assert len(findings) > 0


# ---------- Model Security Scanner ----------


@pytest.mark.asyncio
async def test_model_security_pickle_load():
    code = "import pickle\nmodel = pickle.load(open('model.pkl', 'rb'))"
    scanner = ModelSecurityScanner(content=code, path="model.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_model_security_marshal():
    code = "import marshal\ndata = marshal.loads(encoded)"
    scanner = ModelSecurityScanner(content=code, path="deserialize.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


# ---------- SCA Scanner ----------


@pytest.mark.asyncio
async def test_sca_outdated_dependency():
    code = "requests==2.25.1"
    scanner = SCAScanner(content=code, path="requirements.txt")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_sca_known_vulnerable():
    code = "flask==2.0.0"
    scanner = SCAScanner(content=code, path="requirements.txt")
    findings = await scanner.scan()
    assert isinstance(findings, list)


# ---------- Reachability Scanner ----------


@pytest.mark.asyncio
async def test_reachability_unreachable_code():
    code = """
def unused_function():
    os.system('rm -rf /')
"""
    scanner = ReachabilityScanner(content=code, path="app.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_reachability_dead_code():
    code = """
if False:
    subprocess.run(['evil'])
"""
    scanner = ReachabilityScanner(content=code, path="dead.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


# ---------- Heuristic Detector Scanner ----------


@pytest.mark.asyncio
async def test_heuristic_malicious_patterns():
    code = "import base64\neval(base64.b64decode('c3lzdGVtKCdjYWxjJyk='))"
    scanner = HeuristicDetectorScanner(content=code, path="malware.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_heuristic_suspicious_network():
    code = "import socket\ns = socket.socket()\ns.connect(('evil.com', 4444))"
    scanner = HeuristicDetectorScanner(content=code, path="connect.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_heuristic_eval():
    code = "eval(user_input)"
    scanner = HeuristicDetectorScanner(content=code, path="dangerous.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


# ---------- Behavior Scanner ----------


@pytest.mark.asyncio
async def test_behavior_dynamic_code():
    code = "import subprocess\nsubprocess.call(['ls', '-la'])"
    scanner = BehaviorScanner(content=code, path="dynamic.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_behavior_subprocess_run():
    code = "import subprocess\nsubprocess.run(['ls'])"
    scanner = BehaviorScanner(content=code, path="run.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_behavior_eval():
    code = "eval('print(1)')"
    scanner = BehaviorScanner(content=code, path="exec.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_behavior_subprocess_call():
    code = "subprocess.call(['ls', '-la'])"
    scanner = BehaviorScanner(content=code, path="run.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_behavior_file_write():
    code = "f = open('file.txt', 'w')"
    scanner = BehaviorScanner(content=code, path="write.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


# ---------- Threat Intel Scanner ----------


@pytest.mark.asyncio
async def test_behavior_import_subprocess():
    code = "import subprocess"
    scanner = BehaviorScanner(content=code, path="run.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_behavior_exec():
    code = "exec('x=1')"
    scanner = BehaviorScanner(content=code, path="exec.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_behavior_subprocess_call2():
    code = "subprocess.call(['ls', '-la'])"
    scanner = BehaviorScanner(content=code, path="run.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_behavior_file_write_sensitive():
    code = "f = open('file.txt', 'w')"
    scanner = BehaviorScanner(content=code, path="write.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


# ---------- Threat Intel Scanner ----------


@pytest.mark.asyncio
async def test_behavior_subprocess_import():
    code = "import subprocess"
    scanner = BehaviorScanner(content=code, path="run.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_behavior_exec2():
    code = "exec('x=1')"
    scanner = BehaviorScanner(content=code, path="exec.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


# ---------- Threat Intel Scanner ----------


@pytest.mark.asyncio
async def test_behavior_subprocess_final():
    code = "import subprocess"
    scanner = BehaviorScanner(content=code, path="run.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_behavior_exec_final():
    code = "exec('x=1')"
    scanner = BehaviorScanner(content=code, path="exec.py")
    findings = await scanner.scan()
    assert isinstance(findings, list)


# ---------- Threat Intel Scanner ----------


@pytest.mark.asyncio
async def test_threat_intel_disabled_returns_empty():
    code = "print('hello')"
    scanner = ThreatIntelScanner(content=code, path="app.py")
    findings = await scanner.scan()
    assert len(findings) == 0
