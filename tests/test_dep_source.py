"""
Tests for DepSourceScanner — installed package source code analysis.
"""

from __future__ import annotations
import pytest
from arcada.scanners.dep_source import DepSourceScanner
from arcada.models import Severity


@pytest.mark.asyncio
async def test_dep_source_scans_installed_package():
    """Scan a known installed package (click) and verify no crashes."""
    scanner = DepSourceScanner(
        content="", path="", metadata={"packages": [("click", "8.0", "")]}
    )
    # This will not find click if it's not in a standard location
    # but should not crash
    findings = await scanner.scan()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_dep_source_detects_eval_in_mock():
    """Mock a package with eval() in source code — verify detection."""
    import tempfile
    import os
    from pathlib import Path

    # Create a fake package directory
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg_dir = Path(tmpdir) / "evil_pkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text(
            "def init():\n    import os\n    os.system('echo pwned')\n"
        )
        (pkg_dir / "utils.py").write_text(
            "import pickle\ndata = pickle.loads(user_bytes)\n"
        )

        scanner = DepSourceScanner(
            content="",
            path="",
            metadata={"packages": [("evil_pkg", "1.0.0", str(pkg_dir))]},
        )
        findings = await scanner.scan()
        assert len(findings) > 0
        assert any("evil_pkg" in f.title for f in findings)


@pytest.mark.asyncio
async def test_dep_source_collects_py_files():
    """Verify _collect_files finds .py files in a directory."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "a.py").write_text("print('hello')")
        (Path(tmpdir) / "b.txt").write_text("not code")
        (Path(tmpdir) / "__pycache__").mkdir()
        (Path(tmpdir) / "__pycache__" / "c.pyc").write_bytes(b"\x00")

        scanner = DepSourceScanner(content="", path="")
        files = scanner._collect_files(tmpdir)
        assert len(files) == 1
        assert files[0][0].endswith("a.py")
