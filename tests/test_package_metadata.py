"""
Tests for PackageMetadataScanner — PyPI/npm registry analysis.
"""

from __future__ import annotations
import pytest
from arcada.scanners.package_metadata import PackageMetadataScanner
from arcada.models import Severity


@pytest.mark.asyncio
async def test_pypi_check_legit_package():
    """Query PyPI for a well-known package — should not crash."""
    scanner = PackageMetadataScanner(
        content="",
        path="requirements.txt",
        metadata={"packages": [("requests", "==2.31.0")]},
    )
    findings = await scanner.scan()
    assert isinstance(findings, list)
    # requests is legit, should not be flagged as malicious
    assert not any("KNOWN MALICIOUS" in f.title for f in findings)


@pytest.mark.asyncio
async def test_pypi_check_nonexistent_package():
    """Query PyPI for a non-existent package — should flag it."""
    scanner = PackageMetadataScanner(
        content="",
        path="requirements.txt",
        metadata={"packages": [("this-package-definitely-does-not-exist-xyz123", "")]},
    )
    findings = await scanner.scan()
    assert any("not found on PyPI" in f.title for f in findings)


@pytest.mark.asyncio
async def test_pypi_blocklisted_package():
    """Query for a known-malicious package — should flag CRITICAL."""
    scanner = PackageMetadataScanner(
        content="",
        path="requirements.txt",
        metadata={"packages": [("event-stream", "")]},
    )
    findings = await scanner.scan()
    assert any("KNOWN MALICIOUS" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_npm_check_legit_package():
    """Query npm for a well-known package."""
    scanner = PackageMetadataScanner(
        content="", path="package.json", metadata={"packages": [("express", "")]}
    )
    findings = await scanner.scan()
    assert isinstance(findings, list)
    # express is legit
    assert not any("KNOWN MALICIOUS" in f.title for f in findings)


@pytest.mark.asyncio
async def test_npm_check_nonexistent_package():
    """Query npm for a non-existent package."""
    scanner = PackageMetadataScanner(
        content="",
        path="package.json",
        metadata={"packages": [("this-package-definitely-does-not-exist-xyz123", "")]},
    )
    findings = await scanner.scan()
    assert any("not found on npm" in f.title for f in findings)


@pytest.mark.asyncio
async def test_metadata_scanner_auto_detects_npm():
    """Verify _is_npm detects npm packages."""
    scanner = PackageMetadataScanner(content="", path="package.json")
    assert scanner._is_npm("@types/node") is True
    assert scanner._is_npm("express") is True  # path is package.json → npm
    scanner2 = PackageMetadataScanner(content="", path="requirements.txt")
    assert scanner2._is_npm("requests") is False
    assert scanner2._is_npm("@scope/pkg") is True  # scoped packages always npm
