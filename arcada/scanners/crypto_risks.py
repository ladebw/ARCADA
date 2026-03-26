"""
Crypto Risks Scanner
Detects cryptographic weaknesses: weak random, MD5/SHA1 for keys,
ECB mode, hardcoded IVs, non-constant-time comparisons.
High signal-to-noise for AI APIs handling auth tokens.
"""

from __future__ import annotations
import re
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class CryptoRisksScanner(BaseScanner):
    name = "crypto_risks"

    async def scan(self) -> list[ScannerResult]:
        self._detect_weak_random()
        self._detect_weak_hashes()
        self._detect_ecb_mode()
        self._detect_hardcoded_iv()
        self._detect_unsafe_comparison()
        self._detect_raw_encryption()
        self._detect_weak_key_derivation()
        self._detect_insecure_random_module()
        return self.findings

    def _detect_weak_random(self):
        """Detect random.random() or Math.random() used for security purposes."""
        patterns = [
            (r"random\.random\(\)", "random.random() for token/auth"),
            (r"random\.randint\(.*\)", "random.randint() for security"),
            (r"random\.choice\(.*\)", "random.choice() for security"),
            (r"Math\.random\(\)", "Math.random() for token/auth"),
            (
                r"crypto\.randomBytes\([^)]*\)(?!\.toString\('hex'\))",
                "crypto.randomBytes without hex encoding",
            ),
            (r"Math\.floor\(Math\.random\(\)", "Math.random() in floor for token"),
        ]
        security_contexts = [
            r"token",
            r"password",
            r"secret",
            r"key",
            r"auth",
            r"session",
            r"uuid",
            r"nonce",
            r"salt",
            r"verification",
            r"otp",
            r"captcha",
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                is_security = any(
                    re.search(ctx, context, re.IGNORECASE) for ctx in security_contexts
                )
                if is_security:
                    self.add_finding(
                        title=f"Weak random for security: {label}",
                        description=(
                            f"Using {label} for security-sensitive operations. "
                            "random module is not cryptographically secure. "
                            "Tokens, passwords, and session IDs can be predicted."
                        ),
                        severity=Severity.CRITICAL,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Use secrets.token_hex() (Python) or crypto.randomBytes() with hex encoding (Node.js)",
                        impact="Attackers can predict tokens, hijack sessions, bypass authentication.",
                    )

    def _detect_weak_hashes(self):
        """Detect MD5 or SHA1 used for password/key derivation."""
        patterns = [
            (r"hashlib\.md5\(", "hashlib.md5()"),
            (r"hashlib\.sha1\(", "hashlib.sha1()"),
            (r"hashlib\.new\(['\"]md5['\"]", "hashlib.new('md5')"),
            (r"hashlib\.new\(['\"]sha1['\"]", "hashlib.new('sha1')"),
            (r"MessageDigest\.getInstance\(['\"]MD5['\"]", "MessageDigest MD5"),
            (r"MessageDigest\.getInstance\(['\"]SHA-?1['\"]", "MessageDigest SHA-1"),
            (r"CryptoJS\.MD5\(", "CryptoJS.MD5()"),
            (r"CryptoJS\.SHA1\(", "CryptoJS.SHA1()"),
            (r"digest\(['\"]md5['\"]", "digest('md5')"),
            (r"digest\(['\"]sha1['\"]", "digest('sha1')"),
            (r"\.update\(.*md5", "MD5 update"),
            (r"\.update\(.*sha1", "SHA1 update"),
        ]
        weak_contexts = [
            r"password",
            r"secret",
            r"key",
            r"token",
            r"hash",
            r"encrypt",
            r"derive",
            r"pbkdf",
            r"signature",
            r"hmac",
            r"auth",
            r"credential",
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                is_weak = any(
                    re.search(ctx, context, re.IGNORECASE) for ctx in weak_contexts
                )
                if is_weak:
                    self.add_finding(
                        title=f"Weak hash for crypto: {label}",
                        description=(
                            f"Using {label} for password/key derivation. "
                            "MD5 and SHA1 are cryptographically broken and reversible."
                        ),
                        severity=Severity.HIGH,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Use hashlib.pbkdf2_hmac() with SHA-256+ or argon2-cffi",
                        impact="Passwords and keys can be cracked offline.",
                    )

    def _detect_ecb_mode(self):
        """Detect ECB mode block cipher usage."""
        patterns = [
            (r"AES\.MODE_ECB", "AES.MODE_ECB"),
            (r"\.encrypt\(.*mode\s*=\s*.*ECB", "ECB mode encrypt"),
            (r"\.decrypt\(.*mode\s*=\s*.*ECB", "ECB mode decrypt"),
            (r"cipher\.MODE_ECB", "cipher.MODE_ECB"),
            (r"mode\s*=\s*['\"]ECB['\"]", "ECB mode string"),
            (r"CryptoJS\.mode\.ECB", "CryptoJS.mode.ECB"),
            (r"\.createEncryptor\(.*ECB", "ECB createEncryptor"),
            (r"pyaes\.MODE_ECB", "pyaes MODE_ECB"),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                self.add_finding(
                    title=f"ECB mode block cipher: {label}",
                    description=(
                        "Using ECB (Electronic Codebook) mode encryption. "
                        "ECB produces deterministic output - identical plaintext "
                        "blocks produce identical ciphertext blocks, revealing patterns."
                    ),
                    severity=Severity.HIGH,
                    evidence=context,
                    location=f"{self.path}:{lineno}",
                    fix="Use CBC, CTR, or GCM mode with random IVs",
                    impact="Encrypted data leaks patterns and structure.",
                )

    def _detect_hardcoded_iv(self):
        """Detect hardcoded initialization vectors."""
        patterns = [
            (r"iv\s*=\s*['\"][0-9a-fA-F]{32}['\"]", "hardcoded IV (32 hex)"),
            (r"iv\s*=\s*['\"][0-9a-fA-F]{24}['\"]", "hardcoded IV (24 hex)"),
            (r"iv\s*=\s*['\"][0-9a-fA-F]{16}['\"]", "hardcoded IV (16 hex)"),
            (r"iv\s*=\s*b['\"][0-9a-fA-F]+['\"]", "hardcoded IV bytes"),
            (r"IV\s*=\s*['\"][0-9a-fA-F]+['\"]", "hardcoded IV uppercase"),
            (r"iv:\s*['\"][0-9a-fA-F]+['\"]", "IV in dict/string"),
            (r"iv_param\s*=\s*['\"]", "iv_param hardcoded"),
            (r"initializationVector", "initializationVector hardcoded"),
            (
                r"crypto\.createCipheriv\([^,]+,\s*['\"]",
                "createCipheriv with string key",
            ),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                self.add_finding(
                    title=f"Hardcoded initialization vector: {label}",
                    description=(
                        "Using a hardcoded IV (initialization vector). "
                        "IVs should be random and unique per encryption operation."
                    ),
                    severity=Severity.HIGH,
                    evidence=context,
                    location=f"{self.path}:{lineno}",
                    fix="Generate random IV per encryption: os.urandom(16) for AES",
                    impact="Same plaintext produces same ciphertext, enabling pattern analysis.",
                )

    def _detect_unsafe_comparison(self):
        """Detect non-constant-time comparison for secrets."""
        patterns = [
            (
                r"(?:if|elif|while)\s+.*==.*(?:token|secret|password|key|auth|hash)",
                "== on token/secret",
            ),
            (r"(?:if|elif|while)\s+.*==.*(?:api[_-]?key|apikey)", "== on API key"),
            (r"if\s+.*\.equals\(.*\)", "equals() comparison"),
            (r"==\s*(?:hash|digest|signature)", "== on hash/signature"),
            (r"(?:token|secret|password)\s*==", "token/secret =="),
        ]

        exclude_patterns = [
            r"hmac\.compare_digest",
            r"timingSafeEqual",
            r"secrets\.compare_digest",
            r"constanttime",
            r"\.compareTo\(",
            r"compare\(",
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=2):
                if not any(re.search(excl, context) for excl in exclude_patterns):
                    self.add_finding(
                        title=f"Non-constant-time comparison: {label}",
                        description=(
                            "Using == for comparing tokens/passwords/hashes. "
                            "Timing attacks can leak information about the secret."
                        ),
                        severity=Severity.HIGH,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Use hmac.compare_digest() (Python) or crypto.timingSafeEqual() (Node.js)",
                        impact="Timing attacks can reveal valid tokens/passwords.",
                    )

    def _detect_raw_encryption(self):
        """Detect raw encryption without padding."""
        patterns = [
            (r"\.encrypt\([^)]*\)(?!\s*[,)])", "raw encrypt call"),
            (r"\.decrypt\([^)]*\)(?!\s*[,)])", "raw decrypt call"),
            (r"NoPadding", "NoPadding mode"),
            (r"padding\s*=\s*['\"]None['\"]", "padding disabled"),
            (r"\.pad\(", "manual padding"),
            (r"\.unpad\(", "manual unpadding"),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                if "pkcs" not in context.lower() and "oaep" not in context.lower():
                    self.add_finding(
                        title=f"Raw encryption without padding: {label}",
                        description=(
                            "Encryption without proper padding. "
                            "Block ciphers require padding except in certain modes."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Use PKCS7 padding or OAEP for RSA",
                        impact="Potential plaintext recovery in certain attacks.",
                    )

    def _detect_weak_key_derivation(self):
        """Detect weak key derivation functions."""
        patterns = [
            (r"hashlib\.pbkdf2_hmac\(['\"]sha1['\"]", "PBKDF2 with SHA1"),
            (
                r"pbkdf2\([^)]*,\s*iterations\s*=\s*[0-9]{1,5}(?!\d)",
                "low iteration count",
            ),
            (r"scrypt\([^)]*,\s*N\s*=", "scrypt with low N"),
            (r"deriveKey\([^)]*,\s*1[0-9]{3}[,\)]", "deriveKey with low rounds"),
            (r"PasswordBasedEncryption", "PBE without parameters"),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                self.add_finding(
                    title=f"Weak key derivation: {label}",
                    description=(
                        f"Weak key derivation: {label}. "
                        "Low iterations or broken algorithms make keys easily crackable."
                    ),
                    severity=Severity.HIGH,
                    evidence=context,
                    location=f"{self.path}:{lineno}",
                    fix="Use PBKDF2 with SHA-256, 100k+ iterations, or argon2",
                    impact="Passwords/keys can be brute-forced.",
                )

    def _detect_insecure_random_module(self):
        """Detect insecure random module usage instead of secrets in security contexts."""
        patterns = [
            (r"from\s+random\s+import", "import random"),
            (r"import\s+random", "import random"),
            (r"Math\.random", "Math.random"),
            (r"java\.util\.Random", "java.util.Random"),
            (r"new\s+Random\(\)", "new Random()"),
            (
                r"SecureRandom\(.*System\.currentTimeMillis",
                "SecureRandom with predictable seed",
            ),
        ]
        security_contexts = [
            r"token",
            r"password",
            r"secret",
            r"key",
            r"auth",
            r"session",
            r"uuid",
            r"nonce",
            r"salt",
            r"verification",
            r"otp",
            r"captcha",
            r"id",
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                is_security = any(
                    re.search(ctx, context, re.IGNORECASE) for ctx in security_contexts
                )
                if is_security:
                    self.add_finding(
                        title=f"Insecure random module: {label}",
                        description=(
                            f"Using {label} instead of cryptographically secure random. "
                            "This module is predictable and not suitable for security."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Use secrets module (Python) or crypto.randomBytes() (Node.js)",
                        impact="Predictable random values compromise security.",
                    )
