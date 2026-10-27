"""
Offline Authenticode signature verification for PE files (.exe, .dll, .sys, .scr).

Nothing in this module touches the network: no CRL/OCSP lookups, no
timestamp-server calls, no WinVerifyTrust URL retrieval. Trust is decided
purely from two LOCAL sources:

  1. The Windows "Trusted Root Certification Authorities" store, read with
     ssl.enum_certificates("ROOT") (standard library, Windows only - it is the
     same Win32 CertEnumCertificatesInStore call wincertstore wraps, so no
     extra dependency is needed).
  2. A user-managed whitelist folder (config.CERTIFICATES_DIR, default
     <data>/certificates/). Drop purchased company certificates there as
     .crt / .pem / .cer (PEM or DER). A certificate placed there is trusted
     whether it is the code-signing (leaf) cert itself or the CA that issued it.
     New files are picked up automatically; no restart needed.

What "valid" means here (all four must hold):
  a. The PKCS#7 signature over the signed attributes verifies with the signer
     certificate's public key.
  b. The messageDigest attribute matches the signed SpcIndirectDataContent.
  c. The Authenticode hash of the PE file on disk matches the digest that was
     signed (i.e. the file has not been altered since signing).
  d. The signer certificate chains - through signatures that are checked one by
     one - to a certificate that is in the Windows ROOT store or the whitelist.

Known limits (by design, because this is offline):
  * No revocation checking.
  * Certificate expiry is reported (`expired`) but not enforced, because proving
    the file was signed before expiry needs the timestamp countersignature.
  * Only the primary signature is verified (nested dual-signatures are ignored).
  * Catalog-signed files (most Windows system binaries) carry no embedded
    signature and are reported as "unsigned".
"""

from __future__ import annotations

import hashlib
import os
import ssl
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CRYPTO_AVAILABLE = False

import config
from utils.logger import get_logger

logger = get_logger(__name__)

# Result statuses
UNSIGNED = "unsigned"
VALID_WINDOWS = "valid_windows_store"
VALID_CUSTOM = "valid_custom_whitelist"
UNTRUSTED_ROOT = "untrusted_root"        # signature + file integrity OK, issuer not in any trust store
INVALID_SIGNATURE = "invalid_signature"  # PKCS#7 signature / attributes do not verify
DIGEST_MISMATCH = "digest_mismatch"      # file was modified after it was signed
ERROR = "error"                          # unreadable / malformed / unsupported
UNAVAILABLE = "unavailable"              # `cryptography` not installed

TRUSTED_STATUSES = {VALID_WINDOWS, VALID_CUSTOM}

_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
_OID_ANY_EKU = "2.5.29.37.0"
_HASH_BY_OID = {
    "1.3.14.3.2.26": ("sha1", "SHA-1"),
    "2.16.840.1.101.3.4.2.1": ("sha256", "SHA-256"),
    "2.16.840.1.101.3.4.2.2": ("sha384", "SHA-384"),
    "2.16.840.1.101.3.4.2.3": ("sha512", "SHA-512"),
}


class SignatureError(Exception):
    """Malformed or unsupported signature structure."""


@dataclass
class SignatureResult:
    status: str = UNSIGNED
    is_signed: bool = False            # an embedded signature exists
    is_trusted: bool = False           # valid AND chains to a trusted store
    trusted_by: list[str] = field(default_factory=list)   # "windows" and/or "custom"
    signer_subject: str = ""
    issuer: str = ""
    thumbprint_sha256: str = ""
    not_after: str = ""
    expired: bool = False
    digest_algorithm: str = ""
    chain: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


# ---------------------------------------------------------------------------
# Minimal DER reader (enough for PKCS#7 / Authenticode; definite lengths only)
# ---------------------------------------------------------------------------
class _Node:
    __slots__ = ("buf", "tag", "start", "vstart", "end")

    def __init__(self, buf: bytes, pos: int) -> None:
        if pos + 2 > len(buf):
            raise SignatureError("truncated DER")
        self.buf, self.start, self.tag = buf, pos, buf[pos]
        if self.tag & 0x1F == 0x1F:
            raise SignatureError("high-tag-number form not supported")
        length, p = buf[pos + 1], pos + 2
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or n > 4:
                raise SignatureError("indefinite/oversized BER length not supported")
            if p + n > len(buf):
                raise SignatureError("truncated DER length")
            length, p = int.from_bytes(buf[p:p + n], "big"), p + n
        self.vstart, self.end = p, p + length
        if self.end > len(buf):
            raise SignatureError("DER element overruns its container")

    @property
    def value(self) -> bytes:
        return self.buf[self.vstart:self.end]

    @property
    def raw(self) -> bytes:
        return self.buf[self.start:self.end]

    def children(self) -> list["_Node"]:
        out, p = [], self.vstart
        while p < self.end:
            child = _Node(self.buf, p)
            out.append(child)
            p = child.end
        return out


def _oid_str(node: _Node) -> str:
    data = node.value
    if node.tag != 0x06 or not data:
        raise SignatureError("expected OBJECT IDENTIFIER")
    parts = [str(data[0] // 40), str(data[0] % 40)]
    acc = 0
    for byte in data[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


# ---------------------------------------------------------------------------
# Trust store: Windows ROOT store + user whitelist folder
# ---------------------------------------------------------------------------
def _fingerprint(cert: "x509.Certificate") -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _load_windows_roots(stores: tuple[str, ...]) -> dict[str, "x509.Certificate"]:
    """Read trust anchors from the Windows certificate store. Empty dict off-Windows."""
    enum = getattr(ssl, "enum_certificates", None)
    if enum is None:
        return {}
    roots: dict[str, "x509.Certificate"] = {}
    for store in stores:
        try:
            entries = enum(store)
        except (OSError, PermissionError) as exc:
            logger.warning("Could not read Windows store %s: %s", store, exc)
            continue
        for der, encoding, trust in entries:
            if encoding != "x509_asn":
                continue
            # `trust` is True (all purposes) or a set of allowed EKU OIDs.
            if trust is not True and _OID_CODE_SIGNING not in trust and _OID_ANY_EKU not in trust:
                continue
            try:
                cert = x509.load_der_x509_certificate(der)
            except ValueError:
                continue
            roots[_fingerprint(cert)] = cert
    return roots


def _load_certificate_file(path: Path) -> list["x509.Certificate"]:
    data = path.read_bytes()
    if b"PRIVATE KEY" in data:
        logger.warning("%s contains a PRIVATE KEY. Only the certificate is used, but private "
                       "keys should not be stored in this folder.", path.name)
    if b"-----BEGIN" in data:
        return list(x509.load_pem_x509_certificates(data))
    return [x509.load_der_x509_certificate(data)]


class TrustStore:
    """Thread-safe, self-refreshing view of every certificate we are willing to trust."""

    def __init__(self, custom_dir: Path = config.CERTIFICATES_DIR,
                 windows_stores: tuple[str, ...] = config.SIGNATURE_WINDOWS_STORES) -> None:
        self._custom_dir = Path(custom_dir)
        self._windows_stores = windows_stores
        self._lock = threading.Lock()
        self._windows: Optional[dict[str, "x509.Certificate"]] = None
        self._custom: dict[str, "x509.Certificate"] = {}
        self._custom_signature: Optional[tuple] = None
        self.custom_errors: dict[str, str] = {}   # file name -> why it was skipped (for the UI)

    def _folder_signature(self) -> tuple:
        if not self._custom_dir.is_dir():
            return ()
        items = []
        for entry in sorted(self._custom_dir.iterdir()):
            if entry.suffix.lower() in config.SIGNATURE_CUSTOM_CERT_EXTENSIONS and entry.is_file():
                st = entry.stat()
                items.append((entry.name, st.st_mtime_ns, st.st_size))
        return tuple(items)

    def snapshot(self) -> tuple[dict, dict]:
        """Return (windows_roots, custom_certs), reloading whichever changed."""
        with self._lock:
            if self._windows is None:
                self._windows = _load_windows_roots(self._windows_stores)
                logger.info("Loaded %d trust anchor(s) from the Windows store", len(self._windows))
            try:
                sig = self._folder_signature()
            except OSError as exc:
                logger.warning("Cannot read certificate whitelist folder: %s", exc)
                sig = ()
            if sig != self._custom_signature:
                custom: dict[str, "x509.Certificate"] = {}
                errors: dict[str, str] = {}
                for name, _, _ in sig:
                    try:
                        for cert in _load_certificate_file(self._custom_dir / name):
                            custom[_fingerprint(cert)] = cert
                    except (ValueError, OSError) as exc:
                        errors[name] = str(exc)
                        logger.warning("Skipping unreadable certificate %s: %s", name, exc)
                self._custom, self._custom_signature, self.custom_errors = custom, sig, errors
                logger.info("Certificate whitelist: %d certificate(s) from %d file(s)",
                            len(custom), len(sig))
            return self._windows, self._custom


_store_singleton: Optional[TrustStore] = None
_store_lock = threading.Lock()


def get_trust_store() -> TrustStore:
    global _store_singleton
    with _store_lock:
        if _store_singleton is None:
            _store_singleton = TrustStore()
        return _store_singleton


# ---------------------------------------------------------------------------
# PE + Authenticode parsing
# ---------------------------------------------------------------------------
@dataclass
class _PEInfo:
    header: bytes
    checksum_off: int
    secdir_off: int
    size_of_headers: int
    sections: list[tuple[int, int]]   # (raw pointer, raw size)
    cert_off: int
    cert_size: int
    file_size: int


def _u16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 2], "little")


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


def _parse_pe(f, file_size: int) -> _PEInfo:
    head = f.read(64)
    if len(head) < 64 or head[:2] != b"MZ":
        raise SignatureError("not a PE file (no MZ header)")
    pe_off = _u32(head, 0x3C)
    f.seek(pe_off)
    nt = f.read(24)
    if len(nt) < 24 or nt[:4] != b"PE\0\0":
        raise SignatureError("not a PE file (no PE signature)")
    n_sections, opt_size = _u16(nt, 6), _u16(nt, 20)
    opt_off = pe_off + 24
    f.seek(0)
    probe = f.read(min(file_size, opt_off + opt_size + 40 * n_sections + 16))
    if len(probe) < opt_off + opt_size + 40 * n_sections:
        raise SignatureError("truncated PE headers")
    magic = _u16(probe, opt_off)
    if magic == 0x10B:
        dirs_off, nrva_off = opt_off + 96, opt_off + 92
    elif magic == 0x20B:
        dirs_off, nrva_off = opt_off + 112, opt_off + 108
    else:
        raise SignatureError("unknown optional-header magic")
    size_of_headers = _u32(probe, opt_off + 60)
    if not 0 < size_of_headers <= min(file_size, 4 * 1024 * 1024):
        raise SignatureError("implausible SizeOfHeaders")
    f.seek(0)
    header = f.read(size_of_headers)
    sec_entry = dirs_off + 4 * 8
    if _u32(header, nrva_off) <= 4 or sec_entry + 8 > len(header):
        cert_off = cert_size = 0
    else:
        cert_off, cert_size = _u32(header, sec_entry), _u32(header, sec_entry + 4)
    sect_table = opt_off + opt_size
    sections = [(_u32(header, sect_table + 40 * i + 20), _u32(header, sect_table + 40 * i + 16))
                for i in range(n_sections)]
    return _PEInfo(header, opt_off + 64, sec_entry, size_of_headers, sections,
                   cert_off, cert_size, file_size)


def _authenticode_hash(f, info: _PEInfo, algo: str) -> bytes:
    """Hash the PE exactly as Authenticode does (skips checksum, security dir entry, cert table)."""
    h = hashlib.new(algo)
    hdr = info.header
    h.update(hdr[:info.checksum_off])
    h.update(hdr[info.checksum_off + 4:info.secdir_off])
    h.update(hdr[info.secdir_off + 8:info.size_of_headers])
    hashed = info.size_of_headers

    def stream(offset: int, length: int) -> None:
        f.seek(offset)
        remaining = length
        while remaining > 0:
            chunk = f.read(min(1 << 20, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)

    for ptr, size in sorted((s for s in info.sections if s[1] > 0), key=lambda s: s[0]):
        stream(ptr, min(size, max(0, info.file_size - ptr)))
        hashed += size
    extra = info.file_size - hashed - info.cert_size
    if extra > 0:
        stream(hashed, extra)
    return h.digest()


def _parse_pkcs7(blob: bytes) -> dict:
    """Pull the pieces we verify out of the Authenticode PKCS#7 SignedData."""
    root = _Node(blob, 0)
    top = root.children()
    if len(top) < 2 or _oid_str(top[0]) != _OID_SIGNED_DATA:
        raise SignatureError("not a PKCS#7 SignedData structure")
    signed = top[1].children()[0].children()

    encap = signed[2].children()
    if len(encap) < 2:
        raise SignatureError("SignedData has no content")
    content = encap[1].children()[0]                 # SpcIndirectDataContent SEQUENCE
    digest_info = content.children()[1].children()   # DigestInfo {AlgId, OCTET STRING}
    spc_alg_oid = _oid_str(digest_info[0].children()[0])
    spc_digest = digest_info[1].value

    certs: list[bytes] = []
    signer_infos: Optional[_Node] = None
    for node in signed[3:]:
        if node.tag == 0xA0:
            certs = [c.raw for c in node.children()]
        elif node.tag == 0x31:
            signer_infos = node
    if signer_infos is None or not signer_infos.children():
        raise SignatureError("no SignerInfo present")
    si = signer_infos.children()[0].children()

    issuer_der = si[1].children()[0].raw
    serial = int.from_bytes(si[1].children()[1].value, "big", signed=True)
    digest_oid = _oid_str(si[2].children()[0])
    idx, signed_attrs = 3, None
    if si[idx].tag == 0xA0:
        signed_attrs, idx = si[idx], idx + 1
    signature = si[idx + 1].value

    message_digest = None
    if signed_attrs is not None:
        for attr in signed_attrs.children():
            parts = attr.children()
            if _oid_str(parts[0]) == _OID_MESSAGE_DIGEST:
                message_digest = parts[1].children()[0].value
    return {
        "certs": certs, "issuer_der": issuer_der, "serial": serial, "digest_oid": digest_oid,
        "signed_attrs_der": (b"\x31" + signed_attrs.raw[1:]) if signed_attrs is not None else None,
        "message_digest": message_digest, "signature": signature,
        "content_value": content.value, "spc_alg_oid": spc_alg_oid, "spc_digest": spc_digest,
    }


# ---------------------------------------------------------------------------
# Certificate chain / trust
# ---------------------------------------------------------------------------
def _hash_class(oid: str):
    return {"sha1": hashes.SHA1, "sha256": hashes.SHA256,
            "sha384": hashes.SHA384, "sha512": hashes.SHA512}[_HASH_BY_OID[oid][0]]


def _verify_signer_signature(cert: "x509.Certificate", pkcs7: dict) -> None:
    data = pkcs7["signed_attrs_der"] if pkcs7["signed_attrs_der"] is not None else pkcs7["content_value"]
    hash_cls = _hash_class(pkcs7["digest_oid"])
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(pkcs7["signature"], data, padding.PKCS1v15(), hash_cls())
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(pkcs7["signature"], data, ec.ECDSA(hash_cls()))
    else:
        raise SignatureError(f"unsupported signer key type {type(pub).__name__}")


def _build_chain(leaf, embedded: list, windows: dict, custom: dict) -> list:
    """Walk leaf -> issuer, verifying each link's signature, stopping at a trusted cert."""
    trusted = {**windows, **custom}
    pool = list(trusted.values()) + embedded        # trusted issuers are tried first
    chain, cur = [leaf], leaf
    for _ in range(8):
        if _fingerprint(cur) in trusted:
            break
        issuer = None
        for cand in pool:
            if cand.subject != cur.issuer:
                continue
            try:
                cur.verify_directly_issued_by(cand)
            except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
                continue
            issuer = cand
            break
        if issuer is None or _fingerprint(issuer) == _fingerprint(cur):
            break
        chain.append(issuer)
        cur = issuer
    return chain


def _not_after(cert) -> datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    return value if value is not None else cert.not_valid_after.replace(tzinfo=timezone.utc)


def _allows_code_signing(cert) -> bool:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return True
    oids = {o.dotted_string for o in eku}
    return _OID_CODE_SIGNING in oids or _OID_ANY_EKU in oids


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def verify_pe_file(path: str | Path, store: Optional[TrustStore] = None) -> SignatureResult:
    """Verify the embedded Authenticode signature of a PE file. Never raises."""
    if not _CRYPTO_AVAILABLE:
        return SignatureResult(status=UNAVAILABLE,
                               message="The 'cryptography' package is not installed.")
    try:
        return _verify(Path(path), store or get_trust_store())
    except SignatureError as exc:
        return SignatureResult(status=ERROR, is_signed=True, message=f"Malformed signature: {exc}")
    except (OSError, ValueError, IndexError, UnsupportedAlgorithm) as exc:
        return SignatureResult(status=ERROR, message=f"Could not verify signature: {exc}")


def _verify(path: Path, store: TrustStore) -> SignatureResult:
    file_size = path.stat().st_size
    with open(path, "rb") as f:
        info = _parse_pe(f, file_size)
        if info.cert_off == 0 or info.cert_size == 0:
            return SignatureResult(status=UNSIGNED, message="No Authenticode signature present.")
        if info.cert_off + info.cert_size > file_size or info.cert_size < 16:
            raise SignatureError("certificate table points outside the file")
        f.seek(info.cert_off)
        win_cert = f.read(info.cert_size)
        if _u16(win_cert, 6) != 0x0002:      # WIN_CERT_TYPE_PKCS_SIGNED_DATA
            raise SignatureError("unsupported WIN_CERTIFICATE type")
        pkcs7 = _parse_pkcs7(win_cert[8:])

        result = SignatureResult(is_signed=True)
        if pkcs7["digest_oid"] not in _HASH_BY_OID or pkcs7["spc_alg_oid"] not in _HASH_BY_OID:
            raise SignatureError("unsupported or weak digest algorithm")
        result.digest_algorithm = _HASH_BY_OID[pkcs7["spc_alg_oid"]][1]

        # Locate signer certificate (issuer + serial number).
        embedded = []
        for der in pkcs7["certs"]:
            try:
                embedded.append(x509.load_der_x509_certificate(der))
            except ValueError:
                continue
        signer = next((c for c in embedded if c.serial_number == pkcs7["serial"]
                       and c.issuer.public_bytes() == pkcs7["issuer_der"]), None)
        if signer is None:
            raise SignatureError("signer certificate is not embedded in the signature")
        result.signer_subject = signer.subject.rfc4514_string()
        result.issuer = signer.issuer.rfc4514_string()
        result.thumbprint_sha256 = _fingerprint(signer)
        result.not_after = _not_after(signer).isoformat()
        result.expired = _not_after(signer) < datetime.now(timezone.utc)

        # (a)+(b) signature and signed-attribute integrity
        content_hash = hashlib.new(_HASH_BY_OID[pkcs7["digest_oid"]][0], pkcs7["content_value"]).digest()
        if pkcs7["message_digest"] is not None and pkcs7["message_digest"] != content_hash:
            result.status, result.message = INVALID_SIGNATURE, "Signed attributes do not match the signed content."
            return result
        try:
            _verify_signer_signature(signer, pkcs7)
        except InvalidSignature:
            result.status, result.message = INVALID_SIGNATURE, "Signature does not verify against the signer certificate."
            return result

        # (c) the file itself
        actual = _authenticode_hash(f, info, _HASH_BY_OID[pkcs7["spc_alg_oid"]][0])
        if actual != pkcs7["spc_digest"]:
            result.status, result.message = DIGEST_MISMATCH, "File contents changed after it was signed."
            return result

    # (d) trust
    if not _allows_code_signing(signer):
        result.status, result.message = UNTRUSTED_ROOT, "Signer certificate is not valid for code signing."
        return result
    windows, custom = store.snapshot()
    chain = _build_chain(signer, embedded, windows, custom)
    result.chain = [c.subject.rfc4514_string() for c in chain]
    fps = {_fingerprint(c) for c in chain}
    if fps & custom.keys():
        result.trusted_by.append("custom")
    if fps & windows.keys():
        result.trusted_by.append("windows")
    if result.trusted_by:
        result.is_trusted = True
        result.status = VALID_WINDOWS if "windows" in result.trusted_by else VALID_CUSTOM
        result.message = "Signature valid; chain trusted by " + " and ".join(result.trusted_by) + " store."
        if result.expired:
            result.message += " Note: the signer certificate has expired (timestamp not checked offline)."
    else:
        result.status = UNTRUSTED_ROOT
        result.message = ("Signature is intact but the issuing certificate is in neither the Windows "
                          "trusted-root store nor the certificates/ whitelist folder.")
    return result
