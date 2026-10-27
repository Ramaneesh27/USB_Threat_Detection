"""
Self-contained tests for scanners/signature_verifier.py (run: python -m unittest discover tests).

They build a tiny synthetic PE, sign it Authenticode-style with throw-away keys, and check every
verdict. Nothing here needs Windows. (Verifying a *real* Microsoft-signed binary is still worth
doing once on Windows - see README_CHANGES.md.)
"""
import datetime as dt
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scanners import signature_verifier as sv


# ---- tiny DER encoder -------------------------------------------------------
def der(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 128 else bytes([0x80 | (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + body

def seq(*p): return der(0x30, b"".join(p))
def sset(*p): return der(0x31, b"".join(p))
def octet(b): return der(0x04, b)
def integer(i): return der(0x02, i.to_bytes((i.bit_length() + 8) // 8, "big"))
def null(): return b"\x05\x00"
def oid(s):
    a = [int(x) for x in s.split(".")]
    out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        chunk = [v & 0x7F]; v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F)); v >>= 7
        out += bytes(reversed(chunk))
    return der(0x06, out)


# ---- key / cert helpers -----------------------------------------------------
def make_cert(cn, key, issuer_cn=None, issuer_key=None, ca=False, eku=True):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
         .not_valid_after(now + dt.timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


def make_pe():
    f = bytearray(0x400)
    f[0:2] = b"MZ"; f[0x3C:0x40] = (0x80).to_bytes(4, "little")
    f[0x80:0x84] = b"PE\0\0"
    f[0x86:0x88] = (1).to_bytes(2, "little")          # one section
    f[0x94:0x96] = (240).to_bytes(2, "little")        # optional header size (PE32+)
    opt = 0x98
    f[opt:opt + 2] = (0x20B).to_bytes(2, "little")
    f[opt + 60:opt + 64] = (0x200).to_bytes(4, "little")   # SizeOfHeaders
    f[opt + 108:opt + 112] = (16).to_bytes(4, "little")    # NumberOfRvaAndSizes
    sect = opt + 240
    f[sect + 16:sect + 20] = (0x200).to_bytes(4, "little")  # SizeOfRawData
    f[sect + 20:sect + 24] = (0x200).to_bytes(4, "little")  # PointerToRawData
    f[0x200:0x400] = bytes(range(256)) * 2
    return f


def sign_pe(pe: bytearray, leaf_key, leaf_cert, extra_certs):
    opt = 0x98; chk = opt + 64; sec = opt + 112 + 32
    pe_hash = hashlib.sha256(bytes(pe[:chk]) + bytes(pe[chk + 4:sec]) + bytes(pe[sec + 8:0x200]) + bytes(pe[0x200:0x400])).digest()
    content = seq(seq(oid("1.3.6.1.4.1.311.2.1.15"), seq()), seq(seq(oid("2.16.840.1.101.3.4.2.1"), null()), octet(pe_hash)))
    content_value = content[len(content) - (len(content) - 4):] if False else der_value(content)
    md = hashlib.sha256(content_value).digest()
    attrs_body = seq(oid("1.2.840.113549.1.9.3"), sset(oid("1.3.6.1.4.1.311.2.1.4"))) + seq(oid("1.2.840.113549.1.9.4"), sset(octet(md)))
    sig = leaf_key.sign(der(0x31, attrs_body), padding.PKCS1v15(), hashes.SHA256())
    si = seq(integer(1), seq(leaf_cert.issuer.public_bytes(), integer(leaf_cert.serial_number)),
             seq(oid("2.16.840.1.101.3.4.2.1"), null()), der(0xA0, attrs_body),
             seq(oid("1.2.840.113549.1.1.1"), null()), octet(sig))
    certs = b"".join(c.public_bytes(serialization.Encoding.DER) for c in [leaf_cert] + extra_certs)
    sd = seq(integer(1), sset(seq(oid("2.16.840.1.101.3.4.2.1"), null())),
             seq(oid("1.3.6.1.4.1.311.2.1.4"), der(0xA0, content)), der(0xA0, certs), sset(si))
    blob = seq(oid("1.2.840.113549.1.7.2"), der(0xA0, sd))
    blob += b"\0" * (-len(blob) % 8)
    win = (len(blob) + 8).to_bytes(4, "little") + (0x0200).to_bytes(2, "little") + (2).to_bytes(2, "little") + blob
    out = bytearray(pe)
    out[sec:sec + 4] = len(pe).to_bytes(4, "little"); out[sec + 4:sec + 8] = len(win).to_bytes(4, "little")
    return bytes(out) + win


def der_value(node_bytes):
    n = sv._Node(node_bytes, 0)
    return n.value


class SignatureVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = rsa.generate_private_key(65537, 2048)
        cls.ca = make_cert("Test Root CA", cls.ca_key, ca=True, eku=False)
        cls.leaf_key = rsa.generate_private_key(65537, 2048)
        cls.leaf = make_cert("Acme Code Signing", cls.leaf_key, "Test Root CA", cls.ca_key)
        cls.signed = sign_pe(make_pe(), cls.leaf_key, cls.leaf, [cls.ca])

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.certdir = self.tmp / "certs"; self.certdir.mkdir()
        self.exe = self.tmp / "app.exe"

    def store(self, windows=None):
        orig = sv._load_windows_roots
        sv._load_windows_roots = lambda stores: dict(windows or {})
        self.addCleanup(setattr, sv, "_load_windows_roots", orig)
        return sv.TrustStore(self.certdir, ("ROOT",))

    def run_verify(self, data, store):
        self.exe.write_bytes(data)
        return sv.verify_pe_file(self.exe, store)

    def test_unsigned(self):
        self.assertEqual(self.run_verify(bytes(make_pe()), self.store()).status, sv.UNSIGNED)

    def test_untrusted_without_whitelist(self):
        r = self.run_verify(self.signed, self.store())
        self.assertEqual(r.status, sv.UNTRUSTED_ROOT); self.assertTrue(r.is_signed); self.assertFalse(r.is_trusted)

    def test_custom_whitelist_ca_pem(self):
        (self.certdir / "ca.pem").write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        r = self.run_verify(self.signed, self.store())
        self.assertEqual(r.status, sv.VALID_CUSTOM, r.message); self.assertEqual(r.trusted_by, ["custom"])

    def test_custom_whitelist_leaf_der(self):
        (self.certdir / "company.cer").write_bytes(self.leaf.public_bytes(serialization.Encoding.DER))
        self.assertEqual(self.run_verify(self.signed, self.store()).status, sv.VALID_CUSTOM)

    def test_whitelist_picked_up_without_restart(self):
        st = self.store()
        self.assertEqual(self.run_verify(self.signed, st).status, sv.UNTRUSTED_ROOT)
        (self.certdir / "ca.crt").write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        self.assertEqual(self.run_verify(self.signed, st).status, sv.VALID_CUSTOM)

    def test_windows_store(self):
        st = self.store(windows={sv._fingerprint(self.ca): self.ca})
        r = self.run_verify(self.signed, st)
        self.assertEqual(r.status, sv.VALID_WINDOWS); self.assertEqual(r.trusted_by, ["windows"])

    def test_tampered_file_detected(self):
        (self.certdir / "ca.pem").write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        data = bytearray(self.signed); data[0x250] ^= 0xFF
        self.assertEqual(self.run_verify(bytes(data), self.store()).status, sv.DIGEST_MISMATCH)

    def test_tampered_signature_detected(self):
        (self.certdir / "ca.pem").write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        data = bytearray(self.signed)
        i = data.rindex(self.leaf.issuer.public_bytes())  # inside SignerInfo, before the signature
        data[len(data) - 40] ^= 0xFF                      # flip a byte inside the RSA signature
        self.assertEqual(self.run_verify(bytes(data), self.store()).status, sv.INVALID_SIGNATURE)

    def test_attacker_cannot_borrow_whitelisted_cert(self):
        """Self-signed attacker signature that merely EMBEDS the whitelisted CA must not be trusted."""
        (self.certdir / "ca.pem").write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        k = rsa.generate_private_key(65537, 2048)
        evil = make_cert("Acme Code Signing", k)          # same name, own key
        blob = sign_pe(make_pe(), k, evil, [self.ca])
        self.assertEqual(self.run_verify(blob, self.store()).status, sv.UNTRUSTED_ROOT)

    def test_non_code_signing_cert_rejected(self):
        (self.certdir / "ca.pem").write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        k = rsa.generate_private_key(65537, 2048)
        bad = make_cert("Web Only", k, "Test Root CA", self.ca_key)
        bad = (x509.CertificateBuilder().subject_name(bad.subject).issuer_name(bad.issuer).public_key(k.public_key())
               .serial_number(5).not_valid_before(bad.not_valid_before_utc).not_valid_after(bad.not_valid_after_utc)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(self.ca_key, hashes.SHA256()))
        self.assertEqual(self.run_verify(sign_pe(make_pe(), k, bad, [self.ca]), self.store()).status, sv.UNTRUSTED_ROOT)

    def test_bad_cert_files_are_skipped(self):
        (self.certdir / "junk.crt").write_bytes(b"not a cert")
        (self.certdir / "ca.pem").write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        st = self.store()
        self.assertEqual(self.run_verify(self.signed, st).status, sv.VALID_CUSTOM)
        self.assertIn("junk.crt", st.custom_errors)

    def test_garbage_file_never_raises(self):
        self.assertEqual(self.run_verify(b"MZ" + b"\0" * 10, self.store()).status, sv.ERROR)


if __name__ == "__main__":
    unittest.main()
