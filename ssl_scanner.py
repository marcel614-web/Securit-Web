#!/usr/bin/env python3
"""
SSL Scanner v2.2 – Analyse SSL/TLS professionnelle
Cipher suites : test individuel par suite (multi-thread)
HSTS : http.client avec suivi manuel des redirections (changement d'hôte géré)
"""

import ssl
import socket
import datetime
import json
import hashlib
import time
import re
import warnings
import http.client
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

warnings.filterwarnings("ignore", message=".*TLS.*")
warnings.filterwarnings("ignore", message=".*SSL.*")

# ─────────────────────────────────────────
#  Structures de données
# ─────────────────────────────────────────

@dataclass
class CertificateInfo:
    subject: Dict[str, str]
    issuer: Dict[str, str]
    version: int
    serial_number: str
    not_before: str
    not_after: str
    days_until_expiry: int
    is_expired: bool
    san: List[str]
    signature_algorithm: str
    fingerprint_sha1: str
    fingerprint_sha256: str
    is_self_signed: bool
    wildcard: bool
    key_type: str
    key_bits: int


@dataclass
class ProtocolSupport:
    ssl2: bool
    ssl3: bool
    tls10: bool
    tls11: bool
    tls12: bool
    tls13: bool


@dataclass
class CipherSuite:
    name: str
    protocol: str
    bits: int
    strength: str


@dataclass
class SecurityHeaders:
    hsts: Optional[str]
    hsts_max_age: Optional[int]
    hsts_preload: bool
    hsts_include_subdomains: bool


@dataclass
class VulnerabilityCheck:
    name: str
    vulnerable: bool
    description: str
    severity: str


@dataclass
class ScanResult:
    host: str
    port: int
    ip_address: str
    scan_time: str
    duration_ms: float
    grade: str
    score: int
    certificate: Optional[CertificateInfo]
    protocol_support: Optional[ProtocolSupport]
    cipher_suites: List[CipherSuite]
    security_headers: Optional[SecurityHeaders]
    vulnerabilities: List[VulnerabilityCheck]
    errors: List[str]
    warnings: List[str]


# ─────────────────────────────────────────
#  Liste des suites connues par protocole
# ─────────────────────────────────────────

CIPHER_SUITES_BY_PROTO = {
    "TLSv1.3": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256",
    ],
    "TLSv1.2": [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-CHACHA20-POLY1305",
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA256",
        "AES128-SHA256",
        "AES256-SHA",
        "AES128-SHA",
        "DES-CBC3-SHA",
        "RC4-SHA",
        "RC4-MD5",
        "NULL-SHA",
        "NULL-MD5",
    ],
    "TLSv1.1": [
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA",
        "DHE-RSA-AES256-SHA",
        "DHE-RSA-AES128-SHA",
        "AES256-SHA",
        "AES128-SHA",
        "DES-CBC3-SHA",
        "RC4-SHA",
        "RC4-MD5",
    ],
    "TLSv1.0": [
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA",
        "DHE-RSA-AES256-SHA",
        "DHE-RSA-AES128-SHA",
        "AES256-SHA",
        "AES128-SHA",
        "DES-CBC3-SHA",
        "RC4-SHA",
        "RC4-MD5",
    ],
    "SSLv3": [
        "AES256-SHA",
        "AES128-SHA",
        "DES-CBC3-SHA",
        "RC4-SHA",
        "RC4-MD5",
        "NULL-SHA",
        "NULL-MD5",
    ],
}

CIPHER_BITS_MAP: Dict[str, int] = {
    "TLS_AES_256_GCM_SHA384": 256,
    "TLS_AES_128_GCM_SHA256": 128,
    "TLS_CHACHA20_POLY1305_SHA256": 256,
    "TLS_AES_128_CCM_SHA256": 128,
    "TLS_AES_128_CCM_8_SHA256": 128,
    "ECDHE-ECDSA-AES256-GCM-SHA384": 256,
    "ECDHE-ECDSA-AES128-GCM-SHA256": 128,
    "ECDHE-ECDSA-CHACHA20-POLY1305": 256,
    "ECDHE-ECDSA-AES256-SHA384": 256,
    "ECDHE-ECDSA-AES128-SHA256": 128,
    "ECDHE-ECDSA-AES256-SHA": 256,
    "ECDHE-ECDSA-AES128-SHA": 128,
    "ECDHE-ECDSA-DES-CBC3-SHA": 112,
    "ECDHE-RSA-AES256-GCM-SHA384": 256,
    "ECDHE-RSA-AES128-GCM-SHA256": 128,
    "ECDHE-RSA-CHACHA20-POLY1305": 256,
    "ECDHE-RSA-AES256-SHA384": 256,
    "ECDHE-RSA-AES128-SHA256": 128,
    "ECDHE-RSA-AES256-SHA": 256,
    "ECDHE-RSA-AES128-SHA": 128,
    "ECDHE-RSA-DES-CBC3-SHA": 112,
    "ECDHE-RSA-RC4-SHA": 128,
    "DHE-RSA-AES256-GCM-SHA384": 256,
    "DHE-RSA-AES128-GCM-SHA256": 128,
    "DHE-RSA-CHACHA20-POLY1305": 256,
    "DHE-RSA-AES256-SHA256": 256,
    "DHE-RSA-AES128-SHA256": 128,
    "DHE-RSA-AES256-SHA": 256,
    "DHE-RSA-AES128-SHA": 128,
    "DHE-RSA-DES-CBC3-SHA": 112,
    "DHE-DSS-AES256-GCM-SHA384": 256,
    "DHE-DSS-AES128-GCM-SHA256": 128,
    "DHE-DSS-AES256-SHA256": 256,
    "DHE-DSS-AES128-SHA256": 128,
    "DHE-DSS-AES256-SHA": 256,
    "DHE-DSS-AES128-SHA": 128,
    "AES256-GCM-SHA384": 256,
    "AES128-GCM-SHA256": 128,
    "AES256-SHA256": 256,
    "AES128-SHA256": 128,
    "AES256-SHA": 256,
    "AES128-SHA": 128,
    "DES-CBC3-SHA": 112,
    "RC4-SHA": 128,
    "RC4-MD5": 128,
    "NULL-SHA": 0,
    "NULL-MD5": 0,
    "EXP-RC4-MD5": 40,
    "EXP-DES-CBC-SHA": 40,
}

INSECURE_KW = ["NULL", "EXP-", "EXPORT", "ANON", "ANULL", "ENULL", "RC4", "RC2", "IDEA"]
WEAK_KW     = ["DES-CBC3", "3DES", "DES-CBC-", "SEED"]


def _cipher_strength(name: str, bits: int) -> str:
    nu = name.upper()
    for kw in INSECURE_KW:
        if kw in nu:
            return "insecure"
    if bits == 0:
        bits = CIPHER_BITS_MAP.get(name, 0)
    if bits > 0 and bits < 112:
        return "insecure"
    for kw in WEAK_KW:
        if kw in nu:
            return "weak"
    if any(x in nu for x in ["GCM", "CCM", "POLY1305", "CHACHA20", "TLS_"]):
        return "strong"
    return "acceptable"


# ─────────────────────────────────────────
#  Parseur ASN.1 DER (complet)
# ─────────────────────────────────────────

class _DER:
    OID_MAP = {
        "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L",
        "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
        "1.2.840.113549.1.9.1": "email",
        "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
        "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
        "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
        "1.2.840.113549.1.1.1": "rsaEncryption",
        "1.2.840.10045.2.1": "ecPublicKey",
        "1.2.840.10040.4.1": "dsaEncryption",
        "1.3.101.110": "X25519", "1.3.101.111": "X448",
        "1.2.840.10045.3.1.7": "P-256",
        "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521",
        "1.3.132.0.10": "secp256k1",
    }
    EC_BITS = {"P-256": 256, "P-384": 384, "P-521": 521, "secp256k1": 256}

    @staticmethod
    def rl(data: bytes, pos: int) -> Tuple[int, int]:
        b = data[pos]; pos += 1
        if not (b & 0x80):
            return b, pos
        n = b & 0x7f
        ln = 0
        for _ in range(n):
            ln = (ln << 8) | data[pos]; pos += 1
        return ln, pos

    @staticmethod
    def tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
        tag = data[pos]; pos += 1
        ln, pos = _DER.rl(data, pos)
        return tag, data[pos:pos+ln], pos+ln

    @staticmethod
    def oid(data: bytes) -> str:
        if not data: return ""
        res = [str(data[0]//40), str(data[0]%40)]
        v = 0
        for b in data[1:]:
            v = (v << 7) | (b & 0x7f)
            if not (b & 0x80):
                res.append(str(v)); v = 0
        return ".".join(res)

    @staticmethod
    def name(data: bytes) -> Dict[str, str]:
        res = {}
        pos = 0
        while pos < len(data):
            try:
                _, rdn, pos = _DER.tlv(data, pos)
                rp = 0
                while rp < len(rdn):
                    _, atv, rp = _DER.tlv(rdn, rp)
                    ap = 0
                    _, ob, ap = _DER.tlv(atv, ap)
                    _, vb, _  = _DER.tlv(atv, ap)
                    o = _DER.OID_MAP.get(_DER.oid(ob), _DER.oid(ob))
                    try: v = vb.decode("utf-8", errors="replace")
                    except: v = vb.hex()
                    res[o] = v
            except: break
        return res

    @staticmethod
    def time(data: bytes, tag: int) -> Optional[datetime.datetime]:
        try:
            s = data.decode("ascii")
            if tag == 0x17 and len(s) >= 12:
                yy = int(s[0:2])
                yr = 2000+yy if yy < 50 else 1900+yy
                return datetime.datetime(yr, int(s[2:4]), int(s[4:6]),
                                         int(s[6:8]), int(s[8:10]), int(s[10:12]))
            elif tag == 0x18 and len(s) >= 14:
                return datetime.datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]),
                                         int(s[8:10]), int(s[10:12]), int(s[12:14]))
        except: pass
        return None

    @classmethod
    def parse(cls, der: bytes) -> dict:
        r = {"subject":{}, "issuer":{}, "not_before":None, "not_after":None,
             "sig_alg":"unknown", "san":[], "key_type":"unknown", "key_bits":0,
             "version":3, "serial":""}
        try:
            _, cert, _ = cls.tlv(der, 0)
            pos = 0
            _, tbs,  pos = cls.tlv(cert, pos)
            _, siga, pos = cls.tlv(cert, pos)
            sap = 0; _, sa_oid, sap = cls.tlv(siga, sap)
            r["sig_alg"] = cls.OID_MAP.get(cls.oid(sa_oid), cls.oid(sa_oid))
            cls._tbs(tbs, r)
        except: pass
        return r

    @classmethod
    def _tbs(cls, data: bytes, r: dict):
        pos = 0; field = 0
        while pos < len(data):
            try:
                tag, val, pos = cls.tlv(data, pos)
                if tag == 0xa0:
                    _, vv, _ = cls.tlv(val, 0)
                    r["version"] = int.from_bytes(vv,"big")+1; continue
                if field == 0:   r["serial"] = val.hex().upper()
                elif field == 1:
                    p2=0; _, ob, p2 = cls.tlv(val,p2)
                    o = cls.oid(ob); r["sig_alg"] = cls.OID_MAP.get(o,o)
                elif field == 2: r["issuer"]  = cls.name(val)
                elif field == 3:
                    vp=0
                    nbt,nbv,vp = cls.tlv(val,vp)
                    nat,nav,_  = cls.tlv(val,vp)
                    r["not_before"] = cls.time(nbv,nbt)
                    r["not_after"]  = cls.time(nav,nat)
                elif field == 4: r["subject"] = cls.name(val)
                elif field == 5: cls._spki(val, r)
                elif tag == 0xa3: cls._exts(val, r)
                field += 1
            except: break

    @classmethod
    def _spki(cls, data: bytes, r: dict):
        try:
            p=0; _, alg, p = cls.tlv(data,p); _, bs, _ = cls.tlv(data,p)
            ap=0; _, ob, ap = cls.tlv(alg,ap); kalg = cls.OID_MAP.get(cls.oid(ob),"")
            key_bytes = bs[1:] if bs else b""
            if "rsa" in kalg.lower():
                r["key_type"] = "RSA"
                try:
                    _, seq, _ = cls.tlv(key_bytes,0); _, nb, _ = cls.tlv(seq,0)
                    if nb and nb[0]==0: nb=nb[1:]
                    r["key_bits"] = len(nb)*8
                except: r["key_bits"] = len(key_bytes)*8
            elif "ec" in kalg.lower():
                r["key_type"] = "EC"
                try:
                    _, cb, _ = cls.tlv(alg,ap)
                    cn = cls.OID_MAP.get(cls.oid(cb),"")
                    r["key_bits"] = cls.EC_BITS.get(cn, len(key_bytes)*4)
                except: r["key_bits"] = len(key_bytes)*4
            elif "ed25519" in kalg.lower():
                r["key_type"]="Ed25519"; r["key_bits"]=256
            elif "dsa" in kalg.lower():
                r["key_type"]="DSA"; r["key_bits"]=len(key_bytes)*8
            else:
                r["key_type"]=kalg or "unknown"; r["key_bits"]=len(key_bytes)*8
        except: pass

    @classmethod
    def _exts(cls, data: bytes, r: dict):
        try:
            _, seq, _ = cls.tlv(data,0); p=0
            while p < len(seq):
                _, ext, p = cls.tlv(seq,p)
                ep=0; _, ob, ep = cls.tlv(ext,ep)
                eo = cls.oid(ob)
                if ext[ep] == 0x01: _,_,ep = cls.tlv(ext,ep)
                if ep < len(ext):
                    _, osv, _ = cls.tlv(ext,ep)
                    if eo == "2.5.29.17": cls._san(osv, r)
        except: pass

    @classmethod
    def _san(cls, data: bytes, r: dict):
        try:
            _, seq, _ = cls.tlv(data,0); p=0
            while p < len(seq):
                gt, gv, p = cls.tlv(seq,p)
                t = gt & 0x1f
                if   t == 2: r["san"].append(gv.decode("ascii","replace"))
                elif t == 7:
                    if len(gv)==4:  r["san"].append(".".join(str(b) for b in gv))
                    elif len(gv)==16:
                        r["san"].append(":".join(format(int.from_bytes(gv[i:i+2],"big"),"x")
                                                 for i in range(0,16,2)))
        except: pass


def analyze_certificate(der: bytes) -> CertificateInfo:
    p = _DER.parse(der)
    subject = p["subject"]
    issuer  = p["issuer"]
    now     = datetime.datetime.utcnow()

    if p["not_after"]:
        days_left  = (p["not_after"] - now).days
        is_expired = days_left < 0
        not_after_s  = p["not_after"].strftime("%Y-%m-%d %H:%M:%S UTC")
        not_before_s = p["not_before"].strftime("%Y-%m-%d %H:%M:%S UTC") if p["not_before"] else "N/A"
    else:
        days_left, is_expired = -1, True
        not_after_s = not_before_s = "N/A"

    sha1   = ":".join(hashlib.sha1(der).hexdigest().upper()[i:i+2]   for i in range(0,40,2))
    sha256 = ":".join(hashlib.sha256(der).hexdigest().upper()[i:i+2] for i in range(0,64,2))

    def _norm(d): return {k:v.strip() for k,v in d.items()}
    is_self_signed = bool(subject and issuer and _norm(subject) == _norm(issuer))

    cn = subject.get("CN", "")
    return CertificateInfo(
        subject=subject, issuer=issuer,
        version=p["version"], serial_number=p["serial"],
        not_before=not_before_s, not_after=not_after_s,
        days_until_expiry=days_left, is_expired=is_expired,
        san=p["san"], signature_algorithm=p["sig_alg"],
        fingerprint_sha1=sha1, fingerprint_sha256=sha256,
        is_self_signed=is_self_signed, wildcard=cn.startswith("*."),
        key_type=p["key_type"], key_bits=p["key_bits"],
    )


# ─────────────────────────────────────────
#  Détection des protocoles
# ─────────────────────────────────────────

def _try_tls(host: str, port: int, minv, maxv, timeout: float = 5.0) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try:
            ctx.minimum_version = minv
            ctx.maximum_version = maxv
        except AttributeError:
            pass
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                ss.do_handshake()
                return True
    except: return False


def check_protocol_support(host: str, port: int, timeout: float = 10.0) -> ProtocolSupport:
    tls13 = _try_tls(host, port, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, timeout)
    tls12 = _try_tls(host, port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, timeout)

    TLSv1_1 = getattr(ssl.TLSVersion, 'TLSv1_1', None)
    tls11 = _try_tls(host, port, TLSv1_1, TLSv1_1, timeout) if TLSv1_1 else False

    TLSv1_0 = getattr(ssl.TLSVersion, 'TLSv1_0', None)
    tls10 = _try_tls(host, port, TLSv1_0, TLSv1_0, timeout) if TLSv1_0 else False

    return ProtocolSupport(ssl2=False, ssl3=False,
                           tls10=tls10, tls11=tls11, tls12=tls12, tls13=tls13)


# ─────────────────────────────────────────
#  Énumération des suites (test individuel)
# ─────────────────────────────────────────

def _test_cipher(host: str, port: int, cipher_name: str, proto_version, timeout: float):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = proto_version
            ctx.maximum_version = proto_version
        except AttributeError:
            pass
        ctx.set_ciphers(cipher_name)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ss.do_handshake()
                actual_cipher, proto, bits = ss.cipher()
                if actual_cipher and actual_cipher.upper() == cipher_name.upper():
                    return (cipher_name, proto if proto else "TLS", bits)
    except Exception:
        pass
    return None


def enumerate_ciphers(host: str, port: int, timeout: float = 10.0) -> List[CipherSuite]:
    result = []
    seen = set()

    proto_support = check_protocol_support(host, port, timeout)

    version_map = {}
    if proto_support.tls13:
        version_map["TLSv1.3"] = ssl.TLSVersion.TLSv1_3
    if proto_support.tls12:
        version_map["TLSv1.2"] = ssl.TLSVersion.TLSv1_2
    if proto_support.tls11:
        TLSv1_1 = getattr(ssl.TLSVersion, 'TLSv1_1', None)
        if TLSv1_1:
            version_map["TLSv1.1"] = TLSv1_1
    if proto_support.tls10:
        TLSv1_0 = getattr(ssl.TLSVersion, 'TLSv1_0', None)
        if TLSv1_0:
            version_map["TLSv1.0"] = TLSv1_0

    tasks = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for proto_name, proto_enum in version_map.items():
            suite_list = CIPHER_SUITES_BY_PROTO.get(proto_name, [])
            for cipher_name in suite_list:
                if cipher_name in seen:
                    continue
                tasks.append(executor.submit(_test_cipher, host, port, cipher_name, proto_enum, timeout))

        for future in as_completed(tasks):
            res = future.result()
            if res and res[0] not in seen:
                seen.add(res[0])
                name, proto_label, bits = res
                bits_final = bits if bits > 0 else CIPHER_BITS_MAP.get(name, 0)
                strength = _cipher_strength(name, bits_final)
                result.append(CipherSuite(name=name, protocol=proto_label, bits=bits_final, strength=strength))

    order = {"strong": 0, "acceptable": 1, "weak": 2, "insecure": 3}
    result.sort(key=lambda c: (order.get(c.strength, 9), c.name))
    return result


# ─────────────────────────────────────────
#  En-têtes de sécurité HTTP (FONCTIONNEL)
# ─────────────────────────────────────────

def check_security_headers(host: str, port: int, timeout: float = 8.0) -> SecurityHeaders:
    """Récupère l'en-tête HSTS en suivant jusqu'à 3 redirections HTTPS.
       Capture l'en-tête sur la première réponse qui le contient, même en cas de redirection ultérieure."""
    hsts = None
    hsts_max_age = None
    preload = False
    subdomains = False

    current_host = host
    current_port = port
    path = "/"
    max_redirects = 3
    redirect_count = 0

    try:
        while redirect_count <= max_redirects:
            conn = http.client.HTTPSConnection(current_host, current_port, timeout=timeout)
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            resp = conn.getresponse()

            # Vérifier systématiquement si cette réponse contient HSTS
            raw = resp.getheader("Strict-Transport-Security")
            if raw:
                hsts = raw
                hsts_max_age = None
                preload = False
                subdomains = False
                for part in [p.strip().lower() for p in raw.split(";")]:
                    if part.startswith("max-age="):
                        try: hsts_max_age = int(part.split("=")[1])
                        except: pass
                    elif part == "includesubdomains": subdomains = True
                    elif part == "preload":           preload    = True

            # Si redirection
            if resp.status in (301, 302, 307, 308):
                location = resp.getheader("Location")
                conn.close()
                if not location:
                    break

                if location.startswith("https://"):
                    parsed = urlparse(location)
                    current_host = parsed.hostname
                    current_port = parsed.port if parsed.port else 443
                    path = parsed.path if parsed.path else "/"
                    if parsed.query:
                        path += "?" + parsed.query
                elif location.startswith("http://"):
                    break
                elif location.startswith("/"):
                    path = location
                else:
                    # Chemin relatif
                    if not path.endswith("/"):
                        path = path.rsplit("/", 1)[0] + "/"
                    path = path.rstrip("/") + "/" + location.lstrip("/")

                redirect_count += 1
                continue

            # Pas de redirection : on sort de la boucle
            conn.close()
            break

    except Exception:
        pass

    return SecurityHeaders(hsts=hsts, hsts_max_age=hsts_max_age,
                           hsts_preload=preload, hsts_include_subdomains=subdomains)

# ─────────────────────────────────────────
#  Vulnérabilités
# ─────────────────────────────────────────

def check_vulnerabilities(cert: Optional[CertificateInfo],
                          proto: Optional[ProtocolSupport],
                          ciphers: List[CipherSuite]) -> List[VulnerabilityCheck]:
    V = []
    def v(name, vuln, desc, sev): V.append(VulnerabilityCheck(name, vuln, desc, sev))

    v("POODLE (SSLv3)",  proto.ssl3  if proto else False,
      "SSLv3 vulnérable à POODLE (CVE-2014-3566)", "high")
    v("DROWN (SSLv2)",   proto.ssl2  if proto else False,
      "SSLv2 expose à DROWN (CVE-2016-0800)", "critical")
    v("TLS 1.0 activé",  proto.tls10 if proto else False,
      "TLS 1.0 obsolète — BEAST, POODLE-TLS (RFC 8996)", "medium")
    v("TLS 1.1 activé",  proto.tls11 if proto else False,
      "TLS 1.1 obsolète depuis 2021 (RFC 8996)", "low")

    insecure = [c for c in ciphers if c.strength == "insecure"]
    weak     = [c for c in ciphers if c.strength == "weak"]
    v("Cipher suites insécurisées", bool(insecure),
      f"Détectées : {', '.join(c.name for c in insecure[:3])}",  "high")
    v("Cipher suites faibles (3DES…)", bool(weak),
      f"Faibles : {', '.join(c.name for c in weak[:3])}",  "medium")

    no_pfs = [c for c in ciphers if c.strength in ("strong","acceptable")
              and not any(x in c.name.upper() for x in ["ECDHE","DHE","TLS_"])]
    v("Absence de Forward Secrecy", bool(no_pfs),
      "Des ciphers sans PFS (RSA key exchange) sont disponibles", "medium")

    if cert:
        v("Certificat expiré",        cert.is_expired,
          "Le certificat a expiré et n'est plus valide", "critical")
        v("Certificat expire bientôt (<30j)",
          not cert.is_expired and 0 <= cert.days_until_expiry < 30,
          f"Expire dans {cert.days_until_expiry} jours", "medium")
        v("Certificat auto-signé",    cert.is_self_signed,
          "Non reconnu par les navigateurs", "high")
        sig = cert.signature_algorithm.lower()
        v("Signature MD5 (cassée)",   "md5" in sig,
          "MD5 cryptographiquement cassé depuis 2004", "critical")
        v("Signature SHA-1 (obsolète)", "sha1" in sig and "md5" not in sig,
          "SHA-1 déprécié (RFC 9155)", "medium")
        if cert.key_type == "RSA" and cert.key_bits > 0:
            v("Clé RSA < 2048 bits",
              cert.key_bits < 2048,
              f"Clé de {cert.key_bits} bits — minimum recommandé : 2048", "high")

    return V


# ─────────────────────────────────────────
#  Score et note
# ─────────────────────────────────────────

def calculate_grade(cert: Optional[CertificateInfo],
                    proto: Optional[ProtocolSupport],
                    ciphers: List[CipherSuite],
                    vulns: List[VulnerabilityCheck],
                    headers: Optional[SecurityHeaders]) -> Tuple[str, int]:
    score = 100
    ded   = []

    if proto:
        if proto.ssl2:  ded.append(40)
        if proto.ssl3:  ded.append(20)
        if proto.tls10: ded.append(10)
        if proto.tls11: ded.append(5)
        if not proto.tls12 and not proto.tls13: ded.append(30)

    if cert:
        if cert.is_expired:               ded.append(50)
        elif cert.days_until_expiry <  7: ded.append(25)
        elif cert.days_until_expiry < 30: ded.append(10)
        if cert.is_self_signed:           ded.append(25)
        sig = cert.signature_algorithm.lower()
        if "md5"  in sig: ded.append(30)
        elif "sha1" in sig: ded.append(15)
        if cert.key_type == "RSA" and cert.key_bits > 0:
            if   cert.key_bits < 1024: ded.append(30)
            elif cert.key_bits < 2048: ded.append(20)

    ded.append(min(sum(1 for c in ciphers if c.strength=="insecure")*5, 20))
    ded.append(min(sum(1 for c in ciphers if c.strength=="weak")*2,     10))

    for vv in vulns:
        if vv.vulnerable and vv.severity == "critical": ded.append(25)

    if proto and proto.tls13:
        score = min(score + 3, 100)
    if headers and headers.hsts and headers.hsts_max_age and headers.hsts_max_age >= 31536000:
        score = min(score + 5, 100)

    score = max(0, score - sum(ded))
    grade = ("A+" if score>=95 else "A" if score>=85 else "B" if score>=75 else
             "C"  if score>=65 else "D" if score>=50 else "E" if score>=30 else "F")
    return grade, score


# ─────────────────────────────────────────
#  Scanner principal
# ─────────────────────────────────────────

def _resolve_ip(host: str) -> str:
    try: return socket.gethostbyname(host)
    except: return "N/A"


class SSLScanner:
    def __init__(self, timeout: float = 10.0, check_protocols: bool = True,
                 check_headers: bool = True):
        self.timeout = timeout
        self.check_protocols = check_protocols
        self.check_headers = check_headers

    def scan(self, host: str, port: int = 443) -> ScanResult:
        t0 = time.time()
        errors: List[str] = []
        warnings: List[str] = []
        ip       = _resolve_ip(host)
        st       = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        cert_info = None; protocols = None; ciphers = []; headers = None

        # 1. Certificat
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
                    if der:
                        cert_info = analyze_certificate(der)
        except socket.timeout:
            errors.append(f"Timeout ({self.timeout}s) — hôte injoignable")
        except ConnectionRefusedError:
            errors.append(f"Connexion refusée sur {host}:{port}")
        except ssl.SSLError as e:
            errors.append(f"Erreur SSL : {e}")
        except socket.gaierror:
            errors.append(f"Résolution DNS impossible : {host}")
        except Exception as e:
            errors.append(f"Erreur : {e}")

        # 2. Protocoles
        if not errors and self.check_protocols:
            try:
                protocols = check_protocol_support(host, port, timeout=self.timeout)
                if protocols.tls10: warnings.append("TLS 1.0 activé — devrait être désactivé")
                if protocols.tls11: warnings.append("TLS 1.1 activé — devrait être désactivé")
            except Exception as e:
                warnings.append(f"Détection protocoles partielle : {e}")

        # 3. Ciphers (test individuel)
        if not errors:
            try:
                ciphers = enumerate_ciphers(host, port, timeout=self.timeout)
            except Exception as e:
                warnings.append(f"Énumération des ciphers impossible : {e}")

        # 4. Headers (HSTS)
        if not errors and self.check_headers:
            try:
                headers = check_security_headers(host, port, timeout=self.timeout)
                if not headers.hsts:
                    warnings.append("HSTS absent — risque de downgrade HTTP")
            except Exception as e:
                warnings.append(f"Vérification HSTS échouée : {e}")

        # 5-6. Vulns & score
        vulns = check_vulnerabilities(cert_info, protocols, ciphers)
        grade, score = calculate_grade(cert_info, protocols, ciphers, vulns, headers)
        if errors: grade, score = "N/A", 0

        return ScanResult(
            host=host, port=port, ip_address=ip, scan_time=st,
            duration_ms=round((time.time()-t0)*1000, 1),
            grade=grade, score=score,
            certificate=cert_info, protocol_support=protocols,
            cipher_suites=ciphers, security_headers=headers,
            vulnerabilities=vulns, errors=errors, warnings=warnings,
        )

    def scan_to_dict(self, host, port=443): return asdict(self.scan(host, port))
    def scan_to_json(self, host, port=443, indent=2):
        return json.dumps(self.scan_to_dict(host, port), indent=indent, default=str)


# ─────────────────────────────────────────
#  Rapport console
# ─────────────────────────────────────────

def print_report(r: ScanResult):
    C = {"reset":"\033[0m","bold":"\033[1m","red":"\033[91m","green":"\033[92m",
         "yellow":"\033[93m","cyan":"\033[96m","gray":"\033[90m"}
    def c(col,txt): return f"{C.get(col,'')}{txt}{C['reset']}"
    GC={"A+":"green","A":"green","B":"cyan","C":"yellow","D":"yellow","E":"red","F":"red","N/A":"gray"}

    print("\n"+"═"*64)
    print(c("bold",f"  SSL SCAN — {r.host}:{r.port}"))
    print("═"*64)
    print(f"  IP     : {r.ip_address}")
    print(f"  Scan   : {r.scan_time}  ({r.duration_ms} ms)")
    print(f"  Note   : {c(GC.get(r.grade,'gray'),c('bold',r.grade))}   Score : {r.score}/100")

    for e in r.errors:   print(f"\n  {c('red','✖')} {e}")
    for w in r.warnings: print(f"  {c('yellow','⚠')} {w}")

    if r.certificate:
        ct = r.certificate
        ec = "red" if ct.is_expired else ("yellow" if ct.days_until_expiry<30 else "green")
        print(f"\n{c('bold','  CERTIFICAT')}")
        print(f"    CN           : {ct.subject.get('CN','N/A')}")
        print(f"    Organisation : {ct.subject.get('O','N/A')}")
        print(f"    Émetteur     : {ct.issuer.get('O',ct.issuer.get('CN','N/A'))}")
        print(f"    Algo. sign.  : {ct.signature_algorithm}")
        print(f"    Clé          : {ct.key_type} {ct.key_bits} bits")
        print(f"    Expire       : {c(ec,ct.not_after)}  ({ct.days_until_expiry}j)")
        print(f"    Auto-signé   : {c('red','OUI') if ct.is_self_signed else 'non'}")
        if ct.san: print(f"    SAN          : {', '.join(ct.san[:5])}"+(f"  +{len(ct.san)-5}"if len(ct.san)>5 else""))

    if r.protocol_support:
        p=r.protocol_support
        print(f"\n{c('bold','  PROTOCOLES')}")
        for nm,ok,bad in [("SSLv2",p.ssl2,True),("SSLv3",p.ssl3,True),
                           ("TLS 1.0",p.tls10,True),("TLS 1.1",p.tls11,True),
                           ("TLS 1.2",p.tls12,False),("TLS 1.3",p.tls13,False)]:
            col="red"if(ok and bad)else"green"if(not ok and bad)or(ok and not bad)else"gray"
            print(f"    {nm:<10}: {c(col,'✔ activé' if ok else '✖ inactif')}")

    if r.cipher_suites:
        SC={"strong":"green","acceptable":"cyan","weak":"yellow","insecure":"red"}
        print(f"\n{c('bold','  CIPHER SUITES (top 8)')}")
        for cs in r.cipher_suites[:8]:
            print(f"    {c(SC.get(cs.strength,'gray'),'●')} {cs.name:<46}{cs.bits:>4} bits  [{cs.strength}]")

    if r.vulnerabilities:
        SC2={"critical":"red","high":"red","medium":"yellow","low":"cyan","info":"gray"}
        print(f"\n{c('bold','  VULNÉRABILITÉS')}")
        for vv in r.vulnerabilities:
            col=SC2.get(vv.severity,"gray") if vv.vulnerable else "green"
            print(f"    {c(col,'✖' if vv.vulnerable else '✔')} [{vv.severity.upper():<8}] {vv.name}")
            if vv.vulnerable: print(f"         {c('gray',vv.description)}")

    if r.security_headers:
        h=r.security_headers
        print(f"\n{c('bold','  SÉCURITÉ HTTP')}")
        if h.hsts:
            print(f"    HSTS             : {c('green','✔ activé')}  max-age={h.hsts_max_age}")
            print(f"    includeSubDomains: {'✔' if h.hsts_include_subdomains else '✖'}")
            print(f"    preload          : {'✔' if h.hsts_preload else '✖'}")
        else:
            print(f"    HSTS             : {c('red','✖ absent')}")

    print("\n"+"═"*64+"\n")


# ─────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────

def main():
    import argparse, sys
    p = argparse.ArgumentParser(description="SSL Scanner v2.2 — Analyse SSL/TLS")
    p.add_argument("hosts", nargs="+")
    p.add_argument("--port","-p",  type=int,   default=443)
    p.add_argument("--json","-j",  action="store_true")
    p.add_argument("--output","-o")
    p.add_argument("--no-protocols", action="store_true", help="Désactiver la vérification des protocoles")
    p.add_argument("--no-headers",   action="store_true", help="Désactiver la vérification HSTS")
    p.add_argument("--timeout","-t", type=float, default=10.0)
    args = p.parse_args()

    scanner = SSLScanner(timeout=args.timeout,
                         check_protocols=not args.no_protocols,
                         check_headers=not args.no_headers)
    results = []
    for host in args.hosts:
        host = re.sub(r"^https?://","", host.strip().rstrip("/")).split("/")[0]
        print(f"\n[*] Scan de {host}:{args.port} …", file=sys.stderr)
        r = scanner.scan(host, args.port)
        if args.json or args.output: results.append(asdict(r))
        else: print_report(r)

    if args.json or args.output:
        out = json.dumps(results[0] if len(results)==1 else results, indent=2, default=str)
        if args.output:
            with open(args.output,"w") as f: f.write(out)
            print(f"[+] Sauvegardé dans {args.output}", file=sys.stderr)
        else: print(out)

if __name__ == "__main__":
    main()