#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Post-Quantum Anonymous and Traceable Authentication Experiments for Multi-Agent Vehicular Collaboration

Ubuntu 22.04 + Python 3 + liboqs-python runnable experiment script.

This V2 file implements the revised SCI-paper protocol with KEM-DEM tracing, signed credential requests, audit evidence, and experiments:
1. Basic performance benchmark for the proposed full scheme.
2. Baseline comparison:
   - ECDSA-P256 baseline, if cryptography is available.
   - Direct ML-DSA authentication.
   - PQ anonymous authentication without traceability.
   - PQ traceable authentication without anonymity.
   - Proposed PQ anonymous traceable authentication.
3. Ablation studies:
   - without anonymous credential;
   - without trace ciphertext;
   - without context binding;
   - static anonymous key vs periodic refresh;
   - JSON encoding vs compact binary encoding estimate.
4. Scalability experiments under different numbers of agents.
5. Security validation attacks:
   - message tampering;
   - signature tampering;
   - credential tampering;
   - unregistered agent forgery;
   - replay attack;
   - wrong tracing key.
6. Optional security-level comparison:
   - ML-DSA-44/65/87 and ML-KEM-512/768/1024, if supported by your liboqs build.

Important scope:
- This is a research prototype for the authentication layer.
- It is not a production V2X protocol stack.
- The compact binary size is an implementation-oriented estimate obtained by replacing
  base64 strings with raw bytes and using simple length-prefixed fields.

Example commands:
    python3 pq_agent_vanet_experiments.py --mode demo
    python3 pq_agent_vanet_experiments.py --mode bench --agents 10 --rounds 1000
    python3 pq_agent_vanet_experiments.py --mode compare --agents 10 --rounds 1000
    python3 pq_agent_vanet_experiments.py --mode ablation --agents 10 --rounds 1000
    python3 pq_agent_vanet_experiments.py --mode attack --rounds 100
    python3 pq_agent_vanet_experiments.py --mode scalability --rounds 1000
    python3 pq_agent_vanet_experiments.py --mode levels --rounds 500
    python3 pq_agent_vanet_experiments.py --mode all --agents 10 --rounds 500
"""

from __future__ import annotations

import argparse
import base64
import copy
import csv
import hashlib
import json
import math
import os
import random
import statistics
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import oqs
except Exception as exc:  # pragma: no cover
    print("[ERROR] Cannot import oqs. Please install liboqs-python first.")
    print("        pip install liboqs-python")
    print(f"        Detail: {exc}")
    raise

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTOGRAPHY_AVAILABLE = True
except Exception:  # pragma: no cover
    CRYPTOGRAPHY_AVAILABLE = False


VERSION = 1
DOMAIN_CREDENTIAL = "PQ-VANET-CREDENTIAL-V2"
DOMAIN_MESSAGE = "PQ-VANET-MESSAGE-V2"
DOMAIN_TRACE_AAD = "PQ-VANET-TRACE-AAD-V2"
DOMAIN_TRACE_KEY = b"PQ-VANET-TRACE-KEY-V2"
DOMAIN_DIRECT = "PQ-VANET-DIRECT-AUTH-V2"
DOMAIN_ECDSA = "PQ-VANET-ECDSA-BASELINE-V2"

SIG_ALG_DEFAULT_CANDIDATES = ("ML-DSA-65", "Dilithium3")
KEM_ALG_DEFAULT_CANDIDATES = ("ML-KEM-768", "Kyber768")

SIG_LEVEL_CANDIDATES = [
    ("ML-DSA-44", "Dilithium2"),
    ("ML-DSA-65", "Dilithium3"),
    ("ML-DSA-87", "Dilithium5"),
]
KEM_LEVEL_CANDIDATES = [
    ("ML-KEM-512", "Kyber512"),
    ("ML-KEM-768", "Kyber768"),
    ("ML-KEM-1024", "Kyber1024"),
]

BINARY_FIELD_NAMES = {
    "session_pk",
    "issuer_sig",
    "agent_sig",
    "kem_ct",
    "nonce",
    "ciphertext",
    "public_key",
    "signature",
    "credential_signature",
    "ecdsa_sig",
    "ecdsa_public_key",
}


# ---------------------------------------------------------------------------
# Basic utilities
# ---------------------------------------------------------------------------

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def canonical(obj: Any) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_ts() -> int:
    return int(time.time())


def mean_ms(values_sec: Sequence[float]) -> float:
    return statistics.mean(values_sec) * 1000.0 if values_sec else 0.0


def p95_ms(values_sec: Sequence[float]) -> float:
    if not values_sec:
        return 0.0
    ordered = sorted(values_sec)
    idx = int(math.ceil(0.95 * len(ordered))) - 1
    idx = max(0, min(idx, len(ordered) - 1))
    return ordered[idx] * 1000.0


def avg(values: Sequence[float]) -> float:
    return statistics.mean(values) if values else 0.0


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    ensure_dir(os.path.dirname(path) or ".")
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_table(title: str, rows: List[Dict[str, Any]]) -> None:
    print(f"\n=== {title} ===")
    if not rows:
        print("No data.")
        return
    cols = list(rows[0].keys())
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    header = " | ".join(c.ljust(widths[c]) for c in cols)
    sep = "-+-".join("-" * widths[c] for c in cols)
    print(header)
    print(sep)
    for r in rows:
        print(" | ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def flip_one_byte_b64(text: str) -> str:
    data = bytearray(b64d(text))
    if not data:
        return text
    data[0] ^= 0x01
    return b64e(bytes(data))


def compact_binary_size(obj: Any, key_hint: Optional[str] = None) -> int:
    """
    Estimate compact binary encoding size.

    The prototype packets use JSON and base64 for readability. This estimator replaces
    known base64 fields with their raw byte lengths and uses simple length-prefix costs.
    It is meant for a fair communication-overhead discussion, not as a normative codec.
    """
    if obj is None:
        return 1
    if isinstance(obj, bool):
        return 1
    if isinstance(obj, int):
        return 8
    if isinstance(obj, float):
        return 8
    if isinstance(obj, str):
        if key_hint in BINARY_FIELD_NAMES:
            try:
                return 4 + len(b64d(obj))
            except Exception:
                pass
        return 4 + len(obj.encode("utf-8"))
    if isinstance(obj, list):
        return 4 + sum(compact_binary_size(x) for x in obj)
    if isinstance(obj, dict):
        total = 4
        for k, v in obj.items():
            total += 2 + len(str(k).encode("utf-8"))
            total += compact_binary_size(v, key_hint=str(k))
        return total
    return 4 + len(str(obj).encode("utf-8"))


def make_message(seq: int, payload_size: int = 256) -> Dict[str, Any]:
    payload_text = "X" * max(0, payload_size)
    return {
        "version": VERSION,
        "domain": DOMAIN_MESSAGE,
        "msg_id": str(uuid.uuid4()),
        "timestamp": now_ts(),
        "nonce": str(uuid.uuid4()),
        "agent_group_id": f"CAG-{seq % 7}",
        "road_segment": f"RSU-{seq % 11}",
        "event_type": random.choice([
            "cooperative-perception",
            "emergency-warning",
            "lane-change-coordination",
            "federated-update-hash",
        ]),
        "content": {
            "seq": seq,
            "payload_hash": sha256_hex(payload_text.encode("utf-8")),
            "payload": payload_text,
            "confidence": round(0.80 + random.random() * 0.19, 4),
        },
    }


def derive_aes_key(shared_secret: bytes, info: bytes = DOMAIN_TRACE_KEY) -> bytes:
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("cryptography is required for AES-GCM trace encryption.")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def derive_trace_aes_key(shared_secret: bytes, binding: Dict[str, Any]) -> bytes:
    """
    Derive the DEM encryption key from the ML-KEM shared secret and credential-bound context.

    This implements the KEM-DEM design used in the paper:
        (ct, ss) <- ML-KEM.Encaps(pk_tr)
        k        <- KDF(ss || apk || validity || ctx || H(req))
        c_id     <- AEAD.Enc_k(trace, aad)

    The HKDF info field contains a hash of the binding data so that the resulting
    AES-GCM key is cryptographically tied to the anonymous public key, validity,
    credential context, and request evidence.
    """
    binding_hash = hashlib.sha256(canonical(binding)).digest()
    return derive_aes_key(shared_secret, info=DOMAIN_TRACE_KEY + b"|" + binding_hash)


# ---------------------------------------------------------------------------
# liboqs compatibility wrappers
# ---------------------------------------------------------------------------

def choose_mechanism(candidates: Sequence[str], enabled: Sequence[str], kind: str) -> str:
    for name in candidates:
        if name in enabled:
            return name
    raise RuntimeError(
        f"No supported {kind} mechanism found. Tried {list(candidates)}. "
        f"Enabled mechanisms include: {list(enabled)[:20]}..."
    )


def close_oqs(obj: Any) -> None:
    if obj is not None and hasattr(obj, "free"):
        try:
            obj.free()
        except Exception:
            pass


@contextmanager
def oqs_signature(alg: str, secret_key: Optional[bytes] = None):
    sig = None
    try:
        if secret_key is None:
            sig = oqs.Signature(alg)
        else:
            try:
                sig = oqs.Signature(alg, secret_key)
            except TypeError:
                sig = oqs.Signature(alg, secret_key=secret_key)
        yield sig
    finally:
        close_oqs(sig)


@contextmanager
def oqs_kem(alg: str, secret_key: Optional[bytes] = None):
    kem = None
    try:
        if secret_key is None:
            kem = oqs.KeyEncapsulation(alg)
        else:
            try:
                kem = oqs.KeyEncapsulation(alg, secret_key)
            except TypeError:
                kem = oqs.KeyEncapsulation(alg, secret_key=secret_key)
        yield kem
    finally:
        close_oqs(kem)


@dataclass
class KeyPair:
    public_key: bytes
    secret_key: bytes


def sig_keygen(sig_alg: str) -> KeyPair:
    with oqs_signature(sig_alg) as sig:
        pk = sig.generate_keypair()
        if hasattr(sig, "export_secret_key"):
            sk = sig.export_secret_key()
        elif hasattr(sig, "private_key"):
            sk = sig.private_key
        else:
            raise RuntimeError("Cannot export secret key from this oqs.Signature object.")
        return KeyPair(public_key=pk, secret_key=sk)


def sig_sign(sig_alg: str, secret_key: bytes, message: bytes) -> bytes:
    with oqs_signature(sig_alg, secret_key) as sig:
        try:
            return sig.sign(message)
        except TypeError:
            return sig.sign(message, secret_key)


def sig_verify(sig_alg: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        with oqs_signature(sig_alg) as sig:
            return bool(sig.verify(message, signature, public_key))
    except Exception:
        return False


def kem_keygen(kem_alg: str) -> KeyPair:
    with oqs_kem(kem_alg) as kem:
        pk = kem.generate_keypair()
        if hasattr(kem, "export_secret_key"):
            sk = kem.export_secret_key()
        elif hasattr(kem, "secret_key"):
            sk = kem.secret_key
        else:
            raise RuntimeError("Cannot export secret key from this oqs.KeyEncapsulation object.")
        return KeyPair(public_key=pk, secret_key=sk)


def kem_encapsulate(kem_alg: str, public_key: bytes) -> Tuple[bytes, bytes]:
    with oqs_kem(kem_alg) as kem:
        if hasattr(kem, "encap_secret"):
            return kem.encap_secret(public_key)
        if hasattr(kem, "encapsulate"):
            return kem.encapsulate(public_key)
        raise RuntimeError("This liboqs-python KEM object has no encapsulation method.")


def kem_decapsulate(kem_alg: str, secret_key: bytes, ciphertext: bytes) -> bytes:
    with oqs_kem(kem_alg, secret_key) as kem:
        if hasattr(kem, "decap_secret"):
            return kem.decap_secret(ciphertext)
        if hasattr(kem, "decapsulate"):
            return kem.decapsulate(ciphertext)
        raise RuntimeError("This liboqs-python KEM object has no decapsulation method.")


def load_default_algorithms() -> Tuple[str, str]:
    enabled_sig = oqs.get_enabled_sig_mechanisms()
    enabled_kem = oqs.get_enabled_kem_mechanisms()
    sig_alg = choose_mechanism(SIG_ALG_DEFAULT_CANDIDATES, enabled_sig, "signature")
    kem_alg = choose_mechanism(KEM_ALG_DEFAULT_CANDIDATES, enabled_kem, "KEM")
    return sig_alg, kem_alg


def get_level_algorithms() -> List[Tuple[str, str, str]]:
    enabled_sig = oqs.get_enabled_sig_mechanisms()
    enabled_kem = oqs.get_enabled_kem_mechanisms()
    levels = []
    names = ["NIST-L1", "NIST-L3", "NIST-L5"]
    for name, sig_candidates, kem_candidates in zip(names, SIG_LEVEL_CANDIDATES, KEM_LEVEL_CANDIDATES):
        sig_alg = next((x for x in sig_candidates if x in enabled_sig), None)
        kem_alg = next((x for x in kem_candidates if x in enabled_kem), None)
        if sig_alg and kem_alg:
            levels.append((name, sig_alg, kem_alg))
    return levels


def print_environment(sig_alg: str, kem_alg: str) -> None:
    print("=== Environment ===")
    if hasattr(oqs, "oqs_version"):
        try:
            print(f"liboqs version        : {oqs.oqs_version()}")
        except Exception:
            pass
    if hasattr(oqs, "oqs_python_version"):
        try:
            print(f"liboqs-python version : {oqs.oqs_python_version()}")
        except Exception:
            pass
    print(f"Signature algorithm  : {sig_alg}")
    print(f"KEM algorithm        : {kem_alg}")
    print(f"cryptography ECDSA   : {'enabled' if CRYPTOGRAPHY_AVAILABLE else 'disabled'}")


# ---------------------------------------------------------------------------
# ECDSA baseline wrappers
# ---------------------------------------------------------------------------

def ecdsa_keygen() -> Tuple[Any, bytes]:
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("cryptography is not available; ECDSA baseline is disabled.")
    sk = ec.generate_private_key(ec.SECP256R1())
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    return sk, pk_bytes


def ecdsa_sign(sk: Any, message: bytes) -> bytes:
    return sk.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
        pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Shared data classes
# ---------------------------------------------------------------------------

@dataclass
class AgentState:
    real_id: str
    pq_keypair: Optional[KeyPair] = None
    session_keypair: Optional[KeyPair] = None
    credential: Optional[Dict[str, Any]] = None
    ecdsa_private_key: Any = None
    ecdsa_public_key: Optional[bytes] = None


class ReplayCache:
    def __init__(self):
        self.seen: set[str] = set()

    def check_and_add(self, nonce: str) -> bool:
        if nonce in self.seen:
            return False
        self.seen.add(nonce)
        return True


# ---------------------------------------------------------------------------
# Scheme base and concrete schemes
# ---------------------------------------------------------------------------

class SchemeBase:
    name = "Base"

    def __init__(
        self,
        sig_alg: str,
        kem_alg: str,
        issuer_name: str = "TA-RSU-EXP-01",
        payload_size: int = 256,
        context_binding: bool = True,
        replay_protection: bool = True,
    ):
        self.sig_alg = sig_alg
        self.kem_alg = kem_alg
        self.issuer_name = issuer_name
        self.payload_size = payload_size
        self.context_binding = context_binding
        self.replay_protection = replay_protection
        self.replay_cache = ReplayCache()

    def setup(self) -> None:
        raise NotImplementedError

    def reset_verifier_state(self) -> None:
        self.replay_cache = ReplayCache()

    def new_agent(self, idx: int) -> AgentState:
        raise NotImplementedError

    def prepare_agent(self, agent: AgentState, seq: int = 0) -> None:
        raise NotImplementedError

    def create_packet(self, agent: AgentState, seq: int) -> Dict[str, Any]:
        raise NotImplementedError

    def verify_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        raise NotImplementedError

    def trace_packet(self, packet: Dict[str, Any]) -> Optional[str]:
        return None

    def supports_trace(self) -> bool:
        return False

    def properties(self) -> Dict[str, str]:
        return {
            "pq_security": "No",
            "anonymity": "No",
            "traceability": "No",
            "context_binding": "Yes" if self.context_binding else "No",
        }

    def _message_signing_material(self, message: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
        if self.context_binding:
            return {
                "domain": DOMAIN_MESSAGE,
                "message": message,
                "extra": extra,
            }
        # Ablation: context fields such as road segment, group id, timestamp, and nonce
        # are not bound to the signature. This permits cross-context replay/misuse.
        return {
            "domain": DOMAIN_MESSAGE,
            "content_only": message.get("content", {}),
            "extra": extra,
        }

    def _check_message_context(self, message: Dict[str, Any]) -> Tuple[bool, str]:
        if not self.context_binding:
            return True, "context check disabled"
        ts = int(message.get("timestamp", 0))
        if abs(now_ts() - ts) > 300:
            return False, "timestamp outside acceptable window"
        nonce = str(message.get("nonce", ""))
        if self.replay_protection and not self.replay_cache.check_and_add(nonce):
            return False, "replay detected"
        required = ["msg_id", "agent_group_id", "road_segment", "event_type", "content"]
        for key in required:
            if key not in message:
                return False, f"missing context field: {key}"
        return True, "context valid"


class DirectMLDSAScheme(SchemeBase):
    name = "Direct ML-DSA"

    def setup(self) -> None:
        self.registered_pk_hashes: Dict[str, str] = {}

    def new_agent(self, idx: int) -> AgentState:
        return AgentState(real_id=f"vehicle-real-id-{idx:04d}", pq_keypair=sig_keygen(self.sig_alg))

    def prepare_agent(self, agent: AgentState, seq: int = 0) -> None:
        if agent.pq_keypair is None:
            agent.pq_keypair = sig_keygen(self.sig_alg)
        self.registered_pk_hashes[sha256_hex(agent.pq_keypair.public_key)] = agent.real_id

    def create_packet(self, agent: AgentState, seq: int) -> Dict[str, Any]:
        assert agent.pq_keypair is not None
        message = make_message(seq, self.payload_size)
        pk_b64 = b64e(agent.pq_keypair.public_key)
        material = self._message_signing_material(message, {
            "domain": DOMAIN_DIRECT,
            "public_key_hash": sha256_hex(agent.pq_keypair.public_key),
            "real_id": agent.real_id,
        })
        sig = sig_sign(self.sig_alg, agent.pq_keypair.secret_key, canonical(material))
        return {
            "scheme": self.name,
            "message": message,
            "real_agent_id": agent.real_id,
            "sig_alg": self.sig_alg,
            "public_key": pk_b64,
            "signature": b64e(sig),
        }

    def verify_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            message = packet["message"]
            ok, reason = self._check_message_context(message)
            if not ok:
                return False, reason
            pk = b64d(packet["public_key"])
            pk_hash = sha256_hex(pk)
            if pk_hash not in self.registered_pk_hashes:
                return False, "public key is not registered"
            if packet.get("real_agent_id") != self.registered_pk_hashes[pk_hash]:
                return False, "real identity does not match registered public key"
            material = self._message_signing_material(message, {
                "domain": DOMAIN_DIRECT,
                "public_key_hash": pk_hash,
                "real_id": packet.get("real_agent_id"),
            })
            if not sig_verify(packet["sig_alg"], pk, canonical(material), b64d(packet["signature"])):
                return False, "invalid direct ML-DSA signature"
            return True, "valid direct ML-DSA packet"
        except Exception as exc:
            return False, f"parse error: {exc}"

    def properties(self) -> Dict[str, str]:
        return {
            "pq_security": "Yes",
            "anonymity": "No",
            "traceability": "No",
            "context_binding": "Yes" if self.context_binding else "No",
        }


class ECDSABaselineScheme(SchemeBase):
    name = "ECDSA-P256 baseline"

    def setup(self) -> None:
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("cryptography is not available; ECDSA baseline cannot run.")
        self.registered_pk_hashes: Dict[str, str] = {}

    def new_agent(self, idx: int) -> AgentState:
        sk, pk = ecdsa_keygen()
        return AgentState(real_id=f"vehicle-real-id-{idx:04d}", ecdsa_private_key=sk, ecdsa_public_key=pk)

    def prepare_agent(self, agent: AgentState, seq: int = 0) -> None:
        if agent.ecdsa_public_key is None:
            agent.ecdsa_private_key, agent.ecdsa_public_key = ecdsa_keygen()
        self.registered_pk_hashes[sha256_hex(agent.ecdsa_public_key)] = agent.real_id

    def create_packet(self, agent: AgentState, seq: int) -> Dict[str, Any]:
        assert agent.ecdsa_private_key is not None and agent.ecdsa_public_key is not None
        message = make_message(seq, self.payload_size)
        material = self._message_signing_material(message, {
            "domain": DOMAIN_ECDSA,
            "public_key_hash": sha256_hex(agent.ecdsa_public_key),
            "real_id": agent.real_id,
        })
        sig = ecdsa_sign(agent.ecdsa_private_key, canonical(material))
        return {
            "scheme": self.name,
            "message": message,
            "real_agent_id": agent.real_id,
            "ecdsa_public_key": b64e(agent.ecdsa_public_key),
            "ecdsa_sig": b64e(sig),
        }

    def verify_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            message = packet["message"]
            ok, reason = self._check_message_context(message)
            if not ok:
                return False, reason
            pk = b64d(packet["ecdsa_public_key"])
            pk_hash = sha256_hex(pk)
            if pk_hash not in self.registered_pk_hashes:
                return False, "ECDSA public key is not registered"
            if packet.get("real_agent_id") != self.registered_pk_hashes[pk_hash]:
                return False, "real identity does not match registered ECDSA public key"
            material = self._message_signing_material(message, {
                "domain": DOMAIN_ECDSA,
                "public_key_hash": pk_hash,
                "real_id": packet.get("real_agent_id"),
            })
            if not ecdsa_verify(pk, canonical(material), b64d(packet["ecdsa_sig"])):
                return False, "invalid ECDSA signature"
            return True, "valid ECDSA packet"
        except Exception as exc:
            return False, f"parse error: {exc}"

    def properties(self) -> Dict[str, str]:
        return {
            "pq_security": "No",
            "anonymity": "No",
            "traceability": "No",
            "context_binding": "Yes" if self.context_binding else "No",
        }



class CredentialSchemeBase(SchemeBase):
    """Base class for TA-issued anonymous credential schemes.

    V2 revision highlights:
    - each agent has a long-term registration ML-DSA key pair;
    - anonymous credential requests are signed by the long-term key;
    - the credential body contains H(req_i) as audit evidence;
    - issuer signatures use an explicit domain separator;
    - subclasses may add trace envelopes.
    """

    def setup(self) -> None:
        self.issuer_keypair = sig_keygen(self.sig_alg)
        self.tracing_keypair: Optional[KeyPair] = None
        self.audit_db: Dict[str, Dict[str, Any]] = {}
        self.registration_db: Dict[str, Dict[str, Any]] = {}

    def new_agent(self, idx: int) -> AgentState:
        # pq_keypair is used here as the long-term registration key pair lpk_i/lsk_i.
        agent = AgentState(real_id=f"vehicle-real-id-{idx:04d}", pq_keypair=sig_keygen(self.sig_alg))
        self.registration_db[agent.real_id] = {
            "real_agent_id": agent.real_id,
            "long_term_pk_hash": sha256_hex(agent.pq_keypair.public_key),
            "status": "valid",
        }
        return agent

    def _credential_context(self, seq: int) -> Dict[str, Any]:
        # This is a credential-level context/scope. Message-level context is still
        # contained in every signed collaborative message.
        return {
            "issuer_region": self.issuer_name,
            "scope": "regional-collaboration",
            "epoch": seq // 1000,
        }

    def _make_signed_credential_request(self, agent: AgentState, session_pk: bytes, role: str, seq: int, validity_i: int, ctx_i: Dict[str, Any]) -> Tuple[Dict[str, Any], bytes, str]:
        if agent.pq_keypair is None:
            agent.pq_keypair = sig_keygen(self.sig_alg)
        request = {
            "version": VERSION,
            "domain": "PQ-VANET-CREDENTIAL-REQUEST-V2",
            "real_agent_id_hash": sha256_hex(agent.real_id.encode("utf-8")),
            "long_term_pk_hash": sha256_hex(agent.pq_keypair.public_key),
            "session_pk_hash": sha256_hex(session_pk),
            "role": role,
            "validity": validity_i,
            "credential_context": ctx_i,
            "request_nonce": str(uuid.uuid4()),
            "seq": seq,
        }
        request_msg = canonical(request)
        request_sig = sig_sign(self.sig_alg, agent.pq_keypair.secret_key, request_msg)
        # The TA verifies the request before issuing a credential.
        if not sig_verify(self.sig_alg, agent.pq_keypair.public_key, request_msg, request_sig):
            raise RuntimeError("internal error: credential request signature verification failed")
        request_hash = sha256_hex(request_msg + request_sig)
        self.audit_db[request_hash] = {
            "request": request,
            "request_sig": b64e(request_sig),
            "long_term_pk": b64e(agent.pq_keypair.public_key),
            "real_agent_id": agent.real_id,
            "session_pk_hash": sha256_hex(session_pk),
        }
        return request, request_sig, request_hash

    def _issue_body_common(self, agent: AgentState, role: str, seq: int) -> Dict[str, Any]:
        if agent.session_keypair is None:
            agent.session_keypair = sig_keygen(self.sig_alg)
        session_pk = agent.session_keypair.public_key
        issued_at = now_ts()
        valid_to = issued_at + 3600
        ctx_i = self._credential_context(seq)
        request, request_sig, request_hash = self._make_signed_credential_request(
            agent=agent,
            session_pk=session_pk,
            role=role,
            seq=seq,
            validity_i=valid_to,
            ctx_i=ctx_i,
        )
        return {
            "version": VERSION,
            "domain": DOMAIN_CREDENTIAL,
            "issuer": self.issuer_name,
            "sig_alg": self.sig_alg,
            "kem_alg": self.kem_alg,
            "cred_id": str(uuid.uuid4()),
            "role": role,
            "issued_at": issued_at,
            "valid_to": valid_to,
            "session_pk": b64e(session_pk),
            "session_pk_hash": sha256_hex(session_pk),
            "credential_context": ctx_i,
            "request_hash": request_hash,
            "request_sig_hash": sha256_hex(request_sig),
            "policy": {
                "allowed_message_types": [
                    "cooperative-perception",
                    "emergency-warning",
                    "lane-change-coordination",
                    "federated-update-hash",
                ],
                "max_validity_seconds": 3600,
                "context_binding_required": self.context_binding,
            },
            "attributes": {
                "seq": seq,
                "agent_type": "autonomous-vehicular-agent",
            },
        }

    def _credential_signing_message(self, body: Dict[str, Any]) -> bytes:
        return canonical({"domain_separator": "AC", "body": body})

    def _sign_credential_body(self, body: Dict[str, Any]) -> Dict[str, Any]:
        sig = sig_sign(self.sig_alg, self.issuer_keypair.secret_key, self._credential_signing_message(body))
        return {"body": body, "issuer_sig": b64e(sig)}

    def _verify_credential(self, credential: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            body = credential["body"]
            if body.get("issuer") != self.issuer_name:
                return False, "wrong issuer"
            if now_ts() > int(body.get("valid_to", 0)):
                return False, "credential expired"
            session_pk = b64d(body["session_pk"])
            if sha256_hex(session_pk) != body.get("session_pk_hash"):
                return False, "session public key hash mismatch"
            if "request_hash" not in body:
                return False, "missing request audit hash"
            ok = sig_verify(
                self.sig_alg,
                self.issuer_keypair.public_key,
                self._credential_signing_message(body),
                b64d(credential["issuer_sig"]),
            )
            if not ok:
                return False, "invalid issuer signature"
            return True, "credential valid"
        except Exception as exc:
            return False, f"credential parse error: {exc}"

    def _sign_packet_with_session(self, agent: AgentState, message: Dict[str, Any], credential: Dict[str, Any]) -> Dict[str, Any]:
        assert agent.session_keypair is not None
        credential_hash = sha256_hex(canonical(credential))
        material = self._message_signing_material(message, {
            "credential_hash": credential_hash,
            "session_pk_hash": credential["body"]["session_pk_hash"],
            "request_hash": credential["body"].get("request_hash"),
        })
        sig = sig_sign(self.sig_alg, agent.session_keypair.secret_key, canonical(material))
        return {
            "scheme": self.name,
            "message": message,
            "credential": credential,
            "credential_hash": credential_hash,
            "agent_sig_alg": self.sig_alg,
            "agent_sig": b64e(sig),
        }

    def create_packet(self, agent: AgentState, seq: int) -> Dict[str, Any]:
        if agent.credential is None:
            self.prepare_agent(agent, seq)
        assert agent.credential is not None
        message = make_message(seq, self.payload_size)
        return self._sign_packet_with_session(agent, message, agent.credential)

    def verify_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            message = packet["message"]
            ok, reason = self._check_message_context(message)
            if not ok:
                return False, reason
            credential = packet["credential"]
            ok, reason = self._verify_credential(credential)
            if not ok:
                return False, reason
            expected_hash = sha256_hex(canonical(credential))
            if packet.get("credential_hash") != expected_hash:
                return False, "credential hash mismatch"
            body = credential["body"]
            event_type = message.get("event_type")
            if event_type not in body.get("policy", {}).get("allowed_message_types", []):
                return False, "message type not permitted by credential policy"
            if body.get("policy", {}).get("context_binding_required", False) and not self.context_binding:
                # This flag is checked to keep the ablation explicit in the packet semantics.
                pass
            session_pk = b64d(body["session_pk"])
            material = self._message_signing_material(message, {
                "credential_hash": expected_hash,
                "session_pk_hash": body["session_pk_hash"],
                "request_hash": body.get("request_hash"),
            })
            if not sig_verify(packet["agent_sig_alg"], session_pk, canonical(material), b64d(packet["agent_sig"])):
                return False, "invalid anonymous agent signature"
            return True, "packet valid"
        except Exception as exc:
            return False, f"packet parse error: {exc}"


class AnonymousNoTraceScheme(CredentialSchemeBase):
    name = "PQ anonymous w/o trace"

    def prepare_agent(self, agent: AgentState, seq: int = 0) -> None:
        agent.session_keypair = sig_keygen(self.sig_alg)
        body = self._issue_body_common(agent, role="anonymous-vehicle-agent", seq=seq)
        body["trace_mode"] = "none"
        agent.credential = self._sign_credential_body(body)

    def properties(self) -> Dict[str, str]:
        return {
            "pq_security": "Yes",
            "anonymity": "Yes",
            "traceability": "No",
            "context_binding": "Yes" if self.context_binding else "No",
        }


class TraceableNonAnonymousScheme(CredentialSchemeBase):
    name = "PQ traceable w/o anonymity"

    def prepare_agent(self, agent: AgentState, seq: int = 0) -> None:
        agent.session_keypair = sig_keygen(self.sig_alg)
        body = self._issue_body_common(agent, role="identified-vehicle-agent", seq=seq)
        body["trace_mode"] = "plaintext-real-id"
        body["real_agent_id"] = agent.real_id
        agent.credential = self._sign_credential_body(body)

    def supports_trace(self) -> bool:
        return True

    def trace_packet(self, packet: Dict[str, Any]) -> Optional[str]:
        try:
            ok, _ = self._verify_credential(packet["credential"])
            if not ok:
                return None
            return packet["credential"]["body"].get("real_agent_id")
        except Exception:
            return None

    def properties(self) -> Dict[str, str]:
        return {
            "pq_security": "Yes",
            "anonymity": "No",
            "traceability": "Yes",
            "context_binding": "Yes" if self.context_binding else "No",
        }


class ProposedFullScheme(CredentialSchemeBase):
    name = "Proposed full scheme"

    def setup(self) -> None:
        super().setup()
        self.tracing_keypair = kem_keygen(self.kem_alg)

    def _trace_binding(self, body: Dict[str, Any], kem_ct_b64: str) -> Dict[str, Any]:
        return {
            "session_pk_hash": body["session_pk_hash"],
            "valid_to": body["valid_to"],
            "credential_context": body.get("credential_context"),
            "request_hash": body.get("request_hash"),
            "cred_id": body.get("cred_id"),
            "kem_ct_hash": sha256_hex(b64d(kem_ct_b64)),
        }

    def prepare_agent(self, agent: AgentState, seq: int = 0) -> None:
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("cryptography is required for AES-GCM trace encryption.")
        assert self.tracing_keypair is not None
        agent.session_keypair = sig_keygen(self.sig_alg)
        body = self._issue_body_common(agent, role="anonymous-traceable-vehicle-agent", seq=seq)
        session_pk = b64d(body["session_pk"])

        trace_plaintext = {
            "version": VERSION,
            "domain": DOMAIN_CREDENTIAL,
            "trace_version": "KEM-DEM-AESGCM-V2",
            "cred_id": body["cred_id"],
            "real_agent_id": agent.real_id,
            "role": body["role"],
            "session_pk_hash": sha256_hex(session_pk),
            "issued_at": body["issued_at"],
            "valid_to": body["valid_to"],
            "credential_context": body["credential_context"],
            "request_hash": body["request_hash"],
            "request_sig_hash": body["request_sig_hash"],
        }
        kem_ct, ss = kem_encapsulate(self.kem_alg, self.tracing_keypair.public_key)
        kem_ct_b64 = b64e(kem_ct)
        binding = self._trace_binding(body, kem_ct_b64)
        key = derive_trace_aes_key(ss, binding)
        nonce = os.urandom(12)
        aad = {
            "domain": DOMAIN_TRACE_AAD,
            "issuer": self.issuer_name,
            "binding": binding,
        }
        ciphertext = AESGCM(key).encrypt(nonce, canonical(trace_plaintext), canonical(aad))
        body["trace_mode"] = "ml-kem-dem-aesgcm"
        body["trace_envelope"] = {
            "kem_alg": self.kem_alg,
            "aead": "AES-256-GCM",
            "aad": aad,
            "kem_ct": kem_ct_b64,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
        }
        agent.credential = self._sign_credential_body(body)

    def supports_trace(self) -> bool:
        return True

    def trace_packet(self, packet: Dict[str, Any]) -> Optional[str]:
        try:
            assert self.tracing_keypair is not None
            credential = packet["credential"]
            ok, _ = self._verify_credential(credential)
            if not ok:
                return None
            body = credential["body"]
            env = body["trace_envelope"]
            kem_ct = b64d(env["kem_ct"])
            ss = kem_decapsulate(self.kem_alg, self.tracing_keypair.secret_key, kem_ct)
            binding = self._trace_binding(body, env["kem_ct"])
            key = derive_trace_aes_key(ss, binding)
            plaintext = AESGCM(key).decrypt(b64d(env["nonce"]), b64d(env["ciphertext"]), canonical(env["aad"]))
            data = json.loads(plaintext.decode("utf-8"))
            # Trace soundness checks: decrypted trace information must match the signed credential body.
            if data.get("session_pk_hash") != body.get("session_pk_hash"):
                return None
            if data.get("valid_to") != body.get("valid_to"):
                return None
            if data.get("credential_context") != body.get("credential_context"):
                return None
            if data.get("request_hash") != body.get("request_hash"):
                return None
            if data.get("cred_id") != body.get("cred_id"):
                return None
            return data.get("real_agent_id")
        except Exception:
            return None

    def trace_with_wrong_key_for_test(self, packet: Dict[str, Any]) -> Optional[str]:
        """Used only by the attack experiment to confirm that wrong tracing keys fail."""
        wrong = kem_keygen(self.kem_alg)
        old = self.tracing_keypair
        try:
            self.tracing_keypair = wrong
            return self.trace_packet(packet)
        finally:
            self.tracing_keypair = old

    def properties(self) -> Dict[str, str]:
        return {
            "pq_security": "Yes",
            "anonymity": "Yes",
            "traceability": "Yes",
            "context_binding": "Yes" if self.context_binding else "No",
        }


class NoCredentialAblationScheme(SchemeBase):
    name = "Ablation: no credential"

    def setup(self) -> None:
        pass

    def new_agent(self, idx: int) -> AgentState:
        return AgentState(real_id=f"vehicle-real-id-{idx:04d}")

    def prepare_agent(self, agent: AgentState, seq: int = 0) -> None:
        agent.session_keypair = sig_keygen(self.sig_alg)

    def create_packet(self, agent: AgentState, seq: int) -> Dict[str, Any]:
        if agent.session_keypair is None:
            self.prepare_agent(agent, seq)
        assert agent.session_keypair is not None
        message = make_message(seq, self.payload_size)
        pk_hash = sha256_hex(agent.session_keypair.public_key)
        material = self._message_signing_material(message, {
            "session_pk_hash": pk_hash,
            "note": "no TA credential is bound",
        })
        sig = sig_sign(self.sig_alg, agent.session_keypair.secret_key, canonical(material))
        return {
            "scheme": self.name,
            "message": message,
            "session_pk": b64e(agent.session_keypair.public_key),
            "session_pk_hash": pk_hash,
            "agent_sig_alg": self.sig_alg,
            "agent_sig": b64e(sig),
        }

    def verify_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            message = packet["message"]
            ok, reason = self._check_message_context(message)
            if not ok:
                return False, reason
            session_pk = b64d(packet["session_pk"])
            if sha256_hex(session_pk) != packet.get("session_pk_hash"):
                return False, "session public key hash mismatch"
            material = self._message_signing_material(message, {
                "session_pk_hash": packet["session_pk_hash"],
                "note": "no TA credential is bound",
            })
            ok = sig_verify(packet["agent_sig_alg"], session_pk, canonical(material), b64d(packet["agent_sig"]))
            return (ok, "valid signature but no legitimacy proof" if ok else "invalid signature")
        except Exception as exc:
            return False, f"parse error: {exc}"

    def properties(self) -> Dict[str, str]:
        return {
            "pq_security": "Yes",
            "anonymity": "Weak",
            "traceability": "No",
            "context_binding": "Yes" if self.context_binding else "No",
        }


# ---------------------------------------------------------------------------
# Benchmark engines
# ---------------------------------------------------------------------------

SCHEME_CLASSES = [
    DirectMLDSAScheme,
    AnonymousNoTraceScheme,
    TraceableNonAnonymousScheme,
    ProposedFullScheme,
]


def build_scheme(
    scheme_cls: Any,
    sig_alg: str,
    kem_alg: str,
    payload_size: int,
    context_binding: bool = True,
    replay_protection: bool = True,
) -> SchemeBase:
    scheme = scheme_cls(
        sig_alg=sig_alg,
        kem_alg=kem_alg,
        payload_size=payload_size,
        context_binding=context_binding,
        replay_protection=replay_protection,
    )
    scheme.setup()
    return scheme


def benchmark_scheme(
    scheme: SchemeBase,
    agents: int,
    rounds: int,
    refresh_each_round: bool = True,
) -> Dict[str, Any]:
    issue_times: List[float] = []
    sign_times: List[float] = []
    verify_times: List[float] = []
    trace_times: List[float] = []
    json_sizes: List[int] = []
    binary_sizes: List[int] = []

    agent_pool = [scheme.new_agent(i) for i in range(agents)]

    if not refresh_each_round:
        for i, agent in enumerate(agent_pool):
            t = time.perf_counter()
            scheme.prepare_agent(agent, i)
            issue_times.append(time.perf_counter() - t)

    for r in range(rounds):
        agent = agent_pool[r % agents]

        if refresh_each_round or getattr(agent, "credential", None) is None and getattr(agent, "session_keypair", None) is None:
            t0 = time.perf_counter()
            scheme.prepare_agent(agent, r)
            issue_times.append(time.perf_counter() - t0)

        t1 = time.perf_counter()
        packet = scheme.create_packet(agent, r)
        sign_times.append(time.perf_counter() - t1)

        t2 = time.perf_counter()
        ok, reason = scheme.verify_packet(packet)
        verify_times.append(time.perf_counter() - t2)
        if not ok:
            raise RuntimeError(f"{scheme.name} verification failed at round {r}: {reason}")

        if scheme.supports_trace():
            t3 = time.perf_counter()
            traced = scheme.trace_packet(packet)
            trace_times.append(time.perf_counter() - t3)
            if not traced:
                raise RuntimeError(f"{scheme.name} trace failed at round {r}")

        json_sizes.append(len(canonical(packet)))
        binary_sizes.append(compact_binary_size(packet))

    props = scheme.properties()
    return {
        "scheme": scheme.name,
        "pq_security": props["pq_security"],
        "anonymity": props["anonymity"],
        "traceability": props["traceability"],
        "context_binding": props["context_binding"],
        "issue_avg_ms": f"{mean_ms(issue_times):.3f}",
        "issue_p95_ms": f"{p95_ms(issue_times):.3f}",
        "sign_avg_ms": f"{mean_ms(sign_times):.3f}",
        "sign_p95_ms": f"{p95_ms(sign_times):.3f}",
        "verify_avg_ms": f"{mean_ms(verify_times):.3f}",
        "verify_p95_ms": f"{p95_ms(verify_times):.3f}",
        "trace_avg_ms": f"{mean_ms(trace_times):.3f}" if trace_times else "N/A",
        "trace_p95_ms": f"{p95_ms(trace_times):.3f}" if trace_times else "N/A",
        "json_size_avg_B": f"{avg(json_sizes):.1f}",
        "binary_size_est_avg_B": f"{avg(binary_sizes):.1f}",
    }


def run_demo(args: argparse.Namespace) -> None:
    sig_alg, kem_alg = args.sig_alg or load_default_algorithms()[0], args.kem_alg or load_default_algorithms()[1]
    print_environment(sig_alg, kem_alg)
    scheme = build_scheme(ProposedFullScheme, sig_alg, kem_alg, args.payload_size)
    agent = scheme.new_agent(1)
    scheme.prepare_agent(agent, 1)
    packet = scheme.create_packet(agent, 1)
    ok, reason = scheme.verify_packet(packet)
    traced = scheme.trace_packet(packet)
    print("\n=== Demo: Proposed full scheme ===")
    print(f"Verification: {ok}, reason: {reason}")
    print(f"Traced real identity: {traced}")
    print(f"Packet JSON size: {len(canonical(packet))} bytes")
    print(f"Packet compact binary estimated size: {compact_binary_size(packet)} bytes")
    print("Verifier can see role:", packet["credential"]["body"].get("role"))
    print("Credential request hash:", packet["credential"]["body"].get("request_hash"))
    print("Trace mode:", packet["credential"]["body"].get("trace_mode"))
    print("Verifier cannot see real identity in plaintext:", "real_agent_id" not in canonical(packet).decode("utf-8"))


def run_basic_bench(args: argparse.Namespace) -> List[Dict[str, Any]]:
    sig_alg, kem_alg = args.sig_alg or load_default_algorithms()[0], args.kem_alg or load_default_algorithms()[1]
    print_environment(sig_alg, kem_alg)
    scheme = build_scheme(ProposedFullScheme, sig_alg, kem_alg, args.payload_size)
    row = benchmark_scheme(scheme, args.agents, args.rounds, refresh_each_round=True)
    rows = [row]
    print_table("Basic benchmark: proposed full scheme", rows)
    write_csv(os.path.join(args.output_dir, "basic_benchmark.csv"), rows)
    return rows


def run_compare(args: argparse.Namespace) -> List[Dict[str, Any]]:
    sig_alg, kem_alg = args.sig_alg or load_default_algorithms()[0], args.kem_alg or load_default_algorithms()[1]
    print_environment(sig_alg, kem_alg)
    rows: List[Dict[str, Any]] = []

    scheme_classes: List[Any] = []
    if CRYPTOGRAPHY_AVAILABLE and not args.no_ecdsa:
        scheme_classes.append(ECDSABaselineScheme)
    scheme_classes.extend(SCHEME_CLASSES)

    for cls in scheme_classes:
        print(f"\n[RUN] {cls.name}")
        scheme = build_scheme(cls, sig_alg, kem_alg, args.payload_size)
        row = benchmark_scheme(scheme, args.agents, args.rounds, refresh_each_round=True)
        rows.append(row)

    print_table("Comparison with baseline schemes", rows)
    write_csv(os.path.join(args.output_dir, "comparison.csv"), rows)
    return rows


def run_ablation(args: argparse.Namespace) -> List[Dict[str, Any]]:
    sig_alg, kem_alg = args.sig_alg or load_default_algorithms()[0], args.kem_alg or load_default_algorithms()[1]
    print_environment(sig_alg, kem_alg)
    rows: List[Dict[str, Any]] = []

    ablations: List[Tuple[str, Any, bool, bool, bool]] = [
        ("Full proposed", ProposedFullScheme, True, True, True),
        ("Ablation: no credential", NoCredentialAblationScheme, True, True, True),
        ("Ablation: no trace ciphertext", AnonymousNoTraceScheme, True, True, True),
        ("Ablation: no context binding", ProposedFullScheme, False, False, True),
    ]

    for label, cls, context_binding, replay_protection, refresh_each_round in ablations:
        print(f"\n[RUN] {label}")
        scheme = build_scheme(
            cls,
            sig_alg,
            kem_alg,
            args.payload_size,
            context_binding=context_binding,
            replay_protection=replay_protection,
        )
        row = benchmark_scheme(scheme, args.agents, args.rounds, refresh_each_round=refresh_each_round)
        row["scheme"] = label
        rows.append(row)

    # Static/periodic credential refresh experiment for the proposed scheme.
    refresh_rows = run_refresh_ablation_internal(args, sig_alg, kem_alg)

    print_table("Ablation study", rows)
    write_csv(os.path.join(args.output_dir, "ablation.csv"), rows)
    write_csv(os.path.join(args.output_dir, "refresh_ablation.csv"), refresh_rows)
    return rows


def run_refresh_ablation_internal(args: argparse.Namespace, sig_alg: str, kem_alg: str) -> List[Dict[str, Any]]:
    refresh_values = [1, 10, 50, 0]  # 0 means static credential for the whole run.
    rows: List[Dict[str, Any]] = []
    for refresh_every in refresh_values:
        scheme = build_scheme(ProposedFullScheme, sig_alg, kem_alg, args.payload_size)
        agent_pool = [scheme.new_agent(i) for i in range(args.agents)]
        issue_times: List[float] = []
        sign_times: List[float] = []
        verify_times: List[float] = []
        json_sizes: List[int] = []

        for i, agent in enumerate(agent_pool):
            t = time.perf_counter()
            scheme.prepare_agent(agent, i)
            issue_times.append(time.perf_counter() - t)

        for r in range(args.rounds):
            agent = agent_pool[r % args.agents]
            need_refresh = False
            if refresh_every == 1:
                need_refresh = True
            elif refresh_every > 1 and r % refresh_every == 0:
                need_refresh = True
            elif refresh_every == 0:
                need_refresh = False
            if need_refresh:
                t0 = time.perf_counter()
                scheme.prepare_agent(agent, r)
                issue_times.append(time.perf_counter() - t0)
            t1 = time.perf_counter()
            packet = scheme.create_packet(agent, r)
            sign_times.append(time.perf_counter() - t1)
            t2 = time.perf_counter()
            ok, reason = scheme.verify_packet(packet)
            verify_times.append(time.perf_counter() - t2)
            if not ok:
                raise RuntimeError(f"refresh ablation verification failed: {reason}")
            json_sizes.append(len(canonical(packet)))

        if refresh_every == 0:
            refresh_label = "static credential"
            linkability = "High"
        else:
            refresh_label = f"refresh every {refresh_every} msg"
            linkability = "Low" if refresh_every <= 10 else "Medium"
        rows.append({
            "refresh_policy": refresh_label,
            "issue_avg_ms": f"{mean_ms(issue_times):.3f}",
            "sign_avg_ms": f"{mean_ms(sign_times):.3f}",
            "verify_avg_ms": f"{mean_ms(verify_times):.3f}",
            "json_size_avg_B": f"{avg(json_sizes):.1f}",
            "linkability_risk": linkability,
        })
    print_table("Credential refresh ablation", rows)
    return rows


def run_attack(args: argparse.Namespace) -> List[Dict[str, Any]]:
    sig_alg, kem_alg = args.sig_alg or load_default_algorithms()[0], args.kem_alg or load_default_algorithms()[1]
    print_environment(sig_alg, kem_alg)

    rows: List[Dict[str, Any]] = []
    attacks = [
        "message tampering",
        "signature tampering",
        "credential tampering",
        "unregistered agent forgery",
        "replay attack",
        "wrong tracing key",
        "cross-context replay without context binding",
    ]
    results = {name: 0 for name in attacks}

    for r in range(args.rounds):
        # Valid full-scheme packet.
        scheme = build_scheme(ProposedFullScheme, sig_alg, kem_alg, args.payload_size)
        agent = scheme.new_agent(r)
        scheme.prepare_agent(agent, r)
        packet = scheme.create_packet(agent, r)

        ok, reason = scheme.verify_packet(copy.deepcopy(packet))
        if not ok:
            raise RuntimeError(f"valid packet rejected during attack setup: {reason}")

        # 1. Message tampering.
        scheme.reset_verifier_state()
        tampered = copy.deepcopy(packet)
        tampered["message"]["content"]["confidence"] = 0.01
        ok, _ = scheme.verify_packet(tampered)
        if not ok:
            results["message tampering"] += 1

        # 2. Signature tampering.
        scheme.reset_verifier_state()
        tampered = copy.deepcopy(packet)
        tampered["agent_sig"] = flip_one_byte_b64(tampered["agent_sig"])
        ok, _ = scheme.verify_packet(tampered)
        if not ok:
            results["signature tampering"] += 1

        # 3. Credential tampering.
        scheme.reset_verifier_state()
        tampered = copy.deepcopy(packet)
        tampered["credential"]["body"]["role"] = "fake-role"
        tampered["credential_hash"] = sha256_hex(canonical(tampered["credential"]))
        ok, _ = scheme.verify_packet(tampered)
        if not ok:
            results["credential tampering"] += 1

        # 4. Unregistered agent forgery.
        fake = build_scheme(NoCredentialAblationScheme, sig_alg, kem_alg, args.payload_size)
        fake_agent = fake.new_agent(99999 + r)
        fake.prepare_agent(fake_agent, r)
        fake_packet = fake.create_packet(fake_agent, r)
        # Try to feed a no-credential packet to the full verifier.
        ok, _ = scheme.verify_packet(fake_packet)
        if not ok:
            results["unregistered agent forgery"] += 1

        # 5. Replay attack: first verification succeeds, second one fails.
        scheme = build_scheme(ProposedFullScheme, sig_alg, kem_alg, args.payload_size)
        agent = scheme.new_agent(r)
        scheme.prepare_agent(agent, r)
        replay_packet = scheme.create_packet(agent, r)
        ok1, _ = scheme.verify_packet(copy.deepcopy(replay_packet))
        ok2, _ = scheme.verify_packet(copy.deepcopy(replay_packet))
        if ok1 and not ok2:
            results["replay attack"] += 1

        # 6. Wrong tracing key: same credential/issuer but an incorrect ML-KEM secret key.
        try:
            traced = scheme.trace_with_wrong_key_for_test(packet)
            if traced != agent.real_id:
                results["wrong tracing key"] += 1
        except Exception:
            results["wrong tracing key"] += 1

        # 7. Cross-context replay/misuse without context binding.
        # With context binding disabled, modifying road_segment should still verify,
        # proving why the context-binding module is necessary.
        no_ctx = build_scheme(ProposedFullScheme, sig_alg, kem_alg, args.payload_size, context_binding=False, replay_protection=False)
        no_ctx_agent = no_ctx.new_agent(r)
        no_ctx.prepare_agent(no_ctx_agent, r)
        no_ctx_packet = no_ctx.create_packet(no_ctx_agent, r)
        changed_context = copy.deepcopy(no_ctx_packet)
        changed_context["message"]["road_segment"] = "MALICIOUS-NEW-RSU"
        ok, _ = no_ctx.verify_packet(changed_context)
        if ok:
            results["cross-context replay without context binding"] += 1

    for name in attacks:
        if name == "cross-context replay without context binding":
            expected = "Accepted by ablated scheme"
            interpretation = "Shows context binding is necessary"
        elif name == "wrong tracing key":
            expected = "Trace failed"
            interpretation = "Correct tracing authority is required"
        else:
            expected = "Rejected"
            interpretation = "Attack detected"
        rows.append({
            "attack": name,
            "expected_result": expected,
            "success_count": results[name],
            "rounds": args.rounds,
            "rate": f"{(results[name] / max(1, args.rounds)) * 100:.1f}%",
            "interpretation": interpretation,
        })

    print_table("Security validation under typical attacks", rows)
    write_csv(os.path.join(args.output_dir, "attack_validation.csv"), rows)
    return rows


def parse_agent_list(text: str) -> List[int]:
    values: List[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        values.append(int(part))
    return values


def run_scalability(args: argparse.Namespace) -> List[Dict[str, Any]]:
    sig_alg, kem_alg = args.sig_alg or load_default_algorithms()[0], args.kem_alg or load_default_algorithms()[1]
    print_environment(sig_alg, kem_alg)
    agent_counts = parse_agent_list(args.agent_list)
    rows: List[Dict[str, Any]] = []
    for n in agent_counts:
        print(f"\n[RUN] scalability agents={n}")
        scheme = build_scheme(ProposedFullScheme, sig_alg, kem_alg, args.payload_size)
        row = benchmark_scheme(scheme, n, args.rounds, refresh_each_round=False)
        row = {
            "agents": n,
            "issue_avg_ms": row["issue_avg_ms"],
            "sign_avg_ms": row["sign_avg_ms"],
            "verify_avg_ms": row["verify_avg_ms"],
            "trace_avg_ms": row["trace_avg_ms"],
            "json_size_avg_B": row["json_size_avg_B"],
            "binary_size_est_avg_B": row["binary_size_est_avg_B"],
        }
        rows.append(row)
    print_table("Scalability of proposed scheme", rows)
    write_csv(os.path.join(args.output_dir, "scalability.csv"), rows)
    return rows


def run_levels(args: argparse.Namespace) -> List[Dict[str, Any]]:
    levels = get_level_algorithms()
    if not levels:
        print("No complete ML-DSA/ML-KEM security-level pairs are supported by this liboqs build.")
        return []
    rows: List[Dict[str, Any]] = []
    for level_name, sig_alg, kem_alg in levels:
        print(f"\n[RUN] security level {level_name}: {sig_alg} + {kem_alg}")
        scheme = build_scheme(ProposedFullScheme, sig_alg, kem_alg, args.payload_size)
        row = benchmark_scheme(scheme, args.agents, args.rounds, refresh_each_round=True)
        rows.append({
            "level": level_name,
            "sig_alg": sig_alg,
            "kem_alg": kem_alg,
            "issue_avg_ms": row["issue_avg_ms"],
            "sign_avg_ms": row["sign_avg_ms"],
            "verify_avg_ms": row["verify_avg_ms"],
            "trace_avg_ms": row["trace_avg_ms"],
            "json_size_avg_B": row["json_size_avg_B"],
            "binary_size_est_avg_B": row["binary_size_est_avg_B"],
        })
    print_table("Impact of post-quantum security levels", rows)
    write_csv(os.path.join(args.output_dir, "security_levels.csv"), rows)
    return rows


def run_all(args: argparse.Namespace) -> None:
    run_basic_bench(args)
    run_compare(args)
    run_ablation(args)
    run_attack(args)
    run_scalability(args)
    run_levels(args)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Experiments for post-quantum anonymous authentication in multi-agent vehicular collaboration."
    )
    parser.add_argument(
        "--mode",
        choices=["demo", "bench", "compare", "ablation", "attack", "scalability", "levels", "all"],
        default="demo",
    )
    parser.add_argument("--agents", type=int, default=10, help="Number of vehicular agents.")
    parser.add_argument("--rounds", type=int, default=100, help="Benchmark rounds.")
    parser.add_argument("--payload-size", type=int, default=256, help="Payload size in bytes for synthetic messages.")
    parser.add_argument("--agent-list", default="10,30,50,100,200", help="Comma-separated agent counts for scalability mode.")
    parser.add_argument("--sig-alg", default=None, help="Override signature algorithm, e.g., ML-DSA-65.")
    parser.add_argument("--kem-alg", default=None, help="Override KEM algorithm, e.g., ML-KEM-768.")
    parser.add_argument("--output-dir", default="results", help="Directory for CSV outputs.")
    parser.add_argument("--no-ecdsa", action="store_true", help="Disable ECDSA baseline even if cryptography is available.")
    args = parser.parse_args()

    if args.agents < 1:
        print("--agents must be >= 1", file=sys.stderr)
        sys.exit(2)
    if args.rounds < 1:
        print("--rounds must be >= 1", file=sys.stderr)
        sys.exit(2)

    ensure_dir(args.output_dir)

    if args.mode == "demo":
        run_demo(args)
    elif args.mode == "bench":
        run_basic_bench(args)
    elif args.mode == "compare":
        run_compare(args)
    elif args.mode == "ablation":
        run_ablation(args)
    elif args.mode == "attack":
        run_attack(args)
    elif args.mode == "scalability":
        run_scalability(args)
    elif args.mode == "levels":
        run_levels(args)
    elif args.mode == "all":
        run_all(args)

    print(f"\nCSV results are saved in: {os.path.abspath(args.output_dir)}")


if __name__ == "__main__":
    main()
