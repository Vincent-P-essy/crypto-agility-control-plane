"""Minimal, pinned ctypes binding for the liboqs 0.16.0 C API.

The binding deliberately refuses implicit downloads and system-wide discovery. A caller
must point ``OQS_INSTALL_PATH`` at an installation produced by the pinned build script.
"""

from __future__ import annotations

import ctypes as ct
import os
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from crypto_agility.errors import BenchmarkUnavailable

EXPECTED_LIBOQS_VERSION = "0.16.0"
KEM_NAME = "ML-KEM-768"
SIGNATURE_NAME = "ML-DSA-65"
OQS_SUCCESS = 0


class _KEMStruct(ct.Structure):
    _fields_ = [
        ("method_name", ct.c_char_p),
        ("alg_version", ct.c_char_p),
        ("claimed_nist_level", ct.c_ubyte),
        ("ind_cca", ct.c_bool),
        ("length_public_key", ct.c_size_t),
        ("length_secret_key", ct.c_size_t),
        ("length_ciphertext", ct.c_size_t),
        ("length_shared_secret", ct.c_size_t),
        ("length_keypair_seed", ct.c_size_t),
        ("keypair_derand_cb", ct.c_void_p),
        ("keypair_cb", ct.c_void_p),
        ("encaps_cb", ct.c_void_p),
        ("decaps_cb", ct.c_void_p),
    ]


class _SignatureStruct(ct.Structure):
    _fields_ = [
        ("method_name", ct.c_char_p),
        ("alg_version", ct.c_char_p),
        ("claimed_nist_level", ct.c_ubyte),
        ("euf_cma", ct.c_bool),
        ("suf_cma", ct.c_bool),
        ("sig_with_ctx_support", ct.c_bool),
        ("length_public_key", ct.c_size_t),
        ("length_secret_key", ct.c_size_t),
        ("length_signature", ct.c_size_t),
        ("keypair_cb", ct.c_void_p),
        ("sign_cb", ct.c_void_p),
        ("sign_with_ctx_cb", ct.c_void_p),
        ("verify_cb", ct.c_void_p),
        ("verify_with_ctx_cb", ct.c_void_p),
    ]


def _library_file(prefix: Path) -> Path:
    if prefix.is_file():
        candidates = [prefix]
    else:
        candidates = [
            prefix / "lib" / "liboqs.so.9",
            prefix / "lib" / "liboqs.so.0.16.0",
            prefix / "lib" / "liboqs.so",
        ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise BenchmarkUnavailable(
        "liboqs 0.16.0 is unavailable: set OQS_INSTALL_PATH to the output of "
        "scripts/build-liboqs.sh; no package is downloaded implicitly"
    )


class OQSLibrary:
    """Configured liboqs handle with an exact-version and mechanism gate."""

    def __init__(self, install_path: Path | None = None) -> None:
        configured = install_path or (
            Path(value) if (value := os.environ.get("OQS_INSTALL_PATH")) else None
        )
        if configured is None:
            raise BenchmarkUnavailable(
                "OQS_INSTALL_PATH is required; run scripts/build-liboqs.sh .local/oqs first"
            )
        self.path = _library_file(configured)
        try:
            self.native = ct.CDLL(str(self.path), mode=ct.RTLD_LOCAL)
        except OSError as exc:
            raise BenchmarkUnavailable(f"unable to load pinned liboqs: {exc}") from exc
        self._configure_api()
        self.version = self.native.OQS_version().decode("ascii")
        if self.version != EXPECTED_LIBOQS_VERSION:
            raise BenchmarkUnavailable(
                f"liboqs version {self.version!r} is not the pinned {EXPECTED_LIBOQS_VERSION!r}"
            )
        for name, enabled in (
            (KEM_NAME, self.native.OQS_KEM_alg_is_enabled(KEM_NAME.encode())),
            (SIGNATURE_NAME, self.native.OQS_SIG_alg_is_enabled(SIGNATURE_NAME.encode())),
        ):
            if enabled != 1:
                raise BenchmarkUnavailable(
                    f"pinned liboqs was built without required mechanism {name}"
                )

    def _configure_api(self) -> None:
        native = self.native
        native.OQS_version.argtypes = []
        native.OQS_version.restype = ct.c_char_p
        native.OQS_KEM_alg_is_enabled.argtypes = [ct.c_char_p]
        native.OQS_KEM_alg_is_enabled.restype = ct.c_int
        native.OQS_SIG_alg_is_enabled.argtypes = [ct.c_char_p]
        native.OQS_SIG_alg_is_enabled.restype = ct.c_int

        native.OQS_KEM_new.argtypes = [ct.c_char_p]
        native.OQS_KEM_new.restype = ct.POINTER(_KEMStruct)
        native.OQS_KEM_free.argtypes = [ct.POINTER(_KEMStruct)]
        native.OQS_KEM_free.restype = None
        native.OQS_KEM_keypair.argtypes = [
            ct.POINTER(_KEMStruct),
            ct.POINTER(ct.c_ubyte),
            ct.POINTER(ct.c_ubyte),
        ]
        native.OQS_KEM_keypair.restype = ct.c_int
        native.OQS_KEM_encaps.argtypes = [
            ct.POINTER(_KEMStruct),
            ct.POINTER(ct.c_ubyte),
            ct.POINTER(ct.c_ubyte),
            ct.POINTER(ct.c_ubyte),
        ]
        native.OQS_KEM_encaps.restype = ct.c_int
        native.OQS_KEM_decaps.argtypes = [
            ct.POINTER(_KEMStruct),
            ct.POINTER(ct.c_ubyte),
            ct.POINTER(ct.c_ubyte),
            ct.POINTER(ct.c_ubyte),
        ]
        native.OQS_KEM_decaps.restype = ct.c_int

        native.OQS_SIG_new.argtypes = [ct.c_char_p]
        native.OQS_SIG_new.restype = ct.POINTER(_SignatureStruct)
        native.OQS_SIG_free.argtypes = [ct.POINTER(_SignatureStruct)]
        native.OQS_SIG_free.restype = None
        native.OQS_SIG_keypair.argtypes = [
            ct.POINTER(_SignatureStruct),
            ct.POINTER(ct.c_ubyte),
            ct.POINTER(ct.c_ubyte),
        ]
        native.OQS_SIG_keypair.restype = ct.c_int
        native.OQS_SIG_sign.argtypes = [
            ct.POINTER(_SignatureStruct),
            ct.POINTER(ct.c_ubyte),
            ct.POINTER(ct.c_size_t),
            ct.POINTER(ct.c_ubyte),
            ct.c_size_t,
            ct.POINTER(ct.c_ubyte),
        ]
        native.OQS_SIG_sign.restype = ct.c_int
        native.OQS_SIG_verify.argtypes = [
            ct.POINTER(_SignatureStruct),
            ct.POINTER(ct.c_ubyte),
            ct.c_size_t,
            ct.POINTER(ct.c_ubyte),
            ct.c_size_t,
            ct.POINTER(ct.c_ubyte),
        ]
        native.OQS_SIG_verify.restype = ct.c_int

        native.OQS_MEM_cleanse.argtypes = [ct.c_void_p, ct.c_size_t]
        native.OQS_MEM_cleanse.restype = None


def _bytes_buffer(value: bytes) -> Any:
    return (ct.c_ubyte * len(value)).from_buffer_copy(value)


class MLKEM768:
    def __init__(self, library: OQSLibrary, secret_key: bytes | None = None) -> None:
        self.library = library
        self._kem = library.native.OQS_KEM_new(KEM_NAME.encode())
        if not self._kem:
            raise BenchmarkUnavailable(f"{KEM_NAME} could not be initialized")
        details = self._kem.contents
        self.public_key_bytes = int(details.length_public_key)
        self.secret_key_bytes = int(details.length_secret_key)
        self.ciphertext_bytes = int(details.length_ciphertext)
        self.shared_secret_bytes = int(details.length_shared_secret)
        self.details = {
            "name": details.method_name.decode(),
            "implementation": details.alg_version.decode(),
            "nist_level": int(details.claimed_nist_level),
            "ind_cca": bool(details.ind_cca),
        }
        self._secret: Any | None = None
        if secret_key is not None:
            if len(secret_key) != self.secret_key_bytes:
                raise ValueError("invalid ML-KEM secret-key length")
            self._secret = _bytes_buffer(secret_key)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def generate_keypair(self) -> bytes:
        public_key = (ct.c_ubyte * self.public_key_bytes)()
        self._secret = (ct.c_ubyte * self.secret_key_bytes)()
        status = self.library.native.OQS_KEM_keypair(self._kem, public_key, self._secret)
        if status != OQS_SUCCESS:
            raise RuntimeError("ML-KEM key generation failed")
        return bytes(public_key)

    def export_secret_key(self) -> bytes:
        if self._secret is None:
            raise RuntimeError("ML-KEM keypair has not been generated")
        return bytes(self._secret)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        if len(public_key) != self.public_key_bytes:
            raise ValueError("invalid ML-KEM public-key length")
        ciphertext = (ct.c_ubyte * self.ciphertext_bytes)()
        shared_secret = (ct.c_ubyte * self.shared_secret_bytes)()
        public_buffer = _bytes_buffer(public_key)
        status = self.library.native.OQS_KEM_encaps(
            self._kem, ciphertext, shared_secret, public_buffer
        )
        if status != OQS_SUCCESS:
            raise RuntimeError("ML-KEM encapsulation failed")
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if self._secret is None:
            raise RuntimeError("ML-KEM secret key is unavailable")
        if len(ciphertext) != self.ciphertext_bytes:
            raise ValueError("invalid ML-KEM ciphertext length")
        shared_secret = (ct.c_ubyte * self.shared_secret_bytes)()
        ciphertext_buffer = _bytes_buffer(ciphertext)
        status = self.library.native.OQS_KEM_decaps(
            self._kem, shared_secret, ciphertext_buffer, self._secret
        )
        if status != OQS_SUCCESS:
            raise RuntimeError("ML-KEM decapsulation failed")
        return bytes(shared_secret)

    def close(self) -> None:
        if self._secret is not None:
            self.library.native.OQS_MEM_cleanse(
                ct.cast(self._secret, ct.c_void_p), self.secret_key_bytes
            )
            self._secret = None
        if self._kem:
            self.library.native.OQS_KEM_free(self._kem)
            self._kem = ct.POINTER(_KEMStruct)()


class MLDSA65:
    def __init__(self, library: OQSLibrary, secret_key: bytes | None = None) -> None:
        self.library = library
        self._signature = library.native.OQS_SIG_new(SIGNATURE_NAME.encode())
        if not self._signature:
            raise BenchmarkUnavailable(f"{SIGNATURE_NAME} could not be initialized")
        details = self._signature.contents
        self.public_key_bytes = int(details.length_public_key)
        self.secret_key_bytes = int(details.length_secret_key)
        self.signature_bytes = int(details.length_signature)
        self.details = {
            "name": details.method_name.decode(),
            "implementation": details.alg_version.decode(),
            "nist_level": int(details.claimed_nist_level),
            "euf_cma": bool(details.euf_cma),
        }
        self._secret: Any | None = None
        if secret_key is not None:
            if len(secret_key) != self.secret_key_bytes:
                raise ValueError("invalid ML-DSA secret-key length")
            self._secret = _bytes_buffer(secret_key)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def generate_keypair(self) -> bytes:
        public_key = (ct.c_ubyte * self.public_key_bytes)()
        self._secret = (ct.c_ubyte * self.secret_key_bytes)()
        status = self.library.native.OQS_SIG_keypair(self._signature, public_key, self._secret)
        if status != OQS_SUCCESS:
            raise RuntimeError("ML-DSA key generation failed")
        return bytes(public_key)

    def export_secret_key(self) -> bytes:
        if self._secret is None:
            raise RuntimeError("ML-DSA keypair has not been generated")
        return bytes(self._secret)

    def sign(self, message: bytes) -> bytes:
        if self._secret is None:
            raise RuntimeError("ML-DSA secret key is unavailable")
        signature = (ct.c_ubyte * self.signature_bytes)()
        signature_length = ct.c_size_t(self.signature_bytes)
        message_buffer = _bytes_buffer(message)
        status = self.library.native.OQS_SIG_sign(
            self._signature,
            signature,
            ct.byref(signature_length),
            message_buffer,
            len(message),
            self._secret,
        )
        if status != OQS_SUCCESS:
            raise RuntimeError("ML-DSA signing failed")
        return bytes(signature[: signature_length.value])

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        if len(public_key) != self.public_key_bytes:
            raise ValueError("invalid ML-DSA public-key length")
        message_buffer = _bytes_buffer(message)
        signature_buffer = _bytes_buffer(signature)
        public_buffer = _bytes_buffer(public_key)
        return bool(
            self.library.native.OQS_SIG_verify(
                self._signature,
                message_buffer,
                len(message),
                signature_buffer,
                len(signature),
                public_buffer,
            )
            == OQS_SUCCESS
        )

    def close(self) -> None:
        if self._secret is not None:
            self.library.native.OQS_MEM_cleanse(
                ct.cast(self._secret, ct.c_void_p), self.secret_key_bytes
            )
            self._secret = None
        if self._signature:
            self.library.native.OQS_SIG_free(self._signature)
            self._signature = ct.POINTER(_SignatureStruct)()
