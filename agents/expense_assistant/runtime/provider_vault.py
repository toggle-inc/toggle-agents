"""Encrypted, requester-bound provider credentials on a transactional private store.

The storage adapter receives only ciphertext. Supply a dedicated encryption key
from the deployment's secret manager; no environment or shared-key fallback.
"""

import contextlib
import copy
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken


class EncryptedProviderVault:
    def __init__(self, store, encryption_key, *, namespace):
        if not isinstance(namespace, str) or not namespace.strip() or len(namespace) > 512:
            raise ValueError("Explicit provider vault namespace required")
        try:
            self._cipher = Fernet(encryption_key)
        except Exception:
            raise ValueError("Dedicated provider vault encryption key required") from None
        self._store, self._namespace = store, namespace

    @contextlib.contextmanager
    def transaction(self, owner, provider):
        if not isinstance(owner, str) or not owner.startswith("requester-v1:") or provider not in {"mf", "calendar"}:
            raise ValueError("Verified requester owner and provider required")
        binding = [self._namespace, owner, provider]
        encoded_binding = json.dumps(binding, ensure_ascii=True, separators=(",", ":"))
        key = "expense-provider-v1:" + hashlib.sha256(encoded_binding.encode()).hexdigest()
        with self._store.transaction() as records:
            row = records.get(key)
            if row is None:
                data = {}
            else:
                try:
                    if set(row) != {"ciphertext"} or not isinstance(row["ciphertext"], str):
                        raise ValueError
                    plaintext = self._cipher.decrypt(row["ciphertext"].encode("ascii"))
                    if len(plaintext) > 262144:
                        raise ValueError
                    payload = json.loads(plaintext)
                    if payload["binding"] != binding or not isinstance(payload["data"], dict):
                        raise ValueError
                    data = payload["data"]
                except (ValueError, TypeError, KeyError, InvalidToken, UnicodeError):
                    raise ValueError("Provider vault is unavailable") from None
            previous = copy.deepcopy(data)
            yield data
            if data != previous:
                plaintext = json.dumps({"binding": binding, "data": data}, allow_nan=False,
                                       separators=(",", ":")).encode()
                if len(plaintext) > 262144:
                    raise ValueError("Provider credential record exceeds size limit")
                records.put(key, {"ciphertext": self._cipher.encrypt(plaintext).decode("ascii")})
