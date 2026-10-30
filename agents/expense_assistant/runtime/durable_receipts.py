"""Encrypted personal receipt storage on an explicit transactional store.

No local files, credential fallback, network or shared owner. The host supplies
the store/key and optionally an authorized attachment fetcher. References are
opaque and compatible with existing receipt resources, never operating-system
paths. Closing this facade never closes the shared store.
"""

import base64
import hashlib
import json
import re
import uuid

from cryptography.fernet import Fernet

from .providers import MAX_FILE
from .state import ExpenseError


def _format(content, mime):
    signatures = ((b"%PDF-", "application/pdf", "pdf"),
                  (b"\x89PNG\r\n\x1a\n", "image/png", "png"),
                  (b"\xff\xd8\xff", "image/jpeg", "jpg"))
    if not isinstance(content, bytes) or not 0 < len(content) <= MAX_FILE:
        raise ExpenseError("領収書の形式・サイズを確認してください。")
    for magic, expected, extension in signatures:
        if content.startswith(magic) and mime == expected:
            return extension
    if (len(content) >= 12 and content[4:8] == b"ftyp"
            and content[8:12] in (b"heic", b"heix", b"mif1") and mime == "image/heic"):
        return "heic"
    raise ExpenseError("領収書の形式・サイズを確認してください。")


class DurableReceipts:
    def __init__(self, store, encryption_key, owner, namespace, fetcher=None):
        if (not isinstance(owner, str) or not owner.strip() or len(owner) > 512
                or not isinstance(namespace, str) or not namespace.strip() or len(namespace) > 512
                or not callable(getattr(store, "transaction", None))):
            raise ValueError("Explicit personal receipt owner, namespace and store required")
        try:
            self._cipher = Fernet(encryption_key)
        except Exception:
            raise ValueError("Explicit receipt encryption key required") from None
        self.owner, self.namespace, self.fetcher = owner, namespace, fetcher
        self._store, self._closed = store, False

    def _binding(self, name):
        return ["expense-durable-receipt/v1", self.namespace, self.owner, name]

    def _key(self, name):
        value = json.dumps(self._binding(name), ensure_ascii=True, separators=(",", ":"))
        return "expense-durable-receipt-v1:" + hashlib.sha256(value.encode()).hexdigest()

    def save(self, content, content_type):
        extension = _format(content, content_type)
        if self._closed:
            raise ExpenseError("領収書の保存接続は閉じられています。")
        name = uuid.uuid4().hex + "." + extension
        data = {"binding": self._binding(name), "content_type": content_type,
                "content": base64.b64encode(content).decode("ascii"), "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest()}
        try:
            sealed = self._cipher.encrypt(json.dumps(data, separators=(",", ":")).encode()).decode("ascii")
            with self._store.transaction() as records:
                if records.get(self._key(name)) is not None:
                    raise ValueError
                records.put(self._key(name), {"ciphertext": sealed})
        except Exception:
            raise ExpenseError("本人の領収書を安全に保存できません。") from None
        return {"path": "receipt:" + name, "content_type": content_type, "bytes": len(content),
                "resource_uri": "receipt://" + extension + "/" + name}

    def payload(self, reference, *, ocr=False):
        if (self._closed or not isinstance(reference, str)
                or not re.fullmatch(r"receipt:[a-f0-9]{32}\.(pdf|png|jpg|heic)", reference)):
            raise ExpenseError("この本人の有効な領収書参照を指定してください。")
        name = reference.split(":", 1)[1]
        try:
            with self._store.transaction() as records:
                row = records.get(self._key(name))
            if (not isinstance(row, dict) or set(row) != {"ciphertext"}
                    or not isinstance(row["ciphertext"], str) or len(row["ciphertext"]) > MAX_FILE * 2):
                raise ValueError
            raw = self._cipher.decrypt(row["ciphertext"].encode("ascii"))
            if len(raw) > MAX_FILE * 3 // 2:
                raise ValueError
            data = json.loads(raw)
            if (set(data) != {"binding", "content_type", "content", "bytes", "sha256"}
                    or data["binding"] != self._binding(name)):
                raise ValueError
            content = base64.b64decode(data["content"], validate=True)
            extension = _format(content, data["content_type"])
            if (not name.endswith("." + extension) or type(data["bytes"]) is not int
                    or data["bytes"] != len(content) or data["sha256"] != hashlib.sha256(content).hexdigest()):
                raise ValueError
            return {"content": data["content"], "content_type": data["content_type"], "filename": name,
                    "process_type": "2" if ocr else "0", "split_pdf": False}
        except Exception:
            raise ExpenseError("本人の領収書を安全に取得できません。") from None

    def fetch_attachment(self, url):
        if self._closed or self.fetcher is None:
            raise ExpenseError("認可済みの添付取得接続が必要です。")
        content, mime = self.fetcher.get(url)
        return self.save(content, mime)

    def close(self):
        self._closed = True
