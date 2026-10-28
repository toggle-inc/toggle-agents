"""Firestore-backed transactional store for OAuth and Okta session records.

Use a dedicated Firestore Native database and a runtime service account with
only roles/datastore.user. Document IDs are hashes of already-private keys.
The store stages writes until the context exits so every Firestore transaction
performs all reads before writes, while preserving read-your-writes behavior.
"""

import contextlib
import copy
import hashlib
import json


class _FirestoreRecords:
    def __init__(self, client, transaction, collection):
        self._client = client
        self._transaction = transaction
        self._collection = collection
        self._reads = {}
        self._writes = {}

    def _reference(self, key):
        if not isinstance(key, str) or not key:
            raise ValueError("Authorization record key required")
        document_id = hashlib.sha256(key.encode()).hexdigest()
        return self._collection.document(document_id)

    def get(self, key):
        reference = self._reference(key)
        path = reference.path
        if path in self._writes:
            value = self._writes[path]["value"]
            return copy.deepcopy(value)
        if path not in self._reads:
            snapshot = next(iter(self._transaction.get(reference)), None)
            self._reads[path] = snapshot.to_dict() if snapshot and snapshot.exists else None
        stored = self._reads[path]
        return copy.deepcopy(stored["value"]) if stored else None

    def put(self, key, value):
        if not isinstance(value, dict):
            raise ValueError("Authorization records must be JSON objects")
        # Match SQLite's JSON constraints and reject NaN/Infinity before commit.
        validated = json.loads(json.dumps(value, allow_nan=False, separators=(",", ":")))
        reference = self._reference(key)
        self._writes[reference.path] = {"reference": reference, "value": validated}


class FirestoreAuthorizationStore:
    """`AuthorizationStore` implementation using Firestore transactions.

    Pass a Firestore client for tests/embedding, or specify a dedicated database
    ID when running on Google Cloud. A transaction conflict fails closed; callers
    may restart an authorization flow, and refresh clients must serialize calls.
    """

    def __init__(self, client=None, *, database=None, collection="expense_auth_v1"):
        if not isinstance(collection, str) or not collection.strip():
            raise ValueError("Private authorization collection required")
        if client is None:
            if not isinstance(database, str) or not database.strip():
                raise ValueError("A dedicated Firestore database ID is required")
            from google.cloud import firestore

            client = firestore.Client(database=database)
        self.client = client
        self.collection = client.collection(collection)

    @contextlib.contextmanager
    def transaction(self):
        transaction = self.client.transaction(max_attempts=1)
        records = _FirestoreRecords(self.client, transaction, self.collection)
        try:
            yield records
            for write in records._writes.values():
                transaction.set(write["reference"], {"value": write["value"]})
            transaction.commit()
        except BaseException:
            try:
                transaction.rollback()
            except Exception:
                pass
            raise

    def close(self):
        self.client.close()
