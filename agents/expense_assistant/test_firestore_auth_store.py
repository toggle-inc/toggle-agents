import unittest

from runtime.firestore_auth_store import FirestoreAuthorizationStore


class _Snapshot:
    def __init__(self, value):
        self._value = value
        self.exists = value is not None

    def to_dict(self):
        return self._value


class _Reference:
    def __init__(self, client, path):
        self.client, self.path = client, path


class _Collection:
    def __init__(self, client, name):
        self.client, self.name = client, name

    def document(self, key):
        return _Reference(self.client, f"{self.name}/{key}")


class _Transaction:
    def __init__(self, client):
        self.client = client
        self.reads = []
        self.writes = []
        self.committed = False
        self.rolled_back = False

    def get(self, reference):
        if self.writes:
            raise AssertionError("Firestore writes must be staged after all reads")
        self.reads.append(reference.path)
        return iter([_Snapshot(self.client.data.get(reference.path))])

    def set(self, reference, value):
        self.writes.append((reference.path, value))

    def commit(self):
        self.client.events.append(("commit", len(self.reads), len(self.writes)))
        self.client.data.update(dict(self.writes))
        self.committed = True

    def rollback(self):
        self.rolled_back = True


class _Client:
    def __init__(self):
        self.data = {}
        self.events = []
        self.transactions = []

    def collection(self, name):
        return _Collection(self, name)

    def transaction(self, **_):
        transaction = _Transaction(self)
        self.transactions.append(transaction)
        return transaction

    def close(self):
        pass


class FirestoreAuthorizationStoreTests(unittest.TestCase):
    def setUp(self):
        self.client = _Client()
        self.store = FirestoreAuthorizationStore(self.client)

    def test_stages_writes_and_supports_read_your_writes_atomically(self):
        with self.store.transaction() as records:
            records.put("secret-key", {"token": "opaque"})
            self.assertEqual(records.get("secret-key"), {"token": "opaque"})
            self.assertIsNone(records.get("other-key"))
            records.put("other-key", {"active": True})
        transaction = self.client.transactions[-1]
        self.assertEqual(len(transaction.reads), 1)
        self.assertEqual(len(transaction.writes), 2)
        self.assertTrue(transaction.committed)
        self.assertFalse(transaction.rolled_back)
        self.assertEqual(records.get("secret-key"), {"token": "opaque"})

    def test_failed_body_rolls_back_without_committing_staged_records(self):
        with self.assertRaises(RuntimeError):
            with self.store.transaction() as records:
                records.put("secret-key", {"active": True})
                raise RuntimeError("abort")
        transaction = self.client.transactions[-1]
        self.assertTrue(transaction.rolled_back)
        self.assertFalse(transaction.committed)
        self.assertEqual(self.client.data, {})

    def test_rejects_non_json_numeric_values_before_commit(self):
        with self.assertRaises(ValueError):
            with self.store.transaction() as records:
                records.put("secret-key", {"bad": float("nan")})
        self.assertFalse(self.client.transactions[-1].committed)


if __name__ == "__main__":
    unittest.main()
