"""PostgreSQL-backed transactional store for OAuth and Okta session records.

Use a private schema and a database role limited to this schema. The runtime
does not create schemas or tables; apply the accompanying SQL as a DB admin.
"""

import contextlib
import copy
import hashlib
import json
import re


class _PostgresRecords:
    def __init__(self, connection, schema):
        self._connection = connection
        self._table = f'"{schema}"."auth_records"'
        self._reads = {}
        self._writes = {}

    @staticmethod
    def _key(key):
        if not isinstance(key, str) or not key:
            raise ValueError("Authorization record key required")
        return hashlib.sha256(key.encode()).hexdigest()

    def get(self, key):
        db_key = self._key(key)
        if db_key in self._writes:
            return copy.deepcopy(self._writes[db_key])
        if db_key not in self._reads:
            row = self._connection.execute(
                f"SELECT value FROM {self._table} WHERE key = %s FOR UPDATE",
                (db_key,),
            ).fetchone()
            value = row[0] if row else None
            if isinstance(value, str):
                value = json.loads(value)
            self._reads[db_key] = value
        return copy.deepcopy(self._reads[db_key])

    def put(self, key, value):
        db_key = self._key(key)
        if not isinstance(value, dict):
            raise ValueError("Authorization records must be JSON objects")
        validated = json.loads(json.dumps(value, allow_nan=False, separators=(",", ":")))
        self._connection.execute(
            f"INSERT INTO {self._table} (key, value) VALUES (%s, %s::jsonb) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (db_key, json.dumps(validated, allow_nan=False, separators=(",", ":"))),
        )
        self._writes[db_key] = validated


class PostgresAuthorizationStore:
    """`AuthorizationStore` implementation using PostgreSQL transactions.

    Supply a Neon pooled connection string from a secret manager or deployment
    environment. Schema names are SQL identifiers and are restricted to safe
    lowercase names; table data access is always schema-qualified.
    """

    def __init__(self, connection_string, *, schema="expense_assistant_auth", connect=None):
        if not isinstance(connection_string, str) or not connection_string.strip():
            raise ValueError("PostgreSQL connection string required")
        if not isinstance(schema, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise ValueError("Safe PostgreSQL schema name required")
        if connect is None:
            import psycopg

            connect = psycopg.connect
        self._connection_string = connection_string
        self._connect = connect
        self._schema = schema

    @contextlib.contextmanager
    def transaction(self):
        connection = self._connect(self._connection_string)
        try:
            with connection.transaction():
                yield _PostgresRecords(connection, self._schema)
        finally:
            connection.close()

    def close(self):
        """Connections are opened and closed per transaction."""
