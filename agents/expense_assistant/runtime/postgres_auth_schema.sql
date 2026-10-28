-- Apply as a database administrator. Keep this schema and runtime role
-- separate from application schemas such as Nowcast's.
CREATE SCHEMA IF NOT EXISTS expense_assistant_auth;

CREATE TABLE IF NOT EXISTS expense_assistant_auth.auth_records (
    key text PRIMARY KEY,
    value jsonb NOT NULL CHECK (jsonb_typeof(value) = 'object')
);

REVOKE ALL ON SCHEMA expense_assistant_auth FROM PUBLIC;
REVOKE ALL ON TABLE expense_assistant_auth.auth_records FROM PUBLIC;

-- After creating a dedicated runtime role, grant only these permissions:
-- GRANT USAGE ON SCHEMA expense_assistant_auth TO expense_assistant_runtime;
-- GRANT SELECT, INSERT, UPDATE ON TABLE
--   expense_assistant_auth.auth_records TO expense_assistant_runtime;
