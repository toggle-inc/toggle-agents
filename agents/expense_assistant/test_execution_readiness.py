"""Readiness is agent consent + fresh personal grants, never provider UI alone."""

import dataclasses
import unittest
from pathlib import Path

import test_authorization as fixture
from runtime.authorization import AuthorizationError
from runtime.execution_readiness import ExecutionReadiness
from runtime.requester import ConnectionGrant
from runtime.service import ExpenseService
from runtime.state import State
from test_requester import SyntheticMF


class ExecutionReadinessTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.AuthorizationTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.services = {}
        for name, person in self.f.people.items():
            state = State(Path(self.f.directory.name) / (name + '.sqlite'), person.owner)
            self.addCleanup(state.close)
            self.services[name] = ExpenseService(mf=SyntheticMF(person.owner, name), state=state)
        self.calls = []
        self.disconnected = False

        def resolve(person, capability):
            self.calls.append((person.person_id, capability))
            if self.disconnected:
                return None
            return ConnectionGrant(person.tenant_id, person.person_id, person.expires_at,
                                   person.capabilities, self.services[person.person_id],
                                   agent_slug='expense_assistant')

        self.resolve = resolve
        self.ready = ExecutionReadiness(self.f.authority, resolve)
        self.params = {'schema_version': 'agent-execution-readiness-request/v1',
                       'client_id': 'sa', 'request_id': 'synthetic-request-1'}

    def consent(self):
        self.f.code(capabilities=frozenset({'mf:read', 'calendar:read'}))

    def test_connected_providers_are_not_agent_authorization(self):
        result = self.ready.view('alice', self.params)
        self.assertFalse(result['ready'])
        self.assertEqual(result['reason'], 'agent_authorization_required')
        self.assertEqual(self.calls, [])

    def test_partial_consent_cannot_satisfy_broad_registered_client(self):
        self.f.code(capabilities=frozenset({'mf:read'}))
        self.assertEqual(self.ready.view('alice', self.params)['reason'], 'agent_authorization_required')
        self.assertEqual(self.calls, [])

    def test_consent_and_fresh_grants_are_ready_without_tool_execution(self):
        self.consent()
        result = self.ready.view('alice', self.params)
        self.assertTrue(result['ready'])
        self.assertEqual(result['request_id'], self.params['request_id'])
        self.assertEqual(result['expires_at'], self.f.now + 60)
        self.assertEqual({p for p, _ in self.calls}, {'alice'})
        self.assertNotIn('access_token', result)
        self.assertFalse(self.ready.view('bob', self.params)['ready'])

    def test_revocation_and_provider_disconnect_rechecked(self):
        self.consent()
        self.disconnected = True
        self.assertEqual(self.ready.view('alice', self.params)['reason'], 'service_connection_required')
        self.disconnected = False
        self.f.authority.revoke_consent('alice', 'sa')
        self.assertEqual(self.ready.view('alice', self.params)['reason'], 'agent_authorization_required')

    def test_invalid_identity_client_and_request_are_rejected(self):
        for who, patch in [('unknown', {}), ('alice', {'client_id': 'unknown'}),
                           ('alice', {'request_id': 'two words'}), ('alice', {'person_id': 'bob'})]:
            with self.assertRaises(AuthorizationError):
                self.ready.view(who, {**self.params, **patch})

    def test_grant_for_another_person_or_expired_grant_is_not_ready(self):
        self.consent()
        def wrong(person, capability):
            return dataclasses.replace(self.resolve(person, capability), person_id='bob')
        self.assertFalse(ExecutionReadiness(self.f.authority, wrong).view('alice', self.params)['ready'])
        def expired(person, capability):
            return dataclasses.replace(self.resolve(person, capability), expires_at=self.f.now)
        self.assertFalse(ExecutionReadiness(self.f.authority, expired).view('alice', self.params)['ready'])
