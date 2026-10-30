"""Agent-owned company rules and explicit personal attachment profile wiring."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from cryptography.fernet import Fernet

from runtime.business_profile_config import prepare_business_profile, BUSINESS_KEY_ENV
from runtime.receipt_draft_config import prepare_receipt_drafts
from runtime.requester import Requester
from runtime.state import ExpenseError
from runtime.auth_store import SQLiteAuthorizationStore


class ReceiptDraftConfigTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.rules = self.root / 'rules.json'
        self.rules.write_bytes((Path(__file__).parent / 'fixtures/synthetic_company_rules.json').read_bytes())
        self.config = {'rules_file': str(self.rules), 'sha256': hashlib.sha256(self.rules.read_bytes()).hexdigest(),
                       'person_companies': [{'person_id': 'alice', 'company_key': 'synthetic-meeting'}]}
        self.person = Requester('tenant', 'alice', 1900001000, capabilities=frozenset({'attachment:read'}))

    def test_rules_and_company_are_agent_owned_not_supplied_by_tool_or_ocr(self):
        factory = prepare_receipt_drafts(self.config, allowed_people={'alice'})
        builder, company = factory(self.person)
        draft = builder.build({'text': '合計 330円', 'engine': 'tesseract', 'language': 'jpn+eng'},
                              'receipt:' + 'a' * 32 + '.png', company)
        self.assertEqual(draft['company_key'], 'synthetic-meeting')
        self.assertEqual(draft['rule_check']['max_total'], '500')
        self.assertFalse(draft['mf_registered'])
        self.assertTrue(draft['synthetic_rules'])

    def test_unknown_person_and_unregistered_company_fail_before_draft(self):
        factory = prepare_receipt_drafts(self.config, allowed_people={'alice'})
        with self.assertRaises(ExpenseError):
            factory(Requester('tenant', 'bob', 1900001000))
        for person, company in [('bob', 'synthetic-meeting'), ('alice', 'unknown')]:
            bad = copy.deepcopy(self.config)
            bad['person_companies'] = [{'person_id': person, 'company_key': company}]
            with self.assertRaises(ValueError):
                prepare_receipt_drafts(bad, allowed_people={'alice'})

    def test_rules_missing_changed_or_symlinked_after_start_are_refused(self):
        factory = prepare_receipt_drafts(self.config, allowed_people={'alice'})
        builder, company = factory(self.person)
        original = self.rules.read_bytes()
        for change in ('changed', 'missing', 'symlink'):
            if self.rules.exists() or self.rules.is_symlink():
                self.rules.unlink()
            if change == 'changed':
                self.rules.write_bytes(original + b' ')
            elif change == 'symlink':
                other = self.root / 'other.json'
                other.write_bytes(original)
                self.rules.symlink_to(other)
            with self.assertRaises(ExpenseError):
                builder.build({'text': '合計 330円', 'engine': 'tesseract', 'language': 'jpn'},
                              'receipt:' + 'a'*32 + '.png', company)

    def test_attachment_profile_requires_trusted_factory_but_no_mf_write_or_policy(self):
        value = {'enabled': True, 'namespace': 'receipt-drafts', 'capabilities': ['attachment:read'],
                 'financial_writes': False, 'policies': [], 'receipt_drafts': self.config}
        factory = prepare_business_profile(value, environ={BUSINESS_KEY_ENV: Fernet.generate_key().decode()},
                                           allowed_people={'alice'})
        store = SQLiteAuthorizationStore(self.root / 'auth.sqlite')
        self.addCleanup(store.close)
        with self.assertRaises(ValueError):
            factory(None, store)
        profile = factory(None, store, attachment_factory=lambda person: None)
        self.assertFalse(profile.financial_writes)
        self.assertIsNone(profile.policy_factory)
        self.assertIn('prepare_receipt_draft', profile.supported_operations)
        self.assertNotIn('mf_save_draft', profile.supported_operations)

    def test_no_receipt_config_preserves_unavailable_attachment_capability(self):
        value = {'enabled': True, 'namespace': 'receipt-drafts', 'capabilities': ['attachment:read'],
                 'financial_writes': False, 'policies': []}
        with self.assertRaises(ValueError):
            prepare_business_profile(value, environ={BUSINESS_KEY_ENV: Fernet.generate_key().decode()},
                                     allowed_people={'alice'})


if __name__ == '__main__':
    unittest.main()
