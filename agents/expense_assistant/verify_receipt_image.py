#!/usr/bin/env python3
"""Actual local OCR -> encrypted local draft, synthetic fixture, NO MF/network.

Run inside Dockerfile.auth's image with this script and the synthetic PNG mounted
read-only. Source transport is a local test adapter, not evidence of live SA.
The actual OCR executable, parsing, fixed company rules, receipt persistence and
service draft operation are exercised. Missing fields are never fabricated.
"""
import hashlib
import json
from pathlib import Path
import tempfile
from cryptography.fernet import Fernet

from runtime.auth_store import SQLiteAuthorizationStore
from runtime.durable_receipts import DurableReceipts
from runtime.durable_state import DurableState
from runtime.receipt_draft import ReceiptDraftBuilder
from runtime.receipt_ocr import ReceiptOCR
from runtime.service import ExpenseService


def main():
    image = Path('/test/receipt.png').read_bytes()
    owner = 'synthetic-receipt-verification'

    class Source:
        def manifest(self):
            return {'schemaVersion': 'source-attachment-manifest/v1', 'invocationId': 'synthetic-local',
                    'sourceMessageId': 'synthetic-message', 'manifestSha256': hashlib.sha256(image).hexdigest(),
                    'attachments': [{'id': 'receipt-image', 'filename': 'synthetic_receipt.png',
                                     'contentType': 'image/png', 'size': len(image)}]}

        def get(self, reference):
            if reference != 'attachment:receipt-image':
                raise AssertionError('Unknown synthetic attachment')
            return image, 'image/png'

    class NoMF:
        def __init__(self):
            self.owner = owner

        def __getattr__(self, _):
            raise AssertionError('MF operations forbidden in synthetic image verification')

    with tempfile.TemporaryDirectory() as directory:
        store = SQLiteAuthorizationStore(Path(directory) / 'auth.sqlite')
        try:
            key = Fernet.generate_key()
            state = DurableState(store, key, owner, 'synthetic-receipt')
            service = ExpenseService(mf=NoMF(), state=state,
                receipts=DurableReceipts(store, key, owner, 'synthetic-receipt', Source()),
                receipt_ocr=ReceiptOCR(), receipt_drafts=ReceiptDraftBuilder(json.loads(
                    Path('/app/rules/synthetic_company_rules.json').read_text())),
                receipt_company='synthetic-meeting', write_enabled=False)
            draft = service.call('prepare_receipt_draft', {})
            assert draft['fields']['total']['value'] == '330'
            assert draft['fields']['tax_amount']['value'] == '30'
            assert draft['fields']['tax_rate']['value'] == '10'
            assert draft['fields']['date']['value'] == '2026-10-30'
            assert draft['fields']['registration_number']['value'] is None
            assert draft['rule_check']['status'] == 'within_limit'
            assert state.preview_details(draft['preview_id'])['action'] == 'receipt_draft'
            assert draft['mf_registered'] is False and draft['submitted'] is False
            print(json.dumps({'schema': 'actual-ocr-local-draft-verification/v1', 'passed': True,
                              'actual_image_ocr': True, 'source_transport': 'synthetic_local',
                              'mf_operations': 0, 'external_network': False, 'draft': draft}, ensure_ascii=False))
        finally:
            store.close()


if __name__ == '__main__':
    main()
