"""Agent-owned memory management for verified humans, never model tools.

The host supplies a fresh person-scoped service. Model proposals are inactive
until the human confirms exact content through this private, CSRF-bound GUI.
"""
import hashlib
import html
import math
import secrets
import time
import re

from starlette.responses import HTMLResponse, JSONResponse
from .requester import Requester
from .state import ExpenseError

KINDS = {'commuter_pass': '定期券区間', 'base_location': '拠点',
         'formatting': '回答の書式', 'pending': '保留事項', 'preference': '好み・設定'}


class MemoryRequestError(ExpenseError):
    pass


class MemoryManagement:
    def __init__(self, store, resolve, *, clock=time.time):
        if not callable(getattr(store, 'transaction', None)) or not callable(resolve) or not callable(clock):
            raise ValueError('Explicit private memory store and service resolver required')
        self.store, self.resolve, self.clock = store, resolve, clock

    def _state(self, person):
        if (not isinstance(person, Requester) or person.kind != 'human'
                or type(person.expires_at) not in (int, float)
                or not math.isfinite(person.expires_at) or person.expires_at <= self.clock()):
            raise ExpenseError('本人のログインを確認してください。')
        service = self.resolve(person)
        if service.state.owner != person.owner or self.clock() >= person.expires_at:
            raise ExpenseError('本人専用の記憶を確認できません。')
        return service.state

    def view(self, person, *, cursor=None):
        state = self._state(person)
        if cursor is not None and (not isinstance(cursor, str) or not re.fullmatch(r'[a-f0-9]{32}', cursor)):
            raise MemoryRequestError('記憶のページを確認してください。')
        rows = sorted(state.memory_entries(), key=lambda row: row['id'])
        if self.clock() >= person.expires_at:
            raise ExpenseError('本人のログイン期限を確認して画面を開き直してください。')
        if cursor is not None:
            rows = [row for row in rows if row['id'] > cursor]
        entries = rows[:200]
        next_cursor = entries[-1]['id'] if len(rows) > 200 else None
        token = secrets.token_urlsafe(32)
        expires = math.floor(min(person.expires_at, self.clock() + 300))
        if self.clock() >= expires:
            raise ExpenseError('本人のログイン期限を確認して画面を開き直してください。')
        with self.store.transaction() as records:
            records.put('memory-gui:' + hashlib.sha256(token.encode()).hexdigest(), {
                'owner': person.owner, 'expires_at': expires, 'used': False,
                'entries': {row['id']: row['digest'] for row in entries}})
        if self.clock() >= expires:
            raise ExpenseError('本人のログイン期限を確認して画面を開き直してください。')
        return {'schema_version': 'agent-personal-memory/v1', 'agent_slug': 'expense_assistant',
                'csrf_token': token, 'expires_at': expires, 'entries': entries, 'next_cursor': next_cursor}

    def decide(self, person, params):
        if not isinstance(params, dict):
            raise MemoryRequestError('記憶の操作内容を確認してください。')
        action = params.get('action')
        expected = {'csrf_token', 'action', 'id', 'expected_digest'}
        if action == 'update':
            expected |= {'kind', 'content', 'due_date'}
        if (action not in {'accept', 'update', 'delete'} or set(params) != expected
                or any(not isinstance(value, str) for value in params.values())
                or not 1 <= len(params['csrf_token']) <= 256):
            raise MemoryRequestError('記憶の操作内容を確認してください。')
        state = self._state(person)
        key = 'memory-gui:' + hashlib.sha256(params['csrf_token'].encode()).hexdigest()
        with self.store.transaction() as records:
            row = records.get(key)
            if (not row or row.get('owner') != person.owner or row.get('used') is not False
                    or row.get('expires_at', 0) <= self.clock()
                    or row.get('entries', {}).get(params['id']) != params['expected_digest']
                    or self.clock() >= person.expires_at):
                raise ExpenseError('確認画面の本人・内容・期限を確認し、開き直してください。')
            records.put(key, {**row, 'used': True})
        # No approval ID, owner or state path comes from model arguments.
        state = self._state(person)
        if action == 'accept':
            state.confirm_memory(params['id'], params['expected_digest'])
        elif action == 'update':
            state.update_memory(params['id'], params['expected_digest'], params['kind'],
                                params['content'], params['due_date'])
        else:
            state.delete_memory(params['id'], params['expected_digest'])
        return {'schema_version': 'agent-personal-memory-decision/v1', 'action': action,
                'id': params['id'], 'applied': True}

    def render(self, person, *, as_json=False, cursor=None):
        view = self.view(person, cursor=cursor)
        if as_json:
            return JSONResponse(view, headers={'cache-control': 'no-store'})
        esc = lambda value: html.escape(str(value), quote=True)
        parts = ['<!doctype html><html lang="ja"><meta charset="utf-8"><title>本人の記憶</title>',
                 '<h1>本人の記憶</h1><p>確定した設定だけを会話をまたいで参照します。',
                 '秘密や認証情報は保存しないでください。変更後は画面を開き直してください。</p>']
        for row in view['entries']:
            parts.append('<section><h2>' + esc(KINDS.get(row['kind'], row['kind'])) + '</h2><p>'
                         + esc(row['content']) + '</p><p>' + esc(row['status']) + '</p>')
            for action, label in ((('accept', '保存を確定'),) if row['status'] == 'proposed' else ()) + (
                    (('update', '内容を更新'),) if row['status'] == 'active' else ()) + (('delete', '削除'),):
                parts.append('<form method="post" action="/memory/decision">')
                for name, value in {'csrf_token': view['csrf_token'], 'action': action,
                                    'id': row['id'], 'expected_digest': row['digest']}.items():
                    parts.append('<input type="hidden" name="' + name + '" value="' + esc(value) + '">')
                if action == 'update':
                    parts.append('<label>種類<select name="kind">' + ''.join(
                        '<option value="' + key + '"' + (' selected' if key == row['kind'] else '')
                        + '>' + label + '</option>' for key, label in KINDS.items()) + '</select></label>')
                    parts.append('<label>内容<textarea name="content" maxlength="1000">' + esc(row['content'])
                                 + '</textarea></label><label>保留の確認予定日<input type="date" name="due_date" value="'
                                 + esc(row.get('due_date') or '') + '"></label>')
                parts.append('<button type="submit">' + label + '</button></form>')
            parts.append('</section>')
        if not view['entries']:
            parts.append('<p>保存された記憶はありません。会話で記憶候補を依頼してください。</p>')
        if view['next_cursor']:
            parts.append('<a href="/memory?cursor=' + view['next_cursor'] + '">次のページ</a> ')
        if cursor is not None:
            parts.append('<a href="/memory">先頭のページ</a>')
        return HTMLResponse(''.join(parts) + '</html>', headers={'cache-control': 'no-store'})
