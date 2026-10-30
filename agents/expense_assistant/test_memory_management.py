"""Synthetic private GUI confirmations; no providers, Engine or network."""
from dataclasses import replace
import json
from types import SimpleNamespace
import unittest
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet
from authorization_app import create_app
from runtime.durable_state import DurableState
from runtime.memory_management import MemoryManagement, MemoryRequestError
from runtime.requester import Requester
from runtime.service import ExpenseService
from runtime.state import ExpenseError
import test_authorization as auth_fixture
import test_cloud_auth_app as cloud_fixture


class MemoryManagementTests(unittest.TestCase):
    def setUp(self):
        self.store, self.now, self.key = auth_fixture.MemoryStore(), 1000, Fernet.generate_key()
        self.people = {name: Requester('test', name, 5000) for name in ('alice', 'bob')}
        self.manager = MemoryManagement(self.store, self.service, clock=lambda: self.now)

    def service(self, person):
        return ExpenseService(mf=SimpleNamespace(owner=person.owner), state=DurableState(
            self.store, self.key, person.owner, 'synthetic-memory', lambda: self.now))

    def proposal(self, person='alice', content='架空テストでは回答を短くする'):
        return self.service(self.people[person]).propose_teaching('formatting', content)

    def form(self, view, action='accept', index=0, **extra):
        row=view['entries'][index]
        return {'csrf_token': view['csrf_token'], 'action': action, 'id': row['id'],
                'expected_digest': row['digest'], **extra}

    def test_confirmed_only_context_survives_new_service_and_new_manager(self):
        self.proposal()
        alice=self.people['alice']
        self.assertEqual(self.service(alice).expense_context()['teachings'], [])
        view=self.manager.view(alice)
        result=self.manager.decide(alice,self.form(view))
        self.assertTrue(result['applied'])
        fresh=MemoryManagement(self.store,self.service,clock=lambda:self.now)
        self.assertEqual(fresh.view(alice)['entries'][0]['status'],'active')
        self.assertEqual(self.service(alice).expense_context()['teachings'][0]['content'],
                         '架空テストでは回答を短くする')
        self.assertEqual(self.service(self.people['bob']).expense_context()['teachings'],[])
        self.assertNotIn('架空テストでは回答を短くする',json.dumps(self.store.rows,ensure_ascii=False))

    def test_update_delete_and_old_screen_cannot_restore(self):
        self.proposal()
        alice=self.people['alice']
        self.manager.decide(alice,self.form(self.manager.view(alice)))
        first,stale=self.manager.view(alice),self.manager.view(alice)
        self.manager.decide(alice,self.form(first,'update',kind='preference',content='架空の箇条書きを好む',due_date=''))
        with self.assertRaises(ExpenseError):
            self.manager.decide(alice,self.form(stale,'delete'))
        current=self.manager.view(alice)
        self.assertEqual(current['entries'][0]['content'],'架空の箇条書きを好む')
        self.manager.decide(alice,self.form(current,'delete'))
        self.assertEqual(self.manager.view(alice)['entries'],[])
        self.assertEqual(self.service(alice).expense_context()['teachings'],[])

    def test_other_person_csrf_digest_and_replay_fail(self):
        self.proposal()
        alice,bob=self.people.values()
        view=self.manager.view(alice)
        for person,params in ((bob,self.form(view)),
                              (alice,self.form(view,expected_digest='0'*64)),
                              (alice,self.form(view,csrf_token='invalid'))):
            with self.subTest(person=person.person_id,params=params):
                with self.assertRaises(ExpenseError): self.manager.decide(person,params)
        params=self.form(view)
        self.manager.decide(alice,params)
        with self.assertRaises(ExpenseError): self.manager.decide(alice,params)

    def test_expiry_and_resolver_owner_are_checked(self):
        self.proposal()
        alice=self.people['alice']
        view=self.manager.view(alice)
        self.assertLessEqual(view['expires_at'],self.now+300)
        self.now=view['expires_at']
        with self.assertRaises(ExpenseError): self.manager.decide(alice,self.form(view))
        with self.assertRaises(ExpenseError): self.manager.view(replace(alice,expires_at=self.now))
        bad=MemoryManagement(self.store,lambda _:self.service(self.people['bob']),clock=lambda:self.now)
        with self.assertRaises(ExpenseError): bad.view(alice)

    def test_extra_owner_and_invalid_action_are_rejected(self):
        self.proposal()
        view=self.manager.view(self.people['alice'])
        for extra in ({'owner':'bob'},{'action':'grant_admin'},{'csrf_token':False}):
            with self.assertRaises(MemoryRequestError):
                self.manager.decide(self.people['alice'],self.form(view,**extra))

    def test_gui_escapes_content_and_models_cannot_confirm(self):
        self.proposal(content='<b>架空の表示設定</b>')
        page=self.manager.render(self.people['alice']).body.decode()
        self.assertIn('&lt;b&gt;',page)
        self.assertNotIn('<b>架空',page)
        for name in ('confirm_memory','update_memory','delete_memory','accept_fact'):
            with self.assertRaises(ExpenseError): self.service(self.people['alice']).call(name,{})

    def test_201_entries_remain_manageable_and_nonce_is_page_bound(self):
        for i in range(201):
            self.proposal(content='架空の表示設定'+str(i))
        alice=self.people['alice']
        first=self.manager.view(alice)
        self.assertEqual(len(first['entries']),200)
        self.assertIsNotNone(first['next_cursor'])
        second=self.manager.view(alice,cursor=first['next_cursor'])
        self.assertEqual(len(second['entries']),1)
        self.assertIsNone(second['next_cursor'])
        self.assertFalse(set(row['id'] for row in first['entries']) & set(row['id'] for row in second['entries']))
        with self.assertRaises(ExpenseError):
            self.manager.decide(alice,self.form(second,'delete',csrf_token=first['csrf_token']))
        self.manager.decide(alice,self.form(second,'delete'))
        self.assertEqual(len(self.manager.view(alice)['entries']),200)
        self.assertIsNone(self.manager.view(alice)['next_cursor'])
        self.assertEqual(self.manager.view(alice,cursor='f'*32)['entries'],[])
        with self.assertRaises(MemoryRequestError): self.manager.view(alice,cursor='invalid')


class MemoryRouteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        fixture=auth_fixture.AuthorizationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture=fixture
        self.logic=MemoryManagementTests()
        self.logic.setUp()
        self.logic.people=fixture.people
        # Synthetic SSO adapter only: real deployments verify a signed platform assertion.
        authority=fixture.authority
        authority.verify_login=lambda request: self.logic.people.get(request.cookies.get('synthetic_login'))
        authority.store=self.logic.store
        manager=self.logic.manager
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(
            authority,lambda person,cap:None,memory_management=manager)),base_url=authority.issuer)
        self.addAsyncCleanup(self.client.aclose)

    async def test_private_gui_confirm_and_safe_errors(self):
        self.logic.proposal()
        headers={'cookie':'synthetic_login=alice','accept':'application/json'}
        unauth=await self.client.get('/memory',headers={'accept':'application/json'})
        self.assertIn(unauth.status_code,(400,401))
        view=await self.client.get('/memory',headers=headers)
        self.assertEqual(view.status_code,200)
        self.assertEqual(view.headers['cache-control'],'no-store')
        invalid=await self.client.get('/memory?cursor=invalid',headers=headers)
        self.assertEqual(invalid.status_code,400)
        unknown=await self.client.get('/memory?owner=bob',headers=headers)
        self.assertEqual(unknown.status_code,400)
        params=self.logic.form(view.json())
        forged=await self.client.post('/memory/decision',headers={**headers,'origin':'https://wrong.test'},data=params)
        self.assertEqual(forged.status_code,400)
        good=await self.client.post('/memory/decision',headers={**headers,'origin':str(self.client.base_url).rstrip('/')},data=params)
        self.assertEqual(good.status_code,200)
        self.assertTrue(good.json()['applied'])
        repeat=await self.client.post('/memory/decision',headers={**headers,'origin':str(self.client.base_url).rstrip('/')},data=params)
        self.assertEqual(repeat.status_code,409)


class SignedMemoryRouteTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cloud_fixture.CloudAuthTests.setUpClass()

    async def asyncSetUp(self):
        fixture=cloud_fixture.CloudAuthTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture=fixture
        self.key=Fernet.generate_key()
        fixture.env['EXPENSE_BUSINESS_ENCRYPTION_KEY']=self.key.decode()
        fixture.config['business']={'enabled':True,'namespace':'synthetic-memory-cloud',
            'capabilities':['memory:read','memory:propose'],'financial_writes':False,'policies':[]}
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=fixture.app()),
                                     base_url=fixture.config['origin'])
        self.addAsyncCleanup(self.client.aclose)
        self.person=Requester('expense-tenant','person-alice',5000000000)
        self.state=DurableState(fixture.store,self.key,self.person.owner,'synthetic-memory-cloud')
        self.state.propose_fact('formatting','架空テストでは短い箇条書き')

    async def test_signed_person_get_accept_update_delete_and_no_unsigned_access(self):
        fixture=self.fixture
        self.assertEqual((await self.client.get('/memory')).status_code,401)
        view=await self.client.get('/memory',headers=fixture.signed('GET','/memory'))
        self.assertEqual(view.status_code,200)
        self.assertEqual(view.json()['agent_slug'],'expense_assistant')
        self.assertEqual(len(view.json()['entries']),1)
        bob=await self.client.get('/memory',headers=fixture.signed('GET','/memory',subject='bob'))
        self.assertEqual(bob.json()['entries'],[])
        features=await self.client.get('/connections',headers=fixture.signed('GET','/connections'))
        self.assertTrue(features.json()['features']['personal_memory'])
        for action in ('accept','update','delete'):
            current=(await self.client.get('/memory',headers=fixture.signed('GET','/memory'))).json()
            row=current['entries'][0]
            params={'action':action,'id':row['id'],'expected_digest':row['digest'],
                    'csrf_token':current['csrf_token']}
            if action=='update':
                params.update(kind='preference',content='架空の新しい設定',due_date='')
            body=urlencode(params).encode()
            headers={**fixture.signed('POST','/memory/decision',body=body),
                     'content-type':'application/x-www-form-urlencoded'}
            response=await self.client.post('/memory/decision',headers=headers,content=body)
            self.assertEqual(response.status_code,200,response.text)
            self.assertTrue(response.json()['applied'])
        self.assertEqual(self.state.active_facts(),[])

    async def test_tampered_post_body_and_cookie_only_cannot_save(self):
        fixture=self.fixture
        body=b'action=accept'
        headers={**fixture.signed('POST','/memory/decision',body=body),
                 'content-type':'application/x-www-form-urlencoded'}
        response=await self.client.post('/memory/decision',headers=headers,content=body+b'&id=other')
        self.assertEqual(response.status_code,401)
        response=await self.client.post('/memory/decision',headers={
            'cookie':'person=alice','origin':fixture.config['platform_issuer'],
            'content-type':'application/x-www-form-urlencoded'},content=body)
        self.assertEqual(response.status_code,401)
        self.assertEqual(self.state.active_facts(),[])


if __name__=='__main__': unittest.main()
