"""Synthetic OAuth -> real MCP -> signed human GUI -> host restart journey.

No Engine, chat platform, provider API, external network or real personal data.
"""
from contextlib import asynccontextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, parse_qs, urlsplit

import httpx
from cryptography.fernet import Fernet
from cloud_auth_app import create_app, _close_resources
from runtime.auth_store import SQLiteAuthorizationStore
from test_authorization import CHALLENGE, VERIFIER
import test_cloud_auth_app as fixtures


class LongMemoryJourneyTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CloudAuthTests.setUpClass()

    async def asyncSetUp(self):
        self.fixture=fixtures.CloudAuthTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'synthetic-auth.sqlite'
        self.fixture.env['EXPENSE_BUSINESS_ENCRYPTION_KEY']=Fernet.generate_key().decode()
        self.fixture.config['clients'][0]['capabilities']=['memory:read','memory:propose']
        self.fixture.config['business']={'enabled':True,'namespace':'synthetic-memory-journey',
            'capabilities':['memory:read','memory:propose'],'financial_writes':False,'policies':[]}

    @asynccontextmanager
    async def host(self):
        store=SQLiteAuthorizationStore(self.path)
        app=create_app(environ=self.fixture.environment(),store_factory=lambda _:store)
        web=app
        while not hasattr(web,'router'): web=web.app
        try:
            async with web.router.lifespan_context(web):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app),
                    base_url=self.fixture.config['origin']) as client:
                    yield client
        finally:
            _close_resources(app._resources)

    async def token(self,client,subject):
        fixture=self.fixture
        callback=fixture.config['clients'][0]['redirect_uris'][0]
        path='/oauth/authorize?'+urlencode({'response_type':'code','client_id':'sa',
            'redirect_uri':callback,'resource':fixture.config['origin']+'/mcp',
            'scope':'memory:read memory:propose','code_challenge':CHALLENGE,
            'code_challenge_method':'S256','state':'synthetic-memory-state'})
        page=await client.get(path,headers=fixture.signed('GET',path,subject=subject))
        self.assertEqual(page.status_code,200,page.text)
        body=urlencode({'request_id':page.json()['request_id'],'csrf_token':page.json()['csrf_token'],
                        'decision':'approve'}).encode()
        decision=await client.post('/oauth/consent',content=body,headers={
            **fixture.signed('POST','/oauth/consent',subject=subject,body=body),
            'content-type':'application/x-www-form-urlencoded'})
        self.assertEqual(decision.status_code,303,decision.text)
        code=parse_qs(urlsplit(decision.headers['location']).query)['code'][0]
        result=await client.post('/oauth/token',data={'grant_type':'authorization_code','client_id':'sa',
            'code':code,'redirect_uri':callback,'resource':fixture.config['origin']+'/mcp','code_verifier':VERIFIER})
        self.assertEqual(result.status_code,200,result.text)
        return result.json()['access_token']

    async def call(self,client,token,name,args=None):
        reply=await client.post('/mcp',headers={'authorization':'Bearer '+token,
            'accept':'application/json, text/event-stream','mcp-protocol-version':'2025-03-26'},
            json={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args or {}}})
        self.assertEqual(reply.status_code,200,reply.text)
        value=reply.json()['result']
        self.assertFalse(value.get('isError'),value)
        return value.get('structuredContent') or json.loads(value['content'][0]['text'])

    async def view(self,client):
        reply=await client.get('/memory',headers=self.fixture.signed('GET','/memory'))
        self.assertEqual(reply.status_code,200,reply.text)
        return reply.json()

    async def decide(self,client,view,action,subject='alice',**extra):
        row=view['entries'][0]
        body=urlencode({'csrf_token':view['csrf_token'],'action':action,'id':row['id'],
                        'expected_digest':row['digest'],**extra}).encode()
        return await client.post('/memory/decision',content=body,headers={
            **self.fixture.signed('POST','/memory/decision',subject=subject,body=body),
            'content-type':'application/x-www-form-urlencoded'})

    async def test_real_protocol_confirm_restart_update_delete_and_person_isolation(self):
        with patch('socket.create_connection',side_effect=AssertionError('External network forbidden')):
            async with self.host() as client:
                alice,bob=await self.token(client,'alice'),await self.token(client,'bob')
                proposed=await self.call(client,alice,'propose_teaching',{
                    'kind':'formatting','content':'架空テストでは短い箇条書きにする'})
                self.assertEqual(proposed['status'],'proposed')
                self.assertEqual((await self.call(client,alice,'expense_context'))['teachings'],[])
                self.assertEqual((await self.call(client,bob,'expense_context'))['teachings'],[])
                view=await self.view(client)
                other=await self.decide(client,view,'accept',subject='bob')
                self.assertEqual(other.status_code,409)
                accepted=await self.decide(client,view,'accept')
                self.assertEqual(accepted.status_code,200,accepted.text)
            # Brand-new host, resolver, services and DB connection. The previous
            # personal grant and encrypted data survive, not a conversation list.
            async with self.host() as client:
                context=await self.call(client,alice,'expense_context')
                self.assertEqual(context['teachings'][0]['content'],'架空テストでは短い箇条書きにする')
                self.assertTrue(context['teachings_untrusted_data'])
                self.assertEqual((await self.call(client,bob,'expense_context'))['teachings'],[])
                updated=await self.decide(client,await self.view(client),'update',kind='preference',
                    content='架空テストでは一文で回答する',due_date='')
                self.assertEqual(updated.status_code,200,updated.text)
                context=await self.call(client,alice,'expense_context')
                self.assertEqual(context['teachings'][0]['content'],'架空テストでは一文で回答する')
                deleted=await self.decide(client,await self.view(client),'delete')
                self.assertEqual(deleted.status_code,200,deleted.text)
                self.assertEqual((await self.call(client,alice,'expense_context'))['teachings'],[])


if __name__=='__main__': unittest.main()
