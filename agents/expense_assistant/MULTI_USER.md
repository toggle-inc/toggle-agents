# 依頼者本人の接続で動く経費アシスタント

## 到達点と未接続箇所

Git正本に `runtime/requester.py` の依頼者別ディスパッチとアクセス契約を追加した。
合成ユーザー2人で同じ本体を呼び、本人以外の接続・記憶・領収書・承認を利用できないことを検証する。
`deploy.py` は同じアクセス契約を配置パッケージの指示へ生成する。
プロンプトへの同梱は認可の代わりではなく、実行側での検査が必須。

`requester_mcp.py` に複数ユーザー向けHTTP/MCPリソース入口を追加した。
SDKの実HTTP/JSON-RPC経路（インプロセスASGI）で、ツール・領収書・失効・同時実行を検証する。
その入口単体のテストでは本人トークン検証器と外部データは模擬であり、Engine実機の検証ではない。

さらに、エージェント自身が同意UI・コード交換・トークン発行／検証／失効を持つ
`authorization_app.py` と `runtime/authorization.py` を追加した。詳細は [AUTHORIZATION.md](AUTHORIZATION.md)。
このコードはEngineに依存せず、保存先を差し替えられる。

**実会社SSO、実際のEngine／SA／Buzzへの多人数接続、本人別Google OAuthへの置換は未接続。**
既存の `engine_mcp.py` は引き続き一人専用であり、共有Bearerを社員の本人証明として使ってはいけない。
この変更で既存の公開版、接続、トークン、権限は変更しない。

## 共通の実行境界

1. 入口が各リクエストの署名・発行者・宛先・期限・テナントを検証する。
2. 信頼済みアカウント対応表で、プラットフォームの認証済みアカウントを共通の個人IDへ結び付ける。
   同じメール・表示名・本文の名乗りによる自動統合は禁止。管理者・テナント共有キーだけでは本人にならない。
3. `RequesterDispatcher.call(opaque_request_context, operation, arguments)` を信頼済みホストが呼ぶ。
   `authenticate` コールバックが `Requester` を返す。この型の作成自体は認証ではない。
4. `resolve(requester, capability)` が、その個人の現在のサービス同意と当エージェントへの利用許可を検査し、
   本人の資格情報で組み立てた `ExpenseService` と有効期限を `ConnectionGrant` に入れる。
   未連携なら `None`。失効・権限不足は毎回拒否する。共有／管理者／既定の接続へフォールバックしない。
5. ディスパッチがテナント・個人・期限・能力・状態／MF／領収書の所有者を検査し、既存の業務処理を呼ぶ。
6. 金融書き込みは、既存の本人・会社・内容・期限に束縛されたプレビューと別経路の本人承認も必要。
7. 取得結果・エラー・途中経過は既存の `delivery.json` に従って本人だけへ配送する。

`request_context`・認証コールバック・接続ストア・本人ID・接続IDはモデルへ渡すツール引数ではない。
コールバック、資格情報の保存、本人対応表はホストの信頼境界にある。
コールバックが偽装情報を返せる環境をこのモジュールだけで保護することはできない。

接続サービスの全プロバイダ（カレンダー・添付取得を含む）は本人の認可範囲で構築する。
サービス・OAuth保管先・SQLite・領収書の名前空間は `Requester.owner`（テナントと共通個人IDのハッシュ）に固定する。
グローバルな「現在のユーザー」やリクエスト間での認証差し替えは使わない。
実行開始後の失効に対しては、外部APIの失効検証も必要。開始済みのリクエストを遡って取り消せる保証はない。

## ツールとリソースの両方を守る

`call` のほか、領収書リソースには `read_receipt(request_context, reference)` を使う。
これも毎回 `receipt:read` の本人認可を検査する。
旧 `mcp_server.create_server(single_service)` は一人専用のまま。
ツールだけをディスパッチに付け替え、リソースを元の一人用サービスに残す接続は禁止する。
`requester_mcp.create_app(dispatcher, public_host)` は、全ツール・リソースで
リクエストに束縛された認証文脈を渡す。本文に本人IDを足す方式ではない。
認証ヘッダー重複・欠落・不正値は401、正確なHost／Origin以外は拒否する。
ステートレスMCPとリクエスト単位のContextVarを使用し、応答は `Cache-Control: no-store`。
SDKワーカースレッド内でも同じリクエスト文脈を使い、リクエスト終了時に破棄する。
トークン検証と個人の接続解決は初期化時だけではなく、各ツール・リソース呼び出しでも行う。

この入口に渡す `authenticate(token)` は、経費MCP宛ての本人別リソーストークンを
信頼できる発行元・audience・期限・失効・対象個人について検証しなければならない。
Engineの実行JWT、MF API用トークン、共有接続キーを代わりに受理しない。
`requester_mcp.py` 単体はトークンを発行しないが、`authorization_app.create_app` は
同梱のエージェント所有の発行サービスと結び付ける。Engine側に認証機能を追加する方針ではない。
実SSO・本人別サービス接続が未設定の状態で、単に公開URLや共有Bearerを設定して本番公開してはいけない。

## 認証UIと共通基盤との役割分担

- 管理者は共有のOAuthアプリ設定を一度用意する。従業員へキーや環境変数の入力を求めない。
- 本人がサービスの認証画面で同意し、対象エージェントへの利用許可を付ける。
  既に許可済みの接続は再利用できるが、新しいエージェントへの無制限の自動許可はしない。
- 未連携時の `AuthorizationRequiredError` は安全なコードと必要能力だけを持つ。
  ホストが本人に束縛した認証画面を開く。モデルの生成URLや本文のユーザーIDを使わない。
- MFの同意とカレンダーの同意は別。既存iCal実装は個人URL方式のため、社員向けには
  本人別Google OAuth接続等の追加実装が必要。管理者権限で全員の予定を読む設計にはしない。
- 内部能力名（例 `mf:read`）はMF等のOAuthスコープ名ではない。
  ホスト側で実際のスコープ・所属・所有権・同意対象を検証して変換する。

Engine既存実装の確認結果：`oauth_service.SaPrincipal` は検証済みSA主体に対応し、
`ExternalMcpUserToken` はテナント＋SA社員ID＋外部MCP別の保存・失効を扱う。
Harnessの `_sa_oauth_connection_blockers` には未認可・不足スコープ・期限切れの事前検査と
`/sa-oauth/connect/{connection_id}` の導線がある。
ただし、これだけでMFの個人認証や本ディスパッチへの本人情報の受け渡しが完成するわけではない。
既存の共有資格情報／一時資格情報の経路を本人認可と混同しない。

### SAからの本人別接続契約

1. SAで認証された社員が「連携して実行」を選ぶ。SAは対象tenant・SA employee・connectionに束縛した
   一度限りの接続ticketをEngineへ渡し、Engineの `/sa-oauth/connect/{connection_id}` が使用する。
2. Engineはその社員専用のOAuth認可フローを開始し、agentのProtected Resource Metadataから認可サーバーを
   発見する。認可リクエストには登録済み `client_id`、Engine callbackの固定 `redirect_uri`、
   `state`、PKCE S256、`resource`、要求能力を含める。
3. 未ログインならagent配置の `start_login` アダプタが会社SSOへ送り、署名付きstateを検証して
   同じ認可URLへ戻す。`verify_login` が検証済みのtenantとcanonical personを返した後、本人に
   操作能力を表示してagent利用への同意を求める。本人の許可後、agentは一度限りのコードと元のstateを
   Engine callbackへ返す。SSOログインとagent利用許可は別々の操作。
4. Engineはcallbackのstate・redirect URI・PKCEを検証し、発行されたagent resource tokenを
   `tenant + SA employee + connection` の per-user tokenとして保存する。共有tokenや他社員の行を
   フォールバックに使わない。SA employee IDはEngineの内部主体であり、現在のagent OAuth仕様では
   agentへ転送されない。
5. よって、agentのSSO personとSA employeeの同一人物性を、会社の信頼できる本人対応表または
   署名済み本人連携で確認できるまで、接続を利用可能にしてはならない。メールアドレス一致、
   SAのtenant-wide credential、モデルの申告で紐付けない。紐付け不能なら認可・本人別service解決を
   拒否して管理者に対応を依頼する。
6. 以後Engineは、呼出元SA社員のper-user tokenを短命access/refresh tokenとして維持し、agent MCPへ
   Bearerで送る。agentはtokenに束縛されたpersonを検証し、その人のサービス同意・MF credentialを
   毎回解決する。MF OAuth refreshはEngineのagent-token refreshとは別の系列であり、agent側の
   本人専用secret storeで行う。どちらかが失効・解除されたら該当リクエストを止めて再接続を促す。

### Okta OIDC login adapter

会社SSOはOkta OIDCを使う。ホストの `start_login` / `verify_login` adapterはAuthorization Code flow
（confidential web client）で構成し、PKCE S256も有効にする。Okta issuer、client ID、許可済みcallback URI
は環境設定から固定し、任意のissuerやcallbackをリクエスト値から組み立てない。

- 開始時に暗号学的乱数の `state`、`nonce`、PKCE verifierを作り、短時間・一回限りのprivate storeに保存する。
  元の `/oauth/authorize` URLもこのstateレコードに結び付け、queryやcookieの未署名`return_to`は使わない。
- callbackではstateを原子的に一回だけ消費し、authorization codeを固定redirect URIとverifierで交換する。
  ID tokenの署名をdiscovery documentのJWKSで検証し、`iss`、`aud`、`exp`、`iat`、`nonce`を検証する。
- Oktaの安定した`sub`とissuerを外部主体キーにし、tenant内の明示済みidentity linkからcanonical personを解決する。
  `email`、表示名、部署、SA employee IDを使った自動紐付け・自己登録は禁止する。未リンクは拒否する。
- ログイン後はランダムなserver-side session IDのみを`Secure; HttpOnly; SameSite=Lax` cookieで渡す。
  sessionは期限・tenant・canonical personに束縛し、logout/期限切れで失効させる。tokenやID tokenをcookieに入れない。
- client secret、session/state signing key、Okta tokenはSecret Manager等のprivate secret storeで管理し、
  public MCP runtimeへOkta client secretを渡さない。IdP callbackでは任意の同意POSTを再送せず、
  認証後に元の認可GETを再開して同意画面を表示する。

これは配置用adapterの要件であり、Okta org・app・callback URI・secret・常設hostの設定完了を意味しない。
実際のSSO成功は、承認済みOkta appと固定HTTPS hostを結び、ログイン・logout・未リンク拒否を実機で確認してから扱う。

### 実ホストのscope→owner binding

PR #4の `SAApprovalAdapter` / `SAAttachmentAdapter` は、毎回のhost callback
`verify_scope(scope, owner)` が `True` を返すことを要求する。認証ブランチの
`runtime/sa_identity.py` にある `verify_sa_scope(...)` は、このcallbackに渡せる検査部品である。
これはSA署名やログインcookieを検証しない。ホストの `verify_invocation(scope, origin)` が、
固定HTTPSのSA originで最新かつ有効な実行scopeを確認し、scope全体を保持した
`VerifiedSAInvocation` を返した場合だけ利用する。

この検査はscopeの全フィールド（tenant、requester employee、run、harness session、
managed agentとversion、invocation、source/root message、channel）をSAで確認した値と照合する。
ホストは別途、`(tenantId, requesterEmployeeId)` の明示的な本人リンクを解決し、そのcanonical
person IDを `AgentAuthorization.verify_login` と `RequesterDispatcher` の両方で使う。
`verify_sa_scope` はその人の `Requester.owner` を計算し、本人用serviceのownerと一致しなければ拒否する。
リンクは会社SSO subjectまたは同等の認証済みaccount-link手順で作り、email一致から自動生成しない。
ID・scope・権限の検証は各approval/attachment操作前に新しく行い、結果をcacheしない。

```python
from runtime.sa_identity import verify_sa_scope

def scope_belongs_to_service(scope, owner):
    return verify_sa_scope(
        scope,
        owner,
        verify_invocation=sa_gateway.verify_current_invocation,
        resolve_person=identity_links.resolve_sa_employee,
        origin=SA_ORIGIN,
    )
```

`sa_gateway` は配置先の認証済みクライアントであり、実装時に署名・issuer・audience・期限・
tenant・employee・run・session・version・origin/source・現在の権限を検証してから
`VerifiedSAInvocation` を返す。`identity_links` は会社が管理する明示リンクを読む。
未リンク・不明issuer・期限切れ・run変更・権限取り消し・外部API失敗はすべて拒否する。
`scope` の元値はSAの認証済みrequest contextから渡し、本文・添付OCR・model tool argsから作らない。

SA service credentialはこのtrusted hostからSAのapproval/attachment APIへ出す認証専用である。
agentのMCP OAuth client、本人別MF token、EngineがMCPへ送るper-user Bearerとは別に保管する。
個人用MCP endpointへSA credentialを渡さず、レスポンス・tool引数・ログにも出さない。
ホストは短命Bearerを本人ごとに解決するMCP adapterと、内部でSA APIを呼ぶapproval/attachment
adapterを分離し、現在ユーザーのprocess-global cacheを使わない。

### 月末pilotの最小配置条件

- 外部から到達できる固定HTTPS issuerで `authorization_app` と `/mcp` を稼働し、Engineの登録済み
  OAuth client/callbackと一致させる。ローカルPCや一時Preview tunnelを接続先にしない。
- `AgentAuthorization` のcode/consent/family recordsは、複数worker間で原子的なtransactionが
  できる永続private storeへ保存する。単一workerのpilotなら専用永続volume上のprivate SQLiteを使える。
  scale-to-zero/一時filesystemならSQLiteを使わず、durable transactional DB adapterを用意する。
- 会社SSOの `start_login` / `verify_login` と、SA employee→canonical personの明示link tableを接続する。
  canonical personはSA loginとagent MCP resource tokenの両方で同じIDを使い、既存のSA Employee IDを
  別名として扱うには認証済みlinkを先に作る。linkが作れない社員はpilot対象外として拒否する。
- MF Cloud Expense OAuth appの既存client ID/secretを使えるか確認する。使えるappがなければ
  会社管理下でOAuth appを登録してsecretを発行し、Secret ManagerからMF credentialを取り出す。
  各社員は自分のMFIDで同じappを個別認可し、MF refresh/access tokensはcanonical person ownerで
  暗号化保存する。個人用MF tokenを共有・複製しない。
- SA側credentialは対象pilot tenant/managed agentだけに制限し、次の操作だけに使う。
  invocation/run/employee/session/version/sourceの確認、当該invocationの添付metadata/binary GET、
  approval proposalのPOST、本人決定記録のGET。POSTは本人の決定ではなく、確認依頼を作るだけ。
  既存の別scope/service credentialがこの最小範囲を表現できない場合は、権限を広げずPreview用の
  別credentialを用意する。外部OCR、MF書込、ユーザー一覧、admin endpointsの権限は付けない。
- SA credentialを読むIAM bindingは、専用のprivate bridge runtime service accountだけに付ける。
  public MCP/OAuth processのservice accountには付けない。認証bridgeはprivate network/service identityで
  呼び、SA secret・MF secret・user refresh tokensをHTTP、MCP body、trace/logへ出さない。
- 失効hookはEngineのper-user token revokeとagent consent revokeを同期する。MF同意取消・token refresh
  失敗・canonical link停止も毎回のresolverで拒否し、再認証/再リンクを促す。

実接続を始めるには、少なくとも次の判断・アクセスが必要になる。
①pilotの正確なtenant/managed-agent/versionと、社員→SSO canonical IDの対応を承認、
②会社SSOのlogin/callback検証に必要な最小権限、
③上記API操作だけに限定したSA Preview credential、
④既存MF OAuth appの再利用可否（不可ならclient secretの新規発行）、
⑤固定HTTPS host、永続DB、Secret Managerに対する専用runtime IAM。
これらはDraft PRや合成テストの承認には含まれず、設定前にそれぞれ対象を絞って確認する。

Money Forwardのクラウド経費APIは、利用者がMFIDでログインしてアプリを認可したユーザー権限で
tokenを発行する。MF側にはクラウド経費ごとのOAuthアプリ登録とclient secretが必要であり、
refreshでは新しいaccess/refresh tokenが返る。MF client secretは配置側の秘密として保持し、社員へ
入力させない。MF公式の[OAuth/API手順](https://github.com/moneyforward/expense-api-doc) と
[認可エンドポイント](https://developers.biz.moneyforward.com/docs/api/auth/authorize/)、
[トークンエンドポイント](https://developers.biz.moneyforward.com/docs/api/auth/create-token/)を参照。
この確認は仕様資料の照合であり、MFアプリ登録・権限・実ユーザーのOAuth往復成功を意味しない。

## 次の統合段階

1. エージェント所有の認証サービスへ、実会社SSOの検証アダプタと秘密保管先を設定する。
   Engineには既存の外部MCP OAuth経路があり、Harnessはユーザー別に解決したBearerをMCPへ渡す。
   Engine内部の本人IDが自動的に外部MCPへ渡るわけではない。
   経費固有の認証・同意・トークン発行をEngineへ移さない。Engineは利用先の一つとして設定する。
2. 本人別MF・カレンダー接続と安全な認証／失効UIを実装し、Engine既存OAuth経路へ登録する。
3. 合成2人による入口からのE2E、権限解除、期限切れ、別テナント、領収書リソースを検証する。
4. 本人同意を得た実ユーザー2人で読み取り検証する。金融書き込み・一般公開は別途判断する。

検証例（このエージェントフォルダ内で実行）:

```sh
python -m unittest test_requester -v
python -m unittest test_requester_mcp -v
```

これは合成テストであり、実ユーザー接続やEngine実機成功の証跡ではない。
