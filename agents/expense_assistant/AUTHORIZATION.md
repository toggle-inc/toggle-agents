# エージェント自身が持つ認証・同意・リソーストークン

## 配置先から分離するもの

Git正本はこのエージェントフォルダ。Engineへ固有の認証ロジックを追加しない。
`runtime/authorization.py` が利用許可とトークン、`authorization_app.py` が同意UI／OAuth／MCPの入口を管理する。
Engine・SA・Buzzはいずれも利用クライアントまたは実行先の選択肢であり、認証の正本ではない。

配置先から注入するものは、HTTPSの公開origin、許可クライアント設定、SSO検証アダプタ、
トランザクション対応ストレージ、本人別の実プロバイダ接続である。
会社のSSOやMF・Googleの認証サービスそのものをGitへ内蔵するわけではない。

## 実装済み

- 明示登録したpublic clientだけを許可。redirect URI、resource、許可能力は配置設定で固定。
- Okta OIDCのAuthorization Code + PKCE S256ログイン、暗号化した一回限りstate、nonce、
  discovery/JWKS確認、RS256署名・issuer・audience・`azp`・expiry・nonce検証、
  `sub`による明示identity-link解決を `runtime/okta_oidc.py` に実装。
- callback後はランダムなserver-side session IDのみをSecure/HttpOnly/SameSite=Lax cookieへ設定し、
  logoutと期限切れを検証する。ID tokenやOkta client secretはcookieに保存しない。
  メールアドレスやプロフィール属性で本人を自動リンクしない。linkがない場合は拒否する。
- `create_app(..., login_adapter=okta)` は未ログイン認可GETからOktaへ遷移し、固定
  `/login/callback` で元の `/oauth/authorize` URLへ戻す。Okta issuer/client/callback、秘密鍵、
  private transactional store、明示identity-link resolverは配置設定が必要。
- SSOで本人確認した後、本人がHTML画面で許可・拒否・既存許可の解除を選択する。
- 認可コード＋PKCE S256のみ。コードは60秒・一度限り、同意フォームは5分・一度限り。
- 同意は本人・テナント・クライアント・能力に束縛。フォームnonce・Originも検証する。
- アクセストークンはランダムなopaque値、有効期限15分。本人・resource・能力を検証する。
  名前／本文／共有キーから本人を推測しない。発行時の能力は実行時にも上限として維持。
- 初回の同意で更新用トークンも発行する。更新権限に一律の有効期限・放置期限は設けず、
  許可が有効な限り、ログインや同意画面を再表示せずに短命アクセストークンを更新できる。
  生のアクセストークンを無期限にする方式ではない。
- 更新用トークンは交換ごとにローテーションし、使い終わった値は二度使えない。
  同一クライアントによる再利用を検出したら、その連携の現在のaccess／refreshもまとめて失効する。
  accessまたはrefreshのどちらを解除しても、同じ系列の更新権限を失効させる。
- トークン失効、本人によるクライアント単位の同意解除、同意revisionの照合。
  再同意すると以前のrevisionのトークンも失効する。解除後に同意しても旧トークンは復活しない。
- ストアにはトークン・コード・フォームnonceのSHA-256を保存し、生の値は保存しない。
  本人IDや同意内容は機微なメタデータなので、ストア自体も非公開にする。
- ツール・領収書とも発行済みトークンを毎回検証。金融操作の個別承認は引き続き別に必要。
- OAuth metadata、protected-resource metadata、同意、トークン発行、失効のHTTPルート。
  HTTPS／正確なHost、no-store、CSP、クリックジャッキング対策を適用。

## 保存先は差し替える

`runtime/auth_store.py` の `AuthorizationStore.transaction()` を配置アダプタが実装する。
`Records.get/put` を含む処理全体を原子的にcommit／rollbackすることが必須。
別々のGET／SETに置き換えるとコードの二重交換を防げない。

同梱の `SQLiteAuthorizationStore` は単一ホスト向け。公開ソース外の700ディレクトリに600のファイルを置く。
ストアにMF・Googleのトークンを入れる機能はない。それらは別の本人用秘密保管領域に置く。
クラウドで複数レプリカを使う際は、共有のトランザクションストアへ差し替える。
コンテナの一時SQLiteを永続ストアの代わりに使わない。

`runtime/postgres_auth_store.py` にPostgreSQL adapterがある。会社で利用中のNeon/Postgresを使う場合も、
Nowcast等の既存アプリ用schema・DB role・接続文字列を共用せず、専用schema `expense_assistant_auth` と
専用runtime roleを用意する。`runtime/postgres_auth_schema.sql` はDB管理者が適用し、実行roleには
このschemaのUSAGEとauth_records表のSELECT/INSERT/UPDATEだけを付与する。
adapterは各操作をPostgres transactionで実行し、読み取った行をロックして一回限りコードの同時交換を防ぐ。
未作成レコードへの同時アクセスも保護するため、schema単位のtransaction advisory lockを
読み取り前に取得する。同一schemaの認証操作は直列化されるため、実配置では待ち時間・
connection/statement timeoutも監視・設定する。合成モデルで競合とロールバックを検証しているが、
実Neonでの接続・ロック・最小権限検証は別途必要。
Neon pooled connection string等は配置先のSecret Managerから注入し、Git・ログ・クライアントへ出さない。
DB/schema/roleの作成と権限設定はDB管理者が行う。既存Neonの接続文字列をそのまま流用しない。

テストではSQLiteとメモリ用アダプタで同じ発行処理を動かし、
独立したSQLite接続から同じコードを同時交換しても一度だけ成功することを確認する。
更新用トークンの交換も同じトランザクションで行う。
使用済み更新トークンのハッシュは再利用検出に必要なので、有効な系列の履歴を安易に削除しない。

## 信頼済み配置コードから組み立てる

```python
import os

from authorization_app import create_app
from runtime.authorization import AgentAuthorization
from runtime.postgres_auth_store import PostgresAuthorizationStore
from runtime.okta_oidc import OktaOIDCLogin

private_transactional_store = PostgresAuthorizationStore(
    os.environ["EXPENSE_AUTH_DATABASE_URL"], schema="expense_assistant_auth"
)
okta = OktaOIDCLogin(
    private_transactional_store,
    resolve_explicit_okta_link,
    issuer=okta_issuer,
    client_id=okta_client_id,
    client_secret=okta_client_secret,
    callback_uri=public_https_origin + "/login/callback",
    tenant_id=configured_tenant,
    state_encryption_key=private_okta_state_key,
)

authority = AgentAuthorization(
    private_transactional_store,
    okta.verify_login,
    issuer=public_https_origin,
    tenant_id=configured_tenant,
    clients=explicit_public_clients,
)
app = create_app(authority, resolve_own_service, login_adapter=okta)
```

この例の変数は配置先が提供する。Okta callback URLはOkta appにも完全一致で登録する。
`resolve_explicit_okta_link(tenant, issuer, sub)` は会社が管理する本人linkを参照し、
認証済みのcanonical person IDまたは未リンクを返す。自己申告cookie、無署名ヘッダー、
モデル出力、メール一致で本人を選ばない。本モジュールはパスワード収集・独自の社員アカウント管理・
Engine JWTの流用を行わない。

ブラウザで初めて接続する際は、`create_app(..., login_adapter=okta)` を使う。
adapterは `/oauth/authorize` の完全な元URLを暗号化済み・一度限りのstateへ結び付け、
Okta callback後にそのURLへ戻す。任意の `return_to` を受け付けず、クライアントのredirect URIへ直接
戻してはならない。同意POSTはブラウザログインへ再送せず401で停止し、ログイン後に画面から本人が
もう一度選択する。実Okta app設定、host、明示link tableの接続と実機確認は別途必要。

`resolve_own_service(person, capability)` は、その本人のMF・カレンダー等の現在の同意と実接続だけを返す。
本人トークンの取得は、MF・Googleへの利用許可を得た証明ではない。
サービスへの同意が不足していれば停止し、本人用の連携画面を別途案内する。

認証・同意のメソッドは信頼済みWebルート用で、MCP／LLMツールとして登録しない。
TLS終端でASGIのschemeを設定する場合は、信頼した入口からのみ受け付ける。
任意のForwardedヘッダーを信じてHTTPS・本人確認を偽装させない。
リクエスト本文・Authorization・OAuthコード・SSO cookieをアクセスログへ記録しない。

## クライアントによる自動更新

クライアントは初回のtokenレスポンスから `access_token` と `refresh_token` を本人別の秘密保管先へ保存する。
期限前に `/oauth/token` へ `grant_type=refresh_token`、`client_id`、`refresh_token` を送る。
ログインcookieや同意画面の再操作は不要。`resource` は省略できるが、元のresourceに固定される。
`scope` を指定する場合は縮小のみで、初回同意より広い権限は発行しない。

返された新しいaccess／refreshを原子的に保存し、古い更新トークンを再送しない。
同じ連携の更新はクライアント側でも直列化する。並列更新や、結果不明の交換の盲目的な再試行は、
再利用検出によって系列失効となる。`invalid_grant` なら再送を止め、初回の認証フローへ戻す。
解除・不正利用検出・権限取消・資格情報紛失等の例外では再認証が必要となる。

更新APIがあっても、クライアントが更新を呼び出さなければ自動更新にはならない。
実際のSA／Buzz／Engineクライアントの保存・直列更新は実接続時のE2Eで確認する。
MF・Google自身の同意取消・セキュリティポリシーによる失効は別であり、無期限の利用を保証するものではない。

## 今回は対応しないもの／公開前の条件

- 実Okta app/Cloud Run設定、社員の明示identity link投入、実MF・Googleの本人別認証画面への統合、既存Engineでの実OAuth往復。
- 自動クライアント登録、implicit／password／client credentials grant。
- callbackはHTTPSの固定URIだけを受け付ける。ネイティブアプリのloopback URIやカスタムschemeは未対応。
- SA等の実行依頼者と、OAuthで許可したSSO本人との対応付けの実機検証。
  この発行処理だけで、プラットフォーム内の依頼者との同一性まで自動証明できるわけではない。
  各入口の本人別トークン保管・署名済み本人連携を検証し、別人の認証を紐付けさせないこと。
- 公開入口のレート制限、期限切れメタデータの保存期間／削除、バックアップ、監査・アカウント停止連動。
  これらは配置アダプタ／運用を含めて決め、実ユーザー公開前に検証する。

今回の検証は、合成Okta署名鍵・合成SSO/MFで、実際の同意／発行／検証プログラムとSDKのHTTP/JSON-RPCを通すASGIテスト。
本番での本人認証・外部サービス連携成功を意味しない。既存公開版や本人の接続は変更しない。

## 検証と参照

```sh
python -m unittest test_authorization test_authorization_app -v
```

認可コード・PKCEの設計は [OAuth Security BCP (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700.html) を参照。
この実装は適合性認証を受けたものではないため、本番公開前には認証・OAuth境界のレビューと実SSO E2Eを行う。
