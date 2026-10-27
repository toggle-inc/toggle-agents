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
- SSOで本人確認した後、本人がHTML画面で許可・拒否・既存許可の解除を選択する。
  未ログインは401。SSOログイン画面への誘導／コールバックは別のアダプタが必要。
- 認可コード＋PKCE S256のみ。コードは60秒・一度限り、同意フォームは5分・一度限り。
- 同意は本人・テナント・クライアント・能力に束縛。フォームnonce・Originも検証する。
- アクセストークンはランダムなopaque値、有効期限15分。本人・resource・能力を検証する。
  名前／本文／共有キーから本人を推測しない。発行時の能力は実行時にも上限として維持。
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

テストではSQLiteとメモリ用アダプタで同じ発行処理を動かし、
独立したSQLite接続から同じコードを同時交換しても一度だけ成功することを確認する。

## 信頼済み配置コードから組み立てる

```python
from authorization_app import create_app
from runtime.authorization import AgentAuthorization

authority = AgentAuthorization(
    private_transactional_store,
    verify_login_session,
    issuer=public_https_origin,
    tenant_id=configured_tenant,
    clients=explicit_public_clients,
)
app = create_app(authority, resolve_own_service)
```

この例の変数は実際の配置アダプタが提供するもので、設定済みではない。
`verify_login_session(Request)` は会社SSOの署名・発行元・宛先・有効期限・テナントを検証し、
認証済みの共通個人を `Requester` として返す。
自己申告cookie、無署名ヘッダー、モデル出力を返してはならない。
同一の会社SSO／明示的な本人アカウント連携に基づき共通個人IDを決める。メール一致による自動統合は禁止。
本モジュールはパスワード収集・独自の社員アカウント管理・Engine JWTの流用を行わない。

`resolve_own_service(person, capability)` は、その本人のMF・カレンダー等の現在の同意と実接続だけを返す。
本人トークンの取得は、MF・Googleへの利用許可を得た証明ではない。
サービスへの同意が不足していれば停止し、本人用の連携画面を別途案内する。

認証・同意のメソッドは信頼済みWebルート用で、MCP／LLMツールとして登録しない。
TLS終端でASGIのschemeを設定する場合は、信頼した入口からのみ受け付ける。
任意のForwardedヘッダーを信じてHTTPS・本人確認を偽装させない。
リクエスト本文・Authorization・OAuthコード・SSO cookieをアクセスログへ記録しない。

## 今回は対応しないもの／公開前の条件

- 実会社SSOの接続、実MF・Googleの本人別認証画面への統合、既存Engineでの実OAuth往復。
- 自動クライアント登録、refresh token、implicit／password／client credentials grant。
  初期版は15分で再認可が必要。長期利用のUXはrefresh等を別途設計してから拡張する。
- callbackはHTTPSの固定URIだけを受け付ける。ネイティブアプリのloopback URIやカスタムschemeは未対応。
- SA等の実行依頼者と、OAuthで許可したSSO本人との対応付けの実機検証。
  この発行処理だけで、プラットフォーム内の依頼者との同一性まで自動証明できるわけではない。
  各入口の本人別トークン保管・署名済み本人連携を検証し、別人の認証を紐付けさせないこと。
- 公開入口のレート制限、期限切れメタデータの保存期間／削除、バックアップ、監査・アカウント停止連動。
  これらは配置アダプタ／運用を含めて決め、実ユーザー公開前に検証する。

今回の検証は、模擬SSO・模擬MFで、実際の同意／発行／検証プログラムとSDKのHTTP/JSON-RPCを通すASGIテスト。
本番での本人認証・外部サービス連携成功を意味しない。既存公開版や本人の接続は変更しない。

## 検証と参照

```sh
python -m unittest test_authorization test_authorization_app -v
```

認可コード・PKCEの設計は [OAuth Security BCP (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700.html) を参照。
この実装は適合性認証を受けたものではないため、本番公開前には認証・OAuth境界のレビューと実SSO E2Eを行う。
