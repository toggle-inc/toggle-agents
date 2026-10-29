# 専用 expense auth/provider host

`cloud_auth_app.py` は `create_platform_host` と既存の本人別provider APIを構成するASGI factoryです。認証、同意、MF/Googleの本人別接続が対象です。初期設定はowner本人の明示リンク1件のみとし、他の利用者を有効にするときは管理者がリンクを個別追加します。メール照合、自動リンク、既定person、共有ownerへのfallbackはありません。各リンクのperson IDは重複を拒否し、provider vaultを分離します。

配置先は管理者が指定する専用サービスです。実際のサービス名・project・region・配置証跡は非公開の `.deploy/` で管理します。この文書・実装だけではIAM、DB、秘密管理、配置完了を証明しません。

## 必要な設定

環境変数 `EXPENSE_AUTH_CONFIG` に次のJSONを設定します。すべての値は配置管理者が供給します。例は合成データです。実際の本人リンクや配置情報はGitに保存しません。

```json
{
  "origin": "https://expense-auth.example.test",
  "tenant_id": "expense-tenant",
  "platform_issuer": "https://sa-preview.example.test",
  "platform_public_keys": {
    "platform-key-v1": "-----BEGIN PUBLIC KEY-----\nREPLACE_WITH_RSA_PUBLIC_KEY\n-----END PUBLIC KEY-----\n"
  },
  "clients": [
    {
      "client_id": "sa",
      "display_name": "Success Assist",
      "redirect_uris": ["https://sa-preview.example.test/api/chat/agent-oauth-callback"],
      "capabilities": ["mf:read", "calendar:read"]
    }
  ],
  "identity_links": [
    {
      "platform_tenant_id": "explicit-platform-tenant",
      "subject": "explicit-owner-platform-subject",
      "person_id": "explicit-canonical-person"
    }
  ],
  "provider_namespace": "expense-auth-dedicated-v1",
  "ingress_mode": "cloud_run_tls",
  "mf": {
    "client_id": "explicit-mf-app-id",
    "callback_uri": "https://sa-preview.example.test/api/chat/agent-service-callback?provider=mf"
  }
}
```

`origin` と `platform_issuer` は末尾スラッシュなしの完全なHTTPS originです。RSA公開鍵は2048 bit以上、kidは署名側と一致させます。`clients` はOAuthクライアント登録で、redirect URIとcapabilitiesは明示的な許可リストです。例のOAuth callbackパスはplaceholderであり、配置担当者がSA側の実際の登録値を確認します。provider callbackとは別です。

`identity_links` は `(platform_issuer, platform_tenant_id, subject)` の完全一致でのみ内部の `(tenant_id, person_id)` へ解決します。platform tenantと内部tenantを混同しません。未知の本人・別tenant・別issuerは拒否します。リンク追加・削除は管理者による設定変更と再起動で行います。リンク削除だけで既発行OAuth tokenが失効するとは限らないため、既存token・同意の失効も別途行います。

次の専用Secret環境変数を設定します。汎用 `DATABASE_URL` や既存ownerのprovider tokenは読みません。

| 環境変数 | 必要な内容 |
| --- | --- |
| `EXPENSE_AUTH_DATABASE_URL` | 専用PostgreSQL DSN。host/dbname/user/passwordを明示、`sslmode=verify-full`。Cloud Runでは `sslrootcert=/etc/ssl/certs/ca-certificates.crt` を必須とする |
| `EXPENSE_PROVIDER_ENCRYPTION_KEY` | 専用Fernetキー。URL-safe base64でエンコードした32 byte鍵。再起動・全インスタンスで同じ値を維持 |
| `EXPENSE_MF_CLIENT_SECRET` | `mf` を設定するときのMFアプリsecret |
| `EXPENSE_GOOGLE_CLIENT_SECRET` | `google` を設定するときのみGoogleアプリsecret |

Mac固有のcertifiパスは配置担当者がDSN Secret作成時に上記Linuxパスへ置き換えます。アプリはDSNや鍵を自動変換しません。DSNにはlibpq `service` やUnix socketのfallbackを許可しません。root CAファイルはDockerで導入する `ca-certificates` を使います。

初期構成は **MFのみ** です。`google` と `EXPENSE_GOOGLE_CLIENT_SECRET` の両方を省略してください。calendarは `unavailable` と表示され、再認証を求めません。Google追加時は `google: {"client_id": "...", "callback_uri": "https://SA-ORIGIN/api/chat/agent-service-callback?provider=calendar"}` と専用secretを追加します。片方だけ設定した不完全なprovider、provider設定なしの余分なsecretは起動エラーです。両provider省略も可能で、両方 `unavailable` になります。両方設定時は `ProviderHost`、片方のみの場合は暗号化vaultと `build_service_connections` を使います。両方なしの場合も拒否専用adapter経由で同じGUIを構成します。

## DBと権限

配置担当者が専用DB/roleを確認し、`runtime/postgres_auth_schema.sql` を管理者として適用します。schemaは `expense_assistant_auth`、tableは `auth_records` です。runtime roleに必要なのはschemaのUSAGE、tableのSELECT/INSERT/UPDATEのみです。既存アプリDBや広い管理者roleを指定しないでください。アプリはDDLを実行せず、Postgresの取引とロックを既存API経由で使います。`/health` はプロセス生存確認のみでDB疎通を検査しません。DB疎通・権限は配置担当者が別途確認します。

provider tokenは専用鍵、namespace、検証済みrequester owner、providerに束縛して暗号化保存します。既存provider tokenの移行・読み込みは行いません。各本人が新たに接続します。鍵やnamespaceを変更すると既存vaultを読めなくなるため、配置担当者が鍵保管と変更手順を管理します。

## TLS、callbackとログ

Cloud Run用の `ingress_mode: "cloud_run_tls"` は「HTTPポートへ届く全トラフィックが信頼するCloud Run TLS終端を経由する」という配置契約です。配置担当者がサービスの公開経路とコンテナへ直接アクセスできないことを確認します。指定された構成はingress allで、外側のTLS終端保証を使います。入口wrapperがHTTP ASGI scopeを固定 `https` とし、任意の `Forwarded` / `X-Forwarded-*` は除去します。uvicornの `proxy_headers=False` を維持します。Hostは設定originと完全一致する必要があり、転送Hostで書き換えません。Cloud Run以外でこのモードを流用しません。直接ASGI TLSを使う場合は `asgi_tls` とし、実際のscopeがhttpsである必要があります。

ブラウザのprovider callbackは登録した **SA PreviewのGET endpoint** `/api/chat/agent-service-callback?provider=mf`（Googleは `provider=calendar`）へ返します。SA BFFはその都度ログイン済み本人を確認し、agentの **POST `/connections/callback`** に `application/x-www-form-urlencoded` bodyとして `provider`, `code`, `state`（またはerror）を送り、Originを付け、正確なbody bytesと固定targetを署名します。provider code/stateをagent宛URLのqueryへ付けません。署名の非公開鍵はSA BFFにのみ保持します。ブラウザやモデルにassertionを公開しません。既存のplatform assertion protocol、単回jti、60秒以内の有効期限を維持します。

cloud wrapperはGET `/connections/callback` を既存appへ渡す前に405で拒否します。拒否は外部のリクエストURL記録を防ぐものではないため、GET callbackの送信自体を禁止します。legacy GETを使う既存ローカルテストとは構成が異なります。

アプリのaccess logを無効化し、factory/entrypointで標準Python loggingをCRITICALまで無効化します。MCPの `basicConfig(INFO)` も有効化しません。`/health` は `{"status":"ok"}` のみを返し、設定・DB・本人・鍵・provider状態を含めません。無効設定は値を含まないエラーで起動失敗します。配置担当者の実環境確認で `/healthz` は入口で404になるため、アプリのヘルスパスは `/health` のみです。

Cloud Run request logやSA/Vercel側のURL記録はアプリloggingと別です。組織の追加ログsinkにも転送され得るため、`_Default` exclusionだけで十分と判断してはいけません。共有監査sinkを停止せず、配置担当者がBFFのPOST protocol、ブラウザcallback側を含むログ経路、URLに秘密を送信しないことを確認してから接続フローを公開します。

## 配置と検証

ビルドcontextはこのagentフォルダだけです。`Dockerfile.auth` を指定し、配置アーキテクチャは `linux/amd64` を使います。`.dockerignore` はignore-allから必要なroot Pythonファイル、requirements、runtime、同梱foundationだけを許可し、`.deploy`、テスト、bytecodeを除外します。imageは非root UID 10001、起動は `python cloud_auth_app.py`、portは `PORT`（既定8080）です。`mcp_server.py` はrequester MCPのimport依存として同梱します。親・兄弟のソースは不要です。

配置担当者が確認する設定は、サービス名/project/region、TLS入口契約、origin/Host、BFF issuerと公開鍵kid、OAuth client/redirect URI/capabilities、ownerの正確な本人リンク、MF app/callback登録、専用DB/role/schema/CA、Fernet鍵とnamespace、SecretのIAM、POST callback、両側のログ経路です。コードの追加だけでこれらが登録・配置されたとは扱いません。

`resolve_connection` は常にNoneを返します。OAuth認証やprovider接続が成功しても、requester別のtool grantは付与しません。`/mcp` のディスパッチはfail closedです。将来ツールを有効にするときは、検証済み本人・capability・有効期限・対象serviceを束縛した `ConnectionGrant` を返すtrusted resolverを別途実装します。

ローカル検証はagentフォルダから `python -m unittest test_cloud_auth_app test_platform_login test_provider_host test_service_connections test_authorization_host test_provider_vault -v`、リポジトリルートから `python -m unittest discover -s tests -v` を依存導入済み環境で行います。合成鍵・本人・SQLiteを使った検証であり、実MF/Google、クラウドDB、IAM、配置成功を示しません。
