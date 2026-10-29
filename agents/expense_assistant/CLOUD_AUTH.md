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

初期構成は **MFのみ** です。`google` と `EXPENSE_GOOGLE_CLIENT_SECRET` の両方を省略してください。calendarは `not_configured`（設定未完了）と表示され、接続ボタン・再認証・復旧待ちの案内は出しません。Google追加時は `google: {"client_id": "...", "callback_uri": "https://SA-ORIGIN/api/chat/agent-service-callback?provider=calendar"}` と専用secretを追加します。片方だけ設定した不完全なprovider、provider設定なしの余分なsecretは起動エラーです。両provider省略も可能で、両方 `not_configured` になります。両方設定時は `ProviderHost`、片方のみの場合は暗号化vaultと `build_service_connections` を使います。両方なしの場合も拒否専用adapter経由で同じGUIを構成します。

設定済みproviderの実障害・status取得例外は `unavailable` のままです。v1 enum拡張のため、[反映順序](SERVICE_CONNECTIONS.md#v1状態の拡張と反映順序)に従いSA側のsuperset対応をruntimeより先に反映します。Googleアプリ設定・クラウド反映・順序調整はmain担当が行います。

## 読み取り実行のツール一覧

初期クラウド経路は `ProviderExecutionResolver.supported_operations` の操作だけを提供します。HTTPの `tools/list` は、その上限と毎回検証した本人の同意・provider接続の共通範囲を返します。`mf:read` だけのclientには `mf_offices`、`mf_list_transactions`、`mf_list_reports` を提示し、MFの本人接続が利用可能なら実行できます。calendarと配送契約は各能力の同意・実装が揃った場合だけ提示します。

memory、過去科目の候補、領収書取得・保存・OCR、書込・draft保存はこの経路では未提供です。直接呼ばれても `operation_unavailable` とし、再同意やMF全体の再接続を求めません。ツール一覧は認可の代替ではなく、実行時にも本人・tenant・scope・失効と接続を検証します。ローカルstdio入口は従来の全操作・領収書resourceを保持します。

この修正の合成テストは実際のHTTP JSON-RPC、本人別OAuth同意と暗号化vaultを通りますが、クラウド配置・Engine公開版更新・実MFデータ読み取りの成功証跡ではありません。

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

## 本人限定検証から社員展開へ

本人限定は利用対象の設定であり、個人専用のコードやサービスを社員ごとに作る設計ではありません。同じホスト・provider adapterを使い、検証済み本人のtenant/person/providerをキーに同意・tokenを分離します。社員自身によるAPIキー・環境変数・CLI設定は不要とし、接続GUIで自分のサービスへ初回ログイン・同意します。共有するのはアプリ情報のみで、管理者の個人tokenを社員へ共有しません。

初期検証後の展開には、管理者が確認した社員ID一覧による本人リンクの一括登録、プラットフォーム側の利用対象設定、本人別MCP grant resolverの接続が必要です。人数や更新頻度に応じて本人リンクは専用ストアの登録簿へ分離します。メール文字列の一致だけによる自動登録はしません。他の入口も、同じ本人への管理済みリンクと入口ごとの署名trustを登録します。

全社員への利用許可の前に、異なる実利用者2名以上で、他人のtoken・データ・DMに到達しないこと、同意拒否・失効・退職時のtoken失効、refresh後の読み取り、本人と当該エージェントの非公開会話への配送を確認します。Googleアプリの組織内公開設定、providerの許可・制限、ログと保存期間、DB接続数・同時実行上限も配置担当者が確認します。MFの実書き込みはdurableな承認・重複防止ストアを結合した後の別の受入項目です。
