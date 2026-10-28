# ログイン済みプラットフォームの本人確認を利用する

## 方針

社員はSA・Buzz等へログイン済みなら、エージェントのためだけにOktaへ再ログインしない。
本人確認は入口のプラットフォーム、本人証明の検証と共通個人IDへの対応付けはこのGit正本が担う。
MF・カレンダー等への本人の連携同意と、各エージェントへの利用許可は別に検証する。
本人証明の成功だけで `mf:draft` やデータ閲覧・書き込みを許可しない。
エージェントごとのOktaアプリ登録を標準の配置条件にしない。

共通処理は `platform_identity.py`。各フォルダの `_foundation/` に同梱するため、
配置後に親フォルダ・Engine・SAの実装をimportしない。検証器の利用時のみ
`PyJWT[crypto]` が必要。公開リポジトリには社員対応表・実鍵・接続先設定を入れない。

## 本人証明の契約 v1

HTTPSのサーバー間リクエストに `X-Agent-Platform-Assertion` を一つだけ付ける。
ブラウザ・モデル・チャット・ログ・URLにassertionや署名秘密鍵を渡さない。
プラットフォームのBFF（本人用画面とエージェント間のサーバー処理）が、毎回ログインsession・
本人・現在の権限・CSRF・元の連携開始依頼の所有者を検査して署名する。
PAT・guest・agent・共有サービスアカウント・なりすましsessionを本人証明に転用しない。

JWT headerは `alg=RS256`、固定登録した `kid`、`typ=agent-platform-principal+jwt` のみ。
エージェントは2048bit以上のRSA公開鍵を固定設定し、JWT内のURL/JWKから鍵を取得しない。
既存のAPI用assertionやEngine実行ticketを流用しない。

必須claim（その他はv1では拒否）：

| claim | 内容 |
|---|---|
| iss | 実際に本人sessionを確認したplatformのHTTPS origin。Previewと本番は別設定 |
| aud | エージェント認証hostの固定HTTPS origin |
| tenant_id / sub | platform内のtenantと、認証済みの安定した社員ID。Engine tenantやメールではない |
| actor_type / purpose | `human` / `platform_login` |
| iat / exp | 発行・失効時刻。署名proofは最大60秒、未来iatの許容は5秒 |
| auth_expires_at | 元の本人session期限。proof期限とは別、検証時から最長24時間 |
| jti | cryptographic randomの一度限りID。毎リクエスト新規発行 |
| method / target | GET/POST、送信先の絶対URL。query順序・percent encodingも実送信bytesと一致 |
| body_sha256 | 実送信body bytesのSHA-256小文字hex。GETは空bytes |
| origin | 元のbrowser origin。POSTは登録platform issuerと完全一致。GETは空または同issuer |

プラットフォームは署名後にURL/bodyを再serializeしない。
共通処理は署名・全claim・実リクエスト・時刻を検証し、
`resolve_person(issuer, platform_tenant, subject)` の有効な `PlatformPersonLink` を必須にする。
同じメール・表示名・本文の名乗りから自動統合しない。未リンク・停止・tenant違いは拒否。
`jti`はissuer/audience/platform tenantと合わせてhash化し、共有transactional storeで一度だけ消費する。
署名鍵・trust登録の追加は権限境界の変更であり、実環境では別途承認して設定する。

## 経費アシスタントへの接続

`authorization_host.create_platform_host` が、専用Postgres store、共通検証器、
`runtime/platform_login.py`、既存のagent所有OAuth authorityと初回会社別同意を組み立てる。
Oktaのclient ID/secret、callback、agent独自ログインcookieは不要。
本人はBFFが代理する `/oauth/authorize` GETと `/oauth/consent` POSTごとに検証し、
scope内のprivateな値として既存 `Requester` に変換する。HTTP本文の本人IDは受理しない。
MCPは今までどおり本人別のリソーストークンで認証し、platform assertionをBearerの代わりにしない。

認可GETで `Accept: application/json` を指定すると、plainな `agent-consent/v1` を返す。
`request_id` / `csrf_token` / `client_name` / `capabilities[{id,label}]` /
`draft_companies[{id,name}]` / `expires_at` を含む。BFFは同じ本人専用の画面として表示し、
外部HTMLを自分のoriginへ埋め込まない。会社の範囲・能力・保存可否はエージェントが判断する。
同意POSTの元Originは保持し、署名検証済みplatform contextから明示allowlist検査する。
旧来のagent origin検査を無条件に外したり、HTTP Originを書き換えたりしない。
POSTの選択は元の本人・CSRF・期限・会社へ束縛する。GETとPOSTが別人なら失敗する。

## 実SA/Buzz接続前の必須条件（未接続）

- **OAuth連携開始の所有者照合**：BFFは任意のauthorize URL/stateへ署名してはならない。
  OAuth clientが保持するstate/PKCE/tenant/connection/依頼社員を、保存済み本人flowと照合する。
  EngineをOAuth clientに使う入口では、そのadapterに限定照合APIまたは署名descriptor等が必要。
  target/bodyへの署名だけでは、攻撃者のflowに被害者の本人証明を付けるlogin CSRFを防げない。
  この照合が未実装なら、その入口の新しい連携開始機能は公開しない。
- **同意UI/BFF**：現在sessionの本人とflow所有者、同一origin POST/CSRF、会社選択を毎回確認。
  モデル入力・request bodyからsub/tenant/targetを採らず、固定host/pathへだけproxyする。
  証明をbrowserへ返さず、個人用responseを共有cache・起点channelへ出さない。
- **OAuth callbackの保護**：agentからの303をBFFが追随しない。Locationが登録callbackと
  期待stateに一致するか確認してbrowserを戻す。assertion・SA cookieはcallbackへ転送しない。
  code/tokenを別社員へ保存しない。本人用OAuth token保存・直列refreshも必要。
- **trustと個人link**：platformごとの署名鍵・公開鍵/issuer/audience登録、明示person link、
  現在sessionの認証由来チェック。agentからplatform全体の秘密鍵へアクセスしない。
- **運用**：短命proofの使用済みIDの保存期間、監査・レート制限・鍵ローテーション、
  元アカウント停止時の連携/接続の停止を接続adapterで定義・確認する。

今回確認済みなのは、合成platformの実RSA署名とHTTP/JSON-RPCを使ったローカル検証まで。
二人の本人同意→別々のMCP結果、改ざん・期限切れ・異なる起点・別人・replay・未リンク拒否を確認する。
実SA/BuzzのBFF、実鍵/trust/link登録、OAuth client flow所有者照合、実MF接続のE2Eは未実施。
既存の実接続や本番設定を、この変更で自動的に置き換えない。

参考：[JWT BCP](https://www.rfc-editor.org/rfc/rfc8725)、
[OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700)。適合性認証を受けたものではない。
