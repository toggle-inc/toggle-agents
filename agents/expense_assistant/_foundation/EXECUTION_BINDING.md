# 実行と元会話を結ぶ検証契約 v1

状態: **エージェント側の検証・HTTP接続・合成結合テストまで**。
実サービスの署名発行、永続的な会話参照ストア、実行の起動制御、実SA APIへの接続は未完です。
この文書はEngineに履歴取得・選別・解釈・記憶を実装する指示ではありません。
正本はこのGitリポジトリ、配置単位は各agentに同梱する `_foundation/` です。

## 信頼の分担

- sourceサービスは、ログイン済み人間の元投稿と現在の閲覧権限を確認します。
- 実行ホストは、実際の呼出者・対象agent/version/接続・現在sessionを検証して運びます。
  canonicalな個人IDや経費情報を知る必要はありません。
- agentはresource OAuthの本人を毎回確認し、sourceとruntime両方のactorを
  明示アカウントリンクでcanonical tenant/personへ対応させ、一致を確認します。
- 履歴source adapterは、事前に束縛済みのsession、現在ACL、起点の編集削除・失効を検査します。
  履歴の取得・範囲選択・鮮度検査はagentのReaderが行います。履歴は本人承認にはなりません。

名前空間の異なるIDを同一視しません。特にsourceのtenant/employee、runtime tenant/subject、
resourceのcanonical tenant/person、Gitのagent slugは別です。メール・表示名の一致や
モデル本文からの推測、共通管理者キーへのfallbackは使いません。

## 独立した署名

`execution_binding.ExternalExecutionVerifier` は登録済みの固定issuer/audience/RSA公開鍵だけを
使います。RS256、2048 bit以上、kid完全一致、未知header/claim拒否。鍵の自動発見は行いません。
共通claimは `iss, aud, iat, exp, jti, purpose`。`aud` はagentの固定HTTPS originです。
IDは文字列、JWTの時刻は秒、未来発行・期限切れ・非有限時刻を拒否します。

| 証明 | HTTP header | JWT typ / purpose | 最大TTL |
| --- | --- | --- | --- |
| 元投稿の証明 | `X-Agent-Source-Context` | `agent-source-context+jwt` / `source_context` | 300秒 |
| 今回のHTTP実行の証明 | `X-Agent-Execution-Proof` | `agent-execution+jwt` / `external_mcp_execution` | 60秒 |

両方に `target_tenant_id, target_agent_id, target_version_id, invocation_id` を持ち、完全一致を要求します。
agentの固定allowlistは対象tenant/agent/version/connectionをすべて指定します。

元投稿の証明には次のclaimを追加します。

- `source_namespace, source_actor, source_actor_type`（typeは `human` のみ）
- `source_handle`（32 byte CSPRNG由来、base64url 43文字。会話IDや資格情報を埋めない）
- `anchor_revision`（sourceが定義した起点のSHA256 hex）

HTTP実行の証明には次のclaimを追加します。

- `connection_id, session_id`
- `actor_issuer, actor_namespace, actor_subject, actor_type`（typeは `human` のみ）
- `source_grant_sha256`（元投稿JWTそのもののUTF-8 bytes）
- `source_handle_sha256`（handleのASCII bytes）
- `method, target, body_sha256`（今回の正確な要求、固定HTTPS `/mcp`、本文bytes）

このruntime proofにcanonical `person_id`を入れません。source actorとruntime actorは、
それぞれの登録issuer/namespace/subjectを使ってagent側で現在の明示リンクを引き直します。
両方がresource OAuthの本人と一致しない場合は、source問い合わせ前に拒否します。

## HTTP入口

経費agentの `requester_mcp.create_app(..., history_runtime=..., history_resolver=...)` は
両方を明示した場合だけ有効です。既定のcloud factoryは未設定のままです。
本人bearer認証後、有効化された入口だけが本文を最大262,144 bytes・10秒以内で読み、
実bytesのSHA256と固定targetを `scope['agent_execution_request']` に置きます。
この値をHTTPヘッダーやForwarded Host、モデルが選んだJSONから作りません。
本文はMCP SDKへ同じbytesで渡し、ログ・Git・例外に含めません。

`ExternalHistoryResolver` は上記2headerの重複・空値・非ASCII・過大値を拒否し、
署名、要求、本人リンク、期限、targetを検証します。署名が有効でもそれだけで
履歴を読む権限にはなりません。検証済み参照をtrusted source adapterへ渡し、
取得元のnamespace/actor、固定Git slug/platform、source revision、有効期限、
現在sessionとinvocationの固定組を検査してから `HistoryRequestBinding` を作ります。
resource本人とsource本人のIDは構造上も分離します。

無効要求は安全な401のみを返し、例外時にも本人・履歴ContextVarを解除します。
未設定の従来経路には本文buffer、新proof解析、追加HTTP、追加ログインを要求しません。

## 会話参照の一回束縛と起動barrier

1. 信頼済みlauncherがsourceの現在ACL・起点revision・対象配置を確認してhandleを発行します。
   ストアにはhashだけを保存し、元会話・起点・本人・対象・invocationを不変にします。
2. 実行ホストで**まだ起動しない**sessionを作成し、launcherが正確な作成応答を確認します。
3. launcherが認可された作成結果から、そのhandleをsessionへ一回だけCAS束縛します。
   同じsessionへの再確認は冪等、別session・sourceの付替えは拒否します。
4. bind commitと現在状態を確認後、同じsessionだけをactivateします。
   応答喪失時は同じidempotencyでreadbackし、別sessionを勝手に作りません。
5. 履歴readは束縛済みsessionとの一致を検査するだけです。**未束縛を最初のreadに提示された
   sessionへ自動bindしてはいけません**。runtimeの署名単体はbind権限ではありません。

この順序を実ホストで保証する機能はまだ接続していません。特に、create時に即起動する
既存経路へsource proofを足すだけでは条件を満たしません。既存Managed Agentの起動を
一律に変更するのではなく、将来の明示opt-in経路で保証する必要があります。

## 再送・期限・保存

HTTP実行proofのjtiは、issuer/audienceへ束縛したhashキーで原子的に一回消費します。
全instanceで共有するtransactional storeが必要で、単一プロセスのMapを本番代替にしません。
再送は同じsource/sessionを保った新しいHTTP proofを必要とし、業務書込の再実行承認にはなりません。

handleのrenew/rotationはsourceと束縛済みsessionを変えません。元投稿JWTを更新する場合、
実行ホストも新証明を検証して同じ不変tupleを保つ必要があり、その配送は未接続です。
これらは内部の短命な実行証明であって、社員に数分ごとにログイン・同意させる仕様ではありません。
未実装の自動更新を成功扱いせず、期限切れは停止します。

この処理はproviderの権限を追加しません。MF/Calendar token更新や長期本人記憶は別機能です。

## 検証範囲

実RSA署名とSDK HTTPを用いた合成テストで、本文差し替え、別namespace/本人/対象/version/接続、
期限、同時replay、未束縛/別session、編集・失効を拒否し、先行user/assistantの合成印が
`ConversationReader` からMCP応答まで届くことを確認します。
sourceとruntimeの発行側、永続ストア、実APIは合成fixtureであり、実SA/Engine/LLMの
往復成功や本番復旧、長期記憶の復元の証拠ではありません。
