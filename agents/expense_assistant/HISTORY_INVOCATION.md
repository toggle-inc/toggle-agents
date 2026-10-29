# 実行ごとの会話履歴接続契約案

状態: **未接続の設計・純粋validatorのみ**。現行の外部OAuth MCP接続には実行ごとの証明を運ぶ経路がなく、この文書・テスト・`runtime/history_invocation.py` の追加で会話継承が復元したとは扱いません。新しい鍵、scope、Engine変更、クラウド配置は含みません。SA/Buzzの履歴の読み方の正本は引き続き `foundation/` とその同梱版です。本案はそのreaderへ信頼済みInvocationを渡す前段の候補であり、業務判断を入口やEngineへ移すものではありません。

## 独立した2つの証明

投稿を受け付ける時点では実行sessionが未作成なので、source証明に未確定sessionを入れません。

| 証明 | 発行者の役割 | 必須の束縛 |
| --- | --- | --- |
| source grant | 元投稿を本人として受け付け、元会話の現在の閲覧権限を検査するsource adapter | `source_tenant_id`, `source_actor_id`, `agent_id`, `invocation_id`, `anchor_id`, `source_handle` |
| call proof | 現在の実行を知る汎用の実行transport adapter | `tenant_id`, `person_id`, `agent_id`, `invocation_id`, `session_id`, `source_grant_sha256` |

共通claimは `iss`, 固定resourceの `aud`, `iat`, `exp`, `jti`, `purpose`。RS256と明示登録RSA公開鍵（2048 bit以上、kid完全一致）だけを使います。sourceのJWT typは `agent-history-source+jwt`、purposeは `history_source`、最大TTLは300秒です。callは `agent-history-call+jwt` / `history_call` / 最大60秒です。未来の発行時刻、期限切れ、未知claim・header、異なるissuer/audience、異なるsource証明の組合せを拒否します。自動のkey discoveryや本文指定URLへの接続はしません。

`source_handle` は32〜128文字の不透明な参照で、元会話ID、履歴本文、資格情報を埋めません。source側のprivateな対応表へ、本人・tenant・agent・invocation・元会話・thread・anchorを固定します。受信モデルの自己申告IDや配送先DMから元会話を推測しません。handle単体を読取権限やBearer資格情報として使いません。

sourceとcallのissuerは個別に明示して検証します。配置時に誰が何を署名できるかを確認する必要があります。ここで指定するキーはすべて検証用であり、このモジュールは証明を発行しません。

## 読み取り時の境界

1. source adapterは本人の元会話ACLと起点の存在を確認し、固定したsource grantを発行します。sourceの不透明参照は他の会話へ付け替えません。
2. 汎用transportは実際のsessionを検証し、そのMCP要求に対応するcall proofを付けます。instruction内のJSONやモデルが選んだsessionを証拠にしません。現Engineへのこのtransport追加は未実装です。
3. agent hostは毎回resource OAuthの本人認証・同意・失効を検証します。明示的account linkと信頼済み現在実行から `ExpectedHistoryCall` を作り、両証明を検証します。source側actorとagent側canonical personの対応をメールや表示名から推測しません。
4. 検証結果は現在のHTTP要求だけのcontextへ置きます。本人単位の「最新invocation」を共有保存して代用しません。別人・別tenant・別agent・別session・別invocation、あるいはsource証明の差し替えを拒否します。
5. source adapterはhandleを解決するたびに本人ACL、anchorの編集・削除、失効を再検査します。資格情報はMFとは別の本人履歴read用credentialか、本人とsourceへ束縛したread proxyが供給します。通常のMF read同意は拡大しません。
6. `foundation` の `ConversationReader` に検証済みInvocationを渡します。引数なしの `read_conversation_context` は先行userとassistantを同じ範囲で読み、取得前後の再検証で編集・削除・失効を扱います。業務scope一覧では登録済みの履歴toolを消しません。

純粋validatorは署名・binding・TTLまでを検証し、不透明参照を返すだけです。source ACL検査、実資格情報、HTTP header名、署名の配送、source handleの保存・発行・失効、再発行、reader配線は未実装です。TTL内の同一実行での反復読取は許容し、書込承認や単回実行台帳には使いません。長い実行で証明を更新するときも同じsource/anchor/invocation/sessionへ固定する必要があります。

## 受入条件と現在の証拠

- 純粋合成テスト: 別人・tenant・agent・invocation・session、並行する2実行、source証明差し替え、署名改変、issuer/audience/purpose/kid/TTL/期限を検査。
- 共通基盤の既存合成テスト: 先行user/assistant、別thread拒否、編集・削除・失効、再読取を検査。
- **未確認**: 実SA/Buzzの前の投稿に合成印を置く→別の新規投稿でその印と先行assistantを参照→実際のモデル入力と回答を照合。別人・別thread・同時投稿・編集削除・退会で拒否される実機確認も必要。

長期の本人の教え・保留は `expense_context` と本人別Stateの別機能です。ローカル保存は維持されていますが、クラウドの永続Stateと本人の確定UI、memory読取権限の実接続は未完です。履歴をつなぐことや、未提供のmemory広告を隠すことで長期記憶を復元したとは扱いません。


## 既存Managed Agentへの影響境界

`runtime/history_invocation_gate.py` は明示的な `enabled=True` の場合だけ、信頼済みhostが供給するvalidator factory、現在本人・実行のbinding resolver、transport proof loaderを呼ぶ準備用のgateです。既定値と明示的Falseでは常に何も解決せずNoneを返し、追加のcrypto import、鍵/設定読取、proof必須化、本人ログイン、HTTP、履歴tool登録を行いません。リクエストheader・本文・環境変数では有効化できません。有効化したgateも別のagent/接続のgateを変更しません。

既存agent定義、cloud設定schema、接続、認証、応答、MCPルートは変更していません。新headerが未設定・不正でも未opt-in経路では無視し、既存の本人OAuth検査をそのまま行います。不完全な明示opt-inだけをfail closedにします。`test_history_isolation.py` は無効時に新callback・依存・networkを使わないこと、opt-inのinstance隔離と毎回のsession再検証、実SDKの既存HTTPでtool一覧/本人別結果/401が変わらず、履歴HTTP・proof検査が増えないことを合成検証します。

このgate自体も現在のhostへ未配線です。Engine側の明示opt-inと汎用wire、SA側source handle、hostのrequest-local reader注入が揃うまで有効にはなりません。別repositoryの既存Managed Agent全体の実機影響は、Engine担当の既定無効回帰と合わせて確認する必要があります。
