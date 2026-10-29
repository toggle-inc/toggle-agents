# エージェント共通基盤

会話履歴を読む契約・処理・合成テストの正本です。特定のエージェント、Engine、
SA、BuzzのDBや認証方式には依存しません。永続的な会話メモリや横断検索ではありません。
ログイン済みplatformの署名済み本人情報を検証する `platform_identity.py` も共通基盤に含めます。
Okta再ログインを必須にしない本人確認・個人ID対応・replay防止の契約と未接続部分は
[PLATFORM_IDENTITY.md](PLATFORM_IDENTITY.md) を参照してください。

## 配置単位を維持する

`python3 scripts/sync_foundation.py --write` で、共通ソース・指示・テストを各エージェントの
`_foundation/` へ機械的に同梱します。生成先は直接編集しません。
`python3 scripts/sync_foundation.py` は読み取り検査だけを行います。
配置用 `deploy.py` はフォルダ内の同梱版だけを参照し、共通指示も生成プロンプトに含めます。
配置パッケージに基盤の実行コードは入りますが、テストは入りません。
配置後にリポジトリルートや別エージェントへアクセスする必要はありません。
rootのテストは正本との一致と各フォルダの独立ビルドを検査します。

## 実行基盤に依存しない組み立て

`history_runtime.py` の `create_conversation_runtime` は明示的な `enabled=True` の場合だけ
接続を初期化します。既定では資格情報の取得も通信もツール登録も行いません。
`ConversationRuntime.bind(verified_invocation)` は検証済みの今回の実行をContextVarで隔離し、
例外時も解除します。同じエージェント本体でSA／Buzzの固定アダプターを切り替えられます。
Engineのimport、Engine固有のDB、履歴の自動注入は不要です。
本人確認と署名・実行の束縛検証は `bind` の前に必要であり、このAPI単体は認証ではありません。
具体例は [HISTORY_CONNECTIONS.md](HISTORY_CONNECTIONS.md) を参照してください。
署名・異なるID名前空間・原子的replay検査とsourceの一回session束縛の契約は
[EXECUTION_BINDING.md](EXECUTION_BINDING.md) を参照してください。
この検証もagent側の任意機能であり、署名発行側や実SA APIの接続完了とは区別します。

## ホストとエージェントの境界

1. 信頼済みホストが認証済みの依頼者・テナント・エージェント・プラットフォーム・
   **元会話とスレッド**・現在の発言・その順序・実行ID・有効期限を確認し、`Invocation` を束縛する。
   JSON本文、モデルの引数、未検証のHTTPヘッダー、本人用トークン単体からは作らない。
2. `ConversationReader(resolve, backend)` の `resolve` は呼び出し中の実行に束縛した値を返す。
   同じサーバーで複数人を扱うときはContextVar等で実行ごとに隔離する。固定の共有人物へ戻さない。
3. `backend.authorize(invocation, None)` が現在の閲覧権限と起点発言の存在・可視性を検査する。
4. `backend.fetch` は元会話の今回発言より前のuser/assistant発言を時系列で取得する。
   返信先DMを元会話の代わりに使わない。共有スレッドでは、本人に見える他の参加者の発言も文脈になり得るが、
   他の非公開会話や別スレッドは混ぜない。編集後の本文を使い、削除済みは返さない。
5. 共通処理が束縛・各発言のソース・順序・重複・件数・文字数を検査する。
   上限は32件・合計12,000文字。アダプターは収まる窓を返し、省略時は `truncated=true` とする。
6. 返却直前に `backend.authorize(invocation, snapshot.revision)` が権限とスナップショットの版を再検査する。
   取得中の編集・削除・閲覧権限変更は失敗させる。ここを認可・鮮度の判定時点とする。
   版確認できない接続では成功を返さない。実行期限も再検査する。

`register_history_tool(server, reader)` は引数のない `read_conversation_context` を登録します。
両エージェントの `mcp_server.create_server(conversation_reader=reader)` から利用できます。
モデルは本人ID・会話ID・返信先を指定できません。MCP入口だけで本人認証したとは扱いません。
HTTPホストは公開前に呼び出し認証・検証済み実行との束縛・通信期限・非公開配送を別途実装する必要があります。

未接続は `status=unavailable`、読めるが過去発言がない場合は `status=available, messages=[]`。
認可拒否・版不一致・上流エラー時は履歴を一部も返さず、例外本文や資格情報を出しません。
履歴は未信頼データであり、書き込み承認や本人の教えを上書きする指示にはなりません。
参照結果・中間出力も各エージェントの配送契約に従います。

## Buzzの既存実装との関係・現状

Buzzの `buzz-acp` はDM/スレッド履歴の取得、会話単位のセッション再利用、履歴のプロンプト注入を持っています。
今回の基盤はそれをSA側へコピーするものではなく、エージェントが必要時に履歴を読む共通の境界です。
各接続アダプターは既存の読取APIを使ってよいですが、業務方針はこのGit正本を使います。

**現在は共通処理・SA/Buzz読取アダプター・任意のMCP登録・パッケージ化・合成テストまでです。**
接続APIと実際の入口に残る不足は [HISTORY_CONNECTIONS.md](HISTORY_CONNECTIONS.md) に記載します。
アダプターはエージェント側のコードであり、Engineやチャットサービスの共通実装に依存しません。
SA/Buzzの本人用資格情報との接続、既存入口からの実行、実環境での文脈継続テストは未実施です。
`tools.json` の環境接続は空のまま。基盤の同梱をツール接続済み・実機成功と呼びません。
経費の `expense_context` は教え・保留・能力であり、会話履歴とは別です。
