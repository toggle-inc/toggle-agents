# 共通エージェント（疎通確認用）

このフォルダが、1体分の独立した配置単位です。このフォルダだけをコピーしても利用できます。
親フォルダのスクリプト、他のエージェント、agentize-kitのチェックアウトは参照しません。
定義はagentize-kitの基本形式を維持し、生成物の配置には外部の公式
`agentize-dev-cli` の `managed-agent compose` を使います。

## 収録内容

- `agent.json` / `instructions.md`：本体の宣言と指示
- `tools.json` / `skills.json`：能力の宣言
- `qa.json`：合成の検証ケース
- `deploy.py`：このフォルダだけから配置パッケージを生成（通信なし）
- `test_deploy.py`：定義・単独コピー・生成物・誤設定拒否のテスト

## 検証とパッケージ作成

Python 3.11以上。以下はこのフォルダ内で実行します。オフラインビルド自体は標準ライブラリのみです。
任意のMCP入口とその検証には `requirements.txt` の依存をインストールします。

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s . -p 'test_*.py' -v
python3 deploy.py --tenant-id <配置先テナントID>
```

更新する既存エージェントがある場合は、確認済みのIDを明示します。

```sh
python3 deploy.py --tenant-id <配置先テナントID> --agent-id <既存エージェントID>
```

成果物は `.deploy/candidate/` に作られます。既存の成果物は上書きしません。
再ビルドは `--output .deploy/candidate-2` のように新しい出力先を指定してください。
`compose` 後のフォルダには配置ID・版情報が保存されるため、確認せず消して再送しないでください。
コピーするのはGit管理対象だけとし、`.deploy/` や認証情報を含めないでください。

## 配置（DRAFT）

事前に公式 `agentize-dev-cli` をインストールし、配置先へログインしてください。
CLI・実行基盤・その資格情報は外部依存です。「フォルダ単独」はこれらを内蔵する意味ではありません。
配置先の権限・CI必須ルールは維持してください。CI限定の環境へローカルから直接配置しません。

CLIのソース収集はGitの除外設定に従うため、Git管理下の `.deploy/` を直接composeすると
実行コードが保存されません。生成済みパッケージをGitの外へコピーして使います。
配置後も、この一時フォルダの配置ID・版情報を保持してください。

```sh
agent_deploy_stage=$(mktemp -d /tmp/toggle-agent-compose.XXXXXX)
cp -R .deploy/candidate "$agent_deploy_stage/package"
```

まず公式CLIで計画を確認します（API書き込みなし）。

```sh
agentize-dev-cli managed-agent compose --root "$agent_deploy_stage/package" --tenant-id <配置先テナントID> --dry-run
```

計画の接続先・テナント・既存エージェントIDを確認し、配置が承認されている場合だけ実行します。

```sh
agentize-dev-cli managed-agent compose --root "$agent_deploy_stage/package" --tenant-id <配置先テナントID>
```

これはDRAFTの作成・更新です。公開・SA/Buzz/Codexへの接続は自動実行しません。
新規作成では先に対象テナントに同じエージェントがないか確認してください。
失敗・タイムアウト・結果不明の場合は再送せず、管理画面と生成された配置情報で確認します。
配置成功後も、実LLMで検証ケースを評価し、版・指示・能力をreadbackで照合してください。
公開はその後の別承認です。パッケージ生成・dry-run・DRAFT作成を実機動作成功とは扱いません。

## 現在の制限

会話履歴の共通基盤を `_foundation/` に同梱しています。
`mcp_server.create_server(conversation_reader=reader)` で、信頼済みホストが束縛した読取能力だけを登録できます。
readerを省略した既存の使い方はツール未接続のままです。
実行との束縛と閲覧権限を検証した接続を後で配置する場合は、`deploy.py --connection-id <接続ID>` で
生成物だけに指定できます。このオプションは接続自体の作成・検証・権限付与を行いません。
各エージェントの配置に親フォルダは不要です。共通ソースの編集・更新はリポジトリ側で行います。
依頼者・元会話・スレッド・現在の発言・実行IDの認証、現在の閲覧権限と取得版の再検査が必要で、
本文やモデルからのID指定では代用できません。
SA／Buzzの読取アダプターは `_foundation/history_sources.py` に同梱しています。
本人の資格情報・既存入口との実接続と実機確認は未完了です。
接続方法と制限は [_foundation/HISTORY_CONNECTIONS.md](_foundation/HISTORY_CONNECTIONS.md) を参照してください。

ツールなし・記憶なしの合成テスト用です。業務サービスには接続しません。
現在のビルダーはツール・スキル未接続の定義だけを受け付けます。
将来これらを追加した場合は、必要な実装・依存・テストをこのフォルダ内に収め、
ビルダーも拡張してください。未対応の能力は黙って除外せずエラーにします。
公開不能な規則・社員データ・秘密は同梱せず、実行環境から安全に注入します。
