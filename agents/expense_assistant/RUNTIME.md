# 共通経費ランタイム

このフォルダの `runtime/` が業務処理の本体です。SA・Buzz・Codexの指示をここへ複製せず、
同じ定義・同じ本体へ接続する入口を用意します。kickflowや別のエージェントは移植対象ではありません。

## 機能の対応

| 既存の経費アシスタントの機能 | 共通実装 | 公開テストでの検証 |
|---|---|---|
| 本人のMF OAuth連携・更新 | `MFClient` / `mf_auth_url` / `mf_auth_complete` | 模擬HTTP、state・本人・期限・秘密の非表示 |
| 会社選択、期間内の明細、申請・事前申請の参照 | `mf_offices` / `mf_list_transactions` / `mf_list_reports` | 合成データ、会社の曖昧性・申請済み・取得上限 |
| 科目ID・プロジェクト・過去の書式 | `mf_known_items` | 合成データ |
| 支払先・インボイス番号・毎月の出し忘れ | `mf_payee_memory` | 合成データ、会社間の混線防止 |
| iCalの読み取り・繰り返し予定 | `Calendar` / `calendar_events` | 合成ICS、時差・繰り返し・中止 |
| 運賃検索・経路ごとの金額・出典 | `Fares` / `fare_lookup` | 合成HTML。広告の金額を運賃にしない |
| 社内規則・非公開の補足資料 | `PrivatePolicy` / `check_rules` / `read_reference` | 非公開設定のハッシュ固定、参照範囲検証 |
| 添付画像/PDF、過去の領収書 | `Receipts` / `fetch_attachment` / `mf_get_receipt` | 合成バイナリ、形式・所有者・パス制限 |
| 明細作成・修正・削除・領収書OCR | 元と同名の4ツール | 模擬MF。承認、変更検知、再起動後の再送防止 |
| 会社・金額・科目・出席者・出典付きの案 | `form` / プレビュー | 合成フォーム。推測・必須不足では登録しない |
| 定期区間・拠点・書式の教え、廃止 | `State` / `expense_context` / `propose_teaching` | 本人別の提案・承認・履歴 |
| 未来の予定の保留、期日後の再確認 | `State` のpending | 合成時計、完了状態 |
| 能力カード、週1回までの提案 | `expense_context` / `State` | 設定と実機成功を区別、頻度・状況制限 |

業務ツール16個を共通サービスから呼べます。**実アカウントでの全機能成功を示す表ではありません。**
公開テストは模擬サービスのみを使います。実接続の結果は各利用環境で別管理し、実データをGitへ含めません。
申請書の作成・提出を代行する機能は、元の経費アシスタントと同様に提供しません。

## 単独セットアップと検証

```sh
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s . -p 'test_*.py' -v
```

第三者依存はこのフォルダの `requirements.txt` に固定しています。
本体・テスト・依存宣言・配置手順は、このフォルダだけで完結します。

## ローカルMCPの入口

`mcp_server.py` はstdio専用です。匿名HTTPサーバーやトンネルは開きません。

```sh
.venv/bin/python mcp_server.py
```

信頼済みの起動ホストが、本人専用の設定を環境変数または外部のprivate profileから渡します。
設定値・トークン・iCal URL・規則ファイル・社内資料・状態DBはGitへ保存しません。

- `EXPENSE_OWNER_KEY`：起動ホストが検証した本人の識別。本文やモデルが指定する本人ではない。
- `EXPENSE_STATE_ROOT`：公開フォルダ外の私有データ保存先。資格情報・承認台帳・記憶・領収書を保存。
- `MF_CLIENT_ID` / `MF_CLIENT_SECRET` / 必要なら `MF_REDIRECT_URI`：管理者が用意するアプリ設定。
  本人ごとのOAuth承認が必要な点は維持し、共有管理者トークンで代替可能とは仮定しない。
- `KEIHI_ICAL_URL`：本人の非公開iCal URL。
- `EXPENSE_ATTACHMENT_HOSTS`：信頼済み入口が使う添付先の厳密な許可ホスト。ローカル・metadataへの取得は禁止。
- `EXPENSE_PRIVATE_POLICY` / `EXPENSE_POLICY_SHA256`：認可済み規則のPythonモジュールと固定SHA-256。
  既存の規則と同じ `check(..., position=...)` 契約を利用できる。コード実行権限がある管理者だけが設定する。
- `KEIHI_POSITION`：信頼済みの役職設定。モデルが指定しない。
- `EXPENSE_PRIVATE_REFS`：認可済みの補足資料ルート。未設定を「規則点検成功」と扱わない。

`--factory /private/path/profile.py` は管理者が用意する `create_service()` の注入に使います。
**1プロセス＝本人1人のstdioプロファイルです。** 同じプロセスを複数社員へ無認証公開してはいけません。
共有サーバーでは、認証済みリクエストから本人別のサービスを選択する基盤側の実装が必要です。

## 承認とカードの入口契約

`confirm=false` はプレビューID・内容ダイジェスト・有効期限とフォームを返します。
入口は本人に会社・対象・全項目・警告を示し、認証済みの本人操作だけを
`State.approve(preview_id, expected_digest)` へ変換します。このメソッドはMCPへ公開しません。
本人の記憶の確定・廃止・保留完了も、信頼済み入口が `accept_fact` / `retire_fact` / `complete_pending` で行います。

モデルはこれらを直接呼べません。「OK」やボタンの意味の本人性・会話・対象・版への束縛は入口の責務です。
未実装の入口でAIが自分に承認を発行する代替処理を作ってはいけません。
週次提案の `mark_suggestion` は実際に配送した入口が記録し、見回り・急ぎ・失敗中を除外します。
同時に複数の入口から送る場合の配送排他は入口側で保証する必要があります。

Buzzの読み・リアクション・ローカルファイル表示は、フォーム・本人操作・MCPリソースへ分離しました。
表示を表やカードにするSA側の実装、リアクションと対象を結びつけるBuzz側の実装は別の入口作業です。
MCP対応クライアントは `resource_uri` から本人の画像/PDFを読み取れます。

## 配置と未完了事項

### 既存の本人用Buzz設定へ接続する場合

新しいアプリキーやトークンをチャットへ貼り直す必要はありません。
信頼済みのローカル設定手順で、既存の本人用設定への参照を作成できます。

```sh
.venv/bin/python connect.py setup --legacy-env /private/expense/.env --directory /private/common-expense
.venv/bin/python connect.py check --profile /private/common-expense/connection.json --date YYYY-MM-DD --fare-from 東京 --fare-to 品川
.venv/bin/python connect.py serve --profile /private/common-expense/connection.json
```

`.env` は実行・変数展開せずデータとして読みます。接続プロファイルにはファイル参照と本人への束縛だけを保存し、
キー・トークン・カレンダーURLのコピーは保存しません。元の認証ファイルを共用し、必要なOAuth更新結果は
その元ファイルへ原子的に反映するため、旧ランタイムの認証情報だけが古くなる状態を避けます。
複数の新ランタイムと旧ランタイムで同時に認証更新する場合の排他は別途必要です。
既存設定の持ち主と参照先は、初期設定を行う信頼済みホストが確認します。パスのハッシュは本人認証の署名ではありません。

接続は既定で**読み取り専用**です。承認台帳に記録があっても、実行プロファイルが許可しなければ書き込みません。
`check` はMFの会社・明細・申請一覧、カレンダー、規則を読み取り、指定した場合だけ運賃を調べます。
出力は成功可否と件数だけで、明細本文・予定本文・認証情報・非公開URLを表示しません。
補足資料の未設定や実添付ファイルの未検証を、成功とまとめません。
実MFへの作成・更新・削除・OCRは、この接続検査では実行しません。

これはローカルMCPの実接続です。EngineやSAへ自動的に登録したり、個人の認証情報をクラウドへ転送したりしません。

`deploy.py` は定義とランタイムソースを同じ成果物へ収録します。
検証済みの本人専用MCP接続をEngineに登録した後、`--connection-id <接続ID>` で生成物だけへ束縛できます。
正本の `conn_ids` は空のままです。接続を指定しないDRAFTに業務ツールが付いたとは扱いません。
このコード追加だけでHTTPサービス・Engine接続・従業員の認証・SAの@入口を作成することはありません。

残る受入検証は、本人の接続を安全に設定し、同じ配置版をSA/Buzz/Codexから呼び、
承認カード→実行→照合が入口をまたいでも正しく働くことです。実書き込みは対象と内容を承認してから行います。
MFの公式APIが対応する範囲、運賃サイトのHTMLやOAuthの運用要件は、実接続前にも確認してください。
