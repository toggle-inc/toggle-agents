# 経費本体の検証手順と提供範囲

本書はコードと合成検証の受入手順です。実MF保存、実画像の読取、実SA添付、公開版での本人専用返信を成功確認した記録ではありません。提出は本人がMF画面で行います。Gitが公開の間は社内規則・個人データ・鍵を追加しません。

画像本体のローカル実OCR・本人専用の未登録下書き保存は `RECEIPT_DRAFT.md` と `verify_receipt_image.py` の別手順で検証します。固定fixture応答によるfake OCRと区別します。SA実接続での画像本体取得と本人同意は別の受入項目です。

## 人間が最初に確認できる合成検証

依存導入済みPythonで、このagentフォルダから実行します。

```sh
python verify_business.py --report /tmp/expense-business-verification.json
```

実サービスへ通信せず、架空MF・本人・時計・暗号化ローカル保存を使います。レポートの `passed`、件数、各test名と、未確認一覧を確認してください。入力値が固定の成功通知ではなく、各境界の実装を呼んで成功・拒否・再起動・結果不明を検査します。失敗があれば終了コードも非ゼロになります。

| 人間が確認すること | 主なテスト |
| --- | --- |
| 初回の本人・会社別許可がないと保存せず、許可後は候補を固定してMF確認リンクを返す | `test_durable_business`, `test_drafts` |
| OAuth会社選択UIから許可しても、他のscopeを勝手に付与しない | `DurableConsentHTTPTests` |
| 同じ候補の再送は同じ結果、別候補で同じ領収書・同じ内容を重ねて作らない | `test_durable_business`, `test_durable_state` |
| 結果不明・プロセス停止・結果保存失敗でも、自動再送せず照合待ちにする | `test_durable_state` |
| 数MiBの画像を台帳へbase64複製せず、本人別暗号化receiptから送信直前に内容を照合 | `test_durable_business` |
| 別人・別tenant・別namespace・異なる暗号鍵で状態やreceiptを読めない | `test_durable_business`, `test_durable_state` |
| OCR受付を完了扱いせず、登録番号はT＋13桁の形式検査と実在確認を区別 | `test_receipt_workflow`, `test_runtime` |
| カレンダーを実移動と断定せず、未確認駅・重複予定・未来・不明箇所を候補へ補完しない | `test_expense_preview` |
| 一般相談は接続不要、業務状態は未提供・未同意・接続不足・障害を分ける | `test_execution_readiness`, `test_operation_readiness_http` |

## 架空の領収書による一本の業務シナリオ

`test_synthetic_expense_scenario.py` と `fixtures/synthetic_receipt_scenario.json` は公開安全な架空データだけを使います。fake OCRは固定fixtureの読込みであり、画像認識ではありません。PDF署名付きテストbytesを本人別receiptへ保存し、金額不明の候補→不足項目表示・保存停止→架空の本人回答→会社別同意→fake MFの未申請明細create・読戻し→会社と明細一覧リンク→同一候補の再送・別候補の重複停止を通します。提出ツールはありません。実HTTP、実MF書込み、配置、scope変更は行いません。会社同意はtrusted host APIを呼ぶ合成操作で、新しい署名付き人間承認UIの検証ではありません。

別本人のreceipt/候補、別会社への架空規則の流用、推測した登録番号、不正形式、MF結果不明後の再送も停止することを確認します。登録番号は架空のT＋13桁で、実在・適格性を証明しません。

確認された次の修正候補:

- 税率・税額の専用入力と照合は未対応。fixtureの税値を推測・転用せず、未知の引数は拒否します。税込総額の保存成功を税の検証成功と扱いません。
- 架空の1000円上限は警告として表示されます。現本体は警告だけでは保存を止めません。強制上限が必要なら、規則の警告と保存禁止を区別する契約・実装が必要です。
- 不足項目をフォーム契約で示せますが、実UIの質問・回答、実画像の抽出、署名付き人間承認UIとの接続は別途検証が必要です。

## 通常cloud起動の明示profile

`EXPENSE_AUTH_CONFIG` の `business` を省略するか `{"enabled":false}` とすると、従来の読み取り専用経路を維持します。新しいbusiness鍵・規則・providerへのアクセスは要求しません。

まず記憶だけを準備する設定例（値は合成です）:

```json
{
  "enabled": true,
  "namespace": "expense-business-v1",
  "capabilities": ["mf:read", "calendar:read", "memory:read", "memory:propose", "contract:read"],
  "financial_writes": false,
  "policies": []
}
```

専用Fernet鍵を `EXPENSE_BUSINESS_ENCRYPTION_KEY` へ外部注入します。provider vaultや履歴署名の鍵へfallbackしません。同じ本人・tenantから算出したownerとnamespaceに暗号化データを束縛し、既存の専用transactional storeを利用します。新しいDB schemaは要求しません。この設定は実装を有効にするだけで、OAuth clientの登録scopeや本人同意を増やしません。既存の `mf:read` 同意でmemoryを読むことはできません。

金融能力 `mf:draft` / `mf:write` は、別途明示した `financial_writes:true` と認可済みprivate policyが必須です。規則のPythonファイルを公開フォルダ外の `EXPENSE_PRIVATE_POLICY` へ置き、`policies` に既存canonical personごとの `person_id`、許可する `office_ids`、固定 `sha256`、信頼済み `position` を登録します。会社の選択候補をこの範囲に限定し、別会社の実行を止めます。規則ファイルのhash変更・欠落も保存を止めます。運用者が承認した外部コードだけを指定してください。社内規則・役職・設定の実値をこの文書やGitへコピーしません。

新規の未申請明細とOCR送信は `mf:draft` の初回会社別許可を使います。更新・削除は `mf:write` と個別の本人・対象・内容・期限に束縛した承認が必要です。提出APIは提供しません。台帳から画像bytesを除いた新しい候補形式へ切り替える前の未実行候補は、そのまま確認実行できない場合があります。その場合は再候補化し、新しい確認を受けます。旧承認を新内容へ移しません。

## 能力と未接続の区別

| 能力 | 本体の提供条件 | 残る実確認 |
| --- | --- | --- |
| MF会社・明細・申請一覧 | 従来read profile、本人 `mf:read` | 配置版・本人接続のreadback |
| 過去科目・支払先・receipt取得/照合 | durable profile＋本人MF接続・該当capability | 実API・形式・本人隔離 |
| 長期の教え・保留 | durable profile＋各memory scope。確定・廃止はtrusted UIのみ | 本人の確定UIと実保存・再起動 |
| receipt保存・resource読取 | encrypted `DurableReceipts`、resourceには `receipt:read` | 実保存先の容量・保持・復旧 |
| 新規未申請明細/OCR | durable profile＋明示金融有効＋private policy＋`mf:draft`＋初回会社許可 | 承認された実領収書でのMF保存・読戻し・本人DM |
| 更新・削除 | 明示 `mf:write`、exact個別承認、未申請対象のみ | 実対象を本人確認した個別検証 |
| 社内規則 | 会社・役職・hashを外部設定、`rules:read` | 実規則の管理者承認と版 |
| 運賃 | 明示 `fare:read` と固定source adapter、出典提示 | 実検索・IC/区間・定期の本人確認 |
| calendar候補 | 本人 `calendar:read`、本人adapter | 実予定と移動事実の本人確認 |
| SA添付取込 | trusted frozen manifestと本人/sourceを検証するadapterが必要 | 新しいSource Read署名のmetadata/binary経路は未接続。static URLやmodel JSONから権限を作らない |
| private参照資料 | trusted references factoryで外部注入 | 文書権限・版・鮮度の確認 |

同じreceiptのbytes、または領収書のない同一会社・同一payloadの候補は二重登録を止めます。実際に別の同額移動があった場合は本人が事実として区別できる用途・時刻等を確認し、金額を適当に変えて回避しません。手動MF登録、別台帳、再圧縮・切抜き画像を自動照合済みとは扱いません。

永続Stateの1本人recordは1MiBで制限し、容量不足時は履歴・承認・重複claimを削除せず停止します。receipt本体は別の暗号化recordに保存します。長期保持・容量監視・鍵backup・DB管理者によるrollback時の照合は配置の受入条件です。保存済み台帳を巻き戻して金融操作を再実行しません。

## operation readiness v2

既存の `/execution/status` のv1は維持します。明示v2入力は `schema_version:agent-operation-readiness-request/v2`、`request_id`、`client_id`、`operation:null|string` のみです。nullは本人認証を維持した一般相談で、業務scope・provider接続は不要です。個別tool名にはその操作のscopeだけを要求します。

出力は `schema_version:agent-operation-readiness/v2`、`ready`、`required_capabilities`、`reason`、日本語 `description`、`execution_authorization_required`、有効期限です。未提供を未同意と偽装しません。提供元障害を再同意で解消しようとしません。readiness成功は会社・候補・個別承認の代替ではなく、実行時に再検査します。SA/Engineへ業務要件を複製しません。

## 実機で人間が受け入れる順序

1. 対象commit・配置版・本人・会社・scopeを照合し、他のManaged Agentを変更していないことを確認する。
2. MF読み取りと本人専用返信、2発言の会話継承を先に確認する。共有チャンネルに個人情報を返さない。
3. 架空画像は読取候補の確認だけに使い、MFへ送信・登録しない。日付・金額・支払先・T＋13桁の不明項目を推測しないことを確認する。
4. 金融許可の変更が承認されてから本人が初回会社別同意を行い、本人が確認した実在経費だけで未申請明細保存・OCR状態・MF読戻し・再送1件維持を確認する。
5. 許可解除、別人・別会社、再起動、結果不明時の停止と照合を確認する。更新・削除は別の個別承認範囲で行う。提出は本人のMF操作に残す。

これらの実機証跡と未接続項目が揃うまで「完全仕様の実提供完了」とは扱いません。
