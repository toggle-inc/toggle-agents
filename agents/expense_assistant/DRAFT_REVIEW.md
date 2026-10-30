# MF画面で確認する未申請明細の保存

本人別永続profileと実機の受入条件は [BUSINESS_ACCEPTANCE.md](BUSINESS_ACCEPTANCE.md) に整理しています。
画像bytesは候補台帳へ複製せず、本人専用receipt参照・hash・サイズへ固定して送信直前に再照合します。

通常の新規作成は「依頼 → MFへ未申請明細を保存 → 本人専用返信のMFリンクで確認 → 本人が申請」とする。毎回の独自確認画面は使わない。申請書の下書き作成APIや提出APIを実装したという意味ではない。

## 初回の許可

認証済み本人の会社選択・同意画面から、信頼済みホストが本人専用の `State.set_draft_consent(office_ids, consent_id, active=True)` を呼ぶ。モデルからは呼べない。同意には「指定会社への未申請明細の作成・領収書OCR送信を都度確認なしで行う、提出はしない」と表示する。

- `mf:draft` 能力、書き込み有効設定、本人専用State、対象会社の有効な初回同意をすべて必要とする。
- 会社の追加を暗黙に許可しない。既存ユーザーや既存の `mf:write` に自動付与しない。
- 同意は取り消しまで保存される。外部OAuthの期限・更新・失効は別途管理し、無期限のAPIアクセスを保証しない。
- 取り消しはホストから `set_draft_consent([], consent_id, active=False)`。実行直前にも同意の変更・解除を検査する。すでに外部へ送ったリクエストの取消しは保証しない。
- 既存明細の更新・削除や申請提出をこの同意に含めない。更新・削除には従来の対象・変更内容別の承認が必要。

## ツール契約

1. `mf_create_transaction(confirm=False, ...)` または `mf_upload_receipt(confirm=False, ...)` で内部の変更不能な候補を作る。この段階ではMFに書かない。
2. `mf_save_draft(preview_id)` で保存する。金額・会社等を再入力させず、保存済み候補の内容・ダイジェスト・有効期限に束縛して実行する。
3. 次の結果を本人専用の返信へ届ける。入口でMFの業務判断を複製しない。

```json
{
  "review_url": "https://expense.moneyforward.com/transactions",
  "review_link_kind": "transaction_list",
  "review_company": "対象会社名",
  "review_office_id": "対象会社ID",
  "draft_status": "saved_unsubmitted",
  "submitted": false
}
```

通常作成の成功結果には既存の `readback_verified` 等も付く。OCR送信は `draft_status=ocr_processing` であり、明細作成や読取完了を表さない。`mf_receipt_status(upload_preview_id)` で照合する。同じ候補の再試行は既存結果を返し、領収書内容の重複防止も維持する。結果不明の書き込みは再送しない。

確認先の `/transactions` はMFの実画面ナビゲーションで確認した明細一覧URL。個別明細URLではないため、返信には対象会社と、MF側の会社選択が一致するかの注意を添える。処理中・失敗を保存成功として表示しない。リンク・明細・添付・エラーは本人専用に配送し、起点の共有チャンネルには既定の受付だけを返す。

`mf_receipt_status` の状況確認にも同じ会社別の確認リンクを付ける。
`status_message` は日本語の現在状態、`next_step` は本人が次に行う確認を返す。
未送信・処理中・照合待ち・要確認・OCR入力完了を区別し、リンクの存在を保存成功の証拠にしない。
結果不明や照合不能では再送・別明細の新規作成を案内せず、MF側で確認する。
状態の再取得は読み取りのみであり、自動再送・自動修正・提出は行わない。

## 検証範囲

`test_drafts.py` はFakeMFを使い、初回同意後の保存・同意なし/会社違い/取消し/読み取り専用の拒否・実行直前の取消し・更新削除の拒否・OCR処理中表示・同一候補の重複防止を検査する。実MFへの書き込み成功証跡ではない。

`test_requester_mcp.py` では実際のMCP SDKとASGI HTTP/JSON-RPC接続を使い、`mf:draft` だけを許可した本人の内部候補作成→保存→MFリンク返却・readback・再送1件維持、別人の候補参照拒否、同意取消し後の停止、OCR処理中表示、従来の直接書き込み経路の拒否も検査する。認証検証器とMF提供元は合成であり、実SSO・実MFへの接続証跡ではない。

ホストの初回同意UIとの接続、配置済みエージェントへの反映、実際の経費によるMF保存と本人DM配送の一連の確認は別途必要。コード追加だけで既存接続の権限を変更しない。従来の `SA_APPROVAL.md` / `PILOT.md` にある都度確認UIは、別途承認が必要な更新・削除および実験用の経路として保存するが、新規明細の標準フローにはしない。

## 初回同意UIと保存許可の結合

正本の `runtime/draft_consent.py` は、同じ本人別resolverを使って、認証済み本人のMF会社候補を同意画面へ表示する。本人が1社を選択し、CSRFと一回限りのOAuth requestに束縛して許可すると、その本人専用Stateへ会社別の作成許可を記録する。会社ID・本人ID・許可内容をモデルやチャットから渡して発行する経路ではない。

```python
from authorization_app import create_app
from runtime.draft_consent import DraftConsentBinding

binding = DraftConsentBinding(authority, resolve_own_service)
app = create_app(
    authority,
    resolve_own_service,
    login_adapter=verified_okta_login,
    draft_consent=binding,
)
```

この設定は配置先の信頼済みホストが行う。本人のMF接続が無いときは停止し、他人・管理者の接続を代用しない。`mf:draft` のOAuth requestにこのbindingが無ければ同意画面を拒否する。既存の読み取り同意には影響しない。許可解除ではOAuth tokenと会社別作成許可の両方を無効化する。複数の保存先にまたがる操作は、失敗時に作成権限を得られない方向へ止め、未完了の認可コードを金融実行の根拠にしない。

`test_draft_authorization.py` は、合成SSO/MFと実HTTP/OAuth/MCPで、会社選択→初回同意→トークン発行→候補→保存→MFリンク→トークン更新後の再取得を検証する。別人・会社差替え・CSRF不一致・拒否・解除も検査する。実Okta/Neon/MFへの接続検証ではない。

配置時には認証ストアだけでなく、resolverが返す本人別のMF資格情報・State・領収書の永続保存先も必要。Postgres認証adapterを追加しただけで、SQLiteの業務Stateや領収書がサーバーレス環境で永続化されるわけではない。新しいruntimeへ配置する前に、再起動後も同意・重複防止・本人別保存を維持する構成を確認する。
