# 画像からの経費下書き

利用者は領収書画像を1枚添付して「この領収書から経費の下書きを作って」と依頼します。会社の規則を本文へ書き添える必要はありません。`prepare_receipt_draft` は、署名で確認した起点の添付本体を読み、本人専用に暗号化保存し、ローカルのTesseractで文字認識して、エージェントに登録済みの会社ルールを適用します。

下書きは本人専用の保存領域へ保存します。日付・支払先・税込総額・税額・税率・登録番号を画像の文字から抽出し、読めない・複数候補がある項目は確認待ちにします。税額を逆算して埋めたり、登録番号の実在性を確認済みとしたりしません。画像内の文章や利用者の本文で、会社ルール・本人の会社・権限は変更できません。

これはMFへ保存済みの明細ではありません。`mf_registered:false` と `submitted:false` を返します。MF保存には別の本人・会社別許可とMF保存能力が必要です。提出は本人がMF画面で行います。

## エージェント管理の会社設定

会社のルールと本人に適用する会社は、運用者がGit正本と配置設定で管理します。既定の本人や、利用者が書いた規則へのfallbackはありません。ルールが未設定なら管理者側の設定不足として止め、利用者に規則の貼付けを要求しません。

公開安全な架空規則は `fixtures/synthetic_company_rules.json` にあります。コンテナには `/app/rules/synthetic_company_rules.json` として同梱します。実社内規則ではありません。実規則を公開Gitへ入れないでください。

`business` の設定例（本人・hashは配置時に明示）:

```json
{
  "enabled": true,
  "namespace": "expense-receipt-drafts-v1",
  "capabilities": ["attachment:read"],
  "financial_writes": false,
  "policies": [],
  "receipt_drafts": {
    "rules_file": "/app/rules/synthetic_company_rules.json",
    "sha256": "<SHA-256 of approved rules bytes>",
    "person_companies": [
      {"person_id": "<verified canonical person>", "company_key": "synthetic-meeting"}
    ]
  }
}
```

既存の専用ストアと `EXPENSE_BUSINESS_ENCRYPTION_KEY` を使います。履歴の厳格な署名検証と現在の起点添付を読む接続が必要です。単なるURL指定、他人の添付、履歴のないlegacy入口からの取得はできません。アプリに能力を追加しても既存トークンのscopeは増えず、本人のGUI同意が必要です。MFの書き込みscopeは要求しません。

現在の会社対応は、運用者が本人に1つの会社ルールを結び付ける形式です。複数会社の所属を自動推定せず、未登録の会社は拒否します。上限超過はルールの `exceed_action` に従ってwarningとblockを区別します。

## 実画像の再現検証

`Dockerfile.auth` のコンテナは日本語・英語TesseractとPillowを同梱します。PNG/JPEG、10MiB以下・16MP以下に対応。PDF/HEICは明示的に未対応で、読めた扱いにはしません。OCRは外部サービスへ画像を送らず、固定コマンド・時間と出力量の制限付きで実行します。

コンテナのネットワークを無効にし、`fixtures/synthetic_receipt.png` を `/test/receipt.png`、`verify_receipt_image.py` を `/app/verify_receipt_image.py` へread-only mountして、`python /app/verify_receipt_image.py` を実行できます。実OCR・暗号化領収書保存・エージェント管理ルール・下書き保存を通し、330円・税30円・税率10%・2026-10-30を確認します。未記載の登録番号は補いません。

この検証の起点接続はローカル合成adapterです。実SAからの署名付き本体取得・新しい本人同意・DM返信の成功証跡とは分けて扱います。実SA試験でも会社規則や正解の金額を本文に与えないことを受入条件にします。
