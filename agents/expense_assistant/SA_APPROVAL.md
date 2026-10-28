# SAの本人確認結果を経費本体へつなぐ

`runtime/sa_approval.py` は信頼済み実行ホスト用の薄いアダプターです。
MCPツールとして公開せず、モデルが本人や承認を指定する入口にも使いません。
SAの画面・権限判定をここに複製せず、正本の明細内容を不変の確認内容として送ります。

## 契約

- 固定HTTPS originと、認証済みホストから確認した本人・tenant・agent・version・run・session・
  起点message/channel/rootを必須にする。本文の `trusted_request_context` だけを信用しない。
- invocationIdは `agentize-mention:` + 64桁小文字hex。URLではパス要素としてencodeする。
  旧実行でroot/添付manifestが未保存の場合は新しい依頼でやり直す。
- `verify_scope(scope, owner)` は毎回、依頼者と本人用サービスの信頼済みID対応、実行・権限・
  起点と版の有効性を検証する実装をホストから渡す。定数trueの検査では実接続にならない。
- `credential('read'|'write')` はホストのprivate資格情報を返す。SAのサービス資格情報を
  Engineのprompt・LLMツール引数・個人用経費MCPへ渡してはいけない。
- `propose(preview_id)` は本人用DBのsnapshotを読み、SAのapproval POSTへ送る。
  会社・操作・全明細・差分・出典・receipt参照を含む。画像バイト列だけはSHA256とサイズに
  置き換え、元の全snapshotは正本のpreview digestで束縛する。省略項目を推測で埋めない。
  表示用JSONは正本側で2スペースの改行付きに整え、SAはその文字列をそのまま表示する。
  数値・Unicode・全項目を保持し、ダイジェストも実際の表示bytesで照合する。
  表示形式を変えた既存提案は上書きせず、新しいpreviewで本人確認をやり直す。
- SAからのpreview/digest/expiry/payload/contentDigest/scopeと固定の確認画面パスを照合する。
  `propose`だけでは承認しない。
- `execute_approved(preview_id, approval_id)` は実行直前にSAの承認記録をGETし、APPROVED・
  本人・時刻・期限・全内容・scopeを再照合する。外部event IDと証跡を本人用DBへ不変保存し、
  正本のState.approveと保存済みのintentによる実行へつなぐ。新しい自由な実行引数は受け付けない。
- 未実行のまま能力不足等で拒否された場合は、残ったローカル承認だけを取り消す。
  完了・結果不明・領収書claimは解除しない。同じeventを別previewへ再利用しない。
- サービス認証は本人認証の代替ではない。ホスト側の本人ID対応がなければ構築・利用しない。

金融書き込みの台帳・重複防止・MF読戻しは既存の経費本体をそのまま使う。
SAの承認APIが金融書き込みを行うわけではなく、通常のHarness実行承認とも別の仕組み。

## 起点添付の取り込み

`runtime/sa_attachment.py` の `SAAttachmentAdapter` を信頼済みホストで使う。
scope/verify_scope/credential/httpは承認アダプターと同じ契約で、さらにホストが確認した
起点の確定manifest（id/filename/contentType/size）をコンストラクターへ渡す。
manifestやscopeをLLMの本文から作ってはいけない。

`fetch(attachment_id)` はmanifest内の1件だけを固定originの認可付き添付APIからGETする。
ID・percent-encoded filename・MIME・Content-Length・SHA256と実bytesを照合し、
ネットワーク前後の本人とscopeも再確認する。転送・別投稿探索・任意URL・秘密の転送はしない。
SAは25MiBまで転送できるが、経費本体の既存上限10MiBは変更せず、超過は取得前に拒否する。
PDF/PNG/JPEG/HEICのみを既存Receipts.saveのバイナリ形式確認に通す。完全なPDF/画像構文の
安全性検査やOCR実行をこの取込みだけで完了と扱わない。

取得元のorigin・全scopeのdigest・添付ID/名前/MIME/サイズ/hashと、本人用receipt参照の対応を
本人用SQLiteへ不変保存する。承認提案時もその対応を照合し、`source_attachments` に含める。
別のrun・originの領収書や未紐付けの参照で確認画面を生成しない。
過去版で作成済みのSA確認内容は書き換えず、新しいpreviewでこの契約を使う。

添付adapterと承認adapterはホスト向けAPIであり、既存のLLM用fetch_attachment(url)へ
サービス資格情報を付加して公開するものではない。ホストで取得済みreceipt参照だけを
必要な本人限定の実行に渡す。MFのOAuth資格情報も取得・コピー・変更しない。

## 検証段階と未接続部分

合成SA HTTPと実SQLite台帳によるテストで、本人・scope・版・期限・内容・event再利用・
失効・不正転送・能力不足後の承認残留を検証する。実SAの画面・MFへの書込み成功ではない。

実接続には次を揃える必要がある。

1. SA側の対象Previewへのコード・DB・最小サービス資格情報の配置。
2. 実行ホストでのcanonical本人対応と新しい起点/run/version scopeの解決。
3. 認可付き添付取得と、SA添付ID・画像ハッシュ・本人用receipt参照の対応付け。
   source-owned adapterと合成回帰は実装済み。SA Preview上の実取得との結合は未検証。
4. 常設の信頼済みホストでのpropose→本人UI→readback→実行の接続。
5. 本人が会社・内容を承認した実在経費で、MF結果まで実機照合。

秘密を発行・表示したり、本人の実経費へ書き込んだりせずに合成検証を行う。
