# 本人別のサービス接続GUI

接続画面の正本は `runtime/service_connections.py`、HTTP入口は `authorization_app.py`。
EngineやSAのコードをimportせず、エージェントフォルダだけで配置できる。

## 実装した経路

- `GET /connections` はログイン中の本人だけのMF・カレンダー接続状態を表示する。
  `Accept: application/json` では `agent-service-connections/v1` と
  `csrf_token`、`connections[{id,label,status}]` を返す。HTML埋め込みはせずBFF側でもこのデータから表示できる。
- `POST /connections/start` は `provider` と `csrf_token` だけを受け取る。
  本人ID・秘密・任意の遷移先は受け取らない。フォームは本人・5分・一度限りに束縛する。
- `not_connected` / `expired` のときだけ接続ボタンを表示する。
  `unavailable` はサービス障害として表示し、再認証を開始しない。
- statusとbeginは信頼済み配置アダプターが、検証済み本人から毎回解決する。
  モデルの「未接続」という回答を接続状態の根拠にしない。他人・管理者の接続を流用しない。
- beginが返せる遷移先は、登録済みプロバイダーのHTTPS originだけ。
  認証・同意の開始であり、経費の作成・更新・削除ではない。
- platform方式では、既存ログイン検証の署名を上記GET/POSTの正確なURL・本文にも適用する。
  BFFは本人session/CSRFと保存済み依頼・テナント・エージェントの所有者を照合してから署名する。
  assertionやBFF秘密鍵をブラウザ・モデルに渡さない。
- 応答はno-store、CSP/frame-ancestors、no-referrerで保護し、外部エラーや秘密は返さない。

`create_platform_host(..., service_connections_factory=...)` または任意の直接SSO用
`create_host` へ、同じprivate storeを使う `ServiceConnections` のfactoryを渡す。
未設定の場合は503で停止し、接続済みとは表示しない。
実際のprovider認証URL・callback・本人別token storeはモデルではなく配置アダプターで固定する。

## 未完了の実接続

この追加はHTTP/GUI実装と合成署名テストであり、公開ホストの配置や実MF/Googleの接続成功ではない。
現行の一人用 `engine_mcp.py` はこのGUIを公開しない。静的APIキー接続へこのコードを追加しただけで
社員ごとの認証に置き換わるものではない。

実利用には以下を接続し、本人と別人の両方で確認する。

1. 固定HTTPS hostと永続private store、platform BFFの署名鍵/trust/person link。
2. MF/Googleそれぞれの本人別status/begin/callback/秘密保管アダプター。
   既存iCal URLや一人用MFトークンを社員へ共有しない。
3. BFF側のGUI表示とPOST所有者照合。今回追加したrouteへの署名許可は、実host存在と宛先を確認してから設定する。
4. provider callback後の本人別接続保存、解除、refreshとMCP実行権限への接続。
5. 本人未認可と、DNS/transport障害を区別する実行前のtyped状態。
   認証host自体が停止していればGUIへ誘導せずサービス障害として通知する。

運用上の課題を、社員へAPIキーの手入力を求めることで回避しない。
実金融書き込みの確認は、対象・会社・内容を本人が承認した後に別途実施する。
