# エージェントが管理する履歴接続

`history_sources.py` はSA／Buzzの読取APIの差を吸収するアダプターです。
Engine／SA／Buzzのソース変更、専用DB、共通実行基盤の独自ツールは前提にしません。
読み方・範囲・履歴の取り扱いは、このGit正本に置きます。
ただし本人確認・認証済みイベントの供給は、外部からの情報なしには成立しません。
**この実装追加だけで、公開中の@入口との接続が終わったとは扱いません。**

## 任意の実行ホストへの接続

SAでは `SuccessAssistHTTP` が本人用のトークンを使って既存の次のGETだけを呼びます。

- `/api/chat/messages/<今回の発言>`：元会話・スレッド・削除状態の確認。
- `/api/chat/channels/<元会話>/messages`：元スレッドまたは本流の読取。

固定のHTTPS originだけへ接続し、リダイレクト、HTML、過大な応答、範囲外のパスを拒否します。
PAT／OAuthトークンは保存しません。外部の資格情報プロバイダーが呼び出しごとに
`PersonalCredential(tenant, requester, audience, secret, expires_at)` を返します。
これはログイン・同意で確定した本人に対応する値であり、本文の自己申告ではありません。
本人・テナント・送信先・期限が今回の実行と一致しない場合は、通信前に拒否します。

Buzzでは `BuzzCLITransport` が外部にインストールされた公式 `buzz` を使い、
`users get` と `messages get` だけを実行します。モデルにシェルやコマンド入力は渡しません。
鍵は環境変数で子プロセスだけへ渡し、親プロセスの他の資格情報は継承しません。
標準では固定HTTPSリレーのみです。明示オプションでローカルの固定開発リレーも利用できます。
現在は**本人の公開鍵に一致する個人接続のみ**対応します。代理のエージェント鍵・他人の鍵・
共通管理者鍵を代わりに使いません。自身のプロフィールが取得できない場合も拒否します。

どちらも現在のエージェントの投稿者IDを `agent_authors` として接続設定に渡します。
そのIDだけをassistant発言として扱い、本文中の名乗りで発言者を切り替えません。

接続の組み立て例（**信頼済みのプログラム内**。ツール引数にはしない）:

```python
from contextvars import ContextVar
from _foundation.history_sources import (
    SuccessAssistHTTP, SuccessAssistHistory, bind_invocation, create_reader,
)

current = ContextVar("authenticated_invocation", default=None)
source = SuccessAssistHistory(
    SuccessAssistHTTP(configured_origin, personal_credentials),
    agent_authors=configured_bot_ids,
)
reader = create_reader(source, current.get)
# 両エージェントの create_server(..., conversation_reader=reader) へ渡せる。

# 入口がログインと受信イベントを検証した後にのみ行う:
bound = bind_invocation(source, **verified_event)
handle = current.set(bound)
try:
    # 同じ実行コンテキストでエージェントを実行。モデルはIDを指定しない。
    run_agent_with_history_reader(reader)
finally:
    current.reset(handle)
```

`verified_event` は tenant、requester、agent、platform、conversation、thread、anchor、
execution、expires_at の共通項目です。最初の発言は実APIから存在・本人・位置を確認し、
発言の順序もアダプターが算出します。本文やモデルが指定したJSON、未検証のHTTPヘッダー、
あるいは「この人は自分だ」という名前から生成してはいけません。
元会話は返信先の本人DMと別に保持します。資格情報プロバイダーにも同じ実行を渡します。
今回の発言のダイジェストも束縛し、入口で確認してから発言が編集された場合は停止します。

上の例は実行フレームワークへの組込APIであり、HTTP公開用の認証サーバーではありません。
外部HTTPクライアントが実行コンテキストを自由に書き換えられる入口を作ってはいけません。

## 差分・限界

- SAの投稿は編集後の本文を使い、削除の空行は返しません。起点／スレッドの削除は停止します。
- Buzzの編集イベントは元投稿の発言者に一致するものだけを適用し、削除対象は返しません。
  削除・モデレーターの権限検査は認証済みリレーの書込検証を前提とします。
  別スレッドの投稿を混ぜず、今回の発言より前だけを返します。
- SAのページ外に今回の発言があるときは停止します。古いページ全体の自動走査は未対応です。
- Buzzの生イベントが取得上限200件に達した場合、編集の取りこぼしを否定できないため停止します。
  その状態を「履歴がない」とは扱いません。大規模会話用のページングは次の対応です。
- 有効な本人の資格情報を毎回選び直し、取得前後にもAPIを読み直します。
  `consistency=content_readback` を返し、厳密なトランザクションの版保証とは区別します。
  API自体が変更と読取を原子的に保証しない限り、読取直後の変更まで保証することはできません。
- 会話の履歴は文章の文脈であり、経費書き込みの承認・本人の記憶の保存とは別です。

## 現時点の検証範囲

既存API／CLIの応答形式に合わせた合成テスト、スコープ・認証・再読取・編集・削除の検査を行います。
実アカウントの接続、既存の@入口からの起動、公開版の切替は別の証拠が必要です。
現在のSA経費入口が配送先DMだけを渡す場合、**元会話と元発言を提供する情報が不足**します。
また、個人のMF接続があってもSA／Buzzの履歴の読取資格情報があることにはなりません。
この不足を共通管理者キーやプロンプトから推測したIDで補いません。
