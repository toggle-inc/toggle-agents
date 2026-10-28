"""Agent-owned plain-text review fields. No platform renderer or financial authority."""

import datetime as dt

from .state import ExpenseError

ACTIONS = {
    "create": "経費明細の作成",
    "update": "経費明細の修正",
    "upload": "領収書をMFへ送信しOCRで明細化",
    "delete": "経費明細の削除",
}
LABELS = {
    "office": "会社",
    "id": "ID",
    "name": "名称",
    "recognized_at": "利用日",
    "date": "利用日",
    "value": "金額",
    "remark": "内容・支払先",
    "memo": "メモ",
    "ex_item_id": "経費科目ID",
    "ex_item_name": "経費科目",
    "ex_item": "経費科目",
    "report_number": "事前申請番号",
    "project_id": "プロジェクトID",
    "project": "プロジェクト",
    "dept_id": "部門ID",
    "invoice_registration_number": "適格請求書発行事業者登録番号",
    "receipt_path": "本人用領収書参照",
    "receipt": "領収書参照",
    "receipt_input": "添付する領収書",
    "filename": "ファイル名",
    "content_type": "ファイル形式",
    "contentType": "ファイル形式",
    "content_sha256": "内容のSHA256",
    "sha256": "内容のSHA256",
    "bytes": "バイト数",
    "size": "バイト数",
    "process_type": "MF処理種別",
    "split_pdf": "PDFページ分割",
    "transaction_id": "対象明細ID",
    "own_count": "自社の出席者数",
    "other_count": "他社の出席者数",
    "own_names": "自社の代表者",
    "other_names": "他社の代表者",
    "ex_transaction_attendant_count_attributes": "出席者数",
    "ex_transaction_attendant_representative_attributes": "代表者",
    "own_name": "自社",
    "other_name": "他社",
    "sources": "出典",
    "ex_item_options": "経費科目の候補",
    "has_file": "領収書添付あり",
    "in_report": "申請に含まれる",
    "warning": "注意点",
    "automatic_status": "MF処理状態",
    "receipt_file_id": "MF領収書ID",
    "fields": "項目",
    "key": "項目ID",
    "label": "表示名",
    "type": "入力形式",
    "required": "必須項目",
    "status": "確認状態",
    "source": "出典",
    "options": "候補",
    "app": "対象サービス",
    "form": "フォーム名",
    "notes": "注意点",
    "ready": "必要項目が揃っている",
    "authorization": "必要な承認",
}
SECTIONS = {
    "payload": "実行する内容",
    "before": "変更・削除前の明細",
    "form": "入力項目と確認状態",
    "warnings": "注意点",
    "intent": "依頼内容と出典",
    "office": "精算する会社",
    "policy_version": "確認に使用した規則の版",
    "receipt_fingerprint": "重複登録防止の照合情報",
}


def text(value):
    if value is None:
        return "（未設定）"
    if value == "":
        return "（空欄）"
    if type(value) is bool:
        return "はい" if value else "いいえ"
    if type(value) not in (str, int, float):
        raise ExpenseError("確認項目の値を正確に表示できません。")
    return str(value)


def fields(value, label="内容", depth=0):
    """Every leaf, including unknown future keys and empty containers, is shown."""
    if depth > 30:
        raise ExpenseError("確認項目の階層が深すぎます。省略せず分割してください。")
    if isinstance(value, dict):
        if not value:
            return [{"label": label, "value": "項目なし"}]
        return [
            row
            for key in sorted(value)
            for row in fields(value[key], label + " / " + LABELS.get(key, key), depth + 1)
        ]
    if isinstance(value, list):
        if not value:
            return [{"label": label, "value": "項目なし"}]
        return [
            row
            for index, item in enumerate(value, 1)
            for row in fields(item, label + f" [{index}]", depth + 1)
        ]
    return [{"label": label, "value": text(value)}]


def build_presentation(details, snapshot, attachments):
    """Use the exact source-owned snapshot projection, never a model summary."""
    action = ACTIONS.get(details["action"])
    if action is None:
        raise ExpenseError("未対応の確認操作です。")
    company = snapshot.get("office", {})
    sections = [
        {
            "title": "今回承認する操作",
            "fields": [
                {"label": "操作", "value": action},
                {"label": "精算する会社", "value": text(company.get("name", details["office"]))},
                {"label": "会社ID", "value": str(details["office"])},
                {
                    "label": "承認の期限",
                    "value": dt.datetime.fromtimestamp(
                        details["expires_at"], dt.timezone(dt.timedelta(hours=9))
                    ).isoformat(),
                },
                {"label": "申請の提出", "value": "行いません。提出は本人がMF画面で行います。"},
            ],
        }
    ]
    if details["action"] == "upload":
        sections[0]["fields"].append(
            {"label": "注意", "value": "画像の送信によりMFに明細が作られる可能性があります。"}
        )
    order = [key for key in ("before", "payload", "form", "warnings", "intent") if key in snapshot]
    order += sorted(set(snapshot) - set(order))
    for key in order:
        sections.append(
            {
                "title": SECTIONS.get(key, "追加の確認事項: " + key),
                "fields": fields(snapshot[key], SECTIONS.get(key, key)),
            }
        )
    if attachments:
        sections.append(
            {"title": "この依頼に添付された領収書", "fields": fields(attachments, "添付")}
        )
    checked = []
    for section in sections:
        for offset in range(0, len(section["fields"]), 200):
            title = section["title"] + (f" ({offset // 200 + 1})" if offset else "")
            group = section["fields"][offset : offset + 200]
            if not 1 <= len(title) <= 200 or any(
                not 1 <= len(row["label"]) <= 200 or not 1 <= len(row["value"]) <= 16000
                for row in group
            ):
                raise ExpenseError(
                    "確認項目が画面の上限を超えます。内容を省略せず分割してください。"
                )
            checked.append({"title": title, "fields": group})
    if not 1 <= len(checked) <= 100:
        raise ExpenseError("確認項目が多すぎます。内容を省略せず分割してください。")
    return {"title": action + "の確認", "sections": checked}
