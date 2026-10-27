"""Platform-neutral, read-only transport preview. No calendar fetch or MF writes."""

import datetime as dt
import hashlib
import json
from zoneinfo import ZoneInfo


def _text(value, field, *, empty=False):
    if not isinstance(value, str) or len(value) > 500 or (not empty and not value.strip()):
        raise ValueError(f"{field}: expected a non-empty string of at most 500 characters")
    return value.strip()


def _timestamp(value):
    parsed = dt.datetime.fromisoformat(_text(value, "timestamp"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamps need an explicit timezone offset")
    return parsed


def _digest(value):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def build_preview(request):
    """Convert explicitly supplied calendar/fare facts to unapproved draft candidates.

    This function does not authenticate the supplier, resolve stations, look up fares,
    verify company rules or authorize writes. Real adapters must establish those facts.
    Neither calendar attendance nor an input field can authorize a transaction here.
    """
    required = {"timezone", "as_of", "date_from", "date_to", "company", "events", "fares"}
    if not isinstance(request, dict) or set(request) != required:
        raise ValueError("request fields must exactly match the preview contract")
    zone = ZoneInfo(_text(request["timezone"], "timezone"))
    as_of = _timestamp(request["as_of"])
    first = dt.date.fromisoformat(request["date_from"])
    last = dt.date.fromisoformat(request["date_to"])
    if first > last:
        raise ValueError("date_from must not exceed date_to")
    company = _text(request["company"], "company", empty=True)
    events, fares = request["events"], request["fares"]
    if not isinstance(events, list) or len(events) > 500:
        raise ValueError("events must be a list of at most 500 entries")
    if not isinstance(fares, list) or len(fares) > 1000:
        raise ValueError("fares must be a list of at most 1000 entries")

    quotes = {}
    fare_fields = {"date", "from_station", "to_station", "amount_yen", "source_ref"}
    for fare in fares:
        if not isinstance(fare, dict) or set(fare) != fare_fields:
            raise ValueError("fare fields must exactly match the preview contract")
        date = dt.date.fromisoformat(fare["date"]).isoformat()
        origin = _text(fare["from_station"], "from_station")
        destination = _text(fare["to_station"], "to_station")
        amount = fare["amount_yen"]
        if type(amount) is not int or amount <= 0:
            raise ValueError("amount_yen must be a positive integer; no float rounding")
        source = _text(fare["source_ref"], "source_ref")
        key = (date, origin, destination)
        quote = {"amount_yen": amount, "source_ref": source}
        if key in quotes and quotes[key] != quote:
            raise ValueError("conflicting fares need an explicit route selection")
        quotes[key] = quote

    normalized, seen = [], {}
    event_fields = {"id", "start", "end", "summary", "station", "mode", "all_day", "status"}
    for event in events:
        if not isinstance(event, dict) or set(event) != event_fields:
            raise ValueError("event fields must exactly match the preview contract")
        identity = _text(event["id"], "event id")
        _text(event["summary"], "summary")
        _text(event["station"], "station", empty=True)
        if type(event["all_day"]) is not bool:
            raise ValueError("all_day must be boolean")
        if event["mode"] not in {"onsite", "online", "unknown"}:
            raise ValueError("mode must be onsite, online or unknown")
        if event["status"] not in {"confirmed", "cancelled"}:
            raise ValueError("status must be confirmed or cancelled")
        if event["all_day"]:
            start_day = dt.date.fromisoformat(event["start"])
            end_day = dt.date.fromisoformat(event["end"])
            if end_day <= start_day:
                raise ValueError("all-day end must follow its start (exclusive end)")
            start = dt.datetime.combine(start_day, dt.time(), zone)
            end = dt.datetime.combine(end_day, dt.time(), zone)
        else:
            start, end = _timestamp(event["start"]), _timestamp(event["end"])
            if end <= start:
                raise ValueError("event end must follow its start")
        occurrence = (identity, start.isoformat())
        if occurrence in seen:
            if seen[occurrence] != event:
                raise ValueError("conflicting calendar occurrences need reconciliation")
            continue
        seen[occurrence] = event
        normalized.append((start, end, event))
    normalized.sort(key=lambda row: (row[0], row[2]["id"]))

    # Discover overlaps before producing any candidates. A later conflicting event
    # must also invalidate an earlier proposed arrival, not just the later event.
    overlapping = set()
    active = []
    for index, (start, end, event) in enumerate(normalized):
        if event["status"] == "cancelled" or event["all_day"]:
            continue
        active = [(other, finish) for other, finish in active if finish > start]
        if active:
            overlapping.add(index)
            overlapping.update(other for other, _ in active)
        active.append((index, end))

    candidates, skipped = [], []
    previous = None
    for index, (start, end, event) in enumerate(normalized):
        day = start.astimezone(zone).date()
        if not first <= day <= last:
            continue
        reason = None
        if event["status"] == "cancelled":
            # A cancelled entry provides no evidence of any location change.
            skipped.append({"event_id": event["id"], "reason": "cancelled"})
            continue
        if event["all_day"]:
            reason = "all_day"
        elif end > as_of:
            reason = "not_finished"
        elif index in overlapping:
            reason = "overlapping_events"
        elif start.astimezone(zone).date() != end.astimezone(zone).date():
            reason = "cross_day"
        elif event["mode"] != "onsite":
            reason = "not_confirmed_onsite"
        elif not event["station"].strip():
            reason = "station_unconfirmed"
        if reason:
            previous = None
            skipped.append({"event_id": event["id"], "reason": reason})
            continue
        if previous is not None and previous[0].astimezone(zone).date() != day:
            previous = None
        if previous is None:
            skipped.append({"event_id": event["id"], "reason": "origin_unconfirmed"})
            previous = (start, end, event)
            continue
        origin_event = previous[2]
        origin, destination = origin_event["station"].strip(), event["station"].strip()
        previous = (start, end, event)
        if origin == destination:
            skipped.append({"event_id": event["id"], "reason": "same_station"})
            continue
        quote = quotes.get((day.isoformat(), origin, destination))
        unresolved = [
            "actual_travel_unconfirmed",
            "expense_item_unconfirmed",
            "commuter_pass_unchecked",
            "company_rules_unchecked",
        ]
        if not company:
            unresolved.append("company_unconfirmed")
        if quote is None:
            unresolved.append("fare_unconfirmed")
        candidate = {
            "recognized_at": day.isoformat(),
            "company": company or None,
            "from_station": origin,
            "to_station": destination,
            "direction": "one_way",
            "purpose": event["summary"],
            "amount_yen": quote["amount_yen"] if quote else None,
            "fare_source_ref": quote["source_ref"] if quote else None,
            "calendar_sources": [
                {"event_id": origin_event["id"], "start": origin_event["start"]},
                {"event_id": event["id"], "start": event["start"]},
            ],
            "unresolved": unresolved,
            "ready_to_register": False,
        }
        candidate["preview_digest"] = _digest(candidate)
        candidates.append(candidate)
    return {
        "kind": "expense_transport_preview",
        "candidates": candidates,
        "skipped": skipped,
        "writes_performed": 0,
        "limitations": [
            "calendar_and_fares_supplied_by_caller",
            "no_authentication",
            "no_company_rule_check",
            "no_registration_or_submission",
        ],
    }
