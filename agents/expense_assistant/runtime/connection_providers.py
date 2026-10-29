"""Compose the canonical service GUI with trusted per-person provider adapters."""

from .service_connections import ConnectionProvider, ServiceConnections


def build_service_connections(store, *, mf=None, calendar=None, clock=None):
    adapters = {"mf": mf, "calendar": calendar}
    if all(adapter is None for adapter in adapters.values()):
        raise ValueError("At least one real per-person provider adapter is required")
    for adapter in adapters.values():
        if adapter is not None and not all(
            callable(getattr(adapter, method, None)) for method in ("status", "begin", "complete")
        ):
            raise ValueError("Complete per-person provider adapter required")

    def status(person, provider):
        adapter = adapters[provider]
        return "unavailable" if adapter is None else adapter.status(person, provider)

    def invoke(method, person, provider, *args):
        adapter = adapters[provider]
        if adapter is None:
            raise ValueError("Provider deployment is unavailable")
        return getattr(adapter, method)(person, provider, *args)

    return ServiceConnections(
        store,
        providers=(
            ConnectionProvider("mf", "マネーフォワード経費", frozenset({"https://expense.moneyforward.com"})),
            ConnectionProvider("calendar", "Googleカレンダー", frozenset({"https://accounts.google.com"})),
        ),
        status=status,
        begin=lambda person, provider: invoke("begin", person, provider),
        complete=lambda person, provider, params: invoke("complete", person, provider, params),
        **({"clock": clock} if clock is not None else {}),
    )
