from collections import defaultdict
from datetime import datetime
from typing import Any, Callable, Dict, List

_hourly: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
_daily: Dict[str, List[Dict[str, Any]]] = defaultdict(list)


def enqueue(event: Dict[str, Any], frequency: str) -> None:
    key = datetime.utcnow().strftime("%Y-%m-%d-%H" if frequency == "hourly" else "%Y-%m-%d")
    if frequency == "hourly":
        _hourly[key].append(event)
    else:
        _daily[key].append(event)


def flush_hourly(send_func: Callable[[List[Dict[str, Any]]], None]) -> None:
    for key, events in list(_hourly.items()):
        try:
            send_func(events)
        finally:
            del _hourly[key]


def flush_daily(send_func: Callable[[List[Dict[str, Any]]], None]) -> None:
    for key, events in list(_daily.items()):
        try:
            send_func(events)
        finally:
            del _daily[key]
