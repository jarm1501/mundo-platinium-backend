from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional


@dataclass(frozen=True)
class ChatMessage:
    id: int
    ts: int  # unix seconds
    channel: str
    text: str
    from_uid: int
    from_username: str
    from_nivel: int
    to_username: str = ""
    contact_email: str = ""
    contact_phone: str = ""


@dataclass
class SupportTicket:
    username: str
    uid: int
    contact_email: str = ""
    contact_phone: str = ""

    user_text: str = ""
    user_updated_ts: int = 0
    user_event_id: int = 0

    admin_text: str = ""
    admin_updated_ts: int = 0
    admin_event_id: int = 0

    last_event_id: int = 0
    updated_ts: int = 0


_lock = threading.Lock()
_next_id = 1
_messages: Deque[ChatMessage] = deque()

_support_tickets: Dict[str, SupportTicket] = {}
_support_event_id = 1

# Conservación (segundos). Se limpia en cada publish/list.
# - support: mantener 1 semana
# - group/admins: volátil (sin historial); TTL corto para no crecer sin límite
TTL_BY_CHANNEL = {
    "support": 7 * 24 * 60 * 60,
    "group": 6 * 60 * 60,
    "admins": 6 * 60 * 60,
}


def _now() -> int:
    return int(time.time())


def _purge(now: Optional[int] = None) -> None:
    now = _now() if now is None else now
    while _messages:
        msg = _messages[0]
        ttl = int(TTL_BY_CHANNEL.get(msg.channel, TTL_BY_CHANNEL["support"]))
        if msg.ts >= now - ttl:
            break
        _messages.popleft()


def _purge_support(now: Optional[int] = None) -> None:
    now = _now() if now is None else now
    ttl = int(TTL_BY_CHANNEL.get("support", 7 * 24 * 60 * 60))
    cutoff = now - ttl
    dead = [k for (k, t) in _support_tickets.items() if int(t.updated_ts or 0) and int(t.updated_ts) < cutoff]
    for k in dead:
        _support_tickets.pop(k, None)


def publish(
    *,
    channel: str,
    text: str,
    from_uid: int,
    from_username: str,
    from_nivel: int,
    to_username: str = "",
    contact_email: str = "",
    contact_phone: str = "",
) -> ChatMessage:
    global _next_id
    text = (text or "").strip()
    if not text:
        raise ValueError("empty")

    with _lock:
        _purge()
        mid = _next_id
        _next_id += 1
        msg = ChatMessage(
            id=mid,
            ts=_now(),
            channel=channel,
            text=text,
            from_uid=int(from_uid or 0),
            from_username=str(from_username or ""),
            from_nivel=int(from_nivel or 1),
            to_username=str(to_username or ""),
            contact_email=str(contact_email or ""),
            contact_phone=str(contact_phone or ""),
        )
        _messages.append(msg)
        return msg


def support_list_tickets(*, since_event_id: int = 0, limit: int = 200) -> List[SupportTicket]:
    limit = max(1, min(int(limit or 200), 500))
    with _lock:
        _purge_support()
        tickets = list(_support_tickets.values())
        if since_event_id:
            tickets = [t for t in tickets if int(t.last_event_id) > int(since_event_id)]
        tickets.sort(key=lambda t: (int(t.last_event_id), int(t.updated_ts)), reverse=True)
        return tickets[:limit]


def support_get_ticket(*, username: str) -> Optional[SupportTicket]:
    key = (username or "").strip().lower()
    if not key:
        return None
    with _lock:
        _purge_support()
        t = _support_tickets.get(key)
        return t


def support_upsert_user_message(
    *,
    username: str,
    uid: int,
    contact_email: str = "",
    contact_phone: str = "",
    text: str = "",
    delete: bool = False,
) -> SupportTicket:
    global _support_event_id
    key = (username or "").strip().lower()
    if not key:
        raise ValueError("bad user")
    now = _now()

    with _lock:
        _purge_support(now)
        t = _support_tickets.get(key)
        if not t:
            t = SupportTicket(username=key, uid=int(uid or 0), updated_ts=now)
            _support_tickets[key] = t

        # Siempre actualizamos contacto con lo último disponible.
        t.uid = int(uid or t.uid or 0)
        t.contact_email = str(contact_email or t.contact_email or "")
        t.contact_phone = str(contact_phone or t.contact_phone or "")

        ev = _support_event_id
        _support_event_id += 1

        if delete:
            t.user_text = ""
        else:
            t.user_text = (text or "").strip()
        t.user_updated_ts = now
        t.user_event_id = ev
        t.last_event_id = ev
        t.updated_ts = now
        return t


def support_upsert_admin_message(
    *,
    target_username: str,
    text: str = "",
    delete: bool = False,
) -> SupportTicket:
    global _support_event_id
    key = (target_username or "").strip().lower()
    if not key:
        raise ValueError("bad user")
    now = _now()

    with _lock:
        _purge_support(now)
        t = _support_tickets.get(key)
        if not t:
            # Si no existe ticket, lo creamos vacío para permitir respuesta.
            t = SupportTicket(username=key, uid=0, updated_ts=now)
            _support_tickets[key] = t

        ev = _support_event_id
        _support_event_id += 1

        if delete:
            t.admin_text = ""
        else:
            t.admin_text = (text or "").strip()
        t.admin_updated_ts = now
        t.admin_event_id = ev
        t.last_event_id = ev
        t.updated_ts = now
        return t


def list_messages(
    *,
    channel: str,
    since_id: int = 0,
    since_ts: int = 0,
    limit: int = 200,
    to_username: str = "",
) -> List[ChatMessage]:
    limit = max(1, min(int(limit or 200), 500))
    with _lock:
        _purge()
        out: List[ChatMessage] = []
        for msg in _messages:
            if msg.channel != channel:
                continue
            if since_id and msg.id <= since_id:
                continue
            if since_ts and msg.ts < since_ts:
                continue
            if to_username and msg.to_username != to_username:
                continue
            out.append(msg)
        return out[-limit:]


def delete_message(*, msg_id: int) -> bool:
    msg_id = int(msg_id)
    with _lock:
        if not _messages:
            return False
        kept: Deque[ChatMessage] = deque()
        deleted = False
        for msg in _messages:
            if msg.id == msg_id:
                deleted = True
                continue
            kept.append(msg)
        if deleted:
            _messages.clear()
            _messages.extend(kept)
        return deleted


def to_dict(msg: ChatMessage) -> Dict:
    return {
        "id": msg.id,
        "ts": msg.ts,
        "channel": msg.channel,
        "text": msg.text,
        "from_uid": msg.from_uid,
        "from_username": msg.from_username,
        "from_nivel": msg.from_nivel,
        "to_username": msg.to_username,
        "contact_email": msg.contact_email,
        "contact_phone": msg.contact_phone,
    }


def support_ticket_to_dict(t: SupportTicket) -> Dict:
    return {
        "username": t.username,
        "uid": int(t.uid or 0),
        "contact_email": t.contact_email,
        "contact_phone": t.contact_phone,
        "user_text": t.user_text,
        "user_updated_ts": int(t.user_updated_ts or 0),
        "user_event_id": int(t.user_event_id or 0),
        "admin_text": t.admin_text,
        "admin_updated_ts": int(t.admin_updated_ts or 0),
        "admin_event_id": int(t.admin_event_id or 0),
        "last_event_id": int(t.last_event_id or 0),
        "updated_ts": int(t.updated_ts or 0),
    }
