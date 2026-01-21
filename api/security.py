import base64
import hashlib
import hmac
import ipaddress
from dataclasses import dataclass
from typing import Optional

import bcrypt
from django.conf import settings

try:
	from cryptography.fernet import Fernet
except Exception:  # pragma: no cover
	Fernet = None


def _fernet_key() -> bytes:
	raw = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
	return base64.urlsafe_b64encode(raw)


def encrypt_ip(ip: str) -> str:
	if not ip:
		return ""
	if Fernet is None:
		return ip
	f = Fernet(_fernet_key())
	return f.encrypt(ip.encode("utf-8")).decode("utf-8")


def decrypt_ip(token: str) -> str:
	if not token:
		return ""
	if Fernet is None:
		return token
	f = Fernet(_fernet_key())
	return f.decrypt(token.encode("utf-8")).decode("utf-8")


def ip_hash(ip: str) -> str:
	ip = (ip or "").strip()
	if not ip:
		return ""
	key = settings.SECRET_KEY.encode("utf-8")
	return hmac.new(key, ip.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_answer(answer: str) -> str:
	raw = (answer or "").strip().lower().encode("utf-8")
	return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def verify_answer(answer: str, stored_hash: str) -> bool:
	raw = (answer or "").strip().lower().encode("utf-8")
	h = (stored_hash or "").encode("utf-8")
	try:
		return bcrypt.checkpw(raw, h)
	except Exception:
		return False


@dataclass
class GeoHint:
	country: Optional[str]
	region: Optional[str]


def geo_hint(ip: str) -> GeoHint:
	try:
		addr = ipaddress.ip_address(ip)
		if addr.is_loopback:
			return GeoHint(country="LOCAL", region="127.0.0.1")
		if addr.is_private:
			return GeoHint(country="PRIVATE", region="LAN")
	except Exception:
		pass
	return GeoHint(country=None, region=None)
