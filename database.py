import os
import base64
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    remaining_chars: Mapped[int] = mapped_column(Integer, default=0)
    total_limit: Mapped[int] = mapped_column(Integer, default=0)
    total_credits_allocated: Mapped[int] = mapped_column(Integer, default=0)
    access_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    credentials = relationship("Credential", back_populates="user", cascade="all, delete-orphan")
    deployments = relationship("Deployment", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("LoginSession", back_populates="user", cascade="all, delete-orphan")
    voices = relationship("SavedVoice", back_populates="user", cascade="all, delete-orphan")


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True)
    kaggle_username_enc: Mapped[str] = mapped_column(Text)
    kaggle_token_enc: Mapped[str] = mapped_column(Text)
    ngrok_token_enc: Mapped[str] = mapped_column(Text, default="")
    ngrok_domain_enc: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    user = relationship("User", back_populates="credentials")


class Deployment(Base):
    __tablename__ = "deployments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True)
    kernel_id: Mapped[str] = mapped_column(String(200), unique=True)
    kernel_slug: Mapped[str] = mapped_column(String(120))
    public_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="IDLE")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_logs: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    user = relationship("User", back_populates="deployments")


class LoginSession(Base):
    __tablename__ = "login_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user = relationship("User", back_populates="sessions")


class SavedVoice(Base):
    __tablename__ = "saved_voices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    filename: Mapped[str] = mapped_column(String(255))
    mime_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    encrypted_audio: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user = relationship("User", back_populates="voices")


def _get_secret(name):
    try:
        import streamlit as st
        value = st.secrets.get(name, "")
        if value:
            return str(value).strip()
    except Exception:
        pass
    return os.getenv(name, "").strip()


def _db_url():
    url = _get_secret("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is missing.")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[11:]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[13:]
    if url.startswith("postgresql+psycopg://"):
        return url
    raise RuntimeError("DATABASE_URL must be a PostgreSQL connection URL.")


def _fernet():
    key = _get_secret("APP_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("APP_ENCRYPTION_KEY is missing.")
    try:
        return Fernet(key.encode())
    except Exception as exc:
        raise RuntimeError("Invalid APP_ENCRYPTION_KEY.") from exc


ENGINE = create_engine(_db_url(), pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=ENGINE, expire_on_commit=False)


def init_db():
    Base.metadata.create_all(ENGINE)
    inspector = inspect(ENGINE)
    columns = {c["name"] for c in inspector.get_columns("users")}
    with ENGINE.begin() as conn:
        if "is_admin" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE"))
        if "remaining_chars" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN remaining_chars INTEGER NOT NULL DEFAULT 0"))
        if "total_limit" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN total_limit INTEGER NOT NULL DEFAULT 0"))
        if "total_credits_allocated" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN total_credits_allocated INTEGER NOT NULL DEFAULT 0"))
        if "access_expires_at" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN access_expires_at TIMESTAMP WITH TIME ZONE"))
        if "revoked_at" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN revoked_at TIMESTAMP WITH TIME ZONE"))


def _hash_password(password):
    salt = secrets.token_bytes(16)
    rounds = 390000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return f"pbkdf2_sha256${rounds}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def _verify_password(password, stored):
    try:
        scheme, rounds, salt, digest = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.urlsafe_b64decode(salt), int(rounds))
        return hmac.compare_digest(actual, base64.urlsafe_b64decode(digest))
    except Exception:
        return False


def _parse_expiry(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        try:
            dt = datetime.fromisoformat(str(value))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _profile(user):
    expiry = user.access_expires_at
    if expiry and expiry.tzinfo:
        expiry_text = expiry.astimezone(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    elif expiry:
        expiry_text = expiry.strftime("%Y-%m-%d %H:%M:%S")
    else:
        expiry_text = ""
    data = {
        "password": "",
        "expiry_timestamp": expiry_text,
        "total_limit": int(user.total_limit or 0),
        "total_credits_allocated": int(user.total_credits_allocated or 0),
        "remaining_chars": int(user.remaining_chars or 0),
        "is_revoked": not bool(user.is_active),
        "is_admin": bool(user.is_admin),
        "kaggle_username": "",
        "kaggle_token": "",
    }
    return data


def _decrypt_credentials(row):
    if not row:
        return {"kaggle_username": "", "kaggle_token": "", "ngrok_token": "", "ngrok_domain": ""}
    f = _fernet()
    try:
        return {
            "kaggle_username": f.decrypt(row.kaggle_username_enc.encode()).decode(),
            "kaggle_token": f.decrypt(row.kaggle_token_enc.encode()).decode(),
            "ngrok_token": f.decrypt((row.ngrok_token_enc or "").encode()).decode() if row.ngrok_token_enc else "",
            "ngrok_domain": f.decrypt((row.ngrok_domain_enc or "").encode()).decode() if row.ngrok_domain_enc else "",
        }
    except InvalidToken as exc:
        raise RuntimeError("Cannot decrypt stored credentials. Check APP_ENCRYPTION_KEY.") from exc


def _hydrate_local_voices(username, voice_rows):
    folder = Path("cloud_vault") / username / "voices"
    folder.mkdir(parents=True, exist_ok=True)
    wanted = set()
    f = _fernet()
    for row in voice_rows:
        try:
            filename = re.sub(r"[^A-Za-z0-9._ -]", "_", row.filename).strip() or "audio.wav"
            target = folder / filename
            wanted.add(target.name)
            raw = f.decrypt(row.encrypted_audio)
            if not target.exists() or target.read_bytes() != raw:
                target.write_bytes(raw)
        except Exception:
            continue
    for old in folder.iterdir():
        if old.is_file() and old.name not in wanted and old.suffix.lower() in {".wav", ".mp3", ".m4a", ".ogg", ".flac"}:
            try:
                old.unlink()
            except Exception:
                pass


def fetch_live_database():
    init_db()
    users = {}
    with SessionLocal() as db:
        rows = db.query(User).order_by(User.username.asc()).all()
        for user in rows:
            profile = _profile(user)
            creds = db.query(Credential).filter_by(user_id=user.id).first()
            try:
                profile.update(_decrypt_credentials(creds))
            except RuntimeError:
                profile.update({"kaggle_username": "", "kaggle_token": ""})
            voices = db.query(SavedVoice).filter_by(user_id=user.id).order_by(SavedVoice.created_at.desc()).all()
            _hydrate_local_voices(user.username, voices)
            users[user.username.upper()] = profile
    return users


def push_database_updates(updated_db):
    if not isinstance(updated_db, dict):
        return False
    try:
        init_db()
        with SessionLocal() as db:
            for username, data in updated_db.items():
                if not isinstance(data, dict):
                    continue
                uname = str(username).strip().upper()
                user = db.query(User).filter_by(username=uname.lower()).first()
                if not user:
                    user = User(username=uname.lower(), password_hash=_hash_password(str(data.get("password") or secrets.token_urlsafe(24))))
                    db.add(user)
                    db.flush()
                if data.get("password"):
                    user.password_hash = _hash_password(str(data["password"]))
                user.is_admin = bool(data.get("is_admin", False))
                user.is_active = not bool(data.get("is_revoked", False))
                user.revoked_at = utcnow() if not user.is_active else None
                user.remaining_chars = int(data.get("remaining_chars", 0) or 0)
                user.total_limit = int(data.get("total_limit", 0) or 0)
                user.total_credits_allocated = int(data.get("total_credits_allocated", user.total_limit) or 0)
                user.access_expires_at = _parse_expiry(data.get("expiry_timestamp"))
                ku = str(data.get("kaggle_username", "") or "")
                kt = str(data.get("kaggle_token", "") or "")
                if ku or kt:
                    f = _fernet()
                    row = db.query(Credential).filter_by(user_id=user.id).first()
                    vals = {
                        "kaggle_username_enc": f.encrypt(ku.strip().encode()).decode(),
                        "kaggle_token_enc": f.encrypt(kt.strip().encode()).decode(),
                        "ngrok_token_enc": f.encrypt(str(data.get("ngrok_token", "") or "").encode()).decode(),
                        "ngrok_domain_enc": f.encrypt(str(data.get("ngrok_domain", "") or "").encode()).decode(),
                    }
                    if row:
                        for k, v in vals.items():
                            setattr(row, k, v)
                    else:
                        db.add(Credential(user_id=user.id, **vals))
                else:
                    row = db.query(Credential).filter_by(user_id=user.id).first()
                    if row:
                        db.delete(row)
            db.commit()
        return True
    except Exception:
        return False


def authenticate_user(username, password):
    init_db()
    with SessionLocal() as db:
        user = db.query(User).filter_by(username=username.strip().lower(), is_active=True).first()
        if not user or not _verify_password(password, user.password_hash):
            return None
        if user.access_expires_at and user.access_expires_at <= utcnow() and not user.is_admin:
            return None
        return user


def create_session(user_id, days=30):
    raw = secrets.token_urlsafe(48)
    with SessionLocal() as db:
        db.add(LoginSession(user_id=user_id, token_hash=hashlib.sha256(raw.encode()).hexdigest(), expires_at=utcnow() + timedelta(days=days)))
        db.commit()
    return raw


def get_user_by_session(raw):
    if not raw:
        return None
    with SessionLocal() as db:
        row = db.query(LoginSession).filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest()).first()
        if not row or row.expires_at <= utcnow():
            return None
        return db.query(User).filter_by(id=row.user_id, is_active=True).first()


def delete_session(raw):
    if not raw:
        return
    with SessionLocal() as db:
        db.query(LoginSession).filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest()).delete()
        db.commit()


def verify_user_password(user_id, password):
    with SessionLocal() as db:
        user = db.query(User).filter_by(id=user_id).first()
        return bool(user and _verify_password(password, user.password_hash))


def change_password(user_id, password):
    if len(password) < 8:
        return False
    with SessionLocal() as db:
        user = db.query(User).filter_by(id=user_id).first()
        if not user:
            return False
        user.password_hash = _hash_password(password)
        db.commit()
        return True


def save_voice_to_database(username, path: Path):
    if not path.exists():
        return False
    try:
        init_db()
        with SessionLocal() as db:
            user = db.query(User).filter_by(username=username.strip().lower()).first()
            if not user:
                return False
            f = _fernet()
            raw = path.read_bytes()
            existing = db.query(SavedVoice).filter_by(user_id=user.id, filename=path.name[:255]).all()
            for old_row in existing:
                db.delete(old_row)
            row = SavedVoice(user_id=user.id, name=path.stem[:120], filename=path.name[:255], mime_type=_mime(path.suffix), encrypted_audio=f.encrypt(raw))
            db.add(row)
            db.commit()
        return True
    except Exception:
        return False


def delete_voice_from_database(username, voice_stem):
    try:
        init_db()
        with SessionLocal() as db:
            user = db.query(User).filter_by(username=username.strip().lower()).first()
            if not user:
                return False
            rows = db.query(SavedVoice).filter_by(user_id=user.id).all()
            for row in rows:
                if Path(row.filename).stem == voice_stem:
                    db.delete(row)
            db.commit()
        return True
    except Exception:
        return False


def _mime(suffix):
    return {".wav": "audio/wav", ".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".ogg": "audio/ogg", ".flac": "audio/flac"}.get(suffix.lower(), "application/octet-stream")


def get_credentials(user_id):
    with SessionLocal() as db:
        row = db.query(Credential).filter_by(user_id=user_id).first()
        return _decrypt_credentials(row) if row else None


def save_credentials(user_id, kaggle_username, kaggle_token, ngrok_token="", ngrok_domain=""):
    f = _fernet()
    vals = {
        "kaggle_username_enc": f.encrypt(kaggle_username.strip().encode()).decode(),
        "kaggle_token_enc": f.encrypt(kaggle_token.strip().encode()).decode(),
        "ngrok_token_enc": f.encrypt(ngrok_token.strip().encode()).decode(),
        "ngrok_domain_enc": f.encrypt(ngrok_domain.strip().encode()).decode(),
    }
    with SessionLocal() as db:
        row = db.query(Credential).filter_by(user_id=user_id).first()
        if not row:
            db.add(Credential(user_id=user_id, **vals))
        else:
            for k, v in vals.items():
                setattr(row, k, v)
        db.commit()


def get_user_by_username(username):
    with SessionLocal() as db:
        return db.query(User).filter(User.username == username.strip().lower()).first()


def get_user_by_id(user_id):
    with SessionLocal() as db:
        return db.query(User).filter(User.id == user_id, User.is_active == True).first()


def get_deployment(user_id):
    with SessionLocal() as db:
        return db.query(Deployment).filter_by(user_id=user_id).first()


def upsert_deployment(user_id, **values):
    with SessionLocal() as db:
        row = db.query(Deployment).filter_by(user_id=user_id).first()
        if not row:
            row = Deployment(user_id=user_id, **values)
            db.add(row)
        else:
            for k, v in values.items():
                setattr(row, k, v)
        db.commit(); db.refresh(row); return row


def migrate_legacy_json(json_path):
    path = Path(json_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    users = data.get("users", data)
    init_db()
    with SessionLocal() as db:
        for username, profile in users.items():
            uname = str(username).strip().lower()
            existing = db.query(User).filter_by(username=uname).first()
            if existing:
                user = existing
            else:
                user = User(username=uname, password_hash=_hash_password(str(profile.get("password", ""))))
                db.add(user); db.flush()
            if profile.get("password"):
                user.password_hash = _hash_password(str(profile["password"]))
            user.is_admin = bool(profile.get("is_admin", False))
            user.is_active = not bool(profile.get("is_revoked", False))
            user.revoked_at = utcnow() if not user.is_active else None
            user.remaining_chars = int(profile.get("remaining_chars", 0) or 0)
            user.total_limit = int(profile.get("total_limit", profile.get("total_credits_allocated", 0)) or 0)
            user.total_credits_allocated = int(profile.get("total_credits_allocated", user.total_limit) or 0)
            user.access_expires_at = _parse_expiry(profile.get("expiry_timestamp"))
            ku = str(profile.get("kaggle_username", "") or "")
            kt = str(profile.get("kaggle_token", "") or "")
            if ku or kt:
                f = _fernet()
                row = db.query(Credential).filter_by(user_id=user.id).first()
                vals = {
                    "kaggle_username_enc": f.encrypt(ku.encode()).decode(),
                    "kaggle_token_enc": f.encrypt(kt.encode()).decode(),
                    "ngrok_token_enc": f.encrypt(str(profile.get("ngrok_token", "") or "").encode()).decode(),
                    "ngrok_domain_enc": f.encrypt(str(profile.get("ngrok_domain", "") or "").encode()).decode(),
                }
                if row:
                    for k, v in vals.items(): setattr(row, k, v)
                else:
                    db.add(Credential(user_id=user.id, **vals))
            voices = profile.get("voices") or {}
            if isinstance(voices, dict):
                f = _fernet()
                for _, item in voices.items():
                    if not isinstance(item, dict) or not item.get("data"):
                        continue
                    filename = str(item.get("filename") or "audio.wav")
                    exists = db.query(SavedVoice).filter_by(user_id=user.id, filename=filename).first()
                    if exists:
                        continue
                    try:
                        raw = base64.b64decode(item["data"], validate=True)
                        db.add(SavedVoice(user_id=user.id, name=Path(filename).stem[:120], filename=filename[:255], mime_type=_mime(Path(filename).suffix), encrypted_audio=f.encrypt(raw)))
                    except Exception:
                        continue
        db.commit()
    return True


def admin_create_client(username, password, access_days, chars=1000000):
    username = username.strip().lower()
    if len(username) < 3 or len(username) > 80 or len(password) < 8 or int(access_days) < 1:
        return False, "Invalid client details."
    with SessionLocal() as db:
        if db.query(User).filter_by(username=username).first():
            return False, "Username already exists."
        amount = int(chars)
        db.add(User(username=username, password_hash=_hash_password(password), is_active=True, is_admin=False, remaining_chars=amount, total_limit=amount, total_credits_allocated=amount, access_expires_at=utcnow() + timedelta(days=int(access_days))))
        db.commit()
    return True, None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ZAIKO AI STUDIO database utilities")
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--migrate-json", dest="migrate_json")
    args = parser.parse_args()
    if args.init:
        init_db(); print("Database initialized.")
    if args.migrate_json:
        migrate_legacy_json(args.migrate_json); print("Legacy JSON migrated.")
