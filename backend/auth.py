import os, hashlib, secrets, re, time
from datetime import datetime, timezone, timedelta
import jwt
from fastapi import Depends, Header, HTTPException
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, UniqueConstraint, ForeignKey, Index
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATABASE_URL=os.getenv("DATABASE_URL","sqlite:///./mailguard.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL="postgresql://" + DATABASE_URL[len("postgres://"):]
ENVIRONMENT=os.getenv("ENVIRONMENT","development").lower()
engine_kwargs={}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"]={"check_same_thread":False}
else:
    engine_kwargs.update({
        "pool_pre_ping":True,
        "pool_recycle":1800,
        "pool_size":int(os.getenv("DB_POOL_SIZE","5")),
        "max_overflow":int(os.getenv("DB_MAX_OVERFLOW","10")),
    })
engine=create_engine(DATABASE_URL,**engine_kwargs)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False)
Base=declarative_base()
SECRET_KEY=os.getenv("JWT_SECRET","change-this-in-production")
if ENVIRONMENT in {"production","prod"} and (SECRET_KEY == "change-this-in-production" or len(SECRET_KEY) < 32):
    raise RuntimeError("JWT_SECRET must be set to a strong random value (32+ characters) in production.")

class User(Base):
    __tablename__="users"
    id=Column(Integer,primary_key=True)
    email=Column(String(255),unique=True,index=True,nullable=False)
    password_hash=Column(String(255),nullable=False)
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class Scan(Base):
    __tablename__="scans"
    id=Column(Integer,primary_key=True)
    user_id=Column(Integer,ForeignKey("users.id",ondelete="CASCADE"),index=True,nullable=False)
    timestamp=Column(DateTime,default=lambda:datetime.now(timezone.utc))
    prediction=Column(String(20),nullable=False)
    risk_level=Column(String(20),nullable=False)
    risk_score=Column(Integer,nullable=False)
    spam_probability=Column(Float,nullable=False)
    preview=Column(Text,nullable=False)

class OAuthIdentity(Base):
    __tablename__="oauth_identities"
    id=Column(Integer,primary_key=True)
    provider=Column(String(32),nullable=False)
    subject=Column(String(255),nullable=False)
    email=Column(String(255),nullable=False,index=True)
    user_id=Column(Integer,ForeignKey("users.id",ondelete="CASCADE"),index=True,nullable=False)
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint("provider","subject",name="uq_oauth_provider_subject"),)

class OAuthState(Base):
    __tablename__="oauth_states"
    id=Column(Integer,primary_key=True)
    provider=Column(String(32),nullable=False,index=True)
    state_hash=Column(String(64),unique=True,index=True,nullable=False)
    expires_at=Column(DateTime,nullable=False)
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class OAuthCode(Base):
    __tablename__="oauth_codes"
    id=Column(Integer,primary_key=True)
    code_hash=Column(String(64),unique=True,index=True,nullable=False)
    user_id=Column(Integer,ForeignKey("users.id",ondelete="CASCADE"),index=True,nullable=False)
    expires_at=Column(DateTime,nullable=False)
    consumed_at=Column(DateTime,nullable=True)

def _initialize_database():
    attempts=5
    for attempt in range(attempts):
        try:
            Base.metadata.create_all(engine)
            return
        except OperationalError:
            engine.dispose()
            if attempt == attempts - 1:
                raise
            time.sleep(min(2 ** attempt, 8))

_initialize_database()

def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()

def hash_password(password):
    try:
        from argon2 import PasswordHasher
        return "argon2$" + PasswordHasher().hash(password)
    except ImportError:
        salt=secrets.token_bytes(16)
        digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,120000)
        return "pbkdf2$" + salt.hex()+":"+digest.hex()

def verify_password(password,stored):
    try:
        if stored.startswith("argon2$"):
            from argon2 import PasswordHasher
            return PasswordHasher().verify(stored[7:], password)
        if stored.startswith("pbkdf2$"):
            stored=stored[7:]
        salt,digest=stored.split(":")
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),120000).hex()
        return secrets.compare_digest(actual,digest)
    except Exception:
        return False

def valid_email(email):
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email))

def make_token(user):
    return jwt.encode({"sub":str(user.id),"email":user.email,"exp":datetime.now(timezone.utc)+timedelta(hours=24)},SECRET_KEY,algorithm="HS256")

def current_user(authorization:str=Header(default=""),db:Session=Depends(get_db)):
    if not authorization.startswith("Bearer "): raise HTTPException(401,"Authentication required.")
    try:
        payload=jwt.decode(authorization[7:],SECRET_KEY,algorithms=["HS256"])
        user=db.get(User,int(payload["sub"]))
    except Exception: raise HTTPException(401,"Invalid or expired token.")
    if not user: raise HTTPException(401,"User not found.")
    return user
