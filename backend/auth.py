import os, hashlib, secrets, re
from datetime import datetime, timezone, timedelta
import jwt
from fastapi import Depends, Header, HTTPException
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATABASE_URL=os.getenv("DATABASE_URL","sqlite:///./mailguard.db")
engine=create_engine(DATABASE_URL,connect_args={"check_same_thread":False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False)
Base=declarative_base()
SECRET_KEY=os.getenv("JWT_SECRET","change-this-in-production")
ENVIRONMENT=os.getenv("ENVIRONMENT","development").lower()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL="postgresql://" + DATABASE_URL[len("postgres://"): ]
if ENVIRONMENT in {"production","prod"} and SECRET_KEY == "change-this-in-production":
    raise RuntimeError("JWT_SECRET must be set to a strong random value in production.")

class User(Base):
    __tablename__="users"
    id=Column(Integer,primary_key=True)
    email=Column(String(255),unique=True,index=True,nullable=False)
    password_hash=Column(String(255),nullable=False)
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class Scan(Base):
    __tablename__="scans"
    id=Column(Integer,primary_key=True)
    user_id=Column(Integer,index=True,nullable=False)
    timestamp=Column(DateTime,default=lambda:datetime.now(timezone.utc))
    prediction=Column(String(20),nullable=False)
    risk_level=Column(String(20),nullable=False)
    risk_score=Column(Integer,nullable=False)
    spam_probability=Column(Float,nullable=False)
    preview=Column(Text,nullable=False)

Base.metadata.create_all(engine)

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
