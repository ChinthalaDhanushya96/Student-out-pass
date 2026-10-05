from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError

DATABASE_URL = "sqlite:///./outpass.db"
SECRET_KEY = "change-this-secret-key"
ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="Smart Student Outpass Management System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)

class Outpass(Base):
    __tablename__ = "outpasses"
    id = Column(Integer, primary_key=True)
    student_id = Column(Integer, nullable=False)
    reason = Column(Text, nullable=False)
    from_time = Column(DateTime, nullable=False)
    to_time = Column(DateTime, nullable=False)
    destination = Column(String(255), nullable=False)
    guardian_contact = Column(String(30), nullable=False)
    status = Column(String(20), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    role: str

class OutpassCreate(BaseModel):
    reason: str
    from_time: datetime
    to_time: datetime
    destination: str
    guardian_contact: str

class StatusUpdate(BaseModel):
    status: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_token(user):
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(hours=8)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_admin(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

@app.get("/")
def root():
    return {"message": "Smart Student Outpass API is running"}

@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email, User.role == data.role).first()
    if not user or not pwd_context.verify(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email, password or role")
    return {"access_token": create_token(user), "role": user.role, "name": user.name}

@app.post("/outpasses")
def create_outpass(
    data: OutpassCreate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can submit requests")
    if data.to_time <= data.from_time:
        raise HTTPException(status_code=400, detail="To time must be after from time")

    item = Outpass(student_id=user.id, **data.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item

@app.get("/outpasses/my")
def my_outpasses(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Outpass).filter(
        Outpass.student_id == user.id
    ).order_by(Outpass.created_at.desc()).all()

@app.get("/admin/outpasses")
def admin_outpasses(
    search: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    query = db.query(Outpass, User).join(User, Outpass.student_id == User.id)

    if status:
        query = query.filter(Outpass.status == status)

    if search:
        term = f"%{search}%"
        query = query.filter(
            (User.name.ilike(term)) |
            (User.email.ilike(term)) |
            (Outpass.reason.ilike(term)) |
            (Outpass.destination.ilike(term))
        )

    rows = query.order_by(Outpass.created_at.desc()).all()
    return [
        {
            "id": op.id,
            "student_name": u.name,
            "student_email": u.email,
            "reason": op.reason,
            "from_time": op.from_time,
            "to_time": op.to_time,
            "destination": op.destination,
            "guardian_contact": op.guardian_contact,
            "status": op.status,
            "created_at": op.created_at
        }
        for op, u in rows
    ]

@app.patch("/admin/outpasses/{outpass_id}")
def update_outpass_status(
    outpass_id: int,
    data: StatusUpdate,
    user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    if data.status not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="Status must be approved or rejected")

    item = db.query(Outpass).filter(Outpass.id == outpass_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Outpass not found")

    item.status = data.status
    db.commit()
    db.refresh(item)
    return item
