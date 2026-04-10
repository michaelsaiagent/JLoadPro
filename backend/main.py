import os, json
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from jose import JWTError, jwt
from functools import wraps

# ─── Config ───────────────────────────────────────────────────────────────────
SECRET_KEY        = os.environ.get("JLOADPRO_SECRET", "jloadpro-dev-secret-change-in-prod")
ALGORITHM         = "HS256"
TOKEN_EXPIRE_DAYS = 30
DB_PATH           = os.path.join(os.path.dirname(__file__), "jloadpro.db")

# ─── Database ─────────────────────────────────────────────────────────────────
engine  = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)
Base    = declarative_base()

class User(Base):
    __tablename__ = "users"
    id       = Column(Integer, primary_key=True)
    name     = Column(String, nullable=False)
    email    = Column(String, unique=True, nullable=False, index=True)
    password = Column(String, nullable=False)
    company  = Column(String, default="")
    plan     = Column(String, default="free")
    created  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    calcs    = relationship("Calc", back_populates="owner", cascade="all, delete")

class Calc(Base):
    __tablename__ = "calcs"
    id      = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title   = Column(String, default="Untitled Calculation")
    address = Column(String, default="")
    data    = Column(Text, nullable=False)
    created = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                     onupdate=lambda: datetime.now(timezone.utc))
    owner   = relationship("User", back_populates="calcs")

Base.metadata.create_all(engine)

# ─── Auth helpers ─────────────────────────────────────────────────────────────
def make_token(user_id):
    exp = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": str(user_id), "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def user_from_token(token):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return int(payload["sub"])

def user_out(u):
    return {"id": u.id, "name": u.name, "email": u.email,
            "company": u.company, "plan": u.plan,
            "created": u.created.isoformat()}

def calc_out(c):
    return {"id": c.id, "title": c.title, "address": c.address,
            "data": c.data,
            "created": c.created.isoformat(),
            "updated": c.updated.isoformat()}

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        token = auth_header[7:]
        try:
            user_id = user_from_token(token)
        except JWTError:
            return jsonify({"error": "Invalid or expired token"}), 401
        db   = Session()
        user = db.get(User, user_id)
        if not user:
            db.close()
            return jsonify({"error": "User not found"}), 401
        try:
            return f(user, db, *args, **kwargs)
        finally:
            db.close()
    return decorated

# ─── App ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins=[
    "https://jloadpro.com",
    "https://www.jloadpro.com",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
])

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return jsonify({"status": "JLoadPro API running"})

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/auth/signup")
def signup():
    body  = request.get_json(silent=True) or {}
    name  = (body.get("name") or "").strip()
    email = (body.get("email") or "").strip().lower()
    pw    = body.get("password") or ""
    if not name or not email or len(pw) < 6:
        return jsonify({"error": "Name, email, and a password of at least 6 characters are required."}), 400

    db = Session()
    try:
        if db.query(User).filter_by(email=email).first():
            return jsonify({"error": "An account with that email already exists."}), 400
        plan = body.get("plan", "free")
        if plan not in ("free", "pro", "team"):
            plan = "free"
        user = User(name=name, email=email, password=generate_password_hash(pw),
                    company=(body.get("company") or "").strip(), plan=plan)
        db.add(user)
        db.commit()
        db.refresh(user)
        return jsonify({"access_token": make_token(user.id), "token_type": "bearer", "user": user_out(user)})
    finally:
        db.close()

@app.post("/auth/login")
def login():
    body  = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    pw    = body.get("password") or ""
    db    = Session()
    try:
        user = db.query(User).filter_by(email=email).first()
        if not user or not check_password_hash(user.password, pw):
            return jsonify({"error": "Invalid email or password."}), 401
        return jsonify({"access_token": make_token(user.id), "token_type": "bearer", "user": user_out(user)})
    finally:
        db.close()

@app.get("/auth/me")
@require_auth
def me(user, db):
    return jsonify(user_out(user))

# ── Calcs ─────────────────────────────────────────────────────────────────────
@app.get("/calcs")
@require_auth
def list_calcs(user, db):
    calcs = db.query(Calc).filter_by(user_id=user.id)\
               .order_by(Calc.updated.desc()).all()
    return jsonify([calc_out(c) for c in calcs])

@app.post("/calcs")
@require_auth
def create_calc(user, db):
    if user.plan == "free":
        count = db.query(Calc).filter_by(user_id=user.id).count()
        if count >= 1:
            return jsonify({"error": "Free plan is limited to 1 calculation. Upgrade to Pro for unlimited."}), 403
    body = request.get_json(silent=True) or {}
    if not body.get("data"):
        return jsonify({"error": "data is required"}), 400
    calc = Calc(user_id=user.id, title=body.get("title", "Untitled Calculation"),
                address=body.get("address", ""), data=body["data"])
    db.add(calc)
    db.commit()
    db.refresh(calc)
    return jsonify(calc_out(calc)), 201

@app.get("/calcs/<int:calc_id>")
@require_auth
def get_calc(user, db, calc_id):
    calc = db.query(Calc).filter_by(id=calc_id, user_id=user.id).first()
    if not calc:
        return jsonify({"error": "Calculation not found."}), 404
    return jsonify(calc_out(calc))

@app.put("/calcs/<int:calc_id>")
@require_auth
def update_calc(user, db, calc_id):
    calc = db.query(Calc).filter_by(id=calc_id, user_id=user.id).first()
    if not calc:
        return jsonify({"error": "Calculation not found."}), 404
    body = request.get_json(silent=True) or {}
    calc.title   = body.get("title", calc.title)
    calc.address = body.get("address", calc.address)
    calc.data    = body.get("data", calc.data)
    calc.updated = datetime.now(timezone.utc)
    db.commit()
    db.refresh(calc)
    return jsonify(calc_out(calc))

@app.delete("/calcs/<int:calc_id>")
@require_auth
def delete_calc(user, db, calc_id):
    calc = db.query(Calc).filter_by(id=calc_id, user_id=user.id).first()
    if not calc:
        return jsonify({"error": "Calculation not found."}), 404
    db.delete(calc)
    db.commit()
    return jsonify({"ok": True})

# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8001))
    debug = os.environ.get("FLASK_ENV") != "production"
    print(f"JLoadPro API running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
