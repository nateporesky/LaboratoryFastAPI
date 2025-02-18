from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Column, Integer, String, Boolean, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# JWT Configuration
SECRET_KEY = "SECRET_KEYajnkjnknsc"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1800  # 30 hours

app = FastAPI()

# Password Hashing Configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# SQLAlchemy Setup (In-Memory Database)
DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class UserDB(Base):
    """SQLAlchemy Model for Users"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    disabled = Column(Boolean, default=False)
    last_login = Column(String, default=datetime.now(timezone.utc).isoformat())

class QuotaDB(Base):
    """SQLAlchemy Model for Quotas"""
    __tablename__ = "quotas"

    id = Column(Integer, primary_key=True, index=True)
    pi_name = Column(String, nullable=False)
    student_name = Column(String, nullable=False)
    usage = Column(Integer)
    soft_limit = Column(Integer)
    hard_limit = Column(Integer)
    files = Column(Integer)

# Create the database tables
Base.metadata.create_all(bind=engine)

# Insert Hardcoded Data
def init_db():
    """Initialize database with hardcoded users and quota data"""
    db = SessionLocal()

    # Insert Users
    test_users = [
        UserDB(username="amy", email="amy@example.com", hashed_password=pwd_context.hash("password123")),
        UserDB(username="bob", email="bob@example.com", hashed_password=pwd_context.hash("securepass")),
    ]

    for user in test_users:
        db.add(user)

    # Insert Quota Data
    test_quotas = [
        QuotaDB(pi_name="amy", student_name="tom", usage=1, soft_limit=20, hard_limit=25, files=13),
        QuotaDB(pi_name="amy", student_name="mary", usage=12, soft_limit=20, hard_limit=25, files=1401),
        QuotaDB(pi_name="bob", student_name="alice", usage=5, soft_limit=15, hard_limit=30, files=8),
    ]

    for quota in test_quotas:
        db.add(quota)

    db.commit()
    db.close()

init_db()  # Initialize with hardcoded data

# Pydantic Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    username: str
    email: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str

# Dependency to Get Database Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db: Session, username: str):
    """Retrieve user from SQLAlchemy database"""
    return db.query(UserDB).filter(UserDB.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    """Verify user credentials"""
    user = get_user(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username")

    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")

    # Update last login timestamp
    user.last_login = datetime.now(timezone.utc).isoformat()
    db.commit()

    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Generate JWT token"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth_2_scheme), db: Session = Depends(get_db)):
    """Decode JWT token and return the current user"""
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credential_exception
        user = get_user(db, username)
        if user is None:
            raise credential_exception
    except JWTError:
        raise credential_exception

    return user

async def get_current_active_user(current_user: UserDB = Depends(get_current_user)):
    """Ensure user is active"""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# API Endpoints
@app.post("/token", response_model=Token)
# async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
#     """Authenticate user and return JWT token"""
#     user = authenticate_user(db, form_data.username, form_data.password)
    
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

#     return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate user and return JWT token"""
    user = authenticate_user(db, form_data.username, form_data.password)
    
    if user:
        logger.info(f"User {user.username} authenticated successfully at {datetime.now(timezone.utc)}")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Return the current logged-in user's info"""
    return current_user

@app.get("/debug/users/")
async def get_all_users(db: Session = Depends(get_db)):
    users = db.query(UserDB).all()
    return [{"username": user.username, "email": user.email, "hashed_password": user.hashed_password} for user in users]

@app.get("/api/v2/members/")
async def get_members(current_user: UserDB = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Retrieve students under the currently logged-in PI from the database"""
    quotas = db.query(QuotaDB).filter(QuotaDB.pi_name == current_user.username).all()

    if not quotas:
        raise HTTPException(status_code=404, detail="No students found for this PI")

    members = {
        quota.student_name: {
            "usage": quota.usage,
            "soft": quota.soft_limit,
            "hard": quota.hard_limit,
            "files": quota.files
        }
        for quota in quotas
    }
    return {"pi_name": current_user.username, "members": members}

@app.get("/api/v2/summary/")
async def get_summary(current_user: UserDB = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Retrieve summary quota usage for the currently logged-in PI"""
    quotas = db.query(QuotaDB).filter(QuotaDB.pi_name == current_user.username).all()

    if not quotas:
        raise HTTPException(status_code=404, detail="No quota records found for this PI")

    usages = [quota.usage for quota in quotas]

    return {
        "pi_name": current_user.username,
        "usage_sum": sum(usages),
        "usage_avg": sum(usages) // len(usages),
        "usage_max": max(usages)
    }
