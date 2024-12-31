from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import mysql.connector

# Secret key to encode and decode JWT tokens
SECRET_KEY = "4c2235a4831caf092d08f89491ff08c7d125e9828e215350f2702c6ca5df311a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# MySQL connection
mydb = mysql.connector.connect(
    host="localhost",
    user="Board",
    password="@boardKoni1234"
)

koni = mydb.cursor()

# Create database if it doesn't exist
koni.execute("CREATE DATABASE IF NOT EXISTS current")
koni.execute("USE current")

# Create users table if it doesn't exist
koni.execute("""
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    disabled BOOLEAN,
    hashed_password VARCHAR(255) NOT NULL
)
""")

class User(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    koni.execute("SELECT * FROM users WHERE username = %s", (username,))
    result = koni.fetchone()
    if result:
        return UserInDB(
            username=result[0],
            email=result[1],
            full_name=result[2],
            disabled=result[3],
            hashed_password=result[4]
        )

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/signup", response_model=User)
def signup(user: User, password: str):
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(password)
    koni.execute(
        "INSERT INTO users (username, email, full_name, disabled, hashed_password) VALUES (%s, %s, %s, %s, %s)",
        (user.username, user.email, user.full_name, user.disabled, hashed_password)
    )
    mydb.commit()
    return user

@app.post("/signin", response_model=Token)
def sign_in(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
def read_users_me(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user