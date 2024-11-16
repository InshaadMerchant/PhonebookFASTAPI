from fastapi import FastAPI, HTTPException, Depends, status, Security,Query
from pydantic import BaseModel
import re
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from passlib.context import CryptContext
from jose import JWTError, jwt

def valid_name(name):
    pattern = r"^[a-zA-Z]{2,}$|[a-zA-Z]{2,}\s([A-Z]([a-z]+|\.)\s)?[a-zA-Z]{1,}(['']?[a-zA-Z]{2,}-?[a-zA-Z]{2,}|-?[a-zA-Z]{2,})$|^[a-zA-Z]{1,}(['']?[a-zA-Z]{2,}-?[a-zA-Z]{2,}|-?[a-zA-Z]{2,}),\s[a-zA-Z]{2,}(\s[A-Z]([a-z]+|\.))?$"
    return bool(re.match(pattern, name))

def valid_phone_number(phone_number):
    pattern = r"^\d{5}([\.\s]\d{5})?$|^(\+?\d{0,2}[\s\.])?\d{2}[\s\.]\d{2}[\s\.]\d{2}[\s\.]\d{2}$|^(\+?\d{0,2}[\s\.])?\d{4}[\s\.]\d{4}$|^\d{3}[-\.]\d{4}$|^(\+?1[-\s\.]?)?(\(\d{3}\)|\d{3}[\.\s-])\d{3}[\.\s-]\d{4}$|^(\+?\d{1,2}\s)?\(?\d{1,2}\)?[\s.-]\d{3}[\s.-]\d{4}$|^\d{0,3}\s(\d{1,3}\s)?\d{3}\s\d{3}\s\d{4}$"
    return bool(re.match(pattern, phone_number))

app = FastAPI()

with open("config.json") as f:
    config = json.load(f)

SECRET_KEY = config["auth"]["secret"]
ALGORITHM = config["auth"]["algorithm"]
ACCESS_TOKEN_EXPIRE_MINUTES = int(config["auth"]["expiration"])

class Person(BaseModel):
    full_name: str
    phone_number: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
    scopes: list[str] = []

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"read": "Only allow calls to list.", "write": "Can call add and remove.", "user": "Read info about current user."},
)

class User(BaseModel):
    username: str
    full_name: str | None = None
    phone_number: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str

# Mock user database
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "phone_number": "1234567890",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    if username in fake_users_db:
        user_dict = fake_users_db[username]
        return UserInDB(**user_dict)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user

async def get_current_active_user(
    current_user: Annotated[User, Security(get_current_user, scopes=["user"])],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "scopes": form_data.scopes},
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

# Mock phonebook database
phonebook = []

@app.get("/list")
def list_phonebook(current_user: Annotated[User, Security(get_current_active_user, scopes=["read"])]):
    return phonebook

@app.post("/PhoneBook/add")
def add_person(person: Person, current_user: Annotated[User, Security(get_current_active_user, scopes=["read","write"])]):
    if not valid_name(person.full_name):
        raise HTTPException(status_code=400, detail="Invalid format. Please try entering a valid name.")
    if not valid_phone_number(person.phone_number):
        raise HTTPException(status_code=400, detail="Invalid format. Please try entering a valid phone number.")
    phonebook.append(person)
    return {"message": "Person added successfully"}

@app.put("/PhoneBook/deleteByName")
def delete_by_name(full_name: str, current_user: Annotated[User, Security(get_current_active_user, scopes=["read","write"])]):
    if not full_name:
        raise HTTPException(status_code=422, detail="full_name is required")
    if not valid_name(full_name):
        raise HTTPException(status_code=400, detail="Invalid format. Please try entering a valid name.")
    global phonebook
    original_length = len(phonebook)
    phonebook = [p for p in phonebook if p.full_name != full_name]
    if len(phonebook) == original_length:
        raise HTTPException(status_code=404, detail="Person not found")
    return {"message": "Record deleted successfully"}

@app.put("/PhoneBook/deleteByNumber")
def delete_by_number(phone_number: str, current_user: Annotated[User, Security(get_current_active_user, scopes=["read","write"])]):
    if not phone_number:
        raise HTTPException(status_code=422, detail="phone_number is required")
    if not valid_phone_number(phone_number):
        raise HTTPException(status_code=400, detail="Invalid format. Please try entering a valid phone number.")
    global phonebook
    original_length = len(phonebook)
    phonebook = [p for p in phonebook if p.phone_number != phone_number]
    if len(phonebook) == original_length:
        raise HTTPException(status_code=404, detail="Number not found")
    return {"message": "Record deleted successfully"}
