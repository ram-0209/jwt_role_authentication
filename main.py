from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt

app = FastAPI()

SECRET_KEY = "d0c9595ba673d934bf70e943090e6db4f40272abc5ef192db4fc5f65f1aed7ff"
ALGORITHM = "HS256"

# Simulated database of users
users_db = {
    "user1": {
        "username": "user1",
        "email": "user1@example.com",
        "roles": ["user"],
        "password": "user1",
    },
    "admin1": {
        "username": "admin1",
        "email": "admin1@example.com",
        "roles": ["admin"],
        "password": "admin1",
    },
}


class User(BaseModel):
    username: str
    email: str
    roles: list
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class TokenData(BaseModel):
    username: str | None = None


def create_jwt_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.DecodeError:
        return None


security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    username = decode_jwt_token(token).get("username")
    if username is None or username not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    user_data = users_db[username]
    return User(**user_data)


def has_role(role: str):
    def check_role(user: User = Depends(get_current_user)):
        if role in user.roles:
            return True
        return False

    return check_role


@app.post("/login")
async def login(user_info: UserLogin):
    username = user_info.username
    password = user_info.password
    if username not in users_db or users_db[username]["password"] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Login failed"
        )

    user = User(**users_db[username])
    token_data = {"username": user.username}
    token = create_jwt_token(token_data)
    return {"token": token}


@app.get("/admin")
async def admin_route(is_admin: bool = Depends(has_role("admin"))):
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized action"
        )
    return {"message": "You have access"}


@app.get("/user")
async def user_route(is_user: bool = Depends(has_role("user"))):
    if not is_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized action"
        )
    return {"message": "You have Access"}
