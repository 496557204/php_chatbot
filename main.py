from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
import mysql.connector
from mysql.connector import Error
from starlette.staticfiles import StaticFiles

# from cryptography.fernet import Fernet

# 从环境变量获取数据库配置和密钥
DB_HOST = os.getenv("MYSQL_HOST")
DB_PORT = os.getenv("MYSQL_PORT")
DB_NAME = os.getenv("MYSQL_DATABASE_NAME")
DB_USER = os.getenv("MYSQL_USERNAME")
DB_PASSWORD = os.getenv("MYSQL_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# 密码哈希和验证
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 加密密钥
# ENCRYPTION_KEY = Fernet.generate_key()
# cipher_suite = Fernet(ENCRYPTION_KEY)


# 数据库连接函数
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            port=int(DB_PORT),
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        return connection
    except Error as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据库连接错误: {str(e)}"
        )


# 用户模型
class User(BaseModel):
    username: str
    role: str


class UserInDB(User):
    password_hash: str
    salt: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str = None


class Permission(BaseModel):
    resource: str
    action: str


class EncryptedData(BaseModel):
    data: str


# 认证相关函数
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        return UserInDB(**user)
    return None


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    # to_encode = data.copy()
    # if expires_delta:
    #     expire = datetime.utcnow() + expires_delta
    # else:
    #     expire = datetime.utcnow() + timedelta(minutes=15)
    # to_encode.update({"exp": expire})
    # encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return ""


# 路由
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends()):
    return current_user


# @app.post("/encrypt")
# async def encrypt_data(data: EncryptedData, current_user: User = Depends()):
#     encrypted_data = cipher_suite.encrypt(data.data.encode())
#     return {"encrypted_data": encrypted_data.decode()}


# @app.post("/decrypt")
# async def decrypt_data(data: EncryptedData, current_user: User = Depends()):
#     try:
#         decrypted_data = cipher_suite.decrypt(data.data.encode())
#         return {"decrypted_data": decrypted_data.decode()}
#     except:
#         raise HTTPException(status_code=400, detail="解密失败")


# 权限管理路由
@app.get("/permissions")
async def get_user_permissions(username: str, current_user: User = Depends()):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="权限不足")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.resource, p.action 
        FROM permissions p 
        JOIN users u ON p.user_id = u.id 
        WHERE u.username = %s
    """, (username,))
    permissions = cursor.fetchall()
    cursor.close()
    conn.close()

    return permissions


@app.post("/permissions")
async def assign_permission(username: str, permission: Permission, current_user: User = Depends()):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="权限不足")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 获取用户ID
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user_id = cursor.fetchone()[0]

        # 分配权限
        cursor.execute("""
            INSERT INTO permissions (user_id, resource, action) 
            VALUES (%s, %s, %s)
        """, (user_id, permission.resource, permission.action))

        conn.commit()
        return {"message": "权限分配成功"}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()


# 挂载静态文件
app.mount("/static", StaticFiles(directory="static", html=True), name="static")
