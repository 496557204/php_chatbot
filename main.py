from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
import mysql.connector
from mysql.connector import Error
from cryptography.fernet import Fernet
from fastapi.staticfiles import StaticFiles
from typing import List, Optional

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
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)


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
    id: int
    username: str
    role: str
    role_id: int


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


class Role(BaseModel):
    id: int
    name: str
    description: str


class MenuItem(BaseModel):
    id: int
    name: str
    path: str
    icon: str
    sort_order: int


class ChatSession(BaseModel):
    id: int
    title: str
    created_at: datetime


class ChatMessage(BaseModel):
    id: int
    session_id: int
    role: str
    content: str
    created_at: datetime


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[int] = None


# 认证相关函数
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT u.*, r.name as role 
        FROM users u 
        JOIN roles r ON u.role_id = r.id 
        WHERE u.username = %s
    """, (username,))
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

    # 更新最后登录时间
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user.id,))
    conn.commit()
    cursor.close()
    conn.close()

    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
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
        data={"sub": user.username, "role": user.role, "user_id": user.id},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/users/me/last-login")
async def get_last_login(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT last_login FROM users WHERE id = %s", (current_user.id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return {"last_login": result["last_login"]}


@app.get("/roles", response_model=List[Role])
async def get_roles(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, description FROM roles")
    roles = cursor.fetchall()
    cursor.close()
    conn.close()
    return roles


@app.get("/menu-items", response_model=List[MenuItem])
async def get_menu_items(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, path, icon, sort_order FROM menu_items ORDER BY sort_order")
    menus = cursor.fetchall()
    cursor.close()
    conn.close()
    return menus


@app.post("/encrypt")
async def encrypt_data(data: EncryptedData, current_user: User = Depends(get_current_user)):
    encrypted_data = cipher_suite.encrypt(data.data.encode())
    return {"encrypted_data": encrypted_data.decode()}


@app.post("/decrypt")
async def decrypt_data(data: EncryptedData, current_user: User = Depends(get_current_user)):
    try:
        decrypted_data = cipher_suite.decrypt(data.data.encode())
        return {"decrypted_data": decrypted_data.decode()}
    except:
        raise HTTPException(status_code=400, detail="解密失败")


# 权限管理路由
@app.get("/permissions")
async def get_user_permissions(username: str, current_user: User = Depends(get_current_user)):
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
async def assign_permission(username: str, permission: Permission, current_user: User = Depends(get_current_user)):
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


# 聊天功能路由
@app.post("/chat/sessions")
async def create_chat_session(title: str, current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO chat_sessions (user_id, title) VALUES (%s, %s)",
            (current_user.id, title)
        )
        session_id = cursor.lastrowid
        conn.commit()
        return {"session_id": session_id}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.get("/chat/sessions", response_model=List[ChatSession])
async def get_chat_sessions(current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, title, created_at FROM chat_sessions WHERE user_id = %s ORDER BY updated_at DESC",
        (current_user.id,)
    )
    sessions = cursor.fetchall()
    cursor.close()
    conn.close()
    return sessions


@app.post("/chat/messages")
async def send_message(request: ChatRequest, current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 创建新会话（如果不存在）
        if not request.session_id:
            cursor.execute(
                "INSERT INTO chat_sessions (user_id, title) VALUES (%s, %s)",
                (current_user.id, request.message[:50] + "...")
            )
            request.session_id = cursor.lastrowid

        # 保存用户消息
        cursor.execute(
            "INSERT INTO chat_messages (session_id, role, content) VALUES (%s, %s, %s)",
            (request.session_id, "user", request.message)
        )

        # 模拟AI回复（实际项目中应调用大模型API）
        ai_response = f"收到您的消息：{request.message}。这是一个模拟的AI回复，在实际项目中会调用真实的大模型API。"

        cursor.execute(
            "INSERT INTO chat_messages (session_id, role, content) VALUES (%s, %s, %s)",
            (request.session_id, "assistant", ai_response)
        )

        # 更新会话时间
        cursor.execute(
            "UPDATE chat_sessions SET updated_at = NOW() WHERE id = %s",
            (request.session_id,)
        )

        conn.commit()
        return {"response": ai_response, "session_id": request.session_id}
    except Error as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.get("/chat/sessions/{session_id}/messages", response_model=List[ChatMessage])
async def get_chat_messages(session_id: int, current_user: User = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 验证会话属于当前用户
    cursor.execute(
        "SELECT user_id FROM chat_sessions WHERE id = %s",
        (session_id,)
    )
    session = cursor.fetchone()
    if not session or session["user_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="无权访问此会话")

    cursor.execute(
        "SELECT id, session_id, role, content, created_at FROM chat_messages WHERE session_id = %s ORDER BY created_at",
        (session_id,)
    )
    messages = cursor.fetchall()
    cursor.close()
    conn.close()
    return messages


# 挂载静态文件
app.mount("/static", StaticFiles(directory="static", html=True), name="static")
