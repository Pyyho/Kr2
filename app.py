# app.py
from fastapi import FastAPI, HTTPException, status, Response, Request, Header, Depends, Cookie
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, List, Dict, Any
import uuid
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
import time
import re
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = FastAPI(title="Контрольная работа №2")

# Секретный ключ для подписей (в реальном проекте должен храниться в переменных окружения)
SECRET_KEY = "your-secret-key-here-change-in-production"
serializer = URLSafeTimedSerializer(SECRET_KEY)


# ==================== Задание 3.1 ====================

class UserCreate(BaseModel):
    """Pydantic модель для создания пользователя"""
    name: str = Field(..., min_length=1, max_length=50, description="Имя пользователя")
    email: EmailStr = Field(..., description="Email пользователя")
    age: Optional[int] = Field(None, ge=1, le=150, description="Возраст пользователя")
    is_subscribed: Optional[bool] = Field(False, description="Подписка на новости")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Alice",
                "email": "alice@example.com",
                "age": 30,
                "is_subscribed": True
            }
        }


@app.post("/create_user", response_model=UserCreate)
async def create_user(user: UserCreate):
    """
    Создает нового пользователя
    Возвращает данные пользователя в ответе
    """
    return user


# ==================== Задание 3.2 ====================

# Пример данных продуктов
sample_products = [
    {"product_id": 123, "name": "Smartphone", "category": "Electronics", "price": 599.99},
    {"product_id": 456, "name": "Phone Case", "category": "Accessories", "price": 19.99},
    {"product_id": 789, "name": "Iphone", "category": "Electronics", "price": 1299.99},
    {"product_id": 101, "name": "Headphones", "category": "Accessories", "price": 99.99},
    {"product_id": 202, "name": "Smartwatch", "category": "Electronics", "price": 299.99}
]


@app.get("/product/{product_id}")
async def get_product(product_id: int):
    """
    Возвращает информацию о продукте по его ID
    """
    product = next((p for p in sample_products if p["product_id"] == product_id), None)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


@app.get("/products/search")
async def search_products(
        keyword: str,
        category: Optional[str] = None,
        limit: int = 10
):
    """
    Поиск продуктов по ключевому слову и категории
    """
    results = []
    keyword_lower = keyword.lower()

    for product in sample_products:
        # Проверка по ключевому слову в названии
        if keyword_lower in product["name"].lower():
            # Фильтрация по категории, если указана
            if category and product["category"].lower() != category.lower():
                continue
            results.append(product)

    # Ограничение количества результатов
    return results[:limit]


# ==================== Задание 5.1 ====================

# Простая база данных пользователей (в реальном проекте использовать настоящую БД)
users_db = {
    "user123": {"password": "password123", "user_id": str(uuid.uuid4()), "name": "User 123",
                "email": "user123@example.com"},
    "admin": {"password": "admin123", "user_id": str(uuid.uuid4()), "name": "Admin", "email": "admin@example.com"}
}

# Хранилище сессий (в реальном проекте использовать Redis или БД)
sessions = {}


class LoginData(BaseModel):
    username: str
    password: str


@app.post("/login")
async def login(login_data: LoginData, response: Response):
    """
    Аутентификация пользователя и установка cookie сессии
    """
    user = users_db.get(login_data.username)

    if not user or user["password"] != login_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Создание сессии
    session_token = str(uuid.uuid4())
    sessions[session_token] = {
        "user_id": user["user_id"],
        "username": login_data.username,
        "created_at": datetime.now().isoformat()
    }

    # Установка cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=3600,  # 1 час
        secure=False,  # В продакшене должно быть True
        samesite="lax"
    )

    return {"message": "Login successful"}


@app.get("/user")
async def get_user(request: Request, response: Response):
    """
    Защищенный маршрут, требующий аутентификации
    """
    session_token = request.cookies.get("session_token")

    if not session_token or session_token not in sessions:
        response.status_code = 401
        return {"message": "Unauthorized"}

    session_data = sessions[session_token]
    user = users_db.get(session_data["username"])

    if not user:
        response.status_code = 401
        return {"message": "Unauthorized"}

    return {
        "user_id": user["user_id"],
        "username": session_data["username"],
        "name": user["name"],
        "email": user["email"]
    }


# ==================== Задание 5.2 ====================

class LoginDataWithSignature(BaseModel):
    username: str
    password: str


def generate_signature(data: str) -> str:
    """Генерирует подпись для данных"""
    return hmac.new(
        SECRET_KEY.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_signature(data: str, signature: str) -> bool:
    """Проверяет подпись данных"""
    expected = generate_signature(data)
    return hmac.compare_digest(expected, signature)


@app.post("/login/v2")
async def login_v2(login_data: LoginDataWithSignature, response: Response):
    """
    Аутентификация с подписанной cookie
    """
    user = users_db.get(login_data.username)

    if not user or user["password"] != login_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Генерация user_id в формате UUID
    user_id = str(uuid.uuid4())

    # Создание подписи
    signature = generate_signature(user_id)

    # Формирование токена: user_id.signature
    session_token = f"{user_id}.{signature}"

    # Сохраняем связь между user_id и username (в реальном проекте в БД)
    sessions[user_id] = {
        "username": login_data.username,
        "created_at": datetime.now().isoformat()
    }

    # Установка cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=3600,  # 1 час
        secure=False,
        samesite="lax"
    )

    return {"message": "Login successful", "user_id": user_id}


@app.get("/profile")
async def get_profile(session_token: Optional[str] = Cookie(None)):
    """
    Защищенный маршрут с проверкой подписи
    """
    if not session_token:
        raise HTTPException(status_code=401, detail="No session token")

    try:
        # Разделяем токен на части
        user_id, signature = session_token.split('.')

        # Проверяем подпись
        if not verify_signature(user_id, signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

        # Проверяем существование сессии
        if user_id not in sessions:
            raise HTTPException(status_code=401, detail="Session not found")

        user_data = sessions[user_id]

        return {
            "user_id": user_id,
            "username": user_data["username"],
            "profile": {
                "name": users_db.get(user_data["username"], {}).get("name", ""),
                "email": users_db.get(user_data["username"], {}).get("email", "")
            },
            "session_created": user_data["created_at"]
        }

    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token format")
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication failed")


# ==================== Задание 5.3 ====================

class SessionData(BaseModel):
    user_id: str
    username: str
    last_activity: float  # timestamp


# Хранилище сессий с временем активности
active_sessions = {}


@app.post("/login/v3")
async def login_v3(login_data: LoginDataWithSignature, response: Response):
    """
    Аутентификация с динамическим временем жизни сессии
    """
    user = users_db.get(login_data.username)

    if not user or user["password"] != login_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = str(uuid.uuid4())
    current_time = time.time()

    # Создаем данные сессии
    session_data = SessionData(
        user_id=user_id,
        username=login_data.username,
        last_activity=current_time
    )

    # Сохраняем сессию
    active_sessions[user_id] = session_data.dict()

    # Создаем подписанный токен с timestamp
    token_data = f"{user_id}.{int(current_time)}"
    signature = generate_signature(token_data)
    session_token = f"{token_data}.{signature}"

    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=300,  # 5 минут
        secure=False,
        samesite="lax"
    )

    return {"message": "Login successful"}


def verify_session_token(token: str) -> tuple:
    """
    Проверяет валидность токена сессии
    Возвращает (user_id, timestamp) или вызывает исключение
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format")

        user_id, timestamp_str, signature = parts
        timestamp = int(timestamp_str)
        token_data = f"{user_id}.{timestamp_str}"

        # Проверка подписи
        if not verify_signature(token_data, signature):
            raise ValueError("Invalid signature")

        # Проверка timestamp
        current_time = time.time()
        time_diff = current_time - timestamp

        if time_diff > 300:  # Больше 5 минут
            raise ValueError("Session expired")

        return user_id, timestamp

    except (ValueError, TypeError) as e:
        raise ValueError(f"Token validation failed: {str(e)}")


@app.get("/profile/v2")
async def get_profile_v2(request: Request, response: Response):
    """
    Защищенный маршрут с динамическим продлением сессии
    """
    session_token = request.cookies.get("session_token")

    if not session_token:
        raise HTTPException(status_code=401, detail="No session token")

    try:
        # Проверка токена
        user_id, token_timestamp = verify_session_token(session_token)

        # Проверка существования сессии
        if user_id not in active_sessions:
            raise HTTPException(status_code=401, detail="Session not found")

        session_data = active_sessions[user_id]
        current_time = time.time()
        time_since_last_activity = current_time - session_data["last_activity"]

        # Проверка времени последней активности
        if time_since_last_activity > 300:  # Больше 5 минут
            del active_sessions[user_id]
            response.delete_cookie("session_token")
            raise HTTPException(status_code=401, detail="Session expired")

        user_info = users_db.get(session_data["username"], {})

        # Обновление сессии при необходимости
        if 180 <= time_since_last_activity < 300:  # Между 3 и 5 минутами
            # Обновляем время последней активности
            session_data["last_activity"] = current_time
            active_sessions[user_id] = session_data

            # Создаем новый токен
            token_data = f"{user_id}.{int(current_time)}"
            signature = generate_signature(token_data)
            new_token = f"{token_data}.{signature}"

            # Устанавливаем новую cookie
            response.set_cookie(
                key="session_token",
                value=new_token,
                httponly=True,
                max_age=300,
                secure=False,
                samesite="lax"
            )

        elif time_since_last_activity < 180:
            # Не обновляем, но сессия валидна
            pass

        return {
            "user_id": user_id,
            "username": session_data["username"],
            "profile": {
                "name": user_info.get("name", ""),
                "email": user_info.get("email", "")
            },
            "last_activity": datetime.fromtimestamp(session_data["last_activity"]).isoformat(),
            "session_valid_for": max(0, 300 - time_since_last_activity)
        }

    except ValueError as e:
        raise HTTPException(status_code=401, detail="Invalid session")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


# ==================== Задание 5.4 ====================

from pydantic import BaseModel, validator
import re


class CommonHeaders(BaseModel):
    """Модель для обработки общих заголовков"""
    user_agent: str = Field(..., alias="user-agent")
    accept_language: str = Field(..., alias="accept-language")

    class Config:
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "accept-language": "en-US,en;q=0.9,es;q=0.8"
            }
        }

    @validator('accept_language')
    def validate_accept_language(cls, v):
        """Валидация формата Accept-Language"""
        if not v:
            raise ValueError('Accept-Language header is required')

        # Простая проверка формата
        pattern = r'^[a-z]{2}(-[A-Z]{2})?(,[a-z]{2}(-[A-Z]{2})?;q=\d\.\d)*$'
        if not re.match(pattern, v) and v != '*':
            # Не строгая валидация, просто предупреждение
            print(f"Warning: Accept-Language format might be invalid: {v}")

        return v


@app.get("/headers")
async def get_headers(headers: CommonHeaders = Depends()):
    """
    Возвращает заголовки User-Agent и Accept-Language
    """
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language
    }


@app.get("/info")
async def get_info(headers: CommonHeaders = Depends(), response: Response):
    """
    Возвращает информацию о заголовках с приветствием
    """
    # Добавляем серверное время в заголовки ответа
    response.headers["X-Server-Time"] = datetime.now().isoformat()

    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language
        }
    }


# ==================== Дополнительные маршруты для тестирования ====================

@app.post("/logout")
async def logout(response: Response):
    """Выход из системы"""
    response.delete_cookie("session_token")
    return {"message": "Logged out successfully"}


@app.get("/sessions/active")
async def get_active_sessions():
    """Возвращает количество активных сессий (для отладки)"""
    return {
        "active_sessions": len(active_sessions),
        "sessions": list(active_sessions.keys())
    }


@app.get("/")
async def root():
    """Корневой маршрут с информацией о доступных эндпоинтах"""
    return {
        "message": "Контрольная работа №2 по FastAPI",
        "endpoints": {
            "3.1": {
                "POST /create_user": "Создание пользователя"
            },
            "3.2": {
                "GET /product/{product_id}": "Получение продукта по ID",
                "GET /products/search": "Поиск продуктов"
            },
            "5.1": {
                "POST /login": "Базовая аутентификация",
                "GET /user": "Защищенный профиль"
            },
            "5.2": {
                "POST /login/v2": "Аутентификация с подписью",
                "GET /profile": "Профиль с проверкой подписи"
            },
            "5.3": {
                "POST /login/v3": "Аутентификация с динамической сессией",
                "GET /profile/v2": "Профиль с продлением сессии"
            },
            "5.4": {
                "GET /headers": "Получение заголовков",
                "GET /info": "Информация с заголовками"
            }
        }
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)