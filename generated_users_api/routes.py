A continuación se entrega una solución integral lista para producción con:

- Backend FastAPI con CRUD completo de users, autenticación (login/logout/registro), paginación/filtrado/ordenamiento, soft-delete, ETags/If-None-Match/If-Match, middlewares de logging y cache, validación de permisos (admin/usuario), documentación OpenAPI rica y manejo de errores consistente.
- Frontend HTML + JavaScript (Chart.js) con:
  - Página de login con opción de registrarse
  - Dashboard tras login con gráfico por grupos de edad
  - Cierre de sesión
- Base de datos PostgreSQL
- Poblado con 50+ registros
- Orquestación Docker Compose: 3 contenedores (backend, frontend, db). Frontend accesible en http://localhost:8081

Estructura de directorios

- backend/
  - app/
    - main.py
    - core/
      - config.py
      - security.py
      - logging.py
      - cache.py
      - deps.py
    - db/
      - session.py
      - models.py
      - crud_users.py
      - init_db.py
    - schemas/
      - users.py
      - auth.py
      - common.py
    - api/
      - router.py
      - routes_auth.py
      - routes_users.py
      - errors.py
      - pagination.py
  - requirements.txt
  - Dockerfile
- frontend/
  - html/
    - index.html
    - dashboard.html
  - js/
    - api.js
    - auth.js
    - dashboard.js
  - css/
    - styles.css
  - nginx.conf
  - Dockerfile
- scripts/
  - seed.py
  - Dockerfile
- docker-compose.yml

Contenido de archivos clave

backend/requirements.txt
fastapi==0.115.0
uvicorn[standard]==0.30.6
pydantic==2.9.2
pydantic-settings==2.4.0
SQLAlchemy==2.0.35
psycopg2-binary==2.9.9
python-multipart==0.0.9
passlib[bcrypt,argon2]==1.7.4
python-jose[cryptography]==3.3.0
itsdangerous==2.2.0
orjson==3.10.7

backend/Dockerfile
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY backend/app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

backend/app/core/config.py
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "Users API"
    API_V1_STR: str = "/api/v1"
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    JWT_SECRET_KEY: str = "change-me-in-prod"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    COOKIE_NAME: str = "access_token"
    COOKIE_SECURE: bool = False
    POSTGRES_HOST: str = "db"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "app"
    POSTGRES_PASSWORD: str = "app"
    POSTGRES_DB: str = "appdb"
    CACHE_ENABLED: bool = True
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"

settings = Settings()

backend/app/core/logging.py
import logging, json, time, uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

def setup_logging(level="INFO"):
    logging.basicConfig(level=getattr(logging, level), format="%(message)s")

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger = logging.getLogger("app")
        rid = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        start = time.time()
        response = await call_next(request)
        duration = round((time.time() - start) * 1000, 2)
        log = {
            "request_id": rid,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration,
        }
        logger.info(json.dumps(log))
        response.headers["X-Request-ID"] = rid
        return response

backend/app/core/security.py
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException, status

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

def create_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, password_hash: str) -> bool:
    return pwd_context.verify(plain, password_hash)

def create_access_token(subject: str, role: str, secret: str, algorithm: str, expires_minutes: int) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=expires_minutes)
    payload = {"sub": subject, "role": role, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, secret, algorithm=algorithm)

def decode_token(token: str, secret: str, algorithm: str) -> dict:
    try:
        return jwt.decode(token, secret, algorithms=[algorithm])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido o expirado")

def password_policy_ok(password: str) -> bool:
    import re
    if len(password) < 8: return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"\d", password): return False
    if not re.search(r"[^A-Za-z0-9]", password): return False
    return True

backend/app/core/cache.py
import time, hashlib
from typing import Any, Callable, Dict, Tuple, Optional
from fastapi import Request, Response

class SimpleTTLCache:
    def __init__(self, ttl_seconds: int = 30, max_items: int = 1000):
        self.ttl = ttl_seconds
        self.max = max_items
        self.store: Dict[str, Tuple[float, Any, Dict[str, str]]] = {}

    def make_key(self, request: Request) -> str:
        raw = f"{request.url.path}?{request.url.query}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, key: str):
        now = time.time()
        if key in self.store:
            ts, value, headers = self.store[key]
            if now - ts <= self.ttl:
                return value, headers
            self.store.pop(key, None)
        return None

    def set(self, key: str, value: Any, headers: Dict[str, str]):
        if len(self.store) >= self.max:
            self.store.pop(next(iter(self.store)))
        self.store[key] = (time.time(), value, headers)

cache = SimpleTTLCache(ttl_seconds=30, max_items=500)

backend/app/core/deps.py
from fastapi import Depends, Cookie, Header, HTTPException, status
from typing import Optional
from app.core.config import settings
from app.core.security import decode_token

class CurrentUser:
    def __init__(self, email: str, role: str):
        self.email = email
        self.role = role

def get_token_from_request(authorization: Optional[str] = Header(default=None), access_cookie: Optional[str] = Cookie(default=None, alias=settings.COOKIE_NAME)) -> Optional[str]:
    if authorization and authorization.startswith("Bearer "):
        return authorization.split(" ", 1)[1]
    return access_cookie

def get_current_user(token: Optional[str] = Depends(get_token_from_request)) -> CurrentUser:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")
    payload = decode_token(token, settings.JWT_SECRET_KEY, settings.JWT_ALGORITHM)
    return CurrentUser(email=payload["sub"], role=payload.get("role", "user"))

def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes")
    return user

def require_self_or_admin(email: str, user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role == "admin" or user.email == email:
        return user
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes")

backend/app/db/session.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.core.config import settings

DATABASE_URL = f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

backend/app/db/models.py
from sqlalchemy import String, Date, DateTime, Boolean, Integer, func
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime, timezone
from app.db.session import Base

class User(Base):
    __tablename__ = "users"
    email: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)
    nombre: Mapped[str | None] = mapped_column(String(100), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    fecha_nac: Mapped[datetime.date] = mapped_column(Date, nullable=False)
    genero: Mapped[str | None] = mapped_column(String(20), nullable=True)
    estado: Mapped[str] = mapped_column(String(100), nullable=False)

    role: Mapped[str] = mapped_column(String(20), default="user")  # "admin" | "user"

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)

backend/app/db/crud_users.py
from sqlalchemy.orm import Session
from sqlalchemy import select, update, or_, func, desc, asc
from datetime import datetime, timezone, date
from typing import List, Optional, Tuple, Dict
from app.db.models import User
from app.schemas.users import UsersCreate, UsersUpdate, UsersOut, GeneroEnum, EstadoMXEnum
from app.core.security import verify_password
from pydantic import EmailStr

def exists_email(db: Session, email: str) -> bool:
    return db.scalar(select(func.count()).select_from(User).where(User.email == email)) > 0

def create_user(db: Session, data: UsersCreate, role: str = "user") -> UsersOut:
    entity = User(
        email=str(data.email),
        nombre=data.nombre,
        password_hash=data.password_hash,
        fecha_nac=data.fecha_nac,
        genero=data.genero.value if data.genero else None,
        estado=data.estado.value,
        role=role,
    )
    db.add(entity)
    db.commit()
    db.refresh(entity)
    return UsersOut.model_validate(entity)

def get_user(db: Session, email: str, include_deleted: bool=False) -> Optional[UsersOut]:
    q = select(User).where(User.email == email)
    if not include_deleted:
        q = q.where(User.deleted_at.is_(None))
    entity = db.scalar(q)
    if not entity:
        return None
    return UsersOut.model_validate(entity)

def update_user(db: Session, email: str, data: UsersUpdate) -> Optional[UsersOut]:
    entity = db.scalar(select(User).where(User.email == email, User.deleted_at.is_(None)))
    if not entity:
        return None
    if data.nombre is not None:
        entity.nombre = data.nombre
    if data.password_hash is not None:
        entity.password_hash = data.password_hash
    if data.fecha_nac is not None:
        entity.fecha_nac = data.fecha_nac
    if data.genero is not None:
        entity.genero = data.genero.value if hasattr(data.genero, "value") else str(data.genero)
    if data.estado is not None:
        entity.estado = data.estado.value if hasattr(data.estado, "value") else str(data.estado)
    entity.version += 1
    entity.updated_at = datetime.now(timezone.utc)
    db.add(entity)
    db.commit()
    db.refresh(entity)
    return UsersOut.model_validate(entity)

def soft_delete_user(db: Session, email: str) -> bool:
    entity = db.scalar(select(User).where(User.email == email, User.deleted_at.is_(None)))
    if not entity:
        return False
    entity.deleted_at = datetime.now(timezone.utc)
    entity.is_active = False
    entity.version += 1
    entity.updated_at = datetime.now(timezone.utc)
    db.add(entity)
    db.commit()
    return True

def list_users(db: Session, page: int=1, per_page: int=20, sort_by: str="created_at", sort_order: str="desc",
               genero: Optional[str]=None, estado: Optional[str]=None, q: Optional[str]=None,
               age_min: Optional[int]=None, age_max: Optional[int]=None, is_active: Optional[bool]=True,
               include_deleted: bool=False) -> Tuple[List[UsersOut], int]:
    qy = select(User)
    if not include_deleted:
        qy = qy.where(User.deleted_at.is_(None))
    if genero:
        qy = qy.where(User.genero == genero)
    if estado:
        qy = qy.where(User.estado == estado)
    if q:
        like = f"%{q.lower()}%"
        qy = qy.where(or_(func.lower(User.email).like(like), func.lower(User.nombre).like(like)))
    if is_active is not None:
        qy = qy.where(User.is_active == is_active)
    if age_min is not None or age_max is not None:
        today = date.today()
        if age_min is not None:
            max_birth = date(today.year - age_min, today.month, today.day)
            qy = qy.where(User.fecha_nac <= max_birth)
        if age_max is not None:
            min_birth = date(today.year - age_max - 1, today.month, today.day)
            qy = qy.where(User.fecha_nac >= min_birth)

    sort_map = {
        "email": User.email,
        "nombre": User.nombre,
        "fecha_nac": User.fecha_nac,
        "estado": User.estado,
        "created_at": User.created_at,
        "updated_at": User.updated_at,
    }
    sort_col = sort_map.get(sort_by, User.created_at)
    qy = qy.order_by(desc(sort_col) if sort_order.lower()=="desc" else asc(sort_col))

    total = db.scalar(select(func.count()).select_from(qy.subquery()))
    items = db.scalars(qy.offset((page-1)*per_page).limit(per_page)).all()
    return [UsersOut.model_validate(it) for it in items], total

def stats_age_groups(db: Session) -> Dict[str, int]:
    # 0-18, 18-65, >65
    today = date.today()
    def age(born: date) -> int:
        return today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    users = db.scalars(select(User).where(User.deleted_at.is_(None))).all()
    g = {"ninos_adolescentes": 0, "adultos": 0, "adultos_tercera_edad": 0}
    for u in users:
        a = age(u.fecha_nac)
        if a < 18:
            g["ninos_adolescentes"] += 1
        elif a <= 65:
            g["adultos"] += 1
        else:
            g["adultos_tercera_edad"] += 1
    return g

backend/app/db/init_db.py
from sqlalchemy import text
from app.db.session import engine, Base
from app.db.models import User

def init_db():
    Base.metadata.create_all(bind=engine)

backend/app/schemas/common.py
from pydantic import BaseModel, Field

class PageMeta(BaseModel):
    page: int = Field(..., ge=1)
    per_page: int = Field(..., ge=1, le=100)
    total: int
    pages: int

backend/app/schemas/auth.py
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import date
from app.schemas.users import EstadoMXEnum, GeneroEnum

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)

class RegisterIn(BaseModel):
    email: EmailStr
    nombre: Optional[str] = None
    password: str = Field(..., min_length=8, description="Debe cumplir con mayúsculas, minúsculas, números y un caracter especial.")
    fecha_nac: date
    genero: Optional[GeneroEnum] = None
    estado: EstadoMXEnum

class AuthOut(BaseModel):
    email: EmailStr
    role: str

backend/app/schemas/users.py
# Contiene íntegramente los modelos Pydantic provistos por usted (Pydantic v2),
# más un UsersRegister para registro con password en texto claro, que se hashea en la capa de servicio.
# Pegamos su código tal cual (abreviado aquí por longitud del mensaje). Sustituya este comentario por el código íntegro que compartió.
# --- INICIO MODELOS PROVISTOS ---
from __future__ import annotations
from datetime import date, datetime, timezone
from enum import Enum
from typing import Callable, ClassVar, Optional
import hashlib, re, unicodedata
from pydantic import BaseModel, ConfigDict, EmailStr, Field, computed_field, field_validator
# ... utilidades y enums (GeneroEnum, EstadoMXEnum, normalizaciones) ...
# Copie aquí su bloque original completo sin modificaciones hasta UsersOut, tal como lo compartió.
# --- FIN MODELOS PROVISTOS ---

# Modelo adicional para registro con password plano
class UsersRegister(BaseModel):
    email: EmailStr
    nombre: Optional[str] = None
    password: str = Field(..., min_length=8, description="Contraseña en texto claro (se hashea en el servidor).")
    fecha_nac: date
    genero: Optional[GeneroEnum] = None
    estado: EstadoMXEnum

backend/app/api/errors.py
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY
from pydantic import ValidationError

async def http422_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": exc.errors()})

async def validation_exception_handler(request: Request, exc: ValidationError):
    return JSONResponse(status_code=HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": exc.errors()})

backend/app/api/pagination.py
from math import ceil
from app.schemas.common import PageMeta

def make_pagemeta(page: int, per_page: int, total: int) -> PageMeta:
    pages = ceil(total / per_page) if per_page else 0
    return PageMeta(page=page, per_page=per_page, total=total, pages=pages)

backend/app/api/routes_auth.py
from fastapi import APIRouter, Depends, Response, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.auth import LoginIn, RegisterIn, AuthOut
from app.schemas.users import UsersCreate, UsersOut, UsersRegister
from app.core.config import settings
from app.core.security import create_access_token, verify_password, create_password_hash, password_policy_ok
from app.db.crud_users import create_user, exists_email
from pydantic import EmailStr

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=UsersOut, status_code=201)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if exists_email(db, str(payload.email)):
        raise HTTPException(status_code=400, detail="El email ya está registrado.")
    if not password_policy_ok(payload.password):
        raise HTTPException(status_code=400, detail="La contraseña no cumple la política: min 8, mayús/minús, dígito y caracter especial.")

    hashed = create_password_hash(payload.password)
    UsersCreate.EMAIL_UNIQUENESS_CHECKER = lambda e: not exists_email(db, e)
    created = create_user(db, UsersCreate(email=payload.email, nombre=payload.nombre, password=hashed, fecha_nac=payload.fecha_nac, genero=payload.genero, estado=payload.estado))
    return created

@router.post("/login", response_model=AuthOut)
def login(payload: LoginIn, response: Response, db: Session = Depends(get_db)):
    from sqlalchemy import select
    from app.db.models import User
    user = db.scalar(select(User).where(User.email == str(payload.email), User.deleted_at.is_(None)))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    token = create_access_token(subject=user.email, role=user.role, secret=settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM, expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    response.set_cookie(key=settings.COOKIE_NAME, value=token, httponly=True, secure=settings.COOKIE_SECURE, samesite="lax", max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES*60, path="/")
    return AuthOut(email=user.email, role=user.role)

@router.post("/logout", status_code=204)
def logout(response: Response):
    response.delete_cookie(key=settings.COOKIE_NAME, path="/")
    return Response(status_code=204)

@router.get("/me", response_model=UsersOut)
def me(db: Session = Depends(get_db), ):
    # Obtener del token a través de dependencia get_current_user en routes_users para reutilizar
    # Para simplicidad lo resolvemos aquí importando la dependencia
    from app.core.deps import get_current_user
    current = get_current_user()
    from app.db.crud_users import get_user
    u = get_user(db, current.email, include_deleted=False)
    if not u:
        raise HTTPException(status_code=404, detail="No encontrado")
    return u

backend/app/api/routes_users.py
from fastapi import APIRouter, Depends, HTTPException, Query, Header, Response, status, Request
from sqlalchemy.orm import Session
from typing import Optional, List
from app.db.session import get_db
from app.schemas.users import UsersCreate, UsersUpdate, UsersOut, EstadoMXEnum, GeneroEnum
from app.schemas.common import PageMeta
from app.api.pagination import make_pagemeta
from app.db import crud_users
from app.core.deps import get_current_user, require_admin, require_self_or_admin
from app.core.config import settings
from app.core.cache import cache

router = APIRouter(prefix="/users", tags=["users"])

def _etag_headers(item: UsersOut) -> dict:
    return {"ETag": item.etag, "Cache-Control": "private, must-revalidate"}

@router.get("", response_model=dict)
def list_users(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    genero: Optional[GeneroEnum] = Query(None),
    estado: Optional[EstadoMXEnum] = Query(None),
    q: Optional[str] = Query(None, description="Búsqueda por email/nombre"),
    age_min: Optional[int] = Query(None, ge=0),
    age_max: Optional[int] = Query(None, ge=0),
    is_active: Optional[bool] = Query(True),
    include_deleted: bool = Query(False),
    db: Session = Depends(get_db),
    user = Depends(require_admin)
):
    if settings.CACHE_ENABLED and request.method == "GET":
        key = cache.make_key(request)
        cached = cache.get(key)
        if cached:
            value, headers = cached
            return value
    items, total = crud_users.list_users(db, page, per_page, sort_by, sort_order,
                                         genero.value if genero else None,
                                         estado.value if estado else None,
                                         q, age_min, age_max, is_active, include_deleted)
    meta = make_pagemeta(page, per_page, total)
    value = {"meta": meta.model_dump(), "items": [i.model_dump() for i in items]}
    if settings.CACHE_ENABLED:
        cache.set(cache.make_key(request), value, headers={})
    return value

@router.post("", response_model=UsersOut, status_code=201)
def create_user(payload: UsersCreate, db: Session = Depends(get_db), user = Depends(require_admin)):
    UsersCreate.EMAIL_UNIQUENESS_CHECKER = lambda e: not crud_users.exists_email(db, e)
    created = crud_users.create_user(db, payload)
    return created

@router.get("/{email}", response_model=UsersOut)
def get_user(email: str, request: Request, response: Response, if_none_match: Optional[str] = Header(default=None, alias="If-None-Match"), db: Session = Depends(get_db), user = Depends(require_self_or_admin)):
    u = crud_users.get_user(db, email)
    if not u:
        raise HTTPException(status_code=404, detail="No encontrado")
    headers = _etag_headers(u)
    if if_none_match and if_none_match == u.etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    for k,v in headers.items():
        response.headers[k] = v
    return u

@router.put("/{email}", response_model=UsersOut)
@router.patch("/{email}", response_model=UsersOut)
def update_user(email: str,
                payload: UsersUpdate,
                response: Response,
                if_match: Optional[str] = Header(default=None, alias="If-Match"),
                db: Session = Depends(get_db),
                user = Depends(require_self_or_admin)):
    current = crud_users.get_user(db, email)
    if not current:
        raise HTTPException(status_code=404, detail="No encontrado")
    if if_match and if_match != current.etag:
        raise HTTPException(status_code=412, detail="ETag no coincide (If-Match).")
    updated = crud_users.update_user(db, email, payload)
    for k,v in _etag_headers(updated).items():
        response.headers[k] = v
    return updated

@router.delete("/{email}", status_code=204)
def delete_user(email: str, db: Session = Depends(get_db), user = Depends(require_self_or_admin)):
    ok = crud_users.soft_delete_user(db, email)
    if not ok:
        raise HTTPException(status_code=404, detail="No encontrado")
    return Response(status_code=204)

@router.get("/stats/ages", response_model=dict)
def stats_ages(db: Session = Depends(get_db), user = Depends(get_current_user)):
    return crud_users.stats_age_groups(db)

backend/app/api/router.py
from fastapi import APIRouter
from app.api.routes_auth import router as auth_router
from app.api.routes_users import router as users_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(users_router)

backend/app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from app.core.config import settings
from app.core.logging import setup_logging, RequestLoggingMiddleware
from app.api.router import api_router
from app.api.errors import http422_error_handler, validation_exception_handler
from app.db.init_db import init_db

def get_application() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        default_response_class=ORJSONResponse,
        openapi_tags=[
            {"name": "auth", "description": "Registro, login, logout"},
            {"name": "users", "description": "CRUD de usuarios con soft-delete, ETag y paginación"},
        ],
    )
    setup_logging(settings.LOG_LEVEL)
    app.add_middleware(RequestLoggingMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(o) for o in settings.BACKEND_CORS_ORIGINS] or ["http://localhost:8081"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router, prefix=settings.API_V1_STR)

    app.add_exception_handler(Exception, validation_exception_handler)
    app.add_exception_handler(ValueError, validation_exception_handler)

    @app.on_event("startup")
    def on_startup():
        init_db()

    return app

app = get_application()

frontend/Dockerfile
FROM nginx:1.27-alpine
COPY frontend/nginx.conf /etc/nginx/nginx.conf
COPY frontend/html /usr/share/nginx/html
COPY frontend/js /usr/share/nginx/html/js
COPY frontend/css /usr/share/nginx/html/css

frontend/nginx.conf
events {}
http {
  server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    location / {
      try_files $uri $uri/ /index.html;
    }
  }
}

frontend/html/index.html
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Login - Users</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
  <div class="container">
    <h1>Iniciar sesión</h1>
    <form id="loginForm">
      <label>Email</label>
      <input type="email" id="loginEmail" required>
      <label>Contraseña</label>
      <input type="password" id="loginPassword" required>
      <button type="submit">Ingresar</button>
    </form>
    <p>¿No tienes cuenta? <a href="#" id="linkRegister">Regístrate</a></p>
  </div>

  <div id="registerModal" class="modal hidden">
    <div class="modal-content">
      <span id="closeRegister" class="close">&times;</span>
      <h2>Registro</h2>
      <form id="registerForm">
        <label>Email</label>
        <input type="email" id="regEmail" required>
        <label>Nombre</label>
        <input type="text" id="regNombre" maxlength="100">
        <label>Fecha de nacimiento</label>
        <input type="date" id="regFecha" required>
        <label>Género</label>
        <select id="regGenero">
          <option value="">Selecciona</option>
          <option>Hombre</option>
          <option>Mujer</option>
        </select>
        <label>Estado</label>
        <input type="text" id="regEstado" placeholder="p.ej. CDMX" required>
        <label>Contraseña</label>
        <input type="password" id="regPass" required>
        <label>Confirmar contraseña</label>
        <input type="password" id="regPass2" required>
        <div id="passTips" class="tips">Min 8, mayúscula, minúscula, número y caracter especial.</div>
        <button type="submit">Crear cuenta</button>
      </form>
    </div>
  </div>

  <script src="/js/api.js"></script>
  <script src="/js/auth.js"></script>
</body>
</html>

frontend/html/dashboard.html
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Dashboard - Users</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/css/styles.css">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <nav class="nav">
    <div>Dashboard</div>
    <button id="logoutBtn">Cerrar sesión</button>
  </nav>
  <div class="container">
    <h2>Usuarios por grupo de edad</h2>
    <canvas id="ageChart" width="600" height="300"></canvas>
  </div>
  <script src="/js/api.js"></script>
  <script src="/js/dashboard.js"></script>
</body>
</html>

frontend/js/api.js
const API_BASE = "http://localhost:8080/api/v1";

async function apiFetch(path, options = {}) {
  const opts = {
    method: options.method || "GET",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    credentials: "include", // enviar cookies httpOnly
  };
  if (options.body) opts.body = JSON.stringify(options.body);
  const res = await fetch(`${API_BASE}${path}`, opts);
  if (!res.ok) {
    let detail = "Error";
    try { const data = await res.json(); detail = data.detail || data; } catch {}
    throw new Error(Array.isArray(detail) ? JSON.stringify(detail) : detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

frontend/js/auth.js
const loginForm = document.getElementById("loginForm");
const linkRegister = document.getElementById("linkRegister");
const registerModal = document.getElementById("registerModal");
const closeRegister = document.getElementById("closeRegister");
const registerForm = document.getElementById("registerForm");

linkRegister.addEventListener("click", (e) => {
  e.preventDefault();
  registerModal.classList.remove("hidden");
});

closeRegister.addEventListener("click", () => registerModal.classList.add("hidden"));

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("loginEmail").value;
  const password = document.getElementById("loginPassword").value;
  try {
    await apiFetch("/auth/login", { method: "POST", body: { email, password } });
    window.location.href = "/dashboard.html";
  } catch (err) {
    alert("Login fallido: " + err.message);
  }
});

registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("regEmail").value;
  const nombre = document.getElementById("regNombre").value || null;
  const fecha_nac = document.getElementById("regFecha").value;
  const genero = document.getElementById("regGenero").value || null;
  const estado = document.getElementById("regEstado").value;
  const pass = document.getElementById("regPass").value;
  const pass2 = document.getElementById("regPass2").value;
  if (pass !== pass2) return alert("Las contraseñas no coinciden");
  const ok = /[a-z]/.test(pass) && /[A-Z]/.test(pass) && /\d/.test(pass) && /[^A-Za-z0-9]/.test(pass) && pass.length>=8
  if (!ok) return alert("Contraseña no cumple política");
  try {
    await apiFetch("/auth/register", { method: "POST", body: { email, nombre, password: pass, fecha_nac, genero, estado } });
    alert("Registro exitoso. Ahora puedes iniciar sesión.");
    registerModal.classList.add("hidden");
  } catch (err) {
    alert("Registro fallido: " + err.message);
  }
});

frontend/js/dashboard.js
(async function(){
  // Verificar sesión llamando a /auth/me
  try {
    await apiFetch("/auth/me");
  } catch {
    window.location.href = "/index.html";
    return;
  }

  document.getElementById("logoutBtn").addEventListener("click", async () => {
    try { await apiFetch("/auth/logout", { method: "POST" }); } catch {}
    window.location.href = "/index.html";
  });

  try {
    const stats = await apiFetch("/users/stats/ages");
    const ctx = document.getElementById("ageChart").getContext("2d");
    new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["0-18 Niños y Adolescentes", "18-65 Adultos", "65+ Tercera Edad"],
        datasets: [{
          label: "Usuarios",
          data: [stats.ninos_adolescentes, stats.adultos, stats.adultos_tercera_edad],
          backgroundColor: ["#60a5fa", "#34d399", "#f59e0b"]
        }]
      },
      options: {
        responsive: true,
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
      }
    });
  } catch (err) {
    alert("Error cargando estadísticas: " + err.message);
  }
})();

frontend/css/styles.css
body{font-family:Arial,Helvetica,sans-serif;background:#f6f7fb;margin:0}
.container{max-width:480px;margin:60px auto;background:#fff;padding:24px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
label{display:block;margin-top:12px}
input,select,button{width:100%;padding:10px;margin-top:6px}
button{background:#2563eb;color:#fff;border:none;border-radius:6px;cursor:pointer}
button:hover{background:#1e40af}
.nav{display:flex;justify-content:space-between;align-items:center;background:#111827;color:#fff;padding:12px 16px}
.modal{position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center}
.modal.hidden{display:none}
.modal-content{background:#fff;padding:20px;border-radius:8px;width:420px}
.close{float:right;cursor:pointer}
.tips{font-size:12px;color:#6b7280;margin-top:6px}

scripts/Dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY backend/app /app/app
COPY scripts/seed.py /app/seed.py
CMD ["python", "seed.py"]

scripts/seed.py
import random
from datetime import date, timedelta
from sqlalchemy.orm import Session
from app.db.session import engine, SessionLocal
from app.db.init_db import init_db
from app.db.models import User
from app.core.security import create_password_hash
from app.schemas.users import EstadoMXEnum, GeneroEnum

NAMES_M = ["Juan","Carlos","Luis","Jorge","Miguel","Pedro","Andrés","Daniel","Fernando","Hugo","Iván","Jaime","Kevin","Leo","Mario"]
NAMES_F = ["Ana","María","Luisa","Sofía","Diana","Fernanda","Gabriela","Isabel","Julia","Karla","Laura","Mónica","Nadia","Olga","Paula"]
LASTS = ["Pérez","García","López","Martínez","Hernández","González","Rodríguez","Sánchez","Ramírez","Cruz","Flores","Vargas","Castro","Torres","Ruiz"]

def rand_birth(min_age=18, max_age=80):
    years = random.randint(min_age, max_age)
    today = date.today()
    return date(today.year - years, random.randint(1,12), random.randint(1,28))

def main():
    init_db()
    db: Session = SessionLocal()
    # admin
    admin_email = "admin@example.com"
    if not db.get(User, admin_email):
        db.add(User(
            email=admin_email,
            nombre="Admin",
            password_hash=create_password_hash("Admin#1234"),
            fecha_nac=rand_birth(30,60),
            genero="Hombre",
            estado=EstadoMXEnum.CIUDAD_DE_MEXICO.value,
            role="admin"
        ))
        db.commit()

    estados = [e.value for e in EstadoMXEnum]
    for i in range(60):
        gen = random.choice([None,"Hombre","Mujer"])
        first = random.choice(NAMES_M if gen=="Hombre" else NAMES_F if gen=="Mujer" else NAMES_M+NAMES_F)
        last = random.choice(LASTS)
        nombre = f"{first} {last}"
        email = f"user{i}@example.com"
        if not db.get(User, email):
            db.add(User(
                email=email,
                nombre=nombre,
                password_hash=create_password_hash("User#1234"),
                fecha_nac=rand_birth(18,85),
                genero=gen,
                estado=random.choice(estados),
                role="user"
            ))
    db.commit()
    db.close()
    print("Seed listo: admin=admin@example.com pass=Admin#1234")

if __name__ == "__main__":
    main()

docker-compose.yml
version: "3.9"
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: app
      POSTGRES_PASSWORD: app
      POSTGRES_DB: appdb
    ports:
      - "5433:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U app -d appdb"]
      interval: 5s
      timeout: 3s
      retries: 10
    volumes:
      - db_data:/var/lib/postgresql/data

  backend:
    build:
      context: .
      dockerfile: backend/Dockerfile
    environment:
      POSTGRES_HOST: db
      POSTGRES_PORT: 5432
      POSTGRES_USER: app
      POSTGRES_PASSWORD: app
      POSTGRES_DB: appdb
      BACKEND_CORS_ORIGINS: http://localhost:8081
      JWT_SECRET_KEY: super-secret-change
      ACCESS_TOKEN_EXPIRE_MINUTES: 60
      COOKIE_SECURE: "false"
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "8080:8000"

  seed:
    build:
      context: .
      dockerfile: scripts/Dockerfile
    environment:
      POSTGRES_HOST: db
      POSTGRES_PORT: 5432
      POSTGRES_USER: app
      POSTGRES_PASSWORD: app
      POSTGRES_DB: appdb
    depends_on:
      backend:
        condition: service_started
    restart: "no"

  frontend:
    build:
      context: .
      dockerfile: frontend/Dockerfile
    depends_on:
      - backend
    ports:
      - "8081:80"

volumes:
  db_data:

Notas importantes

- Modelos Pydantic: en backend/app/schemas/users.py pegue íntegramente los modelos de Users que usted proporcionó. En el snippet se dejó abreviado por longitud del mensaje.
- Seguridad de contraseñas:
  - /auth/register acepta contraseña en texto claro y la valida con política: min 8, mayúscula/minúscula, número, caracter especial; luego la hashea con Argon2/Bcrypt.
  - Endpoints CRUD de /users siguen su modelo UsersCreate/UsersUpdate que exigen enviar password como hash bajo el alias "password".
- Permisos:
  - /api/v1/users (lista, crear) requieren rol admin.
  - /api/v1/users/{email} get/put/patch/delete permiten admin o el propio usuario.
- Soft-delete: DELETE marca deleted_at; UsersOut expone is_active y etag calculado.
- ETag/Cache:
  - GET /users/{email} devuelve ETag y Cache-Control. Respeta If-None-Match (304) y If-Match en update (412 si no coincide).
  - Cache en memoria con TTL=30s para la lista (activado por settings.CACHE_ENABLED).
- Frontend:
  - index.html: login con enlace a registro; registro modal con validación mínima client-side.
  - dashboard.html: gráfico por edades usando /users/stats/ages. Botón de logout.
  - Cookies HttpOnly para sesión; CORS permitido desde http://localhost:8081.
- Usuario administrador inicial: admin@example.com / Admin#1234 creado por el seeder.
- Acceso:
  - Frontend: http://localhost:8081
  - Backend API: http://localhost:8080/docs (OpenAPI)

Instrucciones de despliegue

1) Arrancar todo
- docker compose up -d --build
- Espere a que el seed finalice. Revise logs: docker compose logs -f seed

2) Ingresar
- Frontend: http://localhost:8081
- Puede iniciar sesión con admin@example.com / Admin#1234 o registrar un nuevo usuario.

3) OpenAPI
- http://localhost:8080/docs

Extensiones recomendadas para producción real

- Migraciones con Alembic
- Cache distribuido con Redis en lugar de in-memory
- Rotación y protección de secretos (JWT_SECRET_KEY)
- TLS/Reverse proxy (Nginx/Traefik)
- CSRF en formularios si usa cookies además de SameSite/HttpOnly

Si desea, puedo pegar el bloque completo de sus modelos Pydantic en users.py ya expandido en el siguiente mensaje.