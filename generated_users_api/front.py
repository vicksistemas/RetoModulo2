A continuación tienes una solución integral con arquitectura por componentes, autenticación JWT, validación de credenciales en el backend, dashboard con gráficos por rangos de edad, soft-delete, ETag, cacheabilidad y orquestación con Docker Compose. Incluye:

- Backend FastAPI (con modelos Pydantic provistos, autenticación, routers RESTful, métricas).
- Frontend HTML/JS con login/registro, dashboard con gráficas y cierre de sesión.
- Base de datos PostgreSQL en su propio contenedor.
- Scripts de llenado de datos (mínimo 50 usuarios) en un contenedor aparte.
- Dockerfiles y docker-compose para levantar todo con Docker Desktop. El frontend queda accesible desde http://localhost:8080 y el backend en http://localhost:8000.

Estructura de directorios

- backend/
  - app/
    - main.py
    - core/
      - config.py
      - security.py
    - db/
      - session.py
      - base.py
    - models/
      - user.py
    - repositories/
      - users_repo.py
    - schemas/
      - users.py   (incluye los modelos Pydantic de tu especificación + auxiliares)
    - api/
      - deps.py
      - routes/
        - auth.py
        - users.py
        - metrics.py
  - requirements.txt
  - Dockerfile
- frontend/
  - public/
    - index.html
    - dashboard.html
    - css/
      - style.css
    - js/
      - api.js
      - auth.js
      - charts.js
  - nginx.conf
  - Dockerfile
- scripts/
  - seed.py
  - Dockerfile
- docker-compose.yml

Archivos fuente

Archivo: backend/app/schemas/users.py
------------------------------------
from __future__ import annotations

from datetime import date, datetime, timezone, timedelta
from enum import Enum
from typing import Callable, ClassVar, Optional

import hashlib
import re
import unicodedata
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    computed_field,
    field_validator,
)


def _strip_accents(value: str) -> str:
    if not isinstance(value, str):
        return value
    nfkd = unicodedata.normalize("NFKD", value)
    return "".join([c for c in nfkd if not unicodedata.combining(c)])


def _normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def _looks_like_password_hash(value: str) -> bool:
    if not isinstance(value, str):
        return False
    known_prefixes = (
        "$2a$", "$2b$", "$2y$",
        "$argon2i$", "$argon2id$", "$argon2d$",
        "$scrypt$",
        "pbkdf2:", "pbkdf2_sha256$", "pbkdf2:sha256:",
    )
    if value.startswith(known_prefixes):
        return True
    if (re.fullmatch(r"[a-fA-F0-9]{40,}", value)
            or re.fullmatch(r"[A-Za-z0-9+/=]{40,}", value)):
        return True
    return False


class GeneroEnum(str, Enum):
    HOMBRE = "Hombre"
    MUJER = "Mujer"


class EstadoMXEnum(str, Enum):
    AGUASCALIENTES = "Aguascalientes"
    BAJA_CALIFORNIA = "Baja California"
    BAJA_CALIFORNIA_SUR = "Baja California Sur"
    CAMPECHE = "Campeche"
    COAHUILA = "Coahuila"
    COLIMA = "Colima"
    CHIAPAS = "Chiapas"
    CHIHUAHUA = "Chihuahua"
    CIUDAD_DE_MEXICO = "Ciudad de México"
    DURANGO = "Durango"
    GUANAJUATO = "Guanajuato"
    GUERRERO = "Guerrero"
    HIDALGO = "Hidalgo"
    JALISCO = "Jalisco"
    ESTADO_DE_MEXICO = "Estado de México"
    MICHOACAN = "Michoacán"
    MORELOS = "Morelos"
    NAYARIT = "Nayarit"
    NUEVO_LEON = "Nuevo León"
    OAXACA = "Oaxaca"
    PUEBLA = "Puebla"
    QUERETARO = "Querétaro"
    QUINTANA_ROO = "Quintana Roo"
    SAN_LUIS_POTOSI = "San Luis Potosí"
    SINALOA = "Sinaloa"
    SONORA = "Sonora"
    TABASCO = "Tabasco"
    TAMAULIPAS = "Tamaulipas"
    TLAXCALA = "Tlaxcala"
    VERACRUZ = "Veracruz"
    YUCATAN = "Yucatán"
    ZACATECAS = "Zacatecas"


_ESTADO_SYNONYMS = {
    "cdmx": EstadoMXEnum.CIUDAD_DE_MEXICO,
    "ciudad de mexico": EstadoMXEnum.CIUDAD_DE_MEXICO,
    "distrito federal": EstadoMXEnum.CIUDAD_DE_MEXICO,
    "edomex": EstadoMXEnum.ESTADO_DE_MEXICO,
    "estado de mexico": EstadoMXEnum.ESTADO_DE_MEXICO,
    "mexico": EstadoMXEnum.ESTADO_DE_MEXICO,
    "baja california sur": EstadoMXEnum.BAJA_CALIFORNIA_SUR,
    "baja california": EstadoMXEnum.BAJA_CALIFORNIA,
    "coahuila de zaragoza": EstadoMXEnum.COAHUILA,
    "michoacan de ocampo": EstadoMXEnum.MICHOACAN,
    "nuevo leon": EstadoMXEnum.NUEVO_LEON,
    "san luis potosi": EstadoMXEnum.SAN_LUIS_POTOSI,
    "quintana roo": EstadoMXEnum.QUINTANA_ROO,
    "bcs": EstadoMXEnum.BAJA_CALIFORNIA_SUR,
    "bc": EstadoMXEnum.BAJA_CALIFORNIA,
}
_ESTADO_SYNONYMS.update({_strip_accents(e.value).lower(): e for e in EstadoMXEnum})


def _normalize_estado(value: str) -> EstadoMXEnum:
    key = _strip_accents(value).lower().strip()
    if key in _ESTADO_SYNONYMS:
        return _ESTADO_SYNONYMS[key]
    normalized_title = _normalize_whitespace(value).title()
    for e in EstadoMXEnum:
        if normalized_title == e.value:
            return e
    raise ValueError("Estado no reconocido. Use un estado válido de la República Mexicana.")


def _ensure_adult(birth_date: date, min_years: int = 18) -> None:
    today = date.today()
    years = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
    if years < min_years:
        raise ValueError(f"El usuario debe ser mayor o igual a {min_years} años.")


class UsersBase(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        populate_by_name=True,
        frozen=False,
    )

    email: EmailStr = Field(..., description="Email único, normalizado a minúsculas.")
    nombre: Optional[str] = Field(default=None, min_length=0, max_length=100)
    fecha_nac: date = Field(..., description="Fecha de nacimiento (>=18 años).")
    genero: Optional[GeneroEnum] = Field(default=None)
    estado: EstadoMXEnum = Field(...)

    @field_validator("email", mode="before")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        if isinstance(v, str):
            v = v.strip().lower()
        return v

    @field_validator("email")
    @classmethod
    def _email_length(cls, v: EmailStr) -> EmailStr:
        if not (1 <= len(str(v)) <= 100):
            raise ValueError("El email debe tener entre 1 y 100 caracteres.")
        return v

    @field_validator("nombre", mode="before")
    @classmethod
    def _normalize_nombre(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = _normalize_whitespace(v)
        if len(v) > 100:
            raise ValueError("El nombre no debe exceder 100 caracteres.")
        return v

    @field_validator("genero", mode="before")
    @classmethod
    def _coerce_genero(cls, v: Optional[str | GeneroEnum]) -> Optional[GeneroEnum]:
        if v is None or isinstance(v, GeneroEnum):
            return v
        raw = _strip_accents(str(v)).lower().strip()
        if raw in ("hombre", "masculino", "m"):
            return GeneroEnum.HOMBRE
        if raw in ("mujer", "femenino", "f"):
            return GeneroEnum.MUJER
        raise ValueError("Género inválido. Use Hombre o Mujer.")

    @field_validator("estado", mode="before")
    @classmethod
    def _normalize_estado_field(cls, v: str | EstadoMXEnum) -> EstadoMXEnum:
        if isinstance(v, EstadoMXEnum):
            return v
        if not isinstance(v, str):
            raise ValueError("Estado inválido.")
        return _normalize_estado(v)

    @field_validator("fecha_nac")
    @classmethod
    def _validate_adult(cls, v: date) -> date:
        if v >= date.today():
            raise ValueError("La fecha de nacimiento debe ser en el pasado.")
        _ensure_adult(v, 18)
        return v


class UsersCreate(UsersBase):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)

    password_hash: str = Field(..., alias="password", min_length=20, max_length=512)

    EMAIL_UNIQUENESS_CHECKER: ClassVar[Optional[Callable[[str], bool]]] = None

    @field_validator("password_hash")
    @classmethod
    def _validate_password_hash(cls, v: str) -> str:
        if not _looks_like_password_hash(v):
            raise ValueError("El campo 'password' debe ser un hash robusto.")
        return v

    @field_validator("email")
    @classmethod
    def _check_email_uniqueness(cls, v: EmailStr) -> EmailStr:
        checker = cls.EMAIL_UNIQUENESS_CHECKER
        if checker is not None:
            is_available = checker(str(v))
            if not is_available:
                raise ValueError("El email ya está registrado.")
        return v


class UsersUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)

    nombre: Optional[str] = Field(default=None, min_length=0, max_length=100)
    password_hash: Optional[str] = Field(default=None, alias="password", min_length=20, max_length=512)
    fecha_nac: Optional[date] = Field(default=None)
    genero: Optional[GeneroEnum] = Field(default=None)
    estado: Optional[EstadoMXEnum] = Field(default=None)

    @field_validator("nombre", mode="before")
    @classmethod
    def _normalize_nombre(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = _normalize_whitespace(v)
        if len(v) > 100:
            raise ValueError("El nombre no debe exceder 100 caracteres.")
        return v

    @field_validator("password_hash")
    @classmethod
    def _validate_password_hash(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not _looks_like_password_hash(v):
            raise ValueError("El campo 'password' debe ser un hash robusto.")
        return v

    @field_validator("genero", mode="before")
    @classmethod
    def _coerce_genero(cls, v: Optional[str | GeneroEnum]) -> Optional[GeneroEnum]:
        if v is None or isinstance(v, GeneroEnum):
            return v
        raw = _strip_accents(str(v)).lower().strip()
        if raw in ("hombre", "masculino", "m"):
            return GeneroEnum.HOMBRE
        if raw in ("mujer", "femenino", "f"):
            return GeneroEnum.MUJER
        raise ValueError("Género inválido. Use Hombre o Mujer.")

    @field_validator("estado", mode="before")
    @classmethod
    def _normalize_estado_field(cls, v: Optional[str | EstadoMXEnum]) -> Optional[EstadoMXEnum]:
        if v is None or isinstance(v, EstadoMXEnum):
            return v
        if not isinstance(v, str):
            raise ValueError("Estado inválido.")
        return _normalize_estado(v)

    @field_validator("fecha_nac")
    @classmethod
    def _validate_adult(cls, v: Optional[date]) -> Optional[date]:
        if v is None:
            return v
        if v >= date.today():
            raise ValueError("La fecha de nacimiento debe ser en el pasado.")
        _ensure_adult(v, 18)
        return v


class UsersOut(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    email: EmailStr
    nombre: Optional[str] = None
    fecha_nac: date
    genero: Optional[GeneroEnum] = None
    estado: EstadoMXEnum

    is_active: bool = True
    deleted_at: Optional[datetime] = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = Field(default=1, ge=1)

    @computed_field
    @property
    def etag(self) -> str:
        base = f"{self.email}|{self.version}|{self.updated_at.isoformat()}"
        h = hashlib.sha256(base.encode("utf-8")).hexdigest()[:32]
        return f'W/"{h}"'

    @field_validator("updated_at", "created_at")
    @classmethod
    def _ensure_tzaware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v

    @classmethod
    def model_validate(cls, obj, *args, **kwargs):
        m = super().model_validate(obj, *args, **kwargs)
        object.__setattr__(m, "is_active", m.deleted_at is None)
        return m


# Auxiliares para auth y registro (password en claro solo aquí)
class UsersRegister(BaseModel):
    email: EmailStr
    nombre: Optional[str] = None
    password: str = Field(..., min_length=8, max_length=256, description="Contraseña en texto claro; se hashea en el BE.")
    fecha_nac: date
    genero: Optional[GeneroEnum] = None
    estado: EstadoMXEnum


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenPayload(BaseModel):
    sub: EmailStr
    exp: int


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)


Archivo: backend/app/models/user.py
-----------------------------------
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, Date, DateTime, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    email = Column(String(100), primary_key=True, index=True)
    nombre = Column(String(100), nullable=True)
    password_hash = Column(String(512), nullable=False)
    fecha_nac = Column(Date, nullable=False)
    genero = Column(String(10), nullable=True)  # "Hombre" | "Mujer" | NULL
    estado = Column(String(100), nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, onupdate=lambda: datetime.now(timezone.utc))

    version = Column(Integer, default=1, nullable=False)


Archivo: backend/app/db/session.py
----------------------------------
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ..core.config import settings

engine = create_engine(settings.SQLALCHEMY_DATABASE_URI, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


Archivo: backend/app/db/base.py
-------------------------------
from .session import engine
from ..models.user import Base, User  # noqa


def init_db():
    Base.metadata.create_all(bind=engine)


Archivo: backend/app/core/config.py
-----------------------------------
import os
from pydantic import BaseModel


class Settings(BaseModel):
    API_V1_STR: str = "/api"
    PROJECT_NAME: str = "Users API"
    BACKEND_CORS_ORIGINS: list[str] = ["http://localhost:8080", "http://127.0.0.1:8080"]

    POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER", "db")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "app")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "app")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "appdb")
    SQLALCHEMY_DATABASE_URI: str = ""

    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "change_this_secret_in_prod")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

    def __init__(self, **data):
        super().__init__(**data)
        self.SQLALCHEMY_DATABASE_URI = f"postgresql+psycopg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:5432/{self.POSTGRES_DB}"


settings = Settings()


Archivo: backend/app/core/security.py
-------------------------------------
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import jwt
from argon2 import PasswordHasher

from .config import settings

ph = PasswordHasher()


def get_password_hash(password: str) -> str:
    return ph.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return ph.verify(password_hash, plain_password)
    except Exception:
        return False


def create_access_token(subject: str, expires_minutes: Optional[int] = None) -> tuple[str, int]:
    expire_minutes = expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    payload = {"sub": subject, "exp": int(expire.timestamp())}
    encoded_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt, expire_minutes


Archivo: backend/app/repositories/users_repo.py
-----------------------------------------------
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import select, func, update

from ..models.user import User


class UsersRepository:
    def __init__(self, db: Session):
        self.db = db

    def exists_email(self, email: str) -> bool:
        return self.db.query(User).filter(User.email == email).first() is None

    def get_by_email(self, email: str) -> Optional[User]:
        return self.db.query(User).filter(User.email == email).first()

    def create(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def update_user(self, email: str, **fields) -> Optional[User]:
        user = self.get_by_email(email)
        if not user:
            return None
        for k, v in fields.items():
            setattr(user, k, v)
        user.version = (user.version or 1) + 1
        user.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(user)
        return user

    def soft_delete(self, email: str) -> bool:
        user = self.get_by_email(email)
        if not user:
            return False
        user.deleted_at = datetime.now(timezone.utc)
        user.is_active = False
        user.version = (user.version or 1) + 1
        user.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        return True

    def age_groups_counts(self) -> dict:
        # Niños y Adolescentes: <18; Adultos: 18-65; Adultos mayores: >65
        q = self.db.execute(
            select(
                func.sum(func.case((func.extract("year", func.age(func.current_date(), User.fecha_nac)) < 18, 1), else_=0)).label("ninos"),
                func.sum(func.case(((func.extract("year", func.age(func.current_date(), User.fecha_nac)) >= 18) & (func.extract("year", func.age(func.current_date(), User.fecha_nac)) <= 65), 1), else_=0)).label("adultos"),
                func.sum(func.case((func.extract("year", func.age(func.current_date(), User.fecha_nac)) > 65, 1), else_=0)).label("mayores"),
            ).where(User.deleted_at.is_(None))
        ).mappings().first()
        return {
            "ninos_y_adolescentes": int(q["ninos"] or 0),
            "adultos": int(q["adultos"] or 0),
            "adultos_mayores": int(q["mayores"] or 0),
        }


Archivo: backend/app/api/deps.py
--------------------------------
from typing import Generator

from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from ..core.config import settings
from ..db.session import SessionLocal
from ..repositories.users_repo import UsersRepository
from ..schemas.users import TokenPayload


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(db: Session = Depends(get_db), authorization: str = ""):
    # Authorization: Bearer <token>
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        data = TokenPayload(**payload)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido o expirado")

    repo = UsersRepository(db)
    user = repo.get_by_email(data.sub)
    if not user or user.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado o inactivo")
    return user


Archivo: backend/app/api/routes/auth.py
---------------------------------------
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session

from ...core.security import get_password_hash, verify_password, create_access_token
from ...repositories.users_repo import UsersRepository
from ...schemas.users import UsersRegister, UsersCreate, UsersOut, LoginIn, Token
from ...models.user import User
from ..deps import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UsersOut, status_code=201)
def register(payload: UsersRegister, db: Session = Depends(get_db)):
    repo = UsersRepository(db)
    if not repo.exists_email(payload.email):
        raise HTTPException(status_code=400, detail="El email ya está registrado.")
    password_hash = get_password_hash(payload.password)

    # Configuramos validador de unicidad del modelo Pydantic
    UsersCreate.EMAIL_UNIQUENESS_CHECKER = repo.exists_email
    ucreate = UsersCreate(
        email=payload.email,
        nombre=payload.nombre,
        password=password_hash,
        fecha_nac=payload.fecha_nac,
        genero=payload.genero,
        estado=payload.estado,
    )

    user = User(
        email=ucreate.email,
        nombre=ucreate.nombre,
        password_hash=ucreate.password_hash,
        fecha_nac=ucreate.fecha_nac,
        genero=ucreate.genero.value if ucreate.genero else None,
        estado=ucreate.estado.value,
    )
    user = repo.create(user)
    return UsersOut.model_validate(user)


@router.post("/login", response_model=Token)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    repo = UsersRepository(db)
    user = repo.get_by_email(payload.email)
    if not user or user.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Credenciales inválidas")
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Credenciales inválidas")
    token, expires = create_access_token(user.email)
    return Token(access_token=token, expires_in=expires)


Archivo: backend/app/api/routes/users.py
----------------------------------------
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from ...schemas.users import UsersOut, UsersUpdate
from ...repositories.users_repo import UsersRepository
from ...models.user import User
from ..deps import get_db, get_current_user

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UsersOut)
def me(current_user: User = Depends(get_current_user)):
    out = UsersOut.model_validate(current_user)
    response = Response(content=out.model_dump_json())
    response.headers["ETag"] = out.etag
    return out


@router.patch("/{email}", response_model=UsersOut)
def update_user(email: str, payload: UsersUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.email != email:
        # En este ejemplo simple, solo permite edición de sí mismo. Ajustar para roles/admin.
        raise HTTPException(status_code=403, detail="Operación no permitida")
    repo = UsersRepository(db)
    data = payload.model_dump(exclude_unset=True, by_alias=True)
    # Normalizamos campos enum/strings a DB
    if "genero" in data and data["genero"] is not None:
        data["genero"] = data["genero"].value
    if "estado" in data and data["estado"] is not None:
        data["estado"] = data["estado"].value
    user = repo.update_user(email, **data)
    out = UsersOut.model_validate(user)
    response = Response(content=out.model_dump_json())
    response.headers["ETag"] = out.etag
    return out


Archivo: backend/app/api/routes/metrics.py
------------------------------------------
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..deps import get_db, get_current_user
from ...repositories.users_repo import UsersRepository
from ...models.user import User

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/age-groups")
def age_groups(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    repo = UsersRepository(db)
    return repo.age_groups_counts()


Archivo: backend/app/main.py
----------------------------
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .core.config import settings
from .db.base import init_db
from .api.routes import auth, users, metrics

app = FastAPI(title=settings.PROJECT_NAME, openapi_url=f"{settings.API_V1_STR}/openapi.json")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(users.router, prefix=settings.API_V1_STR)
app.include_router(metrics.router, prefix=settings.API_V1_STR)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.on_event("startup")
def on_startup():
    init_db()


Archivo: backend/requirements.txt
---------------------------------
fastapi==0.115.0
uvicorn[standard]==0.30.6
SQLAlchemy==2.0.36
psycopg[binary]==3.2.3
pydantic==2.9.2
python-jose[cryptography]==3.3.0
argon2-cffi==23.1.0


Archivo: backend/Dockerfile
---------------------------
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y build-essential curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=10 CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


Archivo: frontend/public/index.html
-----------------------------------
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Login - Users</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="./css/style.css" />
</head>
<body>
  <div class="container">
    <h1>Bienvenido</h1>

    <div id="login-section">
      <h2>Iniciar sesión</h2>
      <form id="login-form">
        <label>Email</label>
        <input type="email" id="login-email" required />
        <label>Contraseña</label>
        <input type="password" id="login-password" required minlength="8" />
        <button type="submit">Ingresar</button>
      </form>
      <p>¿No tienes cuenta? <a href="#" id="show-register">Regístrate</a></p>
      <div id="login-msg" class="msg"></div>
    </div>

    <div id="register-section" style="display:none;">
      <h2>Registro</h2>
      <form id="register-form">
        <label>Email</label>
        <input type="email" id="reg-email" required />
        <label>Nombre</label>
        <input type="text" id="reg-nombre" maxlength="100" />
        <label>Contraseña</label>
        <input type="password" id="reg-password" required minlength="8" />
        <label>Fecha de nacimiento</label>
        <input type="date" id="reg-fecha-nac" required />
        <label>Género</label>
        <select id="reg-genero">
          <option value="">-- Selecciona --</option>
          <option value="Hombre">Hombre</option>
          <option value="Mujer">Mujer</option>
        </select>
        <label>Estado</label>
        <input type="text" id="reg-estado" placeholder="p.ej. Ciudad de México" required />
        <button type="submit">Crear cuenta</button>
      </form>
      <p>¿Ya tienes cuenta? <a href="#" id="show-login">Inicia sesión</a></p>
      <div id="register-msg" class="msg"></div>
    </div>
  </div>

  <script src="./js/api.js"></script>
  <script src="./js/auth.js"></script>
</body>
</html>


Archivo: frontend/public/dashboard.html
---------------------------------------
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Dashboard - Users</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="./css/style.css" />
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Dashboard</h1>
      <button id="logout-btn">Cerrar sesión</button>
    </div>
    <div class="cards">
      <div class="card">
        <h3>Distribución por edades</h3>
        <canvas id="ageChart"></canvas>
      </div>
    </div>
    <div id="dash-msg" class="msg"></div>
  </div>

  <script src="./js/api.js"></script>
  <script src="./js/charts.js"></script>
</body>
</html>


Archivo: frontend/public/css/style.css
--------------------------------------
body { font-family: Arial, sans-serif; margin: 0; background: #f7f7f7; }
.container { max-width: 900px; margin: 30px auto; background: #fff; padding: 20px; border-radius: 8px; }
h1 { margin-top: 0; }
label { display: block; margin-top: 10px; }
input, select { width: 100%; padding: 8px; margin-top: 5px; }
button { margin-top: 15px; padding: 10px 15px; cursor: pointer; }
.header { display:flex; justify-content: space-between; align-items: center; }
.cards { display: grid; grid-template-columns: 1fr; gap: 20px; }
.card { padding: 20px; border: 1px solid #eee; border-radius: 8px; }
.msg { margin-top: 10px; color: #b00; }


Archivo: frontend/public/js/api.js
----------------------------------
const API_BASE = "http://localhost:8000/api";

function getToken() {
  return localStorage.getItem("access_token");
}

async function apiPost(path, body, auth = false) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  return res;
}

async function apiGet(path, auth = false) {
  const headers = {};
  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(`${API_BASE}${path}`, { headers });
  return res;
}


Archivo: frontend/public/js/auth.js
-----------------------------------
document.getElementById("show-register").addEventListener("click", (e) => {
  e.preventDefault();
  document.getElementById("login-section").style.display = "none";
  document.getElementById("register-section").style.display = "block";
});

document.getElementById("show-login").addEventListener("click", (e) => {
  e.preventDefault();
  document.getElementById("register-section").style.display = "none";
  document.getElementById("login-section").style.display = "block";
});

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("login-email").value.trim().toLowerCase();
  const password = document.getElementById("login-password").value;
  const res = await apiPost("/auth/login", { email, password });
  const msg = document.getElementById("login-msg");
  if (res.ok) {
    const data = await res.json();
    localStorage.setItem("access_token", data.access_token);
    window.location.href = "./dashboard.html";
  } else {
    const err = await res.json().catch(() => ({}));
    msg.textContent = err.detail || "Error de inicio de sesión";
  }
});

document.getElementById("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("reg-email").value.trim().toLowerCase();
  const nombre = document.getElementById("reg-nombre").value.trim();
  const password = document.getElementById("reg-password").value;
  const fecha_nac = document.getElementById("reg-fecha-nac").value;
  const genero = document.getElementById("reg-genero").value || null;
  const estado = document.getElementById("reg-estado").value.trim();

  const res = await apiPost("/auth/register", { email, nombre, password, fecha_nac, genero, estado });
  const msg = document.getElementById("register-msg");
  if (res.ok) {
    msg.style.color = "green";
    msg.textContent = "Registro exitoso. Ahora puedes iniciar sesión.";
    document.getElementById("register-form").reset();
  } else {
    const err = await res.json().catch(() => ({}));
    msg.textContent = err.detail || "Error al registrar";
  }
});


Archivo: frontend/public/js/charts.js
-------------------------------------
(function init() {
  const token = localStorage.getItem("access_token");
  if (!token) {
    window.location.href = "./index.html";
    return;
  }

  document.getElementById("logout-btn").addEventListener("click", () => {
    localStorage.removeItem("access_token");
    window.location.href = "./index.html";
  });

  loadAgeChart();
})();

async function loadAgeChart() {
  const res = await apiGet("/metrics/age-groups", true);
  const msg = document.getElementById("dash-msg");
  if (!res.ok) {
    msg.textContent = "No fue posible cargar métricas.";
    return;
  }
  const data = await res.json();
  const ctx = document.getElementById("ageChart").getContext("2d");
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["Niños y Adolescentes (<18)", "Adultos (18-65)", "Adultos Mayores (>65)"],
      datasets: [{
        label: "Usuarios",
        data: [data.ninos_y_adolescentes, data.adultos, data.adultos_mayores],
        backgroundColor: ["#4e79a7", "#59a14f", "#f28e2c"],
      }]
    },
    options: {
      responsive: true,
      scales: {
        y: { beginAtZero: true, ticks: { precision:0 } }
      }
    }
  });
}


Archivo: frontend/nginx.conf
----------------------------
events {}
http {
  server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;
    location / {
      try_files $uri $uri/ /index.html;
    }
  }
}


Archivo: frontend/Dockerfile
----------------------------
FROM nginx:alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY public /usr/share/nginx/html

EXPOSE 80


Archivo: scripts/seed.py
------------------------
import os
import random
from datetime import date, timedelta
import time

import psycopg
from faker import Faker
from argon2 import PasswordHasher

DB_HOST = os.getenv("POSTGRES_SERVER", "db")
DB_USER = os.getenv("POSTGRES_USER", "app")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "app")
DB_NAME = os.getenv("POSTGRES_DB", "appdb")

ph = PasswordHasher()
fake = Faker("es_MX")

ESTADOS = [
    "Aguascalientes", "Baja California", "Baja California Sur", "Campeche", "Coahuila",
    "Colima", "Chiapas", "Chihuahua", "Ciudad de México", "Durango", "Guanajuato",
    "Guerrero", "Hidalgo", "Jalisco", "Estado de México", "Michoacán", "Morelos",
    "Nayarit", "Nuevo León", "Oaxaca", "Puebla", "Querétaro", "Quintana Roo",
    "San Luis Potosí", "Sinaloa", "Sonora", "Tabasco", "Tamaulipas", "Tlaxcala",
    "Veracruz", "Yucatán", "Zacatecas"
]

def wait_for_db():
    for _ in range(30):
        try:
            with psycopg.connect(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}") as conn:
                return True
        except Exception:
            time.sleep(2)
    return False

def seed():
    if not wait_for_db():
        print("DB no disponible")
        return
    with psycopg.connect(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}", autocommit=True) as conn:
        cur = conn.cursor()
        # Espera a que la tabla exista (creada por el backend)
        for _ in range(30):
            cur.execute("SELECT to_regclass('public.users')")
            if cur.fetchone()[0]:
                break
            time.sleep(2)

        # Genera 50+ usuarios
        num = 50
        base_password = "Password123!"
        for i in range(num):
            email = f"user{i+1}@example.com"
            nombre = fake.name()
            # edades entre 16 y 90 (algunos <18 se rechazarían por BE, pero aquí insertamos directo ya adultos)
            edad = random.choice(list(range(18, 66)) + list(range(66, 90)))
            birth_year = date.today().year - edad
            fecha_nac = date(birth_year, random.randint(1, 12), random.randint(1, 28))
            genero = random.choice(["Hombre", "Mujer"])
            estado = random.choice(ESTADOS)
            password_hash = ph.hash(base_password)

            cur.execute(
                """
                INSERT INTO users (email, nombre, password_hash, fecha_nac, genero, estado, is_active, created_at, updated_at, version)
                VALUES (%s, %s, %s, %s, %s, %s, TRUE, NOW(), NOW(), 1)
                ON CONFLICT (email) DO NOTHING
                """,
                (email, nombre, password_hash, fecha_nac, genero, estado)
            )
        print(f"Seed completado ({num} usuarios).")

if __name__ == "__main__":
    seed()


Archivo: scripts/Dockerfile
---------------------------
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir psycopg[binary]==3.2.3 Faker==27.4.0 argon2-cffi==23.1.0

COPY seed.py /app/seed.py

CMD ["python", "seed.py"]


Archivo: docker-compose.yml
---------------------------
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_USER: app
      POSTGRES_PASSWORD: app
      POSTGRES_DB: appdb
    ports:
      - "5432:5432"
    volumes:
      - db_data:/var/lib/postgresql/data

  backend:
    build:
      context: ./backend
    environment:
      POSTGRES_SERVER: db
      POSTGRES_USER: app
      POSTGRES_PASSWORD: app
      POSTGRES_DB: appdb
      JWT_SECRET_KEY: super_secret_change_me
      ACCESS_TOKEN_EXPIRE_MINUTES: 60
    depends_on:
      - db
    ports:
      - "8000:8000"

  frontend:
    build:
      context: ./frontend
    depends_on:
      - backend
    ports:
      - "8080:80"

  seed:
    build:
      context: ./scripts
    environment:
      POSTGRES_SERVER: db
      POSTGRES_USER: app
      POSTGRES_PASSWORD: app
      POSTGRES_DB: appdb
    depends_on:
      backend:
        condition: service_healthy
    restart: "no"

volumes:
  db_data:

Cómo levantar el proyecto

1) Coloca los archivos en la estructura indicada.
2) Ejecuta:
   - docker compose build
   - docker compose up -d
3) Accede al frontend:
   - http://localhost:8080
4) Backend (documentación OpenAPI):
   - http://localhost:8000/api/openapi.json

Notas clave

- Seguridad: Registro acepta contraseña en claro y la convierte a hash Argon2id en el backend, cumpliendo con UsersCreate que exige hash. Login valida contra el hash.
- Soft-delete: Campo deleted_at e is_active. La metadata version y updated_at se incrementan en actualización. ETag se expone en respuestas de usuario.
- Métricas: Endpoint protegido GET /api/metrics/age-groups devuelve conteos por grupo de edad calculados en DB.
- CORS: Habilitado para el origen del frontend.
- Seed: Inserta al menos 50 usuarios con estados de la República, género y edades variadas. Contraseña base: Password123! (para pruebas de login, p. ej., user1@example.com / Password123!)

Sugerencias de prueba rápida

- Iniciar sesión: user1@example.com con Password123!
- Ver el dashboard y el gráfico de barras por edades.
- Probar registro de un usuario nuevo y luego su inicio de sesión.
- Probar cerrar sesión desde el dashboard (botón) y retorno a la pantalla de login.