A continuación se presentan modelos Pydantic de nivel producción para el recurso users (clase Users) con validaciones robustas, separación clara entre modelos de entrada, salida y actualización, y consideraciones de autenticación, caché y soft-delete.

Código Python (Pydantic v2 recomendado)

from __future__ import annotations

from datetime import date, datetime, timezone
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


# -----------------------------
# Utilidades y enums de dominio
# -----------------------------

def _strip_accents(value: str) -> str:
    if not isinstance(value, str):
        return value
    nfkd = unicodedata.normalize("NFKD", value)
    return "".join([c for c in nfkd if not unicodedata.combining(c)])


def _normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def _looks_like_password_hash(value: str) -> bool:
    """
    Heurística conservadora para impedir contraseñas en texto claro.
    Soporta formatos comunes de hashes: bcrypt, argon2, scrypt, pbkdf2.
    """
    if not isinstance(value, str):
        return False

    # Prefijos comunes de hashes robustos
    known_prefixes = (
        "$2a$", "$2b$", "$2y$",  # bcrypt
        "$argon2i$", "$argon2id$", "$argon2d$",  # argon2
        "$scrypt$",  # scrypt (passlib style)
        "pbkdf2:", "pbkdf2_sha256$", "pbkdf2:sha256:",  # pbkdf2 variantes
    )
    if value.startswith(known_prefixes):
        return True

    # Hash hex/base64 sin prefijo: longitud típica >= 40 y muy limitada en alfabeto
    if (re.fullmatch(r"[a-fA-F0-9]{40,}", value)  # sha1/sha256/sha512 hex (no recomendado sha1)
            or re.fullmatch(r"[A-Za-z0-9+/=]{40,}", value)):  # base64 largo
        return True

    return False


class GeneroEnum(str, Enum):
    """Género del usuario."""
    HOMBRE = "Hombre"
    MUJER = "Mujer"


# Conjunto canónico de estados (nombres oficiales comunes)
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


# Sinónimos/normalizaciones aceptadas -> valor canónico del enum
_ESTADO_SYNONYMS = {
    # claves en minúsculas, sin acentos
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

    # identidad (todos)
    **{_strip_accents(e.value).lower(): e for e in EstadoMXEnum},
}


def _normalize_estado(value: str) -> EstadoMXEnum:
    key = _strip_accents(value).lower().strip()
    if key in _ESTADO_SYNONYMS:
        return _ESTADO_SYNONYMS[key]
    # Intento de "title case" y coincidencia directa con Enum
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


# --------------------------------
# Modelos Pydantic para el recurso
# --------------------------------

class UsersBase(BaseModel):
    """
    Atributos base del usuario compartidos entre modelos de entrada y salida (sin credenciales).

    Notas:
    - email se normaliza a minúsculas y no debe exceder 100 caracteres.
    - nombre se normaliza (espacios, capitalización) y permite cadena vacía.
    - genero acepta Hombre | Mujer (insensible a mayúsculas/acentos).
    - estado valida contra el catálogo oficial de estados (con sinónimos comunes).
    - fecha_nac debe indicar mayoría de edad (>= 18 años).

    Ejemplo:
    {
      "email": "usuario@example.com",
      "nombre": "Ana María",
      "fecha_nac": "1990-05-10",
      "genero": "Mujer",
      "estado": "Querétaro"
    }
    """
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        populate_by_name=True,
        frozen=False,
        json_schema_extra={
            "examples": [
                {
                    "email": "usuario@example.com",
                    "nombre": "Juan Pérez",
                    "fecha_nac": "1988-02-01",
                    "genero": "Hombre",
                    "estado": "Ciudad de México",
                }
            ]
        },
    )

    email: EmailStr = Field(
        ...,
        description="Email como llave del usuario. Debe ser único, normalizado a minúsculas.",
    )
    nombre: Optional[str] = Field(
        default=None,
        min_length=0,
        max_length=100,
        description="Nombre del usuario. Puede ser vacío. Se normaliza espacios múltiples.",
    )
    fecha_nac: date = Field(
        ...,
        description="Fecha de nacimiento. Debe ser fecha en el pasado y mayoría de edad (>=18).",
    )
    genero: Optional[GeneroEnum] = Field(
        default=None,
        description="Género del usuario. Valores permitidos: Hombre | Mujer.",
    )
    estado: EstadoMXEnum = Field(
        ...,
        description="Estado de residencia en la República Mexicana.",
    )

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
        # Mantener vacío si así se desea, pero limitar longitud
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
    """
    Modelo de entrada para creación de usuarios.

    Seguridad:
    - password debe ser un hash robusto (NO texto claro). Se valida por patrón y longitud.
      Ejemplos aceptables: bcrypt ($2b$...), argon2 ($argon2id$...), scrypt, pbkdf2.
    - email debe ser único. Puede integrarse un verificador externo de unicidad.

    Ejemplo:
    {
      "email": "nuevo@example.com",
      "nombre": "María López",
      "password": "$2b$12$lC5bG2uFz7b7oVx3k6a7WeUuUxS7o5Qy0mE4cV5oS0z8zI1tO5fFq",
      "fecha_nac": "1992-11-30",
      "genero": "Mujer",
      "estado": "Jalisco"
    }
    """
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        populate_by_name=True,
        json_schema_extra={
            "examples": [
                {
                    "email": "nuevo@example.com",
                    "nombre": "María López",
                    "password": "$argon2id$v=19$m=65536,t=3,p=4$yWJj$ZGVm",
                    "fecha_nac": "1990-06-15",
                    "genero": "Mujer",
                    "estado": "Guanajuato",
                }
            ]
        },
    )

    # Campo de contraseña: se espera HASH, no texto claro.
    password_hash: str = Field(
        ...,
        alias="password",
        min_length=20,
        max_length=512,
        description="Hash de password. NO enviar contraseña en texto claro.",
    )

    # Inyección opcional de verificador de unicidad (p.ej., consulta a DB)
    EMAIL_UNIQUENESS_CHECKER: ClassVar[Optional[Callable[[str], bool]]] = None
    """
    Asigne una función que reciba el email (str) y retorne True si está disponible (único),
    False si está ocupado. Ejemplo:
        UsersCreate.EMAIL_UNIQUENESS_CHECKER = lambda email: not repo.exists_email(email)
    """

    @field_validator("password_hash")
    @classmethod
    def _validate_password_hash(cls, v: str) -> str:
        if not _looks_like_password_hash(v):
            raise ValueError(
                "El campo 'password' debe ser un hash de contraseña (bcrypt/argon2/scrypt/pbkdf2)."
            )
        return v

    @field_validator("email")
    @classmethod
    def _check_email_uniqueness(cls, v: EmailStr) -> EmailStr:
        checker = cls.EMAIL_UNIQUENESS_CHECKER
        if checker is not None:
            try:
                is_available = checker(str(v))
            except Exception as e:
                raise ValueError(f"Error verificando unicidad de email: {e}") from e
            if not is_available:
                raise ValueError("El email ya está registrado.")
        return v


class UsersUpdate(BaseModel):
    """
    Modelo de entrada para actualización parcial de usuarios.

    Notas:
    - email NO es editable (clave del recurso).
    - password, si se envía, debe ser hash (no texto claro).
    - nombre permite cadena vacía; se normaliza.
    - estado y genero validan igual que en creación.

    Ejemplo:
    {
      "nombre": "Juan P. Gómez",
      "password": "$2b$12$2yxu...",
      "genero": "Hombre",
      "estado": "Estado de México"
    }
    """
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        populate_by_name=True,
        json_schema_extra={
            "examples": [
                {
                    "nombre": "Ana M.",
                    "genero": "Mujer",
                    "estado": "CDMX",
                },
                {
                    "password": "pbkdf2_sha256$260000$saltsalt$base64hash=="
                },
            ]
        },
    )

    nombre: Optional[str] = Field(
        default=None,
        min_length=0,
        max_length=100,
        description="Nombre del usuario. Se normaliza espacios múltiples.",
    )
    password_hash: Optional[str] = Field(
        default=None,
        alias="password",
        min_length=20,
        max_length=512,
        description="Hash de password. NO enviar contraseña en texto claro.",
    )
    fecha_nac: Optional[date] = Field(
        default=None,
        description="Fecha de nacimiento. Debe mantener mayoría de edad (>=18).",
    )
    genero: Optional[GeneroEnum] = Field(
        default=None,
        description="Género del usuario. Valores permitidos: Hombre | Mujer.",
    )
    estado: Optional[EstadoMXEnum] = Field(
        default=None,
        description="Estado de residencia en la República Mexicana.",
    )

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
            raise ValueError(
                "El campo 'password' debe ser un hash de contraseña (bcrypt/argon2/scrypt/pbkdf2)."
            )
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
    """
    Modelo de salida (respuesta) para usuarios.

    Consideraciones:
    - No expone el password.
    - Incluye metadatos de auditoría y control de caché: created_at, updated_at, version y etag.
    - Soporta soft-delete mediante deleted_at e is_active.

    Ejemplo:
    {
      "email": "usuario@example.com",
      "nombre": "Juan Pérez",
      "fecha_nac": "1988-02-01",
      "genero": "Hombre",
      "estado": "Ciudad de México",
      "is_active": true,
      "deleted_at": null,
      "created_at": "2024-01-10T12:34:56Z",
      "updated_at": "2024-03-01T08:00:00Z",
      "version": 3,
      "etag": "W/\"a1b2c3d4...\""
    }
    """
    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        json_schema_extra={
            "examples": [
                {
                    "email": "usuario@example.com",
                    "nombre": "Juan Pérez",
                    "fecha_nac": "1988-02-01",
                    "genero": "Hombre",
                    "estado": "Ciudad de México",
                    "is_active": True,
                    "deleted_at": None,
                    "created_at": "2024-01-10T12:34:56Z",
                    "updated_at": "2024-03-01T08:00:00Z",
                    "version": 1,
                    "etag": 'W/"f5ad5b3b2a..."',
                }
            ]
        },
    )

    email: EmailStr = Field(..., description="Email llave del usuario.")
    nombre: Optional[str] = Field(default=None, description="Nombre del usuario.")
    fecha_nac: date = Field(..., description="Fecha de nacimiento.")
    genero: Optional[GeneroEnum] = Field(default=None, description="Género del usuario.")
    estado: EstadoMXEnum = Field(..., description="Estado de residencia.")

    # Soft-delete
    is_active: bool = Field(
        True,
        description="Indica si el usuario está activo. Se vuelve False cuando hay soft-delete.",
    )
    deleted_at: Optional[datetime] = Field(
        default=None,
        description="Fecha de borrado lógico (soft-delete). Nulo si no ha sido eliminado.",
    )

    # Metadatos de auditoría y control de caché
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Fecha de creación (UTC).",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Fecha de última actualización (UTC).",
    )
    version: int = Field(
        default=1,
        ge=1,
        description="Número de versión para control de concurrencia/ETag.",
    )

    @computed_field  # type: ignore[misc]
    @property
    def etag(self) -> str:
        """
        ETag débil generado a partir de email, versión y updated_at.
        Útil para caching y control de concurrencia optimista (If-None-Match / If-Match).
        """
        base = f"{self.email}|{self.version}|{self.updated_at.isoformat()}"
        h = hashlib.sha256(base.encode("utf-8")).hexdigest()[:32]
        return f'W/"{h}"'

    @field_validator("deleted_at")
    @classmethod
    def _sync_is_active(cls, v: Optional[datetime], info) -> Optional[datetime]:
        # Si deleted_at tiene valor, is_active debe ser False; si es None, True.
        # Nota: no mutamos aquí is_active por limitaciones del ciclo; se valida en postinit.
        return v

    @field_validator("updated_at", "created_at")
    @classmethod
    def _ensure_tzaware(cls, v: datetime) -> datetime:
        # Forzar zona horaria UTC para consistencia
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v

    @field_validator("nombre", mode="before")
    @classmethod
    def _normalize_nombre_out(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _normalize_whitespace(v)

    @field_validator("email")
    @classmethod
    def _email_len_out(cls, v: EmailStr) -> EmailStr:
        if not (1 <= len(str(v)) <= 100):
            raise ValueError("El email debe tener entre 1 y 100 caracteres.")
        return v

    # Validación de coherencia soft-delete al final
    @classmethod
    def model_validate(cls, obj, *args, **kwargs):
        m = super().model_validate(obj, *args, **kwargs)
        object.__setattr__(m, "is_active", m.deleted_at is None)
        return m


Notas de integración y buenas prácticas

- Autenticación (auth=True):
  - Estos modelos no exponen la contraseña en respuestas (UsersOut).
  - Para creación/actualización se exige que el campo password sea un hash robusto. Si su flujo requiere aceptar contraseña en texto claro, use un modelo distinto (p. ej. UsersRegister con password_plain) y hashee en la capa de servicio antes de construir UsersCreate.
  - Considere añadir campos como email_verified_at o last_login en su capa de persistencia si aplica.

- Cache/ETag (cache=True):
  - UsersOut expone version y etag calculado. Incremente version y updated_at en cada modificación para habilitar caching y control de concurrencia optimista (If-Match / If-None-Match).

- Soft-delete (soft_delete=True):
  - UsersOut incluye deleted_at e is_active. En su repositorio/servicio, al realizar un borrado lógico, establezca deleted_at = now(UTC). is_active se ajusta automáticamente en el modelo de salida.

- Unicidad de email:
  - Para verificar unicidad en creación, asigne una función a UsersCreate.EMAIL_UNIQUENESS_CHECKER que consulte su almacenamiento (DB/cache). Ejemplo:
    UsersCreate.EMAIL_UNIQUENESS_CHECKER = lambda e: not users_repo.exists_email(e)

- Estados de la República:
  - Se validan contra un Enum con normalización y sinónimos comunes (p. ej. CDMX, EDOMEX, Distrito Federal). Si su dominio exige nombres exactos oficiales, limite la normalización al estricto valor del Enum.

- Mayores de edad:
  - fecha_nac valida >= 18 años. Ajuste la edad mínima según políticas de su producto si fuera necesario.