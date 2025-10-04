A continuaci�n se presentan modelos Pydantic de nivel producci�n para el recurso users (clase Users) con validaciones robustas, separaci�n clara entre modelos de entrada, salida y actualizaci�n, y consideraciones de autenticaci�n, cach� y soft-delete.

C�digo Python (Pydantic v2 recomendado)

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
    Heur�stica conservadora para impedir contrase�as en texto claro.
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

    # Hash hex/base64 sin prefijo: longitud t�pica >= 40 y muy limitada en alfabeto
    if (re.fullmatch(r"[a-fA-F0-9]{40,}", value)  # sha1/sha256/sha512 hex (no recomendado sha1)
            or re.fullmatch(r"[A-Za-z0-9+/=]{40,}", value)):  # base64 largo
        return True

    return False


class GeneroEnum(str, Enum):
    """G�nero del usuario."""
    HOMBRE = "Hombre"
    MUJER = "Mujer"


# Conjunto can�nico de estados (nombres oficiales comunes)
class EstadoMXEnum(str, Enum):
    AGUASCALIENTES = "Aguascalientes"
    BAJA_CALIFORNIA = "Baja California"
    BAJA_CALIFORNIA_SUR = "Baja California Sur"
    CAMPECHE = "Campeche"
    COAHUILA = "Coahuila"
    COLIMA = "Colima"
    CHIAPAS = "Chiapas"
    CHIHUAHUA = "Chihuahua"
    CIUDAD_DE_MEXICO = "Ciudad de M�xico"
    DURANGO = "Durango"
    GUANAJUATO = "Guanajuato"
    GUERRERO = "Guerrero"
    HIDALGO = "Hidalgo"
    JALISCO = "Jalisco"
    ESTADO_DE_MEXICO = "Estado de M�xico"
    MICHOACAN = "Michoac�n"
    MORELOS = "Morelos"
    NAYARIT = "Nayarit"
    NUEVO_LEON = "Nuevo Le�n"
    OAXACA = "Oaxaca"
    PUEBLA = "Puebla"
    QUERETARO = "Quer�taro"
    QUINTANA_ROO = "Quintana Roo"
    SAN_LUIS_POTOSI = "San Luis Potos�"
    SINALOA = "Sinaloa"
    SONORA = "Sonora"
    TABASCO = "Tabasco"
    TAMAULIPAS = "Tamaulipas"
    TLAXCALA = "Tlaxcala"
    VERACRUZ = "Veracruz"
    YUCATAN = "Yucat�n"
    ZACATECAS = "Zacatecas"


# Sin�nimos/normalizaciones aceptadas -> valor can�nico del enum
_ESTADO_SYNONYMS = {
    # claves en min�sculas, sin acentos
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
    raise ValueError("Estado no reconocido. Use un estado v�lido de la Rep�blica Mexicana.")


def _ensure_adult(birth_date: date, min_years: int = 18) -> None:
    today = date.today()
    years = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
    if years < min_years:
        raise ValueError(f"El usuario debe ser mayor o igual a {min_years} a�os.")


# --------------------------------
# Modelos Pydantic para el recurso
# --------------------------------

class UsersBase(BaseModel):
    """
    Atributos base del usuario compartidos entre modelos de entrada y salida (sin credenciales).

    Notas:
    - email se normaliza a min�sculas y no debe exceder 100 caracteres.
    - nombre se normaliza (espacios, capitalizaci�n) y permite cadena vac�a.
    - genero acepta Hombre | Mujer (insensible a may�sculas/acentos).
    - estado valida contra el cat�logo oficial de estados (con sin�nimos comunes).
    - fecha_nac debe indicar mayor�a de edad (>= 18 a�os).

    Ejemplo:
    {
      "email": "usuario@example.com",
      "nombre": "Ana Mar�a",
      "fecha_nac": "1990-05-10",
      "genero": "Mujer",
      "estado": "Quer�taro"
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
                    "nombre": "Juan P�rez",
                    "fecha_nac": "1988-02-01",
                    "genero": "Hombre",
                    "estado": "Ciudad de M�xico",
                }
            ]
        },
    )

    email: EmailStr = Field(
        ...,
        description="Email como llave del usuario. Debe ser �nico, normalizado a min�sculas.",
    )
    nombre: Optional[str] = Field(
        default=None,
        min_length=0,
        max_length=100,
        description="Nombre del usuario. Puede ser vac�o. Se normaliza espacios m�ltiples.",
    )
    fecha_nac: date = Field(
        ...,
        description="Fecha de nacimiento. Debe ser fecha en el pasado y mayor�a de edad (>=18).",
    )
    genero: Optional[GeneroEnum] = Field(
        default=None,
        description="G�nero del usuario. Valores permitidos: Hombre | Mujer.",
    )
    estado: EstadoMXEnum = Field(
        ...,
        description="Estado de residencia en la Rep�blica Mexicana.",
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
        # Mantener vac�o si as� se desea, pero limitar longitud
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
        raise ValueError("G�nero inv�lido. Use Hombre o Mujer.")

    @field_validator("estado", mode="before")
    @classmethod
    def _normalize_estado_field(cls, v: str | EstadoMXEnum) -> EstadoMXEnum:
        if isinstance(v, EstadoMXEnum):
            return v
        if not isinstance(v, str):
            raise ValueError("Estado inv�lido.")
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
    Modelo de entrada para creaci�n de usuarios.

    Seguridad:
    - password debe ser un hash robusto (NO texto claro). Se valida por patr�n y longitud.
      Ejemplos aceptables: bcrypt ($2b$...), argon2 ($argon2id$...), scrypt, pbkdf2.
    - email debe ser �nico. Puede integrarse un verificador externo de unicidad.

    Ejemplo:
    {
      "email": "nuevo@example.com",
      "nombre": "Mar�a L�pez",
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
                    "nombre": "Mar�a L�pez",
                    "password": "$argon2id$v=19$m=65536,t=3,p=4$yWJj$ZGVm",
                    "fecha_nac": "1990-06-15",
                    "genero": "Mujer",
                    "estado": "Guanajuato",
                }
            ]
        },
    )

    # Campo de contrase�a: se espera HASH, no texto claro.
    password_hash: str = Field(
        ...,
        alias="password",
        min_length=20,
        max_length=512,
        description="Hash de password. NO enviar contrase�a en texto claro.",
    )

    # Inyecci�n opcional de verificador de unicidad (p.ej., consulta a DB)
    EMAIL_UNIQUENESS_CHECKER: ClassVar[Optional[Callable[[str], bool]]] = None
    """
    Asigne una funci�n que reciba el email (str) y retorne True si est� disponible (�nico),
    False si est� ocupado. Ejemplo:
        UsersCreate.EMAIL_UNIQUENESS_CHECKER = lambda email: not repo.exists_email(email)
    """

    @field_validator("password_hash")
    @classmethod
    def _validate_password_hash(cls, v: str) -> str:
        if not _looks_like_password_hash(v):
            raise ValueError(
                "El campo 'password' debe ser un hash de contrase�a (bcrypt/argon2/scrypt/pbkdf2)."
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
                raise ValueError("El email ya est� registrado.")
        return v


class UsersUpdate(BaseModel):
    """
    Modelo de entrada para actualizaci�n parcial de usuarios.

    Notas:
    - email NO es editable (clave del recurso).
    - password, si se env�a, debe ser hash (no texto claro).
    - nombre permite cadena vac�a; se normaliza.
    - estado y genero validan igual que en creaci�n.

    Ejemplo:
    {
      "nombre": "Juan P. G�mez",
      "password": "$2b$12$2yxu...",
      "genero": "Hombre",
      "estado": "Estado de M�xico"
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
        description="Nombre del usuario. Se normaliza espacios m�ltiples.",
    )
    password_hash: Optional[str] = Field(
        default=None,
        alias="password",
        min_length=20,
        max_length=512,
        description="Hash de password. NO enviar contrase�a en texto claro.",
    )
    fecha_nac: Optional[date] = Field(
        default=None,
        description="Fecha de nacimiento. Debe mantener mayor�a de edad (>=18).",
    )
    genero: Optional[GeneroEnum] = Field(
        default=None,
        description="G�nero del usuario. Valores permitidos: Hombre | Mujer.",
    )
    estado: Optional[EstadoMXEnum] = Field(
        default=None,
        description="Estado de residencia en la Rep�blica Mexicana.",
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
                "El campo 'password' debe ser un hash de contrase�a (bcrypt/argon2/scrypt/pbkdf2)."
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
        raise ValueError("G�nero inv�lido. Use Hombre o Mujer.")

    @field_validator("estado", mode="before")
    @classmethod
    def _normalize_estado_field(cls, v: Optional[str | EstadoMXEnum]) -> Optional[EstadoMXEnum]:
        if v is None or isinstance(v, EstadoMXEnum):
            return v
        if not isinstance(v, str):
            raise ValueError("Estado inv�lido.")
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
    - Incluye metadatos de auditor�a y control de cach�: created_at, updated_at, version y etag.
    - Soporta soft-delete mediante deleted_at e is_active.

    Ejemplo:
    {
      "email": "usuario@example.com",
      "nombre": "Juan P�rez",
      "fecha_nac": "1988-02-01",
      "genero": "Hombre",
      "estado": "Ciudad de M�xico",
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
                    "nombre": "Juan P�rez",
                    "fecha_nac": "1988-02-01",
                    "genero": "Hombre",
                    "estado": "Ciudad de M�xico",
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
    genero: Optional[GeneroEnum] = Field(default=None, description="G�nero del usuario.")
    estado: EstadoMXEnum = Field(..., description="Estado de residencia.")

    # Soft-delete
    is_active: bool = Field(
        True,
        description="Indica si el usuario est� activo. Se vuelve False cuando hay soft-delete.",
    )
    deleted_at: Optional[datetime] = Field(
        default=None,
        description="Fecha de borrado l�gico (soft-delete). Nulo si no ha sido eliminado.",
    )

    # Metadatos de auditor�a y control de cach�
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Fecha de creaci�n (UTC).",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Fecha de �ltima actualizaci�n (UTC).",
    )
    version: int = Field(
        default=1,
        ge=1,
        description="N�mero de versi�n para control de concurrencia/ETag.",
    )

    @computed_field  # type: ignore[misc]
    @property
    def etag(self) -> str:
        """
        ETag d�bil generado a partir de email, versi�n y updated_at.
        �til para caching y control de concurrencia optimista (If-None-Match / If-Match).
        """
        base = f"{self.email}|{self.version}|{self.updated_at.isoformat()}"
        h = hashlib.sha256(base.encode("utf-8")).hexdigest()[:32]
        return f'W/"{h}"'

    @field_validator("deleted_at")
    @classmethod
    def _sync_is_active(cls, v: Optional[datetime], info) -> Optional[datetime]:
        # Si deleted_at tiene valor, is_active debe ser False; si es None, True.
        # Nota: no mutamos aqu� is_active por limitaciones del ciclo; se valida en postinit.
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

    # Validaci�n de coherencia soft-delete al final
    @classmethod
    def model_validate(cls, obj, *args, **kwargs):
        m = super().model_validate(obj, *args, **kwargs)
        object.__setattr__(m, "is_active", m.deleted_at is None)
        return m


Notas de integraci�n y buenas pr�cticas

- Autenticaci�n (auth=True):
  - Estos modelos no exponen la contrase�a en respuestas (UsersOut).
  - Para creaci�n/actualizaci�n se exige que el campo password sea un hash robusto. Si su flujo requiere aceptar contrase�a en texto claro, use un modelo distinto (p. ej. UsersRegister con password_plain) y hashee en la capa de servicio antes de construir UsersCreate.
  - Considere a�adir campos como email_verified_at o last_login en su capa de persistencia si aplica.

- Cache/ETag (cache=True):
  - UsersOut expone version y etag calculado. Incremente version y updated_at en cada modificaci�n para habilitar caching y control de concurrencia optimista (If-Match / If-None-Match).

- Soft-delete (soft_delete=True):
  - UsersOut incluye deleted_at e is_active. En su repositorio/servicio, al realizar un borrado l�gico, establezca deleted_at = now(UTC). is_active se ajusta autom�ticamente en el modelo de salida.

- Unicidad de email:
  - Para verificar unicidad en creaci�n, asigne una funci�n a UsersCreate.EMAIL_UNIQUENESS_CHECKER que consulte su almacenamiento (DB/cache). Ejemplo:
    UsersCreate.EMAIL_UNIQUENESS_CHECKER = lambda e: not users_repo.exists_email(e)

- Estados de la Rep�blica:
  - Se validan contra un Enum con normalizaci�n y sin�nimos comunes (p. ej. CDMX, EDOMEX, Distrito Federal). Si su dominio exige nombres exactos oficiales, limite la normalizaci�n al estricto valor del Enum.

- Mayores de edad:
  - fecha_nac valida >= 18 a�os. Ajuste la edad m�nima seg�n pol�ticas de su producto si fuera necesario.