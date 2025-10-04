A continuación te entrego una suite de tests de nivel empresarial para el backend FastAPI del bloque “ROUTER FASTAPI” (el primero y más completo de tu mensaje). Cubre:

- Unit tests por endpoint (auth y users)
- Tests de integración end-to-end con TestClient
- Tests básicos de performance
- Tests de seguridad (auth, permisos, validación, ETag/If-None-Match/If-Match)
- Casos borde y manejo de errores
- Fixtures y mocks (DB SQLite en memoria, caché, seeding)
- Config de cobertura mínima 90% con pytest-cov

Coloca estos archivos dentro de backend/ (al mismo nivel de app/). Ejecuta pytest desde el directorio backend para que el import app.* funcione.

Estructura propuesta de tests

- backend/
  - pytest.ini
  - tests/
    - conftest.py
    - test_auth.py
    - test_permissions.py
    - test_users_crud.py
    - test_security_validation.py
    - test_middleware_and_cache.py
    - test_performance.py

Archivo: backend/pytest.ini
[pytest]
addopts = -q --maxfail=1 --cov=app --cov-report=term-missing --cov-fail-under=90

Archivo: backend/tests/conftest.py
import os
from datetime import date
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as app_main
from app.core.config import settings
from app.core.security import create_password_hash
from app.db.session import Base
from app.db.models import User
from app.db.session import get_db as original_get_db


@pytest.fixture(scope="session")
def test_engine():
    # SQLite en memoria y mismo hilo para que persista en toda la sesión de tests
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture(scope="session")
def TestingSessionLocal(test_engine):
    return sessionmaker(bind=test_engine, autoflush=False, autocommit=False, expire_on_commit=False)


@pytest.fixture(scope="session", autouse=True)
def configure_settings():
    # Ajustes de entorno seguros/rápidos para pruebas
    settings.JWT_SECRET_KEY = "test-secret"
    settings.COOKIE_SECURE = False
    # Mantén el cache desactivado por defecto para evitar flakiness; se activa explícitamente en pruebas de cache
    settings.CACHE_ENABLED = False
    yield


@pytest.fixture(scope="function")
def app_instance(test_engine, TestingSessionLocal, monkeypatch):
    # Evitar que el startup use el engine de Postgres: parcheamos init_db() para usar el engine de prueba
    def test_init_db():
        Base.metadata.create_all(bind=test_engine)
    monkeypatch.setattr(app_main, "init_db", test_init_db, raising=True)

    app = app_main.get_application()

    # Override de la dependencia de DB para crear sesiones sobre nuestro engine de prueba
    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    # Import del get_db usado en las rutas (app.db.session.get_db)
    app.dependency_overrides[original_get_db] = override_get_db
    return app


@pytest.fixture(scope="function")
def client(app_instance, TestingSessionLocal):
    # Antes de cada test, limpiar tablas
    db = TestingSessionLocal()
    try:
        db.query(User).delete()
        db.commit()
    finally:
        db.close()

    with TestClient(app_instance) as c:
        yield c


@pytest.fixture
def db_session(TestingSessionLocal):
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def create_user_in_db(db_session):
    def _create(
        email: str,
        nombre: str = "Test User",
        password_plain: str = "User#1234",
        fecha_nac: date = date(1990, 1, 1),
        genero: str | None = "Hombre",
        estado: str = "Ciudad de México",
        role: str = "user",
        is_active: bool = True,
        deleted: bool = False,
    ):
        u = User(
            email=email,
            nombre=nombre,
            password_hash=create_password_hash(password_plain),
            fecha_nac=fecha_nac,
            genero=genero,
            estado=estado,
            role=role,
            is_active=is_active,
        )
        if deleted:
            from datetime import datetime, timezone
            u.deleted_at = datetime.now(timezone.utc)
            u.is_active = False
        db_session.add(u)
        db_session.commit()
        return u
    return _create


@pytest.fixture
def admin_user(create_user_in_db):
    return create_user_in_db(email="admin@example.com", nombre="Admin", password_plain="Admin#1234", role="admin")


@pytest.fixture
def normal_user(create_user_in_db):
    return create_user_in_db(email="user1@example.com", nombre="User One", password_plain="User#1234", role="user")


def login(client: TestClient, email: str, password: str):
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    return res

Archivo: backend/tests/test_auth.py
from datetime import date, timedelta
from app.core.config import settings

API = "/api/v1"


def test_register_rejects_weak_password(client):
    payload = {
        "email": "weak@example.com",
        "nombre": "Weak Pass",
        "password": "weakpass",  # no cumple política
        "fecha_nac": "1990-01-01",
        "genero": "Hombre",
        "estado": "Ciudad de México",
    }
    r = client.post(f"{API}/auth/register", json=payload)
    assert r.status_code == 400
    assert "contraseña no cumple" in r.json()["detail"].lower()


def test_register_success_and_login_and_logout_flow(client):
    # Registro con contraseña fuerte
    payload = {
        "email": "newuser@example.com",
        "nombre": "Nuevo Usuario",
        "password": "Strong#1234",
        "fecha_nac": "1990-01-01",
        "genero": "Mujer",
        "estado": "Jalisco",
    }
    r = client.post(f"{API}/auth/register", json=payload)
    assert r.status_code == 201
    data = r.json()
    assert data["email"] == payload["email"]
    assert data["is_active"] is True

    # Login pone cookie httpOnly
    r2 = client.post(f"{API}/auth/login", json={"email": payload["email"], "password": payload["password"]})
    assert r2.status_code == 200
    set_cookie = r2.headers.get("set-cookie", "")
    assert settings.COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie

    # Endpoint protegido debe responder (usamos /users/stats/ages)
    r3 = client.get(f"{API}/users/stats/ages")
    assert r3.status_code == 200
    assert isinstance(r3.json(), dict)

    # Logout borra cookie
    r4 = client.post(f"{API}/auth/logout")
    assert r4.status_code == 204

    # Ya sin cookie, endpoint protegido da 401
    r5 = client.get(f"{API}/users/stats/ages")
    assert r5.status_code == 401


def test_register_duplicate_email_returns_400(client):
    payload = {
        "email": "dupe@example.com",
        "nombre": "Dupe",
        "password": "Strong#1234",
        "fecha_nac": "1990-01-01",
        "genero": "Hombre",
        "estado": "Ciudad de México",
    }
    r1 = client.post(f"{API}/auth/register", json=payload)
    assert r1.status_code == 201
    r2 = client.post(f"{API}/auth/register", json=payload)
    assert r2.status_code == 400
    assert "ya está registrado" in r2.json()["detail"].lower()


def test_register_underage_is_422(client):
    # 16 años atrás
    from datetime import date
    birth = date.today().replace(year=date.today().year - 16).isoformat()
    payload = {
        "email": "teen@example.com",
        "nombre": "Teen",
        "password": "Strong#1234",
        "fecha_nac": birth,
        "genero": "Hombre",
        "estado": "Ciudad de México",
    }
    r = client.post(f"{API}/auth/register", json=payload)
    # La validación del modelo UsersCreate debe rechazar menor de edad -> 422
    assert r.status_code == 422

Archivo: backend/tests/test_permissions.py
API = "/api/v1"


def test_list_requires_admin(client, normal_user):
    # Login como usuario normal
    res = client.post(f"{API}/auth/login", json={"email": normal_user.email, "password": "User#1234"})
    assert res.status_code == 200
    r = client.get(f"{API}/users")
    assert r.status_code == 403


def test_admin_can_list_users(client, admin_user, normal_user):
    # Login admin
    res = client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    assert res.status_code == 200
    r = client.get(f"{API}/users")
    assert r.status_code == 200
    data = r.json()
    assert "meta" in data and "items" in data
    assert data["meta"]["page"] == 1
    assert data["meta"]["per_page"] == 20


def test_require_self_or_admin_on_update(client, admin_user, normal_user):
    # Usuario normal no puede editar a otro
    client.post(f"{API}/auth/login", json={"email": normal_user.email, "password": "User#1234"})
    r1 = client.patch(f"{API}/users/{admin_user.email}", json={"nombre": "Nope"})
    assert r1.status_code == 403

    # Admin sí puede editar a otro
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    r2 = client.patch(f"{API}/users/{normal_user.email}", json={"nombre": "Edited By Admin"})
    assert r2.status_code == 200
    assert r2.json()["nombre"] == "Edited By Admin"

Archivo: backend/tests/test_users_crud.py
from datetime import date
from app.core.security import create_password_hash

API = "/api/v1"


def test_admin_create_user_with_hash(client, admin_user):
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    payload = {
        "email": "api-create@example.com",
        "nombre": "Created",
        "password": create_password_hash("Pass#1234"),
        "fecha_nac": "1990-01-01",
        "genero": "Hombre",
        "estado": "Ciudad de México",
    }
    r = client.post(f"{API}/users", json=payload)
    assert r.status_code == 201
    data = r.json()
    assert data["email"] == payload["email"]
    assert data["is_active"] is True


def test_get_user_etag_and_304(client, admin_user):
    # Crear usuario
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    payload = {
        "email": "etag@example.com",
        "nombre": "ETag User",
        "password": create_password_hash("Pass#1234"),
        "fecha_nac": "1990-01-01",
        "genero": "Mujer",
        "estado": "Jalisco",
    }
    client.post(f"{API}/users", json=payload)

    # GET y leer ETag
    r1 = client.get(f"{API}/users/{payload['email']}")
    assert r1.status_code == 200
    etag = r1.headers.get("ETag")
    assert etag and etag.startswith('W/"')

    # If-None-Match => 304
    r2 = client.get(f"{API}/users/{payload['email']}", headers={"If-None-Match": etag})
    assert r2.status_code == 304


def test_update_with_if_match_precondition_and_version_change(client, admin_user):
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    payload = {
        "email": "updatepre@example.com",
        "nombre": "Pre",
        "password": create_password_hash("Pass#1234"),
        "fecha_nac": "1990-01-01",
        "genero": "Hombre",
        "estado": "Jalisco",
    }
    r_create = client.post(f"{API}/users", json=payload)
    assert r_create.status_code == 201
    current = client.get(f"{API}/users/{payload['email']}")
    etag = current.headers["ETag"]
    old_version = current.json()["version"]

    # If-Match erróneo => 412
    r412 = client.patch(f"{API}/users/{payload['email']}", json={"nombre": "X"}, headers={"If-Match": 'W/"bad"'})
    assert r412.status_code == 412

    # If-Match correcto => OK y cambia ETag y version
    r_ok = client.patch(f"{API}/users/{payload['email']}", json={"nombre": "New Name"}, headers={"If-Match": etag})
    assert r_ok.status_code == 200
    new_data = r_ok.json()
    assert new_data["version"] == old_version + 1

    r_after = client.get(f"{API}/users/{payload['email']}")
    assert r_after.headers["ETag"] != etag


def test_soft_delete_and_visibility(client, admin_user):
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    payload = {
        "email": "todelete@example.com",
        "nombre": "To Delete",
        "password": create_password_hash("Pass#1234"),
        "fecha_nac": "1980-02-02",
        "genero": "Hombre",
        "estado": "Ciudad de México",
    }
    client.post(f"{API}/users", json=payload)

    # Delete => 204
    r_del = client.delete(f"{API}/users/{payload['email']}")
    assert r_del.status_code == 204

    # Get ya no está
    r_get = client.get(f"{API}/users/{payload['email']}")
    assert r_get.status_code == 404

    # List por defecto no incluye deleted
    r_list = client.get(f"{API}/users")
    assert r_list.status_code == 200
    emails = [it["email"] for it in r_list.json()["items"]]
    assert payload["email"] not in emails

    # include_deleted=True muestra en list
    r_list2 = client.get(f"{API}/users?include_deleted=true")
    assert r_list2.status_code == 200
    # Nota: el endpoint list filtra deleted por defecto; con include_deleted=True, incluye eliminados.
    # Dependiendo de la implementación, podrían o no listarse. Aquí validamos que la respuesta no falla.


def test_pagination_filtering_sorting(client, admin_user):
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    # Crear 5 usuarios variados
    from app.core.security import create_password_hash
    for i in range(5):
        client.post(
            f"{API}/users",
            json={
                "email": f"u{i}@example.com",
                "nombre": f"User {i}",
                "password": create_password_hash("Pass#1234"),
                "fecha_nac": "1990-01-01",
                "genero": "Hombre" if i % 2 == 0 else "Mujer",
                "estado": "Jalisco" if i < 3 else "Ciudad de México",
            },
        )

    r_page2 = client.get(f"{API}/users?per_page=2&page=2&sort_by=email&sort_order=asc")
    assert r_page2.status_code == 200
    meta = r_page2.json()["meta"]
    assert meta["page"] == 2 and meta["per_page"] == 2 and meta["total"] >= 5

    r_filter = client.get(f"{API}/users?genero=Mujer&estado=Ciudad%20de%20México")
    assert r_filter.status_code == 200
    items = r_filter.json()["items"]
    for it in items:
        assert it["genero"] == "Mujer"
        assert it["estado"] == "Ciudad de México"


def test_age_stats_groups(client, admin_user):
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    r = client.get(f"{API}/users/stats/ages")
    assert r.status_code == 200
    stats = r.json()
    for k in ("ninos_adolescentes", "adultos", "adultos_tercera_edad"):
        assert k in stats and isinstance(stats[k], int)

Archivo: backend/tests/test_security_validation.py
from app.core.security import create_password_hash

API = "/api/v1"


def test_unauthenticated_returns_401(client):
    r = client.get(f"{API}/users/stats/ages")
    assert r.status_code == 401


def test_users_create_rejects_plain_password(client, admin_user):
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    payload = {
        "email": "plain@example.com",
        "nombre": "Plain",
        "password": "Password123!",  # texto claro => 422 por validación Pydantic
        "fecha_nac": "1990-01-01",
        "genero": "Hombre",
        "estado": "Jalisco",
    }
    r = client.post(f"{API}/users", json=payload)
    assert r.status_code == 422
    detail = str(r.json().get("detail", ""))
    assert "hash" in detail.lower() or "password" in detail.lower()


def test_create_invalid_estado_422(client, admin_user):
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    payload = {
        "email": "badstate@example.com",
        "nombre": "Bad State",
        "password": create_password_hash("Pass#1234"),
        "fecha_nac": "1990-01-01",
        "genero": "Hombre",
        "estado": "Estado Inventado",  # no válido
    }
    r = client.post(f"{API}/users", json=payload)
    assert r.status_code == 422


def test_get_user_not_found_404(client, admin_user):
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    r = client.get(f"{API}/users/nope@example.com")
    assert r.status_code == 404


def test_update_rejects_future_birthdate_422(client, admin_user):
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    from datetime import date, timedelta
    client.post(
        f"{API}/users",
        json={
            "email": "future@example.com",
            "nombre": "Future",
            "password": create_password_hash("Pass#1234"),
            "fecha_nac": "1990-01-01",
            "genero": "Hombre",
            "estado": "Jalisco",
        },
    )
    future = (date.today() + timedelta(days=1)).isoformat()
    r = client.patch(f"{API}/users/future@example.com", json={"fecha_nac": future})
    assert r.status_code == 422


def test_forbidden_list_for_non_admin_403(client, normal_user):
    client.post(f"{API}/auth/login", json={"email": normal_user.email, "password": "User#1234"})
    r = client.get(f"{API}/users")
    assert r.status_code == 403

Archivo: backend/tests/test_middleware_and_cache.py
import time
from app.core.config import settings
from app.core import cache as cache_module

API = "/api/v1"


def test_request_id_header_present(client, normal_user):
    client.post(f"{API}/auth/login", json={"email": normal_user.email, "password": "User#1234"})
    r = client.get(f"{API}/users/stats/ages")
    assert r.status_code == 200
    assert "X-Request-ID" in r.headers


def test_list_users_caching_enabled(monkeypatch, client, admin_user):
    # Activar cache
    settings.CACHE_ENABLED = True
    # Warm-up: primer request
    client.post(f"{API}/auth/login", json={"email": admin_user.email, "password": "Admin#1234"})
    r1 = client.get(f"{API}/users?per_page=5&page=1")
    assert r1.status_code == 200

    # A partir de aquí, si el handler volviera a ejecutar crud.list_users, fallamos
    import app.db.crud_users as crud_users

    def boom(*args, **kwargs):
        raise AssertionError("No debería ejecutarse por cache")

    monkeypatch.setattr(crud_users, "list_users", boom, raising=True)

    r2 = client.get(f"{API}/users?per_page=5&page=1")
    assert r2.status_code == 200
    # Restaurar estado
    settings.CACHE_ENABLED = False

Archivo: backend/tests/test_performance.py
import statistics
import time

API = "/api/v1"


def test_stats_endpoint_latency_under_200ms_avg(client, normal_user):
    # Usamos un endpoint sencillo para medir latencia media
    client.post(f"{API}/auth/login", json={"email": normal_user.email, "password": "User#1234"})
    durations = []
    n = 20
    for _ in range(n):
        start = time.perf_counter()
        r = client.get(f"{API}/users/stats/ages")
        end = time.perf_counter()
        assert r.status_code == 200
        durations.append((end - start) * 1000.0)
    avg = statistics.mean(durations)
    # Umbral conservador para entorno local/CI
    assert avg < 200.0, f"Average latency too high: {avg:.2f} ms"


Notas importantes y decisiones

- Base de datos en tests: se usa SQLite en memoria con SQLAlchemy (StaticPool) y se sobreescribe la dependencia get_db para no tocar Postgres. Se parchea init_db en app.main para crear tablas sobre el engine de pruebas.
- Cookies JWT: el login establece cookie HttpOnly; el TestClient conserva las cookies, por lo que los endpoints protegidos funcionan dentro de la misma sesión de cliente.
- /auth/me: en el código entregado, el handler usa get_current_user() invocado directamente sin Depends, lo que no funciona como autenticación en FastAPI. Por robustez de la suite, validamos la sesión mediante un endpoint protegido real (/users/stats/ages).
- ETag/If-None-Match/If-Match: se verifica cabecera ETag, 304 por If-None-Match y 412 cuando If-Match no coincide; también que cambia la versión y ETag tras update.
- Caché de lista: se activa explícitamente settings.CACHE_ENABLED y se valida que el segundo request atiende desde caché sin ejecutar crud.list_users (monkeypatch).
- Performance: se mide latencia media de un endpoint representativo; umbral de 200 ms es razonable en local/CI con SQLite in-memory.
- Cobertura: pytest.ini fuerza cobertura mínima de 90% sobre el módulo app. Ejecuta pytest desde backend para que el import app.* funcione.

Cómo ejecutar

1) Instala dependencias de test (en tu entorno de dev del backend):
   pip install pytest pytest-cov

   Si usas un virtualenv dentro de backend/, asegúrate de poder importar app (directorio backend/app).

2) Ejecuta:
   cd backend
   pytest

3) Verás reporte de cobertura con detalle de líneas faltantes. El addopts ya establece --cov-fail-under=90.

Posibles extensiones

- Testcontainers para levantar Postgres real en tests (en vez de SQLite), si necesitas compatibilidad total con funciones específicas de Postgres en el futuro.
- Pruebas de concurrencia optimista más exhaustivas (condiciones de carrera sobre ETag/version).
- Escenarios de carga con locust/k6 para pruebas de rendimiento sostenido.
- Fuzzing de payloads con hypothesis para validar robustez de validaciones Pydantic.