# database.py - Configuración de la conexión y modelo de datos
# Asume que un motor SQLAlchemy, Base y SessionLocal están configurados
# y conectados al servicio 'db' en el docker-compose.

from sqlalchemy import Column, Integer, String, Date, Enum
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    hashed_password = Column(String(100))
    full_name = Column(String(100))
    birth_date = Column(Date)
    gender = Column(Enum('Male', 'Female', name='gender_enum'))
    state = Column(String(50))

# En la implementación real, se agregarían funciones para CRUD,
# hash de contraseñas y obtención de datos agregados para el dashboard.