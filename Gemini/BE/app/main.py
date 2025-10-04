from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import date, timedelta
from typing import Dict
#from .database import User , SessionLocal # Importaciones simuladas

app = FastAPI()

# Permitir CORS para que el frontend (en otro puerto/contenedor) pueda conectarse
origins = [
    "http://localhost",
    "http://localhost:8080", # Puerto del frontend/nginx
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simulamos la dependencia de la sesión de base de datos
#def get_db():
#    db = SessionLocal()
#    try:
#        yield db
#    finally:
#        db.close()

# Función simplificada para simular la autenticación (registro)
@app.post("/auth/register")
def register_user(username: str, password: str):#, db: Session = Depends(get_db)):
    # Lógica de hash de contraseña omitida por brevedad
    # Se simula una inserción
    # db.add(new_user); db.commit()
    return {"message": "Usuario registrado exitosamente"}

# Función simplificada para simular la autenticación (login)
@app.post("/auth/login")
def login_user(username: str, password: str): #, db: Session = Depends(get_db)):
    # Lógica de verificación de contraseña omitida por brevedad
    if username == "admin" and password == "123":
        return {"access_token": "simulated_jwt_token", "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Credenciales incorrectas")

# Endpoint para las estadísticas (Dashboard)
@app.get("/stats/dashboard")
def get_dashboard_stats() -> Dict: #db: Session = Depends(get_db)) -> Dict:
    # --- SIMULACIÓN DE DATOS (En la vida real se harían consultas SQL AGREGADAS) ---
    today = date.today()
    
    # 1. Rangos de Edad (Simulación)
    # 0-17 años: Niños y adolescentes
    # 18-65 años: Adultos
    # >65 años: Tercera edad
    stats_age = {
        "0-17": 55,
        "18-65": 120,
        "66+": 30
    }

    # 2. Género (Simulación)
    stats_gender = {
        "Hombre": 90,
        "Mujer": 115
    }

    # 3. Distribución por Estados (Simulación)
    stats_state = {
        "CDMX": 45,
        "Jalisco": 35,
        "Nuevo León": 25,
        "Estado de México": 60,
        "Otros": 40
    }
    # --------------------------------------------------------------------------

    return {
        "age_distribution": stats_age,
        "gender_distribution": stats_gender,
        "state_distribution": stats_state
    }