# Usa una imagen base ligera
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
#RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    build-essential \
    python3-dev \
    default-libmysqlclient-dev && \
    rm -rf /var/lib/apt/lists/*
RUN pip install fastapi
RUN pip install uvicorn
RUN pip install mysqlclient
RUN pip install sqlalchemy
RUN pip install pydantic
RUN pip install passlib[bcrypt]
COPY app/ .
# Puerto por defecto de Uvicorn
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]