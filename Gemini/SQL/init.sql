-- Crea la base de datos si no existe
CREATE DATABASE IF NOT EXISTS user_db;
USE user_db;

-- Crea la tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    hashed_password VARCHAR(100) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    birth_date DATE NOT NULL,
    gender ENUM('Male', 'Female') NOT NULL,
    state VARCHAR(50) NOT NULL
);

-- Inserta datos de prueba para la simulación del dashboard y login
INSERT INTO users (username, hashed_password, full_name, birth_date, gender, state) VALUES
('admin', '$2b$12$EjX0v...hash', 'Administrador', '1985-05-15', 'Male', 'Jalisco'),
('user1', '$2b$12$EjX0v...hash', 'Ana García', '2010-01-20', 'Female', 'CDMX'),
('user2', '$2b$12$EjX0v...hash', 'Luis Pérez', '1970-11-01', 'Male', 'Nuevo León'),
('user3', '$2b$12$EjX0v...hash', 'Marta Soto', '2023-03-10', 'Female', 'Estado de México');
-- Más inserciones para simular la población total de los gráficos...