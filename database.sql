-- Base de datos del Consultorio (PostgreSQL)
-- Uso:  sudo -u postgres psql -d consultorio_db -f database.sql

CREATE TABLE IF NOT EXISTS Usuarios (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,          -- hash bcrypt, nunca texto plano
    rol VARCHAR(20) NOT NULL DEFAULT 'doctor'
);

-- Por si la tabla ya existía sin la columna rol
ALTER TABLE Usuarios ADD COLUMN IF NOT EXISTS rol VARCHAR(20) NOT NULL DEFAULT 'doctor';

CREATE TABLE IF NOT EXISTS Pacientes (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    sintomas VARCHAR(255) NOT NULL
);

INSERT INTO Pacientes (nombre, sintomas)
SELECT * FROM (VALUES
    ('María López', 'Fiebre y dolor de garganta'),
    ('Juan Pérez', 'Dolor de cabeza persistente'),
    ('Ana Gómez', 'Tos seca desde hace 3 días'),
    ('Carlos Ruiz', 'Dolor abdominal'),
    ('Laura Méndez', 'Revisión de presión arterial')
) AS datos(nombre, sintomas)
WHERE NOT EXISTS (SELECT 1 FROM Pacientes);
