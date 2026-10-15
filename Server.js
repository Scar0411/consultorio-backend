require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Los secretos se leen del archivo .env (que NO se sube a GitHub)
const {
    HOST = '127.0.0.1',
    PORT = 3000,
    JWT_SECRET,
    DB_HOST = 'localhost',
    DB_PORT = 5432,
    DB_USER = 'postgres',
    DB_PASSWORD,
    DB_NAME = 'consultorio_db',
    REGISTRO_ABIERTO = 'false',
} = process.env;

if (!JWT_SECRET || JWT_SECRET.length < 32 || !DB_PASSWORD) {
    console.error('Falta configurar el archivo .env (JWT_SECRET de 32+ caracteres y DB_PASSWORD).');
    process.exit(1);
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

// Configuración de conexión a PostgreSQL
const pool = new Pool({
    user: DB_USER,
    host: DB_HOST,
    password: DB_PASSWORD,
    database: DB_NAME,
    port: Number(DB_PORT),
});

// Prueba de conexión
pool.query('SELECT 1')
    .then(() => console.log('Conectado exitosamente a PostgreSQL'))
    .catch(err => console.error('Error crítico: No se pudo conectar a la BD', err.message));

// Middleware Zero Trust: cada solicitud debe traer un JWT válido
const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'] || '';
    const [tipo, token] = authHeader.split(' ');
    if (tipo !== 'Bearer' || !token) {
        return res.status(401).json({ mensaje: 'Acceso denegado. Se requiere token.' });
    }
    jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }, (err, decoded) => {
        if (err) return res.status(401).json({ mensaje: 'Error al obtener datos seguros. Token inválido.' });
        req.user = decoded;
        next();
    });
};

// Validación básica de entradas
const datosValidos = (username, password) =>
    typeof username === 'string' && typeof password === 'string' &&
    username.length >= 3 && username.length <= 50 && password.length >= 8 && password.length <= 100;

// Endpoint de Registro (Guarda la contraseña ENCRIPTADA)
// Mínimo privilegio: solo funciona si REGISTRO_ABIERTO=true en el .env
app.post('/api/auth/register', async (req, res) => {
    if (REGISTRO_ABIERTO !== 'true') {
        return res.status(403).json({ mensaje: 'El registro está deshabilitado. Solicita tu alta al administrador.' });
    }
    const { username, password } = req.body || {};
    if (!datosValidos(username, password)) {
        return res.status(400).json({ mensaje: 'Usuario (3+ caracteres) y contraseña (8+ caracteres) requeridos.' });
    }
    try {
        const resultCheck = await pool.query('SELECT id FROM Usuarios WHERE username = $1', [username]);
        if (resultCheck.rows.length > 0) {
            return res.status(400).json({ mensaje: 'El usuario ya existe en la base de datos.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO Usuarios (username, password) VALUES ($1, $2)', [username, hashedPassword]);
        res.json({ mensaje: 'Usuario registrado exitosamente. Ya puedes iniciar sesión.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ mensaje: 'Error en el servidor' });
    }
});

// Endpoint de Login (Valida comparando hashes)
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ mensaje: 'Datos inválidos' });
    }
    try {
        const result = await pool.query('SELECT username, password, rol FROM Usuarios WHERE username = $1', [username]);
        if (result.rows.length > 0) {
            const usuarioDb = result.rows[0];
            const contraseñaValida = await bcrypt.compare(password, usuarioDb.password);
            if (contraseñaValida) {
                const token = jwt.sign({ id: usuarioDb.username, rol: usuarioDb.rol }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
                return res.json({ token, mensaje: 'Autenticación exitosa' });
            }
        }
        res.status(401).json({ mensaje: 'Credenciales incorrectas' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ mensaje: 'Error en el servidor' });
    }
});

// Endpoint Protegido
app.get('/api/dashboard', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre, sintomas FROM Pacientes ORDER BY id');
        res.json({ mensaje: 'Conexión a BD segura establecida.', pacientes: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ mensaje: 'Error al consultar BD' });
    }
});

app.listen(Number(PORT), HOST, () => {
    console.log(`Backend Node.js corriendo en http://${HOST}:${PORT}`);
});
