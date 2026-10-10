const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg'); // <-- Importamos PostgreSQL en lugar de mssql
const bcrypt = require('bcryptjs'); 

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = 'tu_clave_secreta_jwt_para_el_consultorio';

// Configuración de conexión a PostgreSQL
const pool = new Pool({
    user: 'postgres',         // Usuario por defecto de Postgres
    host: 'localhost',
    password: 'Admin#1234',   // Tu contraseña estandarizada
    database: 'consultorio_db', // Nombre de tu base de datos (ajusta si le pusiste otro)
    port: 5432,
});

// Prueba de conexión
pool.connect()
    .then(() => console.log('Conectado exitosamente a PostgreSQL'))
    .catch(err => console.error('Error crítico: No se pudo conectar a la BD', err));

// Middleware Zero Trust
const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ mensaje: 'Acceso denegado. Se requiere token.' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ mensaje: 'Error al obtener datos seguros. Token inválido.' });
        req.user = decoded;
        next();
    });
};

// Endpoint de Registro (Guarda la contraseña ENCRIPTADA)
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        // Postgres usa $1, $2 para los parámetros de seguridad
        const resultCheck = await pool.query('SELECT * FROM Usuarios WHERE username = $1', [username]);

        // Postgres devuelve los datos en un arreglo llamado "rows"
        if (resultCheck.rows.length > 0) {
            return res.status(400).json({ mensaje: 'El usuario ya existe en la base de datos.' });
        }

        // --- INICIO DE ENCRIPTACIÓN ---
        const salt = await bcrypt.genSalt(10); 
        const hashedPassword = await bcrypt.hash(password, salt); 
        // --- FIN DE ENCRIPTACIÓN ---

        await pool.query('INSERT INTO Usuarios (username, password) VALUES ($1, $2)', [username, hashedPassword]);

        res.json({ mensaje: 'Usuario registrado exitosamente. Ya puedes iniciar sesión.' });
    } catch (err) {
        res.status(500).json({ mensaje: 'Error en el servidor', error: err.message });
    }
});

// Endpoint de Login (Valida comparando hashes)
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM Usuarios WHERE username = $1', [username]);
        
        if (result.rows.length > 0) {
            const usuarioDb = result.rows[0];
            
            // --- VERIFICACIÓN CRIPTOGRÁFICA ---
            const contraseñaValida = await bcrypt.compare(password, usuarioDb.password);
            
            if (contraseñaValida) {
                const token = jwt.sign({ id: username, rol: 'doctor' }, SECRET_KEY, { expiresIn: '1h' });
                return res.json({ token, mensaje: 'Autenticación exitosa' });
            }
        }
        res.status(401).json({ mensaje: 'Credenciales incorrectas' });
    } catch (err) {
        res.status(500).json({ mensaje: 'Error en el servidor', error: err.message });
    }
});

// Endpoint Protegido
app.get('/api/dashboard', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM Pacientes');
        res.json({ mensaje: 'Conexión a BD segura establecida.', pacientes: result.rows });
    } catch (err) {
        res.status(500).json({ mensaje: 'Error al consultar BD', error: err.message });
    }
});

app.listen(3000, () => {
    console.log('Backend Node.js corriendo en el puerto 3000');
});