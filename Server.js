const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const sql = require('mssql');
const bcrypt = require('bcryptjs'); // <-- Importamos la librería de encriptación

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = 'tu_clave_secreta_jwt_para_el_consultorio';

// Configuración de conexión a SQL Server 2022
const dbConfig = {
    user: 'sa',               // REEMPLAZA CON TU USUARIO
    password: '123456789', // REEMPLAZA CON TU CONTRASEÑA
    server: 'localhost',
    database: 'ConsultorioDB',
    options: {
        encrypt: false, 
        trustServerCertificate: true 
    }
};

sql.connect(dbConfig).then(() => {
    console.log('Conectado exitosamente a SQL Server 2022');
}).catch(err => console.error('Error crítico: No se pudo conectar a la BD', err));

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
        const request = new sql.Request();
        
        const resultCheck = await request
            .input('username', sql.VarChar, username)
            .query('SELECT * FROM Usuarios WHERE username = @username');

        if (resultCheck.recordset.length > 0) {
            return res.status(400).json({ mensaje: 'El usuario ya existe en la base de datos.' });
        }

        // --- INICIO DE ENCRIPTACIÓN ---
        const salt = await bcrypt.genSalt(10); // Generamos entropía
        const hashedPassword = await bcrypt.hash(password, salt); // Hasheamos la contraseña
        // --- FIN DE ENCRIPTACIÓN ---

        await request
            .input('password', sql.VarChar, hashedPassword) // Insertamos el hash, no el texto plano
            .query('INSERT INTO Usuarios (username, password) VALUES (@username, @password)');

        res.json({ mensaje: 'Usuario registrado exitosamente. Ya puedes iniciar sesión.' });
    } catch (err) {
        res.status(500).json({ mensaje: 'Error en el servidor', error: err.message });
    }
});

// Endpoint de Login (Valida comparando hashes)
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const request = new sql.Request();
        
        // Primero buscamos al usuario solo por su nombre
        const result = await request
            .input('username', sql.VarChar, username)
            .query('SELECT * FROM Usuarios WHERE username = @username');
        
        if (result.recordset.length > 0) {
            const usuarioDb = result.recordset[0];
            
            // --- VERIFICACIÓN CRIPTOGRÁFICA ---
            // Comparamos el texto plano recibido con el Hash de la BD
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
        const request = new sql.Request();
        const result = await request.query('SELECT * FROM Pacientes');
        res.json({ mensaje: 'Conexión a BD segura establecida.', pacientes: result.recordset });
    } catch (err) {
        res.status(500).json({ mensaje: 'Error al consultar BD', error: err.message });
    }
});

app.listen(3000, () => {
    console.log('Backend Node.js corriendo en el puerto 3000');
});