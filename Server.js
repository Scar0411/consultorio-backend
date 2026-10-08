const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // Permitir peticiones del Frontend

const SECRET_KEY = 'tu_clave_secreta_jwt_para_el_consultorio';

// Middleware Zero Trust: Valida el token en cada petición
const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ mensaje: 'Acceso denegado. Token requerido.' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ mensaje: 'Token inválido o expirado.' });
        req.user = decoded;
        next();
    });
};

// Endpoint de Autenticación (Login)
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    
    // Aquí conectarías a una base de datos. Por ahora está hardcodeado para pruebas.
    if (username === 'medico' && password === 'seguro123') {
        const token = jwt.sign({ id: 1, rol: 'doctor' }, SECRET_KEY, { expiresIn: '1h' });
        return res.json({ token, mensaje: 'Autenticación exitosa' });
    }
    res.status(401).json({ mensaje: 'Credenciales incorrectas' });
});

// Endpoint Protegido (Dashboard del Consultorio)
app.get('/api/dashboard', verificarToken, (req, res) => {
    res.json({ 
        mensaje: 'Bienvenido al sistema médico.', 
        datos: 'Información confidencial de pacientes accesible solo con JWT.' 
    });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Backend Node.js corriendo en el puerto ${PORT}`));