const express = require('express');
const cookie = require('cookie-parser');
const csrfLib = require('csrf');
const env = require('dotenv');
const crypto = require('crypto');
const bcryptjs = require('bcrypt');
const cors = require('cors');

env.config();

const PORT = process.env.PORT || 3000;
const CLAVE_SECRETA = process.env.SECRET_KEY || 'secret';

const registroUsuarios = [];
const sesiones = {};

const opcionesCookieSegura = () => ({
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
});

const app = express();
app.use(cookie());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: 'http://localhost:3001', credentials: true }));

app.get('/', (_req, res) => {
    res.send('Servidor activo');
});

app.get('/csrf-token', (_req, res) => {
    const token = new csrfLib().create(CLAVE_SECRETA);
    res.json({ csrfToken: token });
});

app.post('/login', async (req, res) => {
    const { username, password, csrfToken } = req.body;

    if (!csrfLib().verify(CLAVE_SECRETA, csrfToken)) {
        return res.status(403).json({ error: 'Token CSRF inválido.' });
    }

    if (!username || !password) {
        return res.status(400).json({ error: 'Faltan usuario o contraseña.' });
    }

    const usuarioEncontrado = await Promise.any(
        registroUsuarios.map(async u => (await bcryptjs.compare(username, u.username)) ? u : null)
    ).catch(() => null);

    const credencialesValidas = usuarioEncontrado && await bcryptjs.compare(password, usuarioEncontrado.password);

    if (!credencialesValidas) {
        return res.status(401).json({ error: 'Credenciales incorrectas.' });
    }

    const idSesion = crypto.randomBytes(16).toString('base64url');
    sesiones[idSesion] = { username };
    res.cookie('sessionId', idSesion, opcionesCookieSegura());
    res.status(200).json({ mensaje: 'Autenticación exitosa.' });
});

app.post('/register', async (req, res) => {
    const { username, password, csrfToken } = req.body;

    if (!csrfLib().verify(CLAVE_SECRETA, csrfToken)) {
        return res.status(403).json({ error: 'Token CSRF inválido.' });
    }

    if (!username || !password) {
        return res.status(400).json({ error: 'Datos incompletos.' });
    }

    const patronUsuario = /^[a-zA-Z][0-9a-zA-Z]{5,49}$/;
    if (!patronUsuario.test(username)) {
        return res.status(400).json({ error: 'Formato de usuario inválido.' });
    }

    const esPasswordFuerte = pwd =>
        pwd.length >= 10 &&
        /[A-Z]/.test(pwd) &&
        /[a-z]/.test(pwd) &&
        /[0-9]/.test(pwd) &&
        /[^A-Za-z0-9\s]/.test(pwd);

    if (!esPasswordFuerte(password)) {
        return res.status(400).json({
            error: 'Contraseña débil. Debe tener mínimo 10 caracteres, mayúscula, minúscula, número y símbolo.'
        });
    }

    const yaExiste = await Promise.any(
        registroUsuarios.map(async u => (await bcryptjs.compare(username, u.username)) ? true : false)
    ).catch(() => false);

    if (yaExiste) {
        return res.status(409).json({ error: 'Este usuario ya está registrado.' });
    }

    const userHash = await bcryptjs.hash(username, 10);
    const passHash = await bcryptjs.hash(password, 10);

    registroUsuarios.push({ username: userHash, password: passHash });
    res.status(201).json({ mensaje: 'Registro completado.' });
});

app.listen(PORT, () => {
    console.log(`Servidor en línea: http://localhost:${PORT}`);
});
