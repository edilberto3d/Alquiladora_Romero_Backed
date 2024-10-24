const express = require('express');
const otplib = require('otplib');
const qrcode = require('qrcode');
const csrf = require('csurf'); // CSRF protection
const csrfProtection = csrf({ cookie: true }); // Configuración de CSRF para proteger con cookies

const mfaRoute = express.Router();

// Habilitar MFA con protección CSRF y cookies
mfaRoute.post('/enable-mfa', csrfProtection, async (req, res) => {
  try {
    const { userId } = req.body;

    // Buscar al usuario por su ID
    const [usuarios] = await req.db.query("SELECT * FROM tblusuarios WHERE idUsuarios = ?", [userId]);
    if (usuarios.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    const usuario = usuarios[0];

    // Generar la clave secreta para MFA
    const mfaSecret = otplib.authenticator.generateSecret();

    // Generar el enlace otpauth para Google Authenticator
    const otpauthURL = otplib.authenticator.keyuri(usuario.Correo, 'TuCodigoSecreto', mfaSecret);

    // Generar código QR
    const qrCode = await qrcode.toDataURL(otpauthURL);

    // Guardar la clave MFA en la base de datos
    await req.db.query("UPDATE tblusuarios SET mfa_secret = ? WHERE idUsuarios = ?", [mfaSecret, usuario.idUsuarios]);

    // Enviar el código QR al cliente para que lo escanee
    res.cookie("mfaToken", "active", { httpOnly: true, secure: true, sameSite: 'Strict' }); // Añadir cookie de MFA
    res.json({
      message: 'MFA habilitado correctamente.',
      qrCode,
    });
  } catch (error) {
    console.error('Error al habilitar MFA:', error);
    res.status(500).json({ message: 'Error al habilitar MFA.' });
  }
});

// Deshabilitar MFA con CSRF y manejo de cookies
mfaRoute.post('/disable-mfa', csrfProtection, async (req, res) => {
  try {
    const { userId } = req.body;

    // Limpiar el campo mfa_secret en la base de datos
    await req.db.query("UPDATE tblusuarios SET mfa_secret = NULL WHERE idUsuarios = ?", [userId]);

    res.clearCookie("mfaToken"); // Eliminar la cookie de MFA
    res.json({ message: 'MFA deshabilitado correctamente.' });
  } catch (error) {
    console.error('Error al deshabilitar MFA:', error);
    res.status(500).json({ message: 'Error al deshabilitar MFA.' });
  }
});

// Verificar MFA con CSRF y manejo de cookies
mfaRoute.post('/verify-mfa', csrfProtection, async (req, res) => {
  try {
    const { userId, token } = req.body;

    if (!userId || !token) {
      return res.status(400).json({ message: 'Faltan datos requeridos: userId o token.' });
    }

    // Buscar al usuario por su ID
    const [usuarios] = await req.db.query("SELECT mfa_secret FROM tblusuarios WHERE idUsuarios = ?", [userId]);
    if (usuarios.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    const { mfa_secret } = usuarios[0];

    // Verificar el token MFA
    const isValidMFA = otplib.authenticator.check(token, mfa_secret);

    if (isValidMFA) {
      return res.json({ message: 'Código MFA verificado correctamente.' });
    } else {
      return res.status(400).json({ message: 'Código MFA incorrecto.' });
    }
  } catch (error) {
    console.error('Error al verificar MFA:', error);
    res.status(500).json({ message: 'Error al verificar MFA.' });
  }
});

// Consultar estado MFA con CSRF
mfaRoute.get('/mfa-status/:userId', csrfProtection, async (req, res) => {
  try {
    const { userId } = req.params;

    // Consultar si el usuario tiene MFA activado
    const [usuarios] = await req.db.query("SELECT mfa_secret FROM tblusuarios WHERE idUsuarios = ?", [userId]);

    if (usuarios.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    const mfaEnabled = usuarios[0].mfa_secret !== null;
    res.json({ mfaEnabled });
  } catch (error) {
    console.error('Error al obtener el estado de MFA:', error);
    res.status(500).json({ message: 'Error al obtener el estado de MFA.' });
  }
});

module.exports = mfaRoute;
