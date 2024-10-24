const otplib = require('otplib'); // Usaremos otplib para generar y verificar códigos TOTP
const qrcode = require('qrcode'); // Librería para generar código QR

// Función para habilitar MFA y generar un código QR
async function enableMFA(req, res) {
    const userId = req.body.userId;

    try {
        // 1. Generar un secreto único para el usuario
        const secret = otplib.authenticator.generateSecret();

        // 2. Crear el URI OTP para Google Authenticator
        const otpauth = otplib.authenticator.keyuri('Usuario', 'TuApp', secret);

        // 3. Generar el código QR
        const qrCodeUrl = await qrcode.toDataURL(otpauth);

        // 4. Almacenar el secreto en la base de datos utilizando req.db
        await req.db.query('UPDATE tblusuarios SET mfa_secret = ? WHERE idUsuarios = ?', [secret, userId]);

        // 5. Devolver el código QR al frontend
        res.json({
            message: 'MFA habilitado correctamente. Escanea el código QR con Google Authenticator.',
            qrCode: qrCodeUrl,
        });
    } catch (error) {
        console.error('Error al habilitar MFA:', error);
        res.status(500).json({ message: 'Error en el servidor.' });
    }
}

// Función para verificar el código TOTP
async function verifyMFA(req, res) {
    const { userId, token } = req.body;

    try {
        // 1. Obtener el secreto MFA desde la base de datos usando req.db
        const [rows] = await req.db.query('SELECT mfa_secret FROM tblusuarios WHERE idUsuarios = ?', [userId]);

        if (rows.length === 0) {
            return res.status(400).json({ message: 'Usuario no encontrado.' });
        }

        const mfaSecret = rows[0].mfa_secret;

        // 2. Verificar el token usando el secreto MFA
        const isValid = otplib.authenticator.check(token, mfaSecret);

        if (isValid) {
            res.json({ message: 'Código MFA verificado correctamente.' });
        } else {
            res.status(400).json({ message: 'Código MFA incorrecto.' });
        }
    } catch (error) {
        console.error('Error al verificar MFA:', error);
        res.status(500).json({ message: 'Error en el servidor.' });
    }
}

module.exports = {
    enableMFA,
    verifyMFA
};
