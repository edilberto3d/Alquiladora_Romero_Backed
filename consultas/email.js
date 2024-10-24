const express = require('express');
const axios = require('axios'); 
const dns = require('dns');
const csrf = require('csurf');
const emailRouter = express.Router();
emailRouter.use(express.json());

const csrfProtection = csrf({ cookie: true });

// Expresión regular de validation
const validateEmailFormat = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Función para verificar los registros MX del dominio
const checkDomainMX = (domain) => {
  return new Promise((resolve, reject) => {
    dns.resolveMx(domain, (err, addresses) => {
      if (err) {
        return reject(err);
      }
      resolve(addresses && addresses.length > 0);
    });
  });
};

// ==================================== Ruta de Validación del CAPTCHA ====================================
emailRouter.post('/validate-captcha',csrfProtection,  async (req, res) => {
  const { captchaToken } = req.body;
  
  try {
    const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
      params: {
        secret:process.env.RECAPTCHA_SECRET_KEY,
        response: captchaToken,
      },
    });

    if (response.data.success) {
      return res.status(200).json({ success: true, message: 'Captcha validado correctamente' });
    } else {
      return res.status(400).json({ success: false, message: 'Captcha no válido' });
    }
  } catch (error) {
    console.error('Error al validar el CAPTCHA:', error);
    return res.status(500).json({ success: false, message: 'Error del servidor' });
  }
});

//Validar Captcha
const verifyCaptcha = async (captchaToken) => {
  const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
    params: {
      secret:  process.env.RECAPTCHA_SECRET_KEY,
      response: captchaToken
    }
  });
  return response.data.success; 
};

  

// Ruta de validacion correo ===============================================================
emailRouter.post('/validate-email',csrfProtection,  async (req, res) => {
  const { email } = req.body;
  const domain = email.split('@')[1];

  // Verifica el formato del correo
  if (!validateEmailFormat(email)) {
    return res.json({ isValid: false, message: 'Formato de correo electrónico no válido.' });
  }
  // Verifica si el dominio tiene registros MX válidos
  try {
    const hasMXRecords = await checkDomainMX(domain);
    if (hasMXRecords) {
      res.json({ isValid: true, message: 'Correo electrónico válido.' });
    } else {
      res.json({ isValid: false, message: 'El dominio no tiene registros MX.' });
    }
  } catch (error) {
    res.json({ isValid: false, message: 'Error al verificar el dominio.' });
  }
});

///==========================================================================================
   //Notificacion de cambio de contraseña 
   emailRouter.post('/send-password-change-notification', csrfProtection, async (req, res) => {
    const { correo, nombreU } = req.body;
    
    // detectamos el error del usuario
    console.log("Datos recibidos para el envío del correo:", correo, nombreU);
    
    // Definir el nombre del destinatario
    const destinatario = nombreU || 'Cliente';

    // Cambia el asunto y el contenido del correo
    const emailData = {
      sender: { name: "Alquiladora Romero", email: "alquiladoraromero@isoftuthh.com" },
      to: [{ email: correo, name: destinatario }],
      subject: "Notificación de cambio de contraseña",
      htmlContent: `
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f5f5f5; padding: 20px;">
          <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; background-color: #fff; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
            <div style="text-align: center; padding-bottom: 20px;">
              <h1 style="color: #007BFF; margin: 0;">Alquiladora Romero</h1>
            </div>
            <div style="text-align: center; padding-bottom: 20px;">
              <h2 style="color: #28A745; font-size: 24px; margin: 0;">Cambio de Contraseña</h2>
            </div>
            <div style="text-align: center; padding: 10px 0;">
              <p style="font-size: 18px; margin: 10px 0;">Hola, <strong>${destinatario}</strong></p>
              <p style="font-size: 16px; margin: 10px 0;">Te informamos que tu contraseña ha sido actualizada con éxito.</p>
              <p style="font-size: 16px; margin: 10px 0;">Si no realizaste este cambio, por favor, contacta con nuestro equipo de soporte de inmediato.</p>
            </div>

            <!-- Redes Sociales -->
            <div style="text-align: center; margin-top: 20px;">
              <p style="font-size: 14px; color: #555;">Síguenos en nuestras redes sociales:</p>
              <div style="display: inline-block; padding: 10px;">
                <a href="https://www.facebook.com/alquiladoraromero" target="_blank" style="text-decoration: none;">
                  <img src="https://upload.wikimedia.org/wikipedia/commons/5/51/Facebook_f_logo_%282019%29.svg" alt="Facebook" style="width: 30px; height: 30px; margin-right: 10px;" />
                </a>
                <a href="https://www.instagram.com/alquiladoraromero" target="_blank" style="text-decoration: none;">
                  <img src="https://upload.wikimedia.org/wikipedia/commons/a/a5/Instagram_icon.png" alt="Instagram" style="width: 30px; height: 30px;" />
                </a>
              </div>
            </div>

            <div style="border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px; text-align: center; font-size: 12px; color: #777;">
              <p>Esta es una notificación automática, por favor no respondas a este correo.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      headers: {
        'X-Mailer': 'Alquiladora Romero Mailer',
        'List-Unsubscribe': '<mailto:alquiladoraromero@isoftuthh.com>',
        'X-Accept-Language': 'es-MX',
        'X-Priority': '1 (Highest)',
      },
    };
  
    try {
      const response = await axios.post("https://api.brevo.com/v3/smtp/email", emailData, {
        headers: {
          'accept': 'application/json',
          'api-key': process.env.API_KEY,
          'content-type': 'application/json',
        },
      });
      res.status(200).json({ message: "Correo de notificación enviado exitosamente" });
    } catch (error) {
      console.error('Error al enviar el correo:', error);
      if (error.response) {
        console.error('Detalles del error:', error.response.data);
        res.status(500).json({ message: "Fallo al enviar el correo", error: error.response.data });
      } else {
        res.status(500).json({ message: "Fallo al enviar el correo", error: error.message });
      }
    }
});


//===========================Enviamos el token al correo ==============================================
emailRouter.post('/send', csrfProtection, async (req, res) => {
    const { correo,captchaToken, shortUUID, nombreU, nombreR } = req.body;
    
    // Verifica el CAPTCHA en el backend
  const captchaVerified = await verifyCaptcha(captchaToken);
  if (!captchaVerified) {
    return res.status(400).json({ message: 'Captcha no válido, por favor intente de nuevo.' });
  }

    
    
    //detectamos el error del usuario
    console.log("Estos datos recibo del correo,", correo,shortUUID, nombreU, nombreR );
    
    // Definir el nombre del destinatario
    const destinatario = nombreU || nombreR || 'Cliente';
  
    const emailData = {
      sender: { name: "Alquiladora Romero", email: "alquiladoraromero@isoftuthh.com" },
      to: [{ email: correo, name: destinatario }],
      subject: "Código de verificación",
      htmlContent: `
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f5f5f5; padding: 20px;">
          <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; background-color: #fff; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
            <div style="text-align: center; padding-bottom: 20px;">
              <h1 style="color: #007BFF; margin: 0;">Alquiladora Romero</h1>
            </div>
            <div style="text-align: center; padding-bottom: 20px;">
              <h2 style="color: #28A745; font-size: 24px; margin: 0;">Código de Verificación</h2>
            </div>
            <div style="text-align: center; padding: 10px 0;">
              <p style="font-size: 18px; margin: 10px 0;">Hola, <strong>${destinatario}</strong></p>
              <p style="font-size: 16px; margin: 10px 0;">Gracias por elegir Alquiladora Romero para tus necesidades de mobiliario.</p>
              <p style="font-size: 16px; margin: 10px 0;">Por favor, utiliza el siguiente código para continuar con el proceso de verificación:</p>
              <p style="font-size: 24px; font-weight: bold; color: #007BFF; margin: 20px 0;">${shortUUID}</p>
            </div>

            <!-- Redes Sociales -->
            <div style="text-align: center; margin-top: 20px;">
              <p style="font-size: 14px; color: #555;">Síguenos en nuestras redes sociales:</p>
              <div style="display: inline-block; padding: 10px;">
                <a href="https://www.facebook.com/alquiladoraromero" target="_blank" style="text-decoration: none;">
                  <img src="https://upload.wikimedia.org/wikipedia/commons/5/51/Facebook_f_logo_%282019%29.svg" alt="Facebook" style="width: 30px; height: 30px; margin-right: 10px;" />
                </a>
                <a href="https://www.instagram.com/alquiladoraromero" target="_blank" style="text-decoration: none;">
                  <img src="https://upload.wikimedia.org/wikipedia/commons/a/a5/Instagram_icon.png" alt="Instagram" style="width: 30px; height: 30px;" />
                </a>
              </div>
            </div>

            <div style="border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px; text-align: center; font-size: 12px; color: #777;">
              <p>Esta es una notificación automática, por favor no respondas a este correo.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      headers: {
        'X-Mailer': 'Alquiladora Romero Mailer',
        'List-Unsubscribe': '<mailto:alquiladoraromero@isoftuthh.com>',
        'X-Accept-Language': 'es-MX',
        'X-Priority': '1 (Highest)',
      },
    };
  
    try {
      const response = await axios.post("https://api.brevo.com/v3/smtp/email", emailData, {
        headers: {
          'accept': 'application/json',
          'api-key': process.env.API_KEY,
          'content-type': 'application/json',
        },
      });
      res.status(200).json({ message: "Email sent successfully" });
    } catch (error) {
      console.error('Error sending email:', error);
      if (error.response) {
        console.error('Error data:', error.response.data);
        res.status(500).json({ message: "Failed to send email", error: error.response.data });
      } else {
        res.status(500).json({ message: "Failed to send email", error: error.message });
      }
    }
});

//Recuperacion de contraseña
emailRouter.post('/cambiarpass', csrfProtection, async (req, res) => {
  const { correo,  shortUUID, nombreU, idUsuario } = req.body;

 
  // Expiración del token en 15 minutos (900000 ms)
  const expiration = Date.now() + 900000;
  const currentDate = new Date();
  const fecha = currentDate.toISOString().split('T')[0]; // Formato YYYY-MM-DD
  const hora = currentDate.toTimeString().split(' ')[0]; // Formato HH:MM:SS



  // Aquí debes guardar el token en la base de datos
  try {
    // Consulta para insertar el token en la base de datos
    const checkTokenQuery = `SELECT * FROM tbltoken WHERE idUsuario = ?`;
    const [existingToken] = await req.db.query(checkTokenQuery, [idUsuario]);

    if (existingToken.length > 0) {
      // Si el token ya existe, actualizar el registro
      const updateTokenQuery = `
        UPDATE tbltoken 
        SET token = ?, expiration = ?, fecha = ?, hora = ? 
        WHERE idUsuario = ?
      `;
      await req.db.query(updateTokenQuery, [shortUUID, expiration, fecha, hora, idUsuario]);
    } else {
      // Si no existe un token, insertar uno nuevo
      const insertTokenQuery = `
        INSERT INTO tbltoken (token, expiration, idUsuario, fecha, hora) 
        VALUES (?, ?, ?, ?, ?)
      `;
      await req.db.query(insertTokenQuery, [shortUUID, expiration, idUsuario, fecha, hora]);
    }


    // Definir el destinatario del correo
    const destinatario = nombreU || 'Cliente';

    const emailData = {
      sender: { name: "Alquiladora Romero", email: "alquiladoraromero@isoftuthh.com" },
      to: [{ email: correo, name: destinatario }],
      subject: "Código de verificación",
      htmlContent: `
        <html>
        <body style="font-family: Arial, sans-serif;">
          <h2>Código de Verificación</h2>
          <p>Hola, <strong>${destinatario}</strong></p>
          <p>Por favor, utiliza el siguiente código para continuar con el proceso de verificación:</p>
          <p style="font-size: 24px; font-weight: bold;">${shortUUID}</p>
        </body>
        </html>
      `,
      headers: {
        'X-Mailer': 'Alquiladora Romero Mailer',
        'X-Priority': '1 (Highest)',
      },
    };

    // Envío del correo
    await axios.post("https://api.brevo.com/v3/smtp/email", emailData, {
      headers: {
        'accept': 'application/json',
        'api-key': process.env.API_KEY,
        'content-type': 'application/json',
      },
    });

    res.status(200).json({ message: "Token enviado exitosamente" });
  } catch (error) {
    console.error('Error al enviar el token o guardar en la base de datos:', error);
    res.status(500).json({ message: 'Error al enviar el token o guardar en la base de datos' });
  }
});





module.exports = emailRouter;
