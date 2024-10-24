



const express = require("express");
const argon2 = require("argon2");
const cookieParser = require("cookie-parser");
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require("uuid")
const rateLimit = require("express-rate-limit");
const winston = require('winston');
const crypto = require("crypto");
const csrf = require('csurf'); 
const { enableMFA, verifyMFA } = require('./mfa'); 

const usuarioRouter = express.Router();
usuarioRouter.use(express.json());
usuarioRouter.use(cookieParser());
const csrfProtection = csrf({ cookie: true });
const otplib = require('otplib');
const qrcode = require('qrcode');

//Variables para el ip
const MAX_FAILED_ATTEMPTS = 5; //Intentos
const LOCK_TIME = 10 * 60 * 1000;  //
const TOKEN_EXPIRATION_TIME = 30 * 60 * 1000; //30 mnts

  //lLAVE SECRETO 
  const SECRET_KEY = process.env.SECRET_KEY.padEnd(32, ' ');

//rEGISTRO DE ERRORRES 
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'login-attempts.log' })
  ]
});
 //Encriptamos el clientId
function encryptClientId(clientId) {
  const IV_LENGTH = 16;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(SECRET_KEY, 'utf-8'), iv);
  let encrypted = cipher.update(clientId, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

//DEscribtar el clienteId
function decryptClientId(encrypted) {
  const [iv, encryptedText] = encrypted.split(":");
  const decipher = crypto.createDecipheriv("aes-256-cbc", SECRET_KEY, Buffer.from(iv, "hex"));
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
 //Obtenemos el Ip de la lap 
function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const ip = forwarded ? forwarded.split(/, /)[0] : req.connection.remoteAddress;
  return ip;
}

//Creamos un identificador unico para el cliente
function getOrCreateClientId(req, res) {
  let clientId = req.cookies.clientId; 
  if (!clientId) {
    clientId = uuidv4(); 
    const encryptedClientId = encryptClientId(clientId);
    res.cookie("clientId", encryptedClientId, { maxAge: 30 * 60 * 1000, httpOnly: true,  secure: process.env.NODE_ENV === "production",  sameSite: "Strict" });
  } else {
    clientId = decryptClientId(clientId);
  }
  return clientId;
}



//=========================================VALIDATION TOKEN
const verifyCaptcha = async (captchaToken) => {
  const secretKey = process.env.RECAPTCHA_SECRET_KEY; 
  
  // Verifica el token con la API de Google
  const response = await axios.post(
    `https://www.google.com/recaptcha/api/siteverify`,
    null,
    {
      params: {
        secret: secretKey,      
        response: captchaToken  
      }
    }
  );

  const { success } = response.data;
  
  if (!success) {
    throw new Error("Falló la verificación del captcha");
  }

  return true;
};
//===================================================LOGIN
//Login
usuarioRouter.post("/login", csrfProtection, async (req, res, next) => {
  try {
    // Extraer email, contraseña y token MFA (si se incluye)
    const { email, contrasena, tokenMFA } = req.body;

    // Validar que se reciban los campos de email y contraseña
    if (!email || !contrasena) {
      return res.status(400).json({ message: "Email y contraseña son obligatorios." });
    }

    // Obtener IP
    const ip = getClientIp(req);
    // Obtener o crear clientId
    const clientId = getOrCreateClientId(req, res);

    // Verificar si la conexión a la base de datos está disponible
    if (!req.db) {
      throw new Error('La conexión a la base de datos no está disponible.');
    }

    // Buscar al usuario por correo
    const query = "SELECT * FROM tblusuarios WHERE Correo = ?";
    const [usuarios] = await req.db.query(query, [email]);

    // Si no se encuentra el usuario
    if (usuarios.length === 0) {
      console.log("Correo o contraseña incorrectos");
      return res.status(401).json({ message: "Correo o contraseña incorrectos." });
    }

    const usuario = usuarios[0];
    console.log("Usuario encontrado: ", usuario);

    // Verificar si el usuario está bloqueado
    const bloqueoQuery = 'SELECT * FROM tblipbloqueados WHERE idUsuarios = ?';
    const [bloqueos] = await req.db.query(bloqueoQuery, [usuario.idUsuarios]);

    if (bloqueos.length > 0) {
      const bloqueo = bloqueos[0];
      if (bloqueo.lock_until && new Date() > new Date(bloqueo.lock_until)) {
        await req.db.query("DELETE FROM tblipbloqueados WHERE idUsuarios = ?", [usuario.idUsuarios]);
        console.log("Tiempo de bloqueo expirado, desbloqueando.");
      } else if (bloqueo.Intentos >= MAX_FAILED_ATTEMPTS) {
        const tiempoRestante = Math.ceil((new Date(bloqueo.lock_until) - new Date()) / 1000);
        console.log("Tiempo restante del desbloqueo", tiempoRestante);
        return res.status(403).json({
          message: `Dispositivo bloqueado. Inténtalo de nuevo en ${tiempoRestante} segundos.`,
          tiempoRestante,
        });
      }
    }

    // Comparar la contraseña con la base de datos
    const validPassword = await argon2.verify(usuario.Passw, contrasena);

    if (!validPassword) {
      await handleFailedAttempt(ip, clientId, usuario.idUsuarios, req.db);
      return res.status(401).json({ message: "Correo o contraseña incorrectos." });
    }

    // Verificar si el usuario tiene MFA habilitado
    if (usuario.mfa_secret ) { 
      // Si MFA está habilitado pero no se recibió el tokenMFA, devolver que MFA es necesario
      if (!tokenMFA) {
        return res.status(200).json({
          message: 'MFA requerido. Por favor ingresa el código de verificación MFA.',
          mfaRequired: true,
          userId: usuario.idUsuarios, // Enviar el userId al frontend para la verificación MFA
        });
      }

      // Si se recibió un tokenMFA, verificarlo
      const isValidMFA = otplib.authenticator.check(tokenMFA, usuario.mfa_secret);

      if (!isValidMFA) {
        return res.status(400).json({ message: 'Código MFA incorrecto.' });
      }

      console.log("MFA verificado correctamente");
    }

    // Eliminar intentos fallidos si la autenticación es exitosa
    await req.db.query("DELETE FROM tblipbloqueados WHERE idUsuarios = ?", [usuario.idUsuarios]);

    // Generar token JWT
    const token = jwt.sign(
      { id: usuario.idUsuarios, nombre: usuario.Nombre, rol: usuario.Rol },
      SECRET_KEY,
      { expiresIn: '30m' }
    );

    // Crear la cookie de sesión
    res.cookie("sesionToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: TOKEN_EXPIRATION_TIME,
    });

    // Responder con éxito
    res.json({
      message: "Login exitoso",
      user: {
        idUsuarios: usuario.idUsuarios,
        nombre: usuario.Nombre,
        rol: usuario.Rol,
      },
    });

    console.log("Login exitoso");
    console.log(`Usuario ${usuario.idUsuarios} inició sesión desde IP: ${ip} y clienteId: ${clientId}`);
    logger.info(`Usuario ${usuario.idUsuarios} inició sesión desde IP: ${ip} y clienteId: ${clientId}`);
  } catch (error) {
    console.error("Error en el login:", error);
    next(error);
  }
});

//qr
usuarioRouter.post('/enable-mfa', csrfProtection, async (req, res) => {
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
    const otpauthURL = otplib.authenticator.keyuri(usuario.Correo, 'TuApp', mfaSecret);

    // Generar código QR
    const qrCode = await qrcode.toDataURL(otpauthURL);

    // Guardar la clave MFA en la base de datos
    await req.db.query("UPDATE tblusuarios SET mfa_secret = ? WHERE idUsuarios = ?", [mfaSecret, usuario.idUsuarios]);

    // Enviar el código QR al cliente para que lo escanee
    res.json({
      message: 'MFA habilitado correctamente.',
      qrCode,
    });
  } catch (error) {
    console.error('Error al habilitar MFA:', error);
    res.status(500).json({ message: 'Error al habilitar MFA.' });
  }
});





//================================Manejo de intentos fallidos de login=======================================
async function handleFailedAttempt(ip, clientId, idUsuarios, db) {
 
    // Obtener la fecha y hora actual
    const currentDate = new Date();
    const fechaActual = currentDate.toISOString().split('T')[0];
    const horaActual = currentDate.toTimeString().split(' ')[0];

    // Consultar si ya existe un bloqueo para este usuario
    const [result] = await db.query("SELECT * FROM tblipbloqueados WHERE idUsuarios = ?", [idUsuarios]);

    if (result.length === 0) {
      // Si no hay registros, insertamos uno nuevo
      await db.query(
        "INSERT INTO tblipbloqueados (idUsuarios, Ip, clienteId, Fecha, Hora, Intentos) VALUES (?, ?, ?, ?, ?, ?)",
        [idUsuarios, ip, clientId, fechaActual, horaActual, 1]
      );
      logger.info(`Registro de bloqueo creado para el usuario con ID ${idUsuarios}`);
    } else {
      // Si ya existe un registro, actualizamos los intentos fallidos
      const bloqueo = result[0];
      const newAttempts = bloqueo.Intentos + 1;

      if (newAttempts >= MAX_FAILED_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + LOCK_TIME);
        await db.query(
          "UPDATE tblipbloqueados SET Intentos = ?, Fecha = ?, Hora = ?, lock_until = ? WHERE idUsuarios = ?",
          [newAttempts, fechaActual, horaActual, lockUntil, idUsuarios]
        );
        logger.info(`Usuario ${idUsuarios} ha alcanzado el número máximo de intentos. Bloqueado hasta ${lockUntil}`);
      } else {
        await db.query(
          "UPDATE tblipbloqueados SET Intentos = ?, Fecha = ?, Hora = ? WHERE idUsuarios = ?",
          [newAttempts, fechaActual, horaActual, idUsuarios]
        );
        logger.info(`Usuario ${idUsuarios} ha fallado otro intento. Total intentos fallidos: ${newAttempts}`);
      }
    }

    // Registrar el intento fallido
    logger.warn(`Intento fallido desde IP: ${ip} y clientId: ${clientId} para el usuario con ID ${idUsuarios}`);
  } 



//======================================================================


//Middleware para validar token
const verifyToken = (req, res, next) => {
  const token = req.cookies.sesionToken;


  if (!token) {
    return res.status(403).json({ message: "No tienes token de acceso." });
  }

  try {
     
    const decoded = jwt.verify(token, SECRET_KEY);
    const now = Math.floor(Date.now() / 1000);
    
    // Si el token expira en menos de 2 minutos, renovamos el token
    const timeRemaining = decoded.exp - now;
    if (timeRemaining < 2 * 60) {
      const newToken = jwt.sign({ id: decoded.id, nombre: decoded.nombre, rol: decoded.rol }, SECRET_KEY, { expiresIn: '30m' });
      res.cookie("sesionToken", newToken, {
        httpOnly: true,
         secure: process.env.NODE_ENV === "production", 
        sameSite: "Strict",
        maxAge: TOKEN_EXPIRATION_TIME,
      });
      console.log("Token renovado exitosamente.");
    } else {
      console.log(`Tiempo restante para el token: ${timeRemaining} segundos.`);
    }

    req.user = decoded;
    next();
  } catch (error) {
    // Capturar errores relacionados con la verificación del token
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "El token ha expirado. Por favor, inicia sesión nuevamente." });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(400).json({ message: "El token proporcionado no es válido." });
    } else {
      return res.status(500).json({ message: "Error interno del servidor." });
    }
  }
};

// Ruta protegida 
usuarioRouter.get("/perfil", verifyToken, async (req, res) => {
  const userId = req.user.id;

  try{
  //Hacemos la consulat de la db
  const query = "SELECT Nombre, ApellidoP, ApellidoM, Correo, Telefono, Rol, foto_Perfil, Fecha_ActualizacionF  FROM tblusuarios WHERE idUsuarios = ?";
  const [result] = await req.db.query(query, [userId]);

  if (result.length === 0) {
    return res.status(404).json({ message: "Usuario no encontrado." });
  }

  const usuario = result[0];

  console.log("Iniciaste correctamente con los siguientes datos:", usuario);
   // Enviar los datos del perfil al frontend
   res.json({
    message: "Perfil obtenido correctamente",
    user: {
      id: userId,
      nombre: usuario.Nombre,
      apellidoP: usuario.ApellidoP,
      apellidoM: usuario.ApellidoM,
      correo: usuario.Correo,
      telefono: usuario.Telefono,
      rol: usuario.Rol,
      foto_perfil: usuario.foto_Perfil,
      Fecha_ActualizacionF: usuario.Fecha_ActualizacionF
    }
  });

} catch (error) {
  console.error("Error al obtener el perfil del usuario:", error);
  res.status(500).json({ message: "Error al obtener el perfil del usuario." });
}
});

//============================================================================
  //Actualizamos el foto de perfil
  usuarioRouter.patch("/perfil/:id/foto",  csrfProtection, async (req, res) => {
    const userId = req.params.id;
    const { foto_perfil } = req.body; // Revisa que foto_perfil llegue bien

    if (!foto_perfil) {
      return res.status(400).json({ message: "Falta la imagen de perfil." });
    }

    try {
      const query = "UPDATE tblusuarios SET Foto_Perfil = ?, Fecha_ActualizacionF = ? WHERE idUsuarios = ?";
      const [updateResult] = await req.db.query(query, [foto_perfil, new Date().toISOString(), userId]);

      if (updateResult.affectedRows === 0) {
        return res.status(404).json({ message: "Usuario no encontrado." });
      }

      res.json({
        message: "Foto de perfil actualizada correctamente.",
        foto_perfil
      });
    } catch (error) {
      console.error("Error al actualizar la foto de perfil:", error);
      res.status(500).json({ message: "Error al actualizar la foto de perfil." });
    }
});

//===============================================================================================
   //Actulizar el dato de usaurio en especifico
   usuarioRouter.patch("/perfil/:id/:field", csrfProtection, async (req, res) => {
    const {id, field} = req.params;
    const {value}= req.body;

    // Lista de campos permitidos
    const allowedFields = ['nombre', 'apellidoP', 'apellidoM', 'telefono'];

    if (!allowedFields.includes(field)) {
      return res.status(400).json({ message: "Campo no permitido para actualización." });
    }

    try{
      const query = `UPDATE tblusuarios SET ${field} = ? WHERE idUsuarios = ?`;
      const [result] = await req.db.query(query, [value, id]);

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Usuario no encontrado." });
      }
    res.json({
      message: `${field} actualizado correctamente`,
      updatedField: value,
    });
  } catch (error) {
    console.error(`Error al actualizar ${field}:`, error);
    res.status(500).json({ message: `Error al actualizar ${field}.` });
  }
});


//Validar toke cambio contraseña=============================================
// Endpoint para validar el token de recuperación de contraseña
usuarioRouter.post("/validarToken/contrasena", csrfProtection, async (req, res, next) => {
  try {
    const { idUsuario, token } = req.body;

    // Verificar si se recibieron los datos correctos
    if (!idUsuario || !token) {
      return res.status(400).json({ message: "ID de usuario o token no proporcionado." });
    }

    // Verificar el token en la tabla tbltoken
    const queryToken = "SELECT * FROM tbltoken WHERE idUsuario = ? AND token = ?";
    const [tokenRecord] = await req.db.query(queryToken, [idUsuario, token]);

    if (tokenRecord.length === 0) {
      return res.status(400).json({ message: "Token inválido o no encontrado." });
    }

    // Verificar si el token ha expirado
    const currentTime = Date.now();
    const expirationTime = tokenRecord[0].expiration;

    if (currentTime > expirationTime) {
      return res.status(400).json({ message: "El token ha expirado." });
    }

    // Si el token es válido, eliminarlo de la tabla tbltoken
    const deleteTokenQuery = "DELETE FROM tbltoken WHERE idUsuario = ? AND token = ?";
    await req.db.query(deleteTokenQuery, [idUsuario, token]);

    // Si todo es correcto
    return res.status(200).json({ message: "Token válido. Puede proceder con el cambio de contraseña. El token ha sido eliminado." });

  } catch (error) {
    console.error("Error al validar el token:", error);
    return res.status(500).json({ message: "Error al validar el token." });
  }
});









//Creamos los Cookies==============================================
   //Eliminar Cookies
   usuarioRouter.post("/Delete/login",  csrfProtection ,(req, res) => {
    res.clearCookie("sesionToken", {
      httpOnly: true,
       secure: process.env.NODE_ENV === "production", 
      sameSite: "Strict",
    });
    console.log("Sesión cerrada correctamente.");
  
    res.json({ message: "Sesión cerrada correctamente." });
  });


//=========================================================================================
// Obtenemos Todos Los Usuarios
usuarioRouter.get("/", async (req, res, next) => {
  try {
    const [usuarios] = await req.db.query("SELECT * FROM tblusuarios");
    res.json(usuarios);
  } catch (error) {
    next(error);
  }
});

//=================================================================================

//Insert
usuarioRouter.post("/", csrfProtection, async (req, res, next) => {
  try {
    const {
      nombre,
      apellidoPaterno,
      apellidoMaterno,
      email,
      contrasena,
      telefono,
    } = req.body;
    //HASHEAMOS LA CONTRASEÑA CON ARGON2
    const hashedPassword = await argon2.hash(contrasena);

    const query =
      "INSERT INTO tblusuarios (Nombre, ApellidoP, ApellidoM, Correo, Telefono, Passw, Rol) VALUES (?, ?, ?, ?, ?, ?,?)";
    const [result] = await req.db.query(query, [
      nombre,
      apellidoPaterno,
      apellidoMaterno,
      email,
      telefono,
      hashedPassword,
      "Cliente",
    ]);

    res
      .status(201)
      .json({
        message: "Usuario creado exitosamente",
        userId: result.insertId,
      });
  } catch (error) {
    next(error); 
  }
});


//=========================================================================================
//validar contraseña actual
// Endpoint para verificar la contraseña actual
usuarioRouter.post("/verify-password", csrfProtection, async (req, res) => {
  const { idUsuario, currentPassword } = req.body;
  console.log("Esye es lo que recibe,", idUsuario, currentPassword)

  if (!idUsuario || !currentPassword) {
    return res.status(400).json({ message: "ID de usuario o contraseña no proporcionados." });
  }

  try {
    // Consulta para obtener la contraseña actual del usuario
    const [usuario] = await req.db.query("SELECT Passw FROM tblusuarios WHERE idUsuarios = ?", [idUsuario]);

    if (usuario.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    const hashedPassword = usuario[0].Passw;

    // Verificar la contraseña con Argon2
    const validPassword = await argon2.verify(hashedPassword, currentPassword);

    if (!validPassword) {
      return res.status(401).json({ valid: false, message: "La contraseña actual es incorrecta." });
    }

    return res.status(200).json({ valid: true, message: "La contraseña actual es correcta." });
  } catch (error) {
    console.error("Error al verificar la contraseña:", error);
    return res.status(500).json({ message: "Error interno del servidor." });
  }
});

//Cambiar contraseña y  guradarlo en el historial
usuarioRouter.post("/change-password", csrfProtection, async (req, res) => {
  const { idUsuario, newPassword } = req.body;

  if (!idUsuario || !newPassword) {
    return res.status(400).json({ message: "ID de usuario o nueva contraseña no proporcionados." });
  }

  try {
    // Obtener el historial de contraseñas del usuario
    const [historico] = await req.db.query("SELECT contrasena FROM tblhistorialpass WHERE idUsuarios= ? ORDER BY created_at DESC", [idUsuario]);
    console.log("History", [historico], "Este es la nueva contraseña ", newPassword)


    if (!historico || historico.length === 0) {
      console.log("No hay historial de contraseñas, se procederá a guardar la nueva contraseña.");
    } else {
      // Verificar si la nueva contraseña ya ha sido utilizada anteriormente
      for (let pass of historico) {
        const isMatch = await argon2.verify(pass.contrasena, newPassword); // Comparación correcta
        console.log(isMatch);
        
        if (isMatch) {
          return res.status(400).json({ usedBefore: true, message: "La contraseña ya ha sido utilizada anteriormente." });
        }
      }
    }

    // Hashear la nueva contraseña
    const hashedPassword = await argon2.hash(newPassword);

    // Actualizar la contraseña del usuario
    await req.db.query("UPDATE tblusuarios SET Passw = ? WHERE idUsuarios = ?", [hashedPassword, idUsuario]);

    // Insertar la nueva contraseña en el historial de contraseñas
    await req.db.query("INSERT INTO tblhistorialpass (idUsuarios, contrasena, created_at) VALUES (?, ?, NOW())", [idUsuario, hashedPassword]);

    // Limitar el historial a 3 contraseñas y eliminar la más antigua si es necesario
    const [historial] = await req.db.query("SELECT * FROM tblhistorialpass WHERE idUsuarios = ? ORDER BY created_at DESC", [idUsuario]);
    if (historial.length > 3) {
      const oldPasswordId = historial[3].id; // Obtener el ID de la contraseña más antigua
      await req.db.query("DELETE FROM tblhistorialpass WHERE id = ?", [oldPasswordId]);
    }

    

    return res.status(200).json({ success: true, message: "Contraseña cambiada correctamente." });
  } catch (error) {
    console.error("Error al cambiar la contraseña:", error);
    return res.status(500).json({ message: "Error interno del servidor." });
  }
});



//==================================================================================



module.exports = usuarioRouter;
