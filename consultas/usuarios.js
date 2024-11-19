const express = require("express");
const argon2 = require("argon2");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");
const winston = require("winston");
const crypto = require("crypto");
const { enableMFA, verifyMFA } = require("./mfa");

const usuarioRouter = express.Router();
usuarioRouter.use(express.json());
usuarioRouter.use(cookieParser());

//==========================MFA=========================================
const otplib = require("otplib");
const qrcode = require("qrcode");
const { json } = require("body-parser");

// Configurar winston logger
const logger = winston.createLogger({
  level: "info",
  format: winston.format.simple(),
  transports: [new winston.transports.Console()],
});

//Variables para el ip
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME = 10 * 60 * 1000;
const TOKEN_EXPIRATION_TIME = 30 * 60 * 1000;

if (!process.env.SECRET_KEY) {
  throw new Error("La variable de entorno SECRET_KEY no está definida.");
}
const SECRET_KEY = process.env.SECRET_KEY.padEnd(32, " ");

//Encriptamos el clientId
function encryptClientId(clientId) {
  const IV_LENGTH = 16;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(SECRET_KEY, "utf-8"),
    iv
  );
  let encrypted = cipher.update(clientId, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

//DEscribtar el clienteId
function decryptClientId(encrypted) {
  const [iv, encryptedText] = encrypted.split(":");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    SECRET_KEY,
    Buffer.from(iv, "hex")
  );
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
//Obtenemos el Ip de la lap
function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const ip = forwarded
    ? forwarded.split(/, /)[0]
    : req.connection.remoteAddress;
  return ip;
}

//Creamos un identificador unico para el cliente
function getOrCreateClientId(req, res) {
  let clientId = req.cookies.clientId;
  if (!clientId) {
    clientId = uuidv4();
    const encryptedClientId = encryptClientId(clientId);
    res.cookie("clientId", encryptedClientId, {
      maxAge: 30 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
    });
  } else {
    clientId = decryptClientId(clientId);
  }
  return clientId;
}

//=========================================VALIDATION TOKEN

otplib.authenticator.options = {
  window: 2,
};

//Ruta para detectar la latancia de la red
usuarioRouter.get("/ping", (req, res) => {
  res.status(200).json({ message: "conexion estable" });
});

//===================================================LOGIN
//Login
usuarioRouter.post("/login", async (req, res, next) => {
  try {
    // Extraer email, contraseña y token MFA (si se incluye)
    const { email, contrasena, tokenMFA, clientTimestamp, deviceType } = req.body;
    console.log(
      "Este es los datos que recibe del login",
      email,
      contrasena,
      tokenMFA,
      clientTimestamp,
      deviceType
    );

    // Validar que se reciban los campos de email y contraseña
    if (!email || !contrasena) {
      return res
        .status(400)
        .json({ message: "Email y contraseña son obligatorios." });
    }

    // Obtener IP
    const ip = getClientIp(req);
    // Obtener o crear clientId cookies
    const clientId = getOrCreateClientId(req, res);

    // Verificar si la conexión a la base de datos está disponible
    if (!req.db) {
      throw new Error("La conexión a la base de datos no está disponible.");
    }

    // Buscar al usuario por correo
    const query = "SELECT * FROM tblusuarios WHERE Correo = ?";
    const [usuarios] = await req.db.query(query, [email]);

    // Si no se encuentra el usuario
    if (usuarios.length === 0) {
     
      console.log("Credenciales Incorrectos");
      return res
        .status(401)
        .json({ message: "Credenciales Incorrectos" });
    }
   //=================================================================================================== 
   //Usuario encontrado
    const usuario = usuarios[0];
    console.log("Usuario encontrado: ", usuario);
    //=================================================================================================== 
   

    // Verificar si el usuario está bloqueado
    const bloqueoQuery = "SELECT * FROM tblipbloqueados WHERE idUsuarios = ?";
const [bloqueos] = await req.db.query(bloqueoQuery, [usuario.idUsuarios]);

if (bloqueos.length > 0) {
  const bloqueo = bloqueos[0]; 
  const ahora = new Date();
  const lockUntil = bloqueo.lock_until ? new Date(bloqueo.lock_until) : null;

  console.log("Detalles del bloqueo obtenido:", bloqueo);

  // **1. Verificar si el administrador bloqueó al usuario**
  if (bloqueo.bloqueado === 1) {
    console.log("Usuario bloqueado por el administrador.");
    return res.status(403).json({
      message: "Cuenta bloqueada por el administrador.",
    });
  }

  // **2. Verificar si el tiempo de bloqueo ha expirado y desbloquear si es necesario**
  if (lockUntil && lockUntil <= ahora) {
    console.log("El tiempo de bloqueo ha expirado. Desbloqueando usuario...");
    const desbloqueoQuery = `
      UPDATE tblipbloqueados 
      SET Intentos = 0, lock_until = NULL 
      WHERE idUsuarios = ?`;
    await req.db.query(desbloqueoQuery, [usuario.idUsuarios]);
    bloqueo.Intentos = 0; // Actualizamos el objeto bloqueo en memoria
    bloqueo.lock_until = null;
    console.log("Usuario desbloqueado correctamente.");
  }

  // **3. Verificar si los intentos fallidos han excedido el máximo permitido**
  if (bloqueo.Intentos >= MAX_FAILED_ATTEMPTS) {
    // **3.1. Si lock_until no está establecido, establecerlo ahora**
    if (!lockUntil) {
      const lockTime = new Date(ahora.getTime() + LOCK_TIME);
      const actualizarLockQuery = `
        UPDATE tblipbloqueados 
        SET lock_until = ? 
        WHERE idUsuarios = ?`;
      await req.db.query(actualizarLockQuery, [lockTime, usuario.idUsuarios]);
      bloqueo.lock_until = lockTime; 
    }

    // **3.2. Calcular el tiempo restante de bloqueo**
    const tiempoRestanteSegundos = Math.ceil((bloqueo.lock_until - ahora) / 1000);

    let tiempoRestanteMensaje;
    if (tiempoRestanteSegundos >= 60) {
      const minutos = Math.floor(tiempoRestanteSegundos / 60);
      const segundos = tiempoRestanteSegundos % 60;
      tiempoRestanteMensaje = `${minutos} minuto${minutos !== 1 ? "s" : ""}${
        segundos > 0 ? ` y ${segundos} segundo${segundos !== 1 ? "s" : ""}` : ""
      }`;
    } else {
      tiempoRestanteMensaje = `${tiempoRestanteSegundos} segundo${
        tiempoRestanteSegundos !== 1 ? "s" : ""
      }`;
    }

    console.log(`Usuario bloqueado temporalmente. Tiempo restante: ${tiempoRestanteMensaje}.`);
    return res.status(403).json({
      message: `Usuario bloqueado temporalmente. Inténtalo de nuevo en ${tiempoRestanteMensaje}.`,
      tiempoRestante: tiempoRestanteSegundos,
    });
  }
}

    
    //================================================================================

    // Comparar la contraseña con la base de datos
    const validPassword = await argon2.verify(usuario.Passw, contrasena);

    if (!validPassword) {
      await handleFailedAttempt(ip, clientId, usuario.idUsuarios, req.db);
    
      return res
        .status(401)
        .json({ message: "Credenciales Incorrectos" });
    }
    //==============================================================MFA ATIVADO=====================
    console.log(usuario.mfa_secret);

    if (usuario.mfa_secret) {
      if (!tokenMFA) {
        

        return res.status(200).json({
          message:
            "MFA requerido. Por favor ingresa el código de verificación MFA.",
          mfaRequired: true,
          userId: usuario.idUsuarios,
        });
      }
      // Si se recibió un tokenMFA, verificarlo
      const isValidMFA = otplib.authenticator.check(
        tokenMFA,
        usuario.mfa_secret
      );
      console.log(isValidMFA);

      if (!isValidMFA) {
        
        return res.status(400).json({ message: "Código MFA incorrecto." });
      }
    }

  

    // Generar token JWT
    const token = jwt.sign(
      { id: usuario.idUsuarios, nombre: usuario.Nombre, rol: usuario.Rol },
      SECRET_KEY,
      { expiresIn: "30m" }
    );

    // Crear la cookie de sesión
    res.cookie("sesionToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
      maxAge: TOKEN_EXPIRATION_TIME,
    });

    // Insertar la sesión en tblsesiones
    try {
      const sessionQuery = `
        INSERT INTO tblsesiones (idUsuario, tokenSesion, horaInicio, direccionIP, clienteId, tipoDispositivo)
        VALUES (?, ?, ?, ?, ?, ?)
      `;
      await req.db.query(sessionQuery, [
        usuario.idUsuarios,
        token,
        clientTimestamp,  
        ip,
        clientId,
        deviceType   
      ]);
      console.log("Sesión insertada en tblsesiones");
    } catch (insertError) {
      console.error("Error al insertar la sesión en tblsesiones:", insertError);
      next(error);

    }

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
  } catch (error) {
    console.error("Error en el login:", error);
    next(error);
  }
});


//==================================================SOSPECHOSOS
usuarioRouter.get("/usuarios-sospechosos", async (req, res) => {
  try {
    const [usuarios] = await req.db.query(
      `SELECT u.idUsuarios, u.Nombre, u.ApellidoP, u.Correo, b.intentos AS Intentos, b.intentosReales AS IntentosReales, b.bloqueado
       FROM tblusuarios u
       JOIN tblipbloqueados b ON u.idUsuarios = b.idUsuarios
       WHERE b.intentos >= ? OR b.bloqueado = TRUE`,
      [MAX_FAILED_ATTEMPTS]
    );
    res.status(200).json(usuarios);
  } catch (error) {
    console.error("Error al obtener usuarios sospechosos:", error);
    res.status(500).json({ message: "Error al obtener usuarios sospechosos" });
  }
});

usuarioRouter.post("/bloquear/:idUsuario", async (req, res) => {
  const { idUsuario } = req.params;

  try {
    await req.db.query(
      `UPDATE tblipbloqueados bloqueado = TRUE WHERE idUsuarios = ?`,
      [idUsuario]
    );
    res.status(200).json({ message: "Usuario bloqueado manualmente." });
  } catch (error) {
    console.error("Error al bloquear usuario:", error);
    res.status(500).json({ message: "Error al bloquear usuario." });
  }
});


usuarioRouter.post("/desbloquear/:idUsuario", async (req, res) => {
  const { idUsuario } = req.params;

  try {
    await req.db.query(
      `UPDATE tblipbloqueados SET  bloqueado = FALSE, Intentos = 0,  lock_until = NULL WHERE idUsuarios = ?`,
      [idUsuario]
    );
    res.status(200).json({ message: "Usuario desbloqueado manualmente." });
  } catch (error) {
    console.error("Error al desbloquear usuario:", error);
    res.status(500).json({ message: "Error al desbloquear usuario." });
  }
});

//==============================================================

//qr
usuarioRouter.post("/enable-mfa", async (req, res) => {
  try {
    const { userId } = req.body;

    // Buscar al usuario por su ID
    const [usuarios] = await req.db.query(
      "SELECT * FROM tblusuarios WHERE idUsuarios = ?",
      [userId]
    );
    if (usuarios.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    const usuario = usuarios[0];

    // Generar la clave secreta para MFA
    const mfaSecret = otplib.authenticator.generateSecret();

    // Generar el enlace otpauth para Google Authenticator
    const otpauthURL = otplib.authenticator.keyuri(
      usuario.Correo,
      "TU TOKEN ALQUILADORA ROMERO: ",
      mfaSecret
    );

    // Generar código QR
    const qrCode = await qrcode.toDataURL(otpauthURL);

    // Guardar la clave MFA en la base de datos
    await req.db.query(
      "UPDATE tblusuarios SET mfa_secret = ? WHERE idUsuarios = ?",
      [mfaSecret, usuario.idUsuarios]
    );

    // Enviar el código QR al cliente para que lo escanee
    res.json({
      message: "MFA habilitado correctamente.",
      qrCode,
    });
  } catch (error) {
    console.error("Error al habilitar MFA:", error);
    res.status(500).json({ message: "Error al habilitar MFA." });
  }
});

//================================Manejo de intentos fallidos de login=======================================
async function handleFailedAttempt(ip, clientId, idUsuarios, db) {
  // Obtener la fecha y hora actual
  const currentDate = new Date();
  const fechaActual = currentDate.toISOString().split("T")[0];
  const horaActual = currentDate.toTimeString().split(" ")[0];

  // Consultar si ya existe un bloqueo para este usuario
  const [result] = await db.query(
    "SELECT * FROM tblipbloqueados WHERE idUsuarios = ?",
    [idUsuarios]
  );

  if (result.length === 0) {
    // Si no hay registros, insertamos uno nuevo
    await db.query(
      "INSERT INTO tblipbloqueados (idUsuarios, Ip, clienteId, Fecha, Hora, Intentos, IntentosReales,bloqueado) VALUES (?, ?, ?, ?, ?, ?, ? , ? )",
      [idUsuarios, ip, clientId, fechaActual, horaActual, 1,1,0]
    );
    logger.info(
      `Registro de bloqueo creado para el usuario con ID ${idUsuarios}`
    );
  } else {
    // Si ya existe un registro, actualizamos los intentos fallidos
    const bloqueo = result[0];
    const newAttempts = bloqueo.Intentos + 1;
    const newIntentosReales= bloqueo.IntentosReales + 1;

    if (newAttempts >= MAX_FAILED_ATTEMPTS) {
      const lockUntil = new Date(Date.now() + LOCK_TIME);
      await db.query(
        "UPDATE tblipbloqueados SET Intentos = ?, IntentosReales = ?, Fecha = ?, Hora = ?, lock_until = ? WHERE idUsuarios = ?",
        [newAttempts,newIntentosReales, fechaActual, horaActual, lockUntil, idUsuarios]
      );
      logger.info(
        `Usuario ${idUsuarios} ha alcanzado el número máximo de intentos. Bloqueado hasta ${lockUntil}`
      );
    } else {
      await db.query(
        "UPDATE tblipbloqueados SET Intentos = ?, IntentosReales = ?, Fecha = ?, Hora = ? WHERE idUsuarios = ?",
        [newAttempts, newIntentosReales, fechaActual, horaActual, idUsuarios]
      );
      logger.info(
        `Usuario ${idUsuarios} ha fallado otro intento. Total intentos fallidos: ${newAttempts}`
      );
    }
  }

  // Registrar el intento fallido
  logger.warn(
    `Intento fallido desde IP: ${ip} y clientId: ${clientId} para el usuario con ID ${idUsuarios}`
  );
}

//======================================================================

//Middleware para validar token
const verifyToken = async (req, res, next) => {
  const token = req.cookies.sesionToken;

  if (!token) {
    return res.status(403).json({ message: "No tienes token de acceso." });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const now = Math.floor(Date.now() / 1000);

    // Verificar si la sesión existe y está activa
    const sessionQuery = `
  SELECT * FROM tblsesiones WHERE idUsuario = ? AND tokenSesion = ? AND horaFin IS NULL
`;
    const [sessions] = await req.db.query(sessionQuery, [decoded.id, token]);

    if (sessions.length === 0) {
      // Sesión no encontrada o finalizada
      return res.status(401).json({
        message:
          "Sesión inválida o expirada. Por favor, inicia sesión nuevamente.",
      });
    }

    // Si el token expira en menos de 2 minutos, renovamos el token
    const timeRemaining = decoded.exp - now;
    if (timeRemaining < 2 * 60) {
      const newToken = jwt.sign(
        { id: decoded.id, nombre: decoded.nombre, rol: decoded.rol },
        SECRET_KEY,
        { expiresIn: "30m" }
      );
      res.cookie("sesionToken", newToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "None",
        maxAge: TOKEN_EXPIRATION_TIME,
      });
      const updateSessionQuery = `
      UPDATE tblsesiones
      SET tokenSesion = ?
      WHERE idUsuario = ? AND tokenSesion = ? AND horaFin IS NULL
    `;
      await req.db.query(updateSessionQuery, [newToken, decoded.id, token]);
      token = newToken;

      console.log("Token renovado exitosamente.");
    } else {
      console.log(`Tiempo restante para el token: ${timeRemaining} segundos.`);
    }

    req.user = decoded;
    next();
  } catch (error) {
    // Capturar errores relacionados con la verificación del token
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "El token ha expirado. Por favor, inicia sesión nuevamente.",
      });
    } else if (error.name === "JsonWebTokenError") {
      return res
        .status(400)
        .json({ message: "El token proporcionado no es válido." });
    } else {
      return res.status(500).json({ message: "Error interno del servidor." });
    }
  }
};

// Ruta protegida
usuarioRouter.get("/perfil", verifyToken, async (req, res) => {
  const userId = req.user.id;

  try {
    //Hacemos la consulat de la db
    const query =
      "SELECT Nombre, ApellidoP, ApellidoM, Correo, Telefono, Rol, foto_Perfil, Fecha_ActualizacionF,mfa_secret  FROM tblusuarios WHERE idUsuarios = ?";
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
        Fecha_ActualizacionF: usuario.Fecha_ActualizacionF,
        mfa_secret: usuario.mfa_secret,
      },
    });
  } catch (error) {
    console.error("Error al obtener el perfil del usuario:", error);
    res
      .status(500)
      .json({ message: "Error al obtener el perfil del usuario." });
  }
});

//============================================================================
//Actualizamos el foto de perfil
usuarioRouter.patch("/perfil/:id/foto", async (req, res) => {
  const userId = req.params.id;
  const { foto_perfil } = req.body; // Revisa que foto_perfil llegue bien

  if (!foto_perfil) {
    return res.status(400).json({ message: "Falta la imagen de perfil." });
  }

  try {
    const query =
      "UPDATE tblusuarios SET Foto_Perfil = ?, Fecha_ActualizacionF = ? WHERE idUsuarios = ?";
    const [updateResult] = await req.db.query(query, [
      foto_perfil,
      new Date().toISOString(),
      userId,
    ]);

    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    res.json({
      message: "Foto de perfil actualizada correctamente.",
      foto_perfil,
    });
  } catch (error) {
    console.error("Error al actualizar la foto de perfil:", error);
    res.status(500).json({ message: "Error al actualizar la foto de perfil." });
  }
});

//===============================================================================================
//Actulizar el dato de usaurio en especifico
usuarioRouter.patch("/perfil/:id/:field", async (req, res) => {
  const { id, field } = req.params;
  const { value } = req.body;

  // Lista de campos permitidos
  const allowedFields = ["nombre", "apellidoP", "apellidoM", "telefono"];

  if (!allowedFields.includes(field)) {
    return res
      .status(400)
      .json({ message: "Campo no permitido para actualización." });
  }

  try {
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
usuarioRouter.post(
  "/validarToken/contrasena",

  async (req, res, next) => {
    try {
      const { idUsuario, token } = req.body;

      // Verificar si se recibieron los datos correctos
      if (!idUsuario || !token) {
        return res
          .status(400)
          .json({ message: "ID de usuario o token no proporcionado." });
      }

      // Verificar el token en la tabla tbltoken
      const queryToken =
        "SELECT * FROM tbltoken WHERE idUsuario = ? AND token = ?";
      const [tokenRecord] = await req.db.query(queryToken, [idUsuario, token]);

      if (tokenRecord.length === 0) {
        return res
          .status(400)
          .json({ message: "Token inválido o no encontrado." });
      }

      // Verificar si el token ha expirado
      const currentTime = Date.now();
      const expirationTime = tokenRecord[0].expiration;

      if (currentTime > expirationTime) {
        return res.status(400).json({ message: "El token ha expirado." });
      }

      // Si el token es válido, eliminarlo de la tabla tbltoken
      const deleteTokenQuery =
        "DELETE FROM tbltoken WHERE idUsuario = ? AND token = ?";
      await req.db.query(deleteTokenQuery, [idUsuario, token]);

      // Si todo es correcto
      return res.status(200).json({
        message:
          "Token válido. Puede proceder con el cambio de contraseña. El token ha sido eliminado.",
      });
    } catch (error) {
      console.error("Error al validar el token:", error);
      return res.status(500).json({ message: "Error al validar el token." });
    }
  }
);

//Creamos los Cookies==============================================
//Eliminar Cookies
usuarioRouter.post("/Delete/login", async (req, res) => {
  const token = req.cookies.sesionToken;
  if (!token) {
    return res.status(400).json({ message: "No hay sesión activa." });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

    // Actualizar la horaFin en tblsesiones
    const query = `
      UPDATE tblsesiones
      SET horaFin = NOW()
      WHERE idUsuario = ? AND tokenSesion = ? AND horaFin IS NULL
    `;
    await req.db.query(query, [userId, token]);

    res.clearCookie("sesionToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
    });

    res.json({ message: "Sesión cerrada correctamente." });
  } catch (error) {
    console.error("Error al cerrar la sesión:", error);
    res.status(500).json({ message: "Error al cerrar la sesión." });
  }
});

//=========================================================================================
// Endpoint para cerrar todas las sesiones de un usuario excepto la actual y almacenar la hora del dispositivo
usuarioRouter.post("/cerrar-todas-sesiones", async (req, res) => {
  const { userId, deviceTime } = req.body;
  const currentToken = req.cookies.sesionToken;

  if (!userId || !deviceTime) {
    return res
      .status(400)
      .json({ message: "userId y hora del dispositivo son requeridos." });
  }

  if (!currentToken) {
    return res
      .status(400)
      .json({ message: "Token de sesión no encontrado en las cookies." });
  }

  try {
    const query = `
      UPDATE tblsesiones
      SET horaFin = ?
      WHERE idUsuario = ? AND horaFin IS NULL AND tokenSesion != ?
    `;
    const [result] = await req.db.query(query, [
      deviceTime,
      userId,
      currentToken,
    ]);

    res.json({
      message: "Todas las sesiones excepto la actual han sido cerradas.",
      closedSessions: result.affectedRows,
    });
  } catch (error) {
    console.error("Error al cerrar todas las sesiones:", error);
    res.status(500).json({ message: "Error al cerrar todas las sesiones." });
  }
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
usuarioRouter.post("/", async (req, res, next) => {
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

    res.status(201).json({
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
usuarioRouter.post("/verify-password", async (req, res) => {
  const { idUsuario, currentPassword } = req.body;
  console.log("Esye es lo que recibe,", idUsuario, currentPassword);

  if (!idUsuario || !currentPassword) {
    return res
      .status(400)
      .json({ message: "ID de usuario o contraseña no proporcionados." });
  }

  try {
    // Consulta para obtener la contraseña actual del usuario
    const [usuario] = await req.db.query(
      "SELECT Passw FROM tblusuarios WHERE idUsuarios = ?",
      [idUsuario]
    );

    if (usuario.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    const hashedPassword = usuario[0].Passw;

    // Verificar la contraseña con Argon2
    const validPassword = await argon2.verify(hashedPassword, currentPassword);

    if (!validPassword) {
      return res
        .status(401)
        .json({ valid: false, message: "La contraseña actual es incorrecta." });
    }

    return res
      .status(200)
      .json({ valid: true, message: "La contraseña actual es correcta." });
  } catch (error) {
    console.error("Error al verificar la contraseña:", error);
    return res.status(500).json({ message: "Error interno del servidor." });
  }
});

//Cambiar contraseña y  guradarlo en el historial
usuarioRouter.post("/change-password", async (req, res) => {
  const { idUsuario, newPassword } = req.body;

  if (!idUsuario || !newPassword) {
    return res
      .status(400)
      .json({ message: "ID de usuario o nueva contraseña no proporcionados." });
  }

  try {
    const [historico] = await req.db.query(
      "SELECT contrasena FROM tblhistorialpass WHERE idUsuarios= ? ORDER BY created_at DESC",
      [idUsuario]
    );
    console.log(
      "History",
      [historico],
      "Este es la nueva contraseña ",
      newPassword
    );

    if (!historico || historico.length === 0) {
      console.log(
        "No hay historial de contraseñas, se procederá a guardar la nueva contraseña."
      );
    } else {
      for (let pass of historico) {
        const isMatch = await argon2.verify(pass.contrasena, newPassword);
        console.log(isMatch);

        if (isMatch) {
          return res.status(400).json({
            usedBefore: true,
            message: "La contraseña ya ha sido utilizada anteriormente.",
          });
        }
      }
    }

    // Hashear la nueva contraseña
    const hashedPassword = await argon2.hash(newPassword);

    await req.db.query(
      "UPDATE tblusuarios SET Passw = ? WHERE idUsuarios = ?",
      [hashedPassword, idUsuario]
    );

    await req.db.query(
      "INSERT INTO tblhistorialpass (idUsuarios, contrasena, created_at) VALUES (?, ?, NOW())",
      [idUsuario, hashedPassword]
    );

    const [updatedHistorial] = await req.db.query(
      "SELECT * FROM tblhistorialpass WHERE idUsuarios = ? ORDER BY created_at DESC",
      [idUsuario]
    );

    if (updatedHistorial.length > 3) {
      const oldestPasswordId = updatedHistorial[updatedHistorial.length - 1].id;
      await req.db.query("DELETE FROM tblhistorialpass WHERE id = ?", [
        oldestPasswordId,
      ]);
    }
    // Cerrar todas las sesiones activas del usuario
    await req.db.query(
      "UPDATE tblsesiones SET horaFin = NOW() WHERE idUsuario = ? AND horaFin IS NULL",
      [idUsuario]
    );

    // Eliminar la cookie de sesión
    res.clearCookie("sesionToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
    });

    return res.status(200).json({
      success: true,
      message:
        "Contraseña cambiada correctamente. Todas las sesiones han sido cerradas.",
    });
  } catch (error) {
    console.error("Error al cambiar la contraseña:", error);
    return res.status(500).json({ message: "Error interno del servidor." });
  }
});

//======================sesiones===================================================================
usuarioRouter.post("/sesiones", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "El userId es necesario." });
  }

  try {
    const [sessions] = await req.db.query(
      `
      SELECT 
        id,
        direccionIP,
        horaInicio,
        horaFin,
        tokenSesion,
        tipoDispositivo
      FROM tblsesiones
      WHERE idUsuario = ? AND horaFin IS NULL
    `,
      [userId]
    );

    // Identificar la sesión actual (token coincide con el del usuario)
    const currentToken = req.cookies.sesionToken;
    const sessionsWithCurrentFlag = sessions.map((session) => ({
      ...session,
      isCurrent: session.tokenSesion === currentToken,
    }));

    res.json(sessionsWithCurrentFlag);
  } catch (error) {
    console.error("Error al obtener las sesiones del usuario:", error);
    res
      .status(500)
      .json({ message: "Error al obtener las sesiones del usuario." });
  }
});

//=========================================================================================

// Obtener todos los usuarios con información adicional
usuarioRouter.get("/lista", async (req, res, next) => {
  try {
    const [usuarios] = await req.db.query(`
 SELECT 
      u.idUsuarios,
      u.Correo,
      u.Nombre,
      u.ApellidoP,
      u.ApellidoM,
      u.Rol,
      (SELECT COUNT(*) FROM tblipbloqueados WHERE idUsuarios = u.idUsuarios) AS veces_bloqueado,
      (SELECT COUNT(*) FROM tblhistorialpass WHERE idUsuarios = u.idUsuarios) AS cambios_contrasena,
      (SELECT COUNT(*) FROM tblsesiones WHERE idUsuario = u.idUsuarios) AS veces_sesion
    FROM 
      tblusuarios u
    `);
    res.json(usuarios);
  } catch (error) {
    console.error("Error al obtener la lista de usuarios:", error);
    res.status(500).json({ message: "Error al obtener la lista de usuarios." });
  }
});

//Obtenre mas detalles de sesion del usuario especidifco
usuarioRouter.get("/:idUsuario/sesiones", async (req, res, next) => {
  const { idUsuario } = req.params;
  try {
    const [sesiones] = await req.db.query(
      `
      SELECT 
        id,
        horaInicio,
        horaFin,
        direccionIP,
        tipoDispositivo
      FROM tblsesiones
      WHERE idUsuario = ?
      ORDER BY horaInicio DESC
    `,
      [idUsuario]
    );

    res.json(sesiones);
  } catch (error) {
    console.error("Error al obtener las sesiones del usuario:", error);
    res
      .status(500)
      .json({ message: "Error al obtener las sesiones del usuario." });
  }
});

// Endpoint para registrar la expiración de sesión
usuarioRouter.post("/session-expired", async (req, res) => {
  const { userId } = req.body;
  const ip = getClientIp(req);

  if (!userId) {
    return res.status(400).json({ message: "ID de usuario no proporcionado." });
  }

  try {
    const [sessions] = await req.db.query(
      `SELECT * FROM tblsesiones WHERE idUsuario = ? AND horaFin IS NULL ORDER BY horaInicio DESC LIMIT 1`,
      [userId]
    );

    if (sessions.length === 0) {
      return res.status(404).json({
        message: "No se encontró una sesión activa para este usuario.",
      });
    }

    const session = sessions[0];

    if (session.direccionIP !== ip) {
      return res
        .status(403)
        .json({ message: "No autorizado para cerrar esta sesión." });
    }

    const query = `
      UPDATE tblsesiones
      SET horaFin = NOW()
      WHERE id = ?
    `;
    await req.db.query(query, [session.id]);

    res.json({ message: "Sesión expirada registrada correctamente." });
  } catch (error) {
    console.error("Error al registrar la expiración de sesión:", error);
    res
      .status(500)
      .json({ message: "Error al registrar la expiración de sesión." });
  }
});

//=================================AUDITORIA=================================================
usuarioRouter.post("/auditoria", async (req, res) => {
  const { usuario, correo, accion, dispositivo, ip, fecha_hora, detalles } =
    req.body;

  try {
    const query = `
      INSERT INTO auditoria (usuario, correo, accion, dispositivo, ip, fecha_hora, detalles)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    await req.db.query(query, [
      usuario,
      correo,
      accion,
      dispositivo,
      ip,
      fecha_hora,
      detalles,
    ]);
    res
      .status(200)
      .json({ message: "Registro de auditoría almacenado correctamentex" });
  } catch (error) {
    console.error("Error al guardar el registro de auditoría:", error);
    res
      .status(500)
      .json({ message: "Error al guardar el registro de auditoría" });
  }
});

usuarioRouter.get("/auditoria/lista", async (req, res) => {
  try {
    const query = `
      SELECT 
        id, 
        usuario, 
        correo, 
        accion, 
        dispositivo, 
        ip, 
        fecha_hora, 
        detalles 
      FROM auditoria
      ORDER BY fecha_hora DESC
    `;

    const [auditorias] = await req.db.query(query);

    res.status(200).json(auditorias);
  } catch (error) {
    console.error("Error al obtener los registros de auditoría:", error);
    res
      .status(500)
      .json({ message: "Error al obtener los registros de auditoría" });
  }
});

//==================================================================================

module.exports = usuarioRouter;
