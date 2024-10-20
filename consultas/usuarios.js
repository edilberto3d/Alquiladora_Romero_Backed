const express = require("express");
const argon2 = require("argon2");
const cookieParser = require("cookie-parser");
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require("uuid")
const rateLimit = require("express-rate-limit");
const winston = require('winston');
const crypto = require("crypto");

const usuarioRouter = express.Router();
usuarioRouter.use(express.json());
usuarioRouter.use(cookieParser());

//Variables para el ip
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME = 10 * 60 * 1000; // 10 minutos
const TOKEN_EXPIRATION_TIME = 10 * 60 * 1000; // 10 minutos para el JWT


const SECRET_KEY = process.env.SECRET_KEY.padEnd(32, ' ');


const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'login-attempts.log' })
  ]
});

function encryptClientId(clientId) {
  const IV_LENGTH = 16;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(SECRET_KEY, 'utf-8'), iv);
  let encrypted = cipher.update(clientId, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}


function decryptClientId(encrypted) {
  const [iv, encryptedText] = encrypted.split(":");
  const decipher = crypto.createDecipheriv("aes-256-cbc", SECRET_KEY, Buffer.from(iv, "hex"));
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const ip = forwarded ? forwarded.split(/, /)[0] : req.connection.remoteAddress;
  return ip;
}

function getOrCreateClientId(req, res) {
  let clientId = req.cookies.clientId; 
  if (!clientId) {
    clientId = uuidv4(); 
    const encryptedClientId = encryptClientId(clientId);
    res.cookie("clientId", encryptedClientId, { maxAge: 365 * 24 * 60 * 60 * 1000, httpOnly: true, secure: true, sameSite: "Strict" });
  } else {
    clientId = decryptClientId(clientId);
  }
  return clientId;
}



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
//==================================================================================

//Login
usuarioRouter.post("/login", async (req, res, next) => {
  try {
    const { email, contrasena } = req.body;

    //Obtener Ip
    const ip= getClientIp(req);
    const clientId = getOrCreateClientId(req, res);

    logger.info(`Intento de inicio de sesión desde IP: ${ip}, clientId: ${clientId}`);

  
  
    //Realizamos la tabla de bloqueos
    const bloqueoQuery='SELECT * FROM tblipbloqueados WHERE Ip= ? OR clienteId = ?';
    const [bloqueos]= await req.db.query(bloqueoQuery, [ip, clientId]);

    if (bloqueos.length > 0) {
      const bloqueo = bloqueos[0];
   

      if (bloqueo.lock_until && new Date() > new Date(bloqueo.lock_until)) {
       
        await req.db.query("DELETE FROM tblipbloqueados WHERE Ip = ? OR clienteId = ?", [ip, clientId]);
        console.log("Tiempo de bloqueo expirado, desbloqueando.");
    } else if (bloqueo.Intentos >= MAX_FAILED_ATTEMPTS) {
      
        if (bloqueo.lock_until) {
            const tiempoRestante = Math.ceil((new Date(bloqueo.lock_until) - new Date()) / 1000);
            console.log("Tiempo restante del desbloqueo", tiempoRestante)
            return res.status(403).json({
                message: `Dispositivo bloqueado. Inténtalo de nuevo en ${tiempoRestante} segundos.`,
                tiempoRestante,
            });
          
        } else {
          
            const lockUntil = new Date(Date.now() + LOCK_TIME);
            await req.db.query("UPDATE tblipbloqueados SET lock_until = ? WHERE Ip = ? OR clienteId = ?", [lockUntil, ip, clientId]);
            return res.status(403).json({
                message: "Has superado el número máximo de intentos. Dispositivo bloqueado.",
            });
        }
    }

    }


    //Buscar el usuario por correo en la db
    const query = "SELECT * FROM tblusuarios WHERE Correo = ?";

    const [usuarios] = await req.db.query(query, [email]);


    if (usuarios.length === 0) {
      await handleFailedAttempt(ip, clientId, req.db);
      console.log("Correo  o contraseña incorrectos")
      return res.status(401).json({ message: "Correo o contraseña incorrectos." });
    }


    const usuario = usuarios[0];
    console.log("Usuario ", usuario);

    //Comparamos la contraseña con la que esta en la db
    const validPassword = await argon2.verify(usuario.Passw, contrasena);

    if (!validPassword) {
      await handleFailedAttempt(ip, clientId, req.db);
      return res.status(401).json({ message: "Correo o contraseña incorrectos." });
    }


    //En caso de iniciar sesion eliminar intentos
    await req.db.query("DELETE FROM tblipbloqueados WHERE Ip = ? OR clienteId = ? ", [ip, clientId]);

    //Generamos el token JWT
    const token = jwt.sign({ id: usuario.idUsuarios,nombre: usuario.Nombre, rol: usuario.Rol }, SECRET_KEY, { expiresIn: '10m' });
    
    //Creamos la cookie de sesion con HTToNLY, sECURE, sAMEsITE
    res.cookie("sesionToken", token,{
        httpOnly: true,
        secure:true,
        sameSite: "Strict",
        maxAge:10 * 60 * 1000,
    })


    //Si la contrasela es correcta
    res.json({
      message: "Login exitoso",
      user: {
        idUsuarios: usuario.idUsuarios,
        Nombre: usuario.Nombre,
        ApellidoP: usuario.ApellidoP,
        ApellidoM: usuario.ApellidoM,
        Correo: usuario.Correo,
        Telefono: usuario.Telefono,
        Rol: usuario.Rol,
        // agrega otros campos necesarios
      },
    });
    console.log("login exitoso")
    console.log(`Usuario ${usuario.idUsuarios} inició sesión desde IP: ${ip} y clienteId: ${clientId}`)

    logger.info(`Usuario ${usuario.idUsuarios} inició sesión desde IP: ${ip} y clienteId: ${clientId}`);
  } catch (error) {
    next(error);
  }
});

//================================Manejo de intentos fallidos de login=======================================
async function handleFailedAttempt(ip, clientId, db) {
  const [result] = await db.query("SELECT * FROM tblipbloqueados WHERE Ip = ? OR clienteId = ?", [ip, clientId]);

  const currentDate = new Date();
  const fechaActual = currentDate.toISOString().split('T')[0];
  const horaActual = currentDate.toTimeString().split(' ')[0];

  if (result.length === 0) {
    await db.query("INSERT INTO tblipbloqueados (Ip, clienteId, Fecha, Hora, Intentos) VALUES (?, ?, ?, ?, ?)", 
      [ip, clientId, fechaActual, horaActual, 1]);
  } else {
    const bloqueo = result[0];
    const newAttempts = bloqueo.Intentos + 1;

    if (newAttempts >= MAX_FAILED_ATTEMPTS) {
      const lockUntil = new Date(Date.now() + LOCK_TIME);
      await db.query("UPDATE tblipbloqueados SET Intentos = ?, Fecha = ?, Hora = ?, lock_until = ? WHERE Ip = ? OR clienteId = ?", 
        [newAttempts, fechaActual, horaActual, lockUntil, ip, clientId]);
    } else {
      await db.query("UPDATE tblipbloqueados SET Intentos = ?, Fecha = ?, Hora = ? WHERE Ip = ? OR clienteId = ?", 
        [newAttempts, fechaActual, horaActual, ip, clientId]);
    }
  }

  // Registrar intentos fallidos
  logger.warn(`Intento fallido desde IP: ${ip} y clientId: ${clientId}`);
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
    if (decoded.exp - now < 2 * 60) {
      const newToken = jwt.sign({ id: decoded.id, rol: decoded.rol }, SECRET_KEY, { expiresIn: '10m' });
      res.cookie("sesionToken", newToken, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        maxAge: TOKEN_EXPIRATION_TIME,
      });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Token inválido o caducado." });
  }
};

// Ruta protegida 
usuarioRouter.get("/perfil", verifyToken, (req, res) => {
  console.log("Iniciastes correctamente")
  res.json({ message: "Bienvenido al perfil", user: req.user });
});



//Creamos los Cookies==============================================
   //Eliminar Cookies
   usuarioRouter.post("/Delete/login", (req, res) => {
    res.clearCookie("sesionToken", {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
    });

    res.json({ message: "Sesión cerrada correctamente." });
});


module.exports = usuarioRouter;
