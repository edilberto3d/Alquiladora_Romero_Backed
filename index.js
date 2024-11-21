require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cron = require("node-cron");
const axios = require('axios');
const winston = require("winston");
require("winston-daily-rotate-file");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const helmet = require("helmet"); 
const path = require('path'); 
const fs = require('fs');
const rateLimit = require("express-rate-limit");
const zlib = require('zlib');




// Importación de consultas
const usuarios = require('./consultas/usuarios');
const email = require('./consultas/email');
const imagen = require('./consultas/clsImagenes');
const mfa = require('./consultas/mfa');
const empresa= require('./consultas/datosEmpresa')
const politicas= require('./consultas/politicas');
const terminos= require('./consultas/terminos');
const deslin= require("./consultas/deslin");


const logDirectory = path.join(__dirname, 'logs');
if (!fs.existsSync(logDirectory)) {
  fs.mkdirSync(logDirectory);
}


// Winston: Rotación diaria de logs
const transport = new winston.transports.DailyRotateFile({
  filename: path.join(logDirectory, 'error-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true, // Los archivos de log serán comprimidos
  maxSize: '20m',
  maxFiles: '14d',
});

const logger = winston.createLogger({
  levels: winston.config.npm.levels,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.json()
  ),
  transports: [
    transport,
    new winston.transports.Console({ level: 'error' }),
  ]
});

// Conexión a MySQL usando un Pool
const mysql = require("mysql2/promise");
const app = express();
const port = process.env.PORT || 3001;

// Configuración del pool de conexiones MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10, 
  queueLimit: 0,
  connectTimeout: 10000, 
});



// Middleware de seguridad
app.use(helmet()); 
app.use(express.json());
app.use(cookieParser());




// Configuración de CORS
const allowedOrigins = ['http://localhost:3000','https://alquiladoraromero.isoftuthh.com' ,'https://alquiladora-romero-backed-1.onrender.com', 'https://localhost:3000'];

app.use(cors({
  origin: function (origin, callback) {
    if (allowedOrigins.includes(origin) || !origin) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS', 'PUT'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  credentials: true,
}));

app.options('*', cors());

// Middleware CSRF: Genera y valida el token CSRF
const csrfProtection = csrf({
  cookie: {
    key: '_csrf',
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', 
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax', 
  },
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
});

app.get('/api/get-csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});


// Middleware para usar el pool de conexiones MySQL
app.use(async (req, res, next) => {
  try {
    req.db = pool; // Usamos el pool de conexiones en lugar de crear nuevas
    console.log("Conexión a la base de datos a través del pool.");
    next();
  } catch (error) {
    console.error("Error al conectar con la base de datos", error);
    logger.error({ message: 'Error al conectar con la base de datos', error });
    res.status(500).send("Error de conexión a la base de datos.");
  }
});

// Rutas protegidas por CSRF
app.use('/api/usuarios', csrfProtection, usuarios);
app.use('/api/email',  csrfProtection, email);
app.use('/api/imagenes', csrfProtection, imagen);
app.use('/api/mfa', csrfProtection, mfa);
app.use('/api/empresa', empresa);
app.use('/api/politicas', politicas);
app.use('/api/terminos',terminos);
app.use('/api/deslin',deslin);

// Ruta para registrar errores de cliente
app.post("/api/logError", (req, res) => {
  const { error, errorInfo } = req.body;
  logger.error({ message: error, stack: errorInfo });
  res.status(201).send("Error registrado en el archivo de log.");
});






app.get('/api/logs', async (req, res) => {
  try {
    const logDirectory = path.join(__dirname, 'logs');

    // Verificar si el directorio de logs existe
    if (!fs.existsSync(logDirectory)) {
      console.error('El directorio de logs no existe:', logDirectory);
      return res.status(500).json({ message: 'No se encontró el directorio de logs.' });
    }

    const logFiles = fs.readdirSync(logDirectory).sort((a, b) => {
      return fs.statSync(path.join(logDirectory, b)).mtime - fs.statSync(path.join(logDirectory, a)).mtime;
    });

    const logs = [];
    const maxLogs = 50; // Limita el número de logs que se envían

    for (const file of logFiles) {
      const logPath = path.join(logDirectory, file);
      let content;

      if (file.endsWith('.gz')) {
        // Si el archivo está comprimido, lo descomprimimos
        const compressedData = fs.readFileSync(logPath);
        content = zlib.gunzipSync(compressedData).toString('utf-8');
      } else {
        // Si el archivo no está comprimido, lo leemos normalmente
        content = fs.readFileSync(logPath, 'utf-8');
      }

      const lines = content.split('\n').filter(line => line).map(line => {
        try {
          return JSON.parse(line);
        } catch (err) {
          console.error('Error al parsear línea de log:', err);
          return null; 
        }
      }).filter(line => line !== null);

      logs.push(...lines);
      if (logs.length >= maxLogs) break;
    }

    res.json(logs.slice(0, maxLogs));
  } catch (error) {
    console.error('Error al leer logs:', error);
    res.status(500).json({ message: 'No se pudieron obtener los logs.' });
  }
});


// Middleware de manejo de errores de CSRF
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    res.status(403).json({ message: 'Token CSRF inválido o faltante.' });
  } else {
    next(err);
  }
});

app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500; 
  const errorDetails = {
    message: err.message || 'Error interno del servidor.',
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined, 
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    timestamp: new Date().toISOString(),
  };

  console.error("Error capturado:", errorDetails);
  logger.error(errorDetails);

  res.status(statusCode).json({ 
    success: false, 
    message: err.message || 'Ocurrió un error en el servidor.',
  });
});




// Iniciamos el servidor
app.listen(port, () => {
  console.log(`Servidor conectado a http://localhost:${port}`);
});