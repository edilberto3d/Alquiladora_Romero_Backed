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




// Importación de consultas
const usuarios = require('./consultas/usuarios');
const email = require('./consultas/email');
const imagen = require('./consultas/clsImagenes');
const mfa = require('./consultas/mfa');
const empresa= require('./consultas/datosEmpresa')
const politicas= require('./consultas/politicas');
const terminos= require('./consultas/terminos');
const deslin= require("./consultas/deslin");


// Winston: Rotación diaria de logs
const transport = new winston.transports.DailyRotateFile({
  filename: 'logs/error-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
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
  queueLimit: 0
});

// Middleware de seguridad
app.use(helmet()); 


// Configuración de CORS
const allowedOrigins = ['http://localhost:3000','https://alquiladoraromero.isoftuthh.com' ,'https://alquiladora-romero-backed-1.onrender.com'];

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

app.use(express.json());
app.use(cookieParser());

// Middleware CSRF: Genera y valida el token CSRF
const csrfProtection = csrf({
  cookie: {
    key: '_csrf',
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', 
    sameSite: 'None', 
  },
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
    
    
    const logFiles = fs.readdirSync(logDirectory).sort((a, b) => {
      return fs.statSync(path.join(logDirectory, b)).mtime - fs.statSync(path.join(logDirectory, a)).mtime;
    });

    const logs = [];
    const maxLogs = 10; 

   
    for (const file of logFiles) {
      const logPath = path.join(logDirectory, file);
      const content = fs.readFileSync(logPath, 'utf-8');
      const lines = content.split('\n').filter(line => line).map(line => JSON.parse(line));
      
      logs.push(...lines);
      if (logs.length >= maxLogs) break; 
    }

    res.json(logs.slice(0, maxLogs));
  } catch (error) {
    console.error('Error al leer logs:', error);
    res.status(500).json({ message: 'No se pudieron obtener los logs.' });
  }
});


// Middleware global para manejo de errores
app.use((err, req, res, next) => {
  const errorDetails = {
    message: err.message,
    stack: err.stack,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    timestamp: new Date().toISOString(),
  };
  console.error("Error capturado:", errorDetails);
  logger.error(errorDetails);
  res.status(500).json({ 
    success: false, 
    message: 'Ocurrió un error en el servidor. Nuestro equipo está trabajando para solucionarlo.' 
  });
});


// Iniciamos el servidor
app.listen(port, () => {
  console.log(`Servidor conectado a http://localhost:${port}`);
});
