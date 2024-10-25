require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cron = require("node-cron");
const moment = require('moment-timezone');
const axios = require('axios');
const winston = require("winston");
require("winston-daily-rotate-file");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const helmet = require("helmet"); // Para agregar cabeceras de seguridad

// Importación de consultas
const usuarios = require('./consultas/usuarios');
const email = require('./consultas/email');
const imagen = require('./consultas/clsImagenes');
const mfa = require('./consultas/mfa');
const empresa= require('./consultas/datosEmpresa')

// Winston: Rotación diaria de logs
const transport = new winston.transports.DailyRotateFile({
  filename: 'logs/error-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxSize: '20m',
  maxFiles: '14d',
});

const logger = winston.createLogger({
  level: 'error',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    transport
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
app.use(helmet()); // Cabeceras de seguridad

// Configuración de CORS
const allowedOrigins = ['http://localhost:3000'];

app.use(cors({
  origin: function (origin, callback) {
    if (allowedOrigins.includes(origin) || !origin) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  credentials: true,
}));

app.options('*', cors());

app.use(express.json());
app.use(cookieParser());

// Middleware CSRF: Genera y valida el token CSRF
const csrfProtection = csrf({ cookie: true });
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
app.use('/api/email', csrfProtection, email);
app.use('/api/imagenes', csrfProtection, imagen);
app.use('/api/mfa', csrfProtection, mfa);
app.use('/api/empresa', csrfProtection, empresa);

// Ruta para registrar errores de cliente
app.post("/api/logError", (req, res) => {
  const { error, errorInfo } = req.body;
  logger.error({ message: error, stack: errorInfo });
  res.status(201).send("Error registrado en el archivo de log.");
});

// Middleware global para manejo de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  logger.error({ message: 'Error inesperado en el servidor', error: err.stack });
  res.status(500).send("Algo salió mal.");
});

// Iniciamos el servidor
app.listen(port, () => {
  console.log(`Servidor conectado a http://localhost:${port}`);
});
