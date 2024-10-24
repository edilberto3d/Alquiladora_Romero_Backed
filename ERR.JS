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

// Importamos las consultas
const usuarios = require('./consultas/usuarios');
const email = require('./consultas/email');
const imagen = require('./consultas/clsImagenes');
const mfa = require('./consultas/mfa');

// Configuración de Winston para manejo de logs
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

// Conexión a la base de datos con pool de conexiones
const mysql = require("mysql2/promise");
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10, // Número máximo de conexiones
  queueLimit: 0
});

// Configuración de Express
const app = express();
const port = process.env.PORT || 3001;

// CORS
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

// Middleware de protección CSRF
const csrfProtection = csrf({ cookie: true });

// Ruta para obtener el token CSRF
app.get('/api/get-csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Middleware para conexión a MySQL
app.use(async (req, res, next) => {
  try {
    req.db = await pool.getConnection();
    console.log("Conexión a la base de datos exitosa");
    await req.db.beginTransaction(); // Si estás usando transacciones
    next();
  } catch (error) {
    console.error("Error al conectar con la base de datos", error);
    res.status(500).send("Error de conexión a la base de datos.");
  } finally {
    if (req.db) req.db.release(); // Liberar la conexión
  }
});

// Rutas y API endpoints
app.use('/api/usuarios', csrfProtection, usuarios);
app.use('/api/email', csrfProtection, email);
app.use('/api/imagenes', csrfProtection, imagen);
app.post('/api/enable-mfa', csrfProtection, mfa.enableMFA);
app.post('/api/verify-mfa', csrfProtection, mfa.verifyMFA);

// Ruta para manejo de errores en los logs
app.post("/api/logError", (req, res) => {
  const { error, errorInfo } = req.body;

  // Guardamos el error en el archivo de logs usando Winston
  logger.error({
    message: error,
    stack: errorInfo,
  });

  res.status(201).send("Error registrado en el archivo de log.");
});

// Middleware para verificar el CSRF token en las rutas que lo requieran
app.use('/api/*', (req, res, next) => {
  const csrfToken = req.headers['x-csrf-token'];

  if (!csrfToken) {
    return res.status(403).json({ message: 'CSRF token faltante' });
  }

  next();
});

// Manejador de errores global para capturar cualquier excepción
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ message: 'Error interno del servidor.' });
});

// Iniciamos el servidor
app.listen(port, () => {
  console.log(`Servidor conectado a http://localhost:${port}`);
});
