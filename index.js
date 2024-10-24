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

//iMPORTAMOS LAS CONSULTAS
const usuarios=require('./consultas/usuarios');
const email=require('./consultas/email')
const imagen= require('./consultas/clsImagenes');
const mfa= require('./consultas/mfa')



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




// Realizamos la conexión a la base de datos de mysql
const mysql = require("mysql2/promise");
const app = express();
const port = process.env.PORT || 3001;

// Conexión a mysql
const mysqlConfig = {
    host: process.env.DB_HOST ,
    user: process.env.DB_USER ,
    password: process.env.DB_PASSWORD ,
    database: process.env.DB_NAME,
}

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
// Middleware CSRF: Aquí se genera y valida el token CSRF
const csrfProtection = csrf({ cookie: true });
// Ruta para obtener el token CSRF
app.get('/api/get-csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});


// Función para hacer la conexión a MySQL 
app.use(async (req, res, next) => {
    try {
        req.db = await mysql.createConnection(mysqlConfig); 
        console.log("Conexión a la base de datos exitosa");
        next();
    } catch (error) {
        console.error("Error al conectar con la base de datos", error);
        res.status(500).send("Error de conexión a la base de datos.");
    }
});

 // definir tus rutas
app.use('/api/usuarios', csrfProtection, usuarios);
app.use('/api/email', csrfProtection, email);
app.use('/api/imagenes', csrfProtection, imagen);
app.use('/api/mfa', csrfProtection, mfa);

 app.post("/api/logError", (req, res) => {
    const { error, errorInfo } = req.body;
  
    // Guardamos el error en el archivo de logs usando Winston
    logger.error({
      message: error,
      stack: errorInfo,
    });
  
    res.status(201).send("Error registrado en el archivo de log.");
  });
  

// Iniciamos el servidor
app.listen(port, () => {
    console.log(`servidor contectado a http://localhost:${port}`);
});