require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cron = require("node-cron");
const moment = require('moment-timezone'); 
const axios = require('axios');
const winston = require("winston");

//iMPORTAMOS LAS CONSULTAS
const usuarios=require('./consultas/usuarios');
const email=require('./consultas/email')



const logger = winston.createLogger({
    level: "error",
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    ),
    transports: [
      // Guardamos los errores en un archivo llamado error.log
      new winston.transports.File({ filename: "error.log" }),
    ],
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


app.use(cors({
    origin: "http://localhost:3000", 
    credentials: true 
}));

app.use(express.json());

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
 app.use('/api/usuarios', usuarios);
 app.use('/api/email', email);

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