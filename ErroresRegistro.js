const express = require("express");
const winston = require("winston");
const app = express();

app.use(express.json()); // Para poder recibir JSON en las solicitudes

// Configuramos Winston para guardar los logs de errores en un archivo local
const logger = winston.createLogger({
  level: "error",
  format: winston.format.json(),
  transports: [
    // Guardamos los errores en un archivo llamado error.log
    new winston.transports.File({ filename: "error.log" }),
  ],
});

// Ruta para recibir los errores desde el frontend
app.post("/api/logError", (req, res) => {
  const { error, errorInfo } = req.body;

  // Guardamos el error en el archivo de logs
  logger.error({
    message: error,
    stack: errorInfo,
  });

  res.status(201).send("Error registrado en el archivo de log.");
});

// Iniciar el servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
