const express = require("express");
const csrf = require("csurf");

const politicasRouter = express.Router();
politicasRouter.use(express.json());

// Protección CSRF, usando cookies
const csrfProtection = csrf({ cookie: true });

// Obtener todas las políticas
politicasRouter.get("/", async (req, res) => {
  try {
    // Primero, actualiza todas las políticas con fecha de vigencia expirada
    await req.db.query(
      "UPDATE politicas SET estado = 'no vigente' WHERE fechaVigencia < CURDATE() AND estado = 'vigente'"
    );

    // Verifica que solo una política esté vigente, la más reciente
    const [politicasVigentes] = await req.db.query(
      "SELECT id FROM politicas WHERE estado = 'vigente' ORDER BY created_at DESC"
    );
    if (politicasVigentes.length > 1) {
      for (let i = 1; i < politicasVigentes.length; i++) {
        await req.db.query(
          "UPDATE politicas SET estado = 'no vigente' WHERE id = ?",
          [politicasVigentes[i].id]
        );
      }
    }

    const [politicas] = await req.db.query(
      "SELECT * FROM politicas ORDER BY created_at DESC"
    );

    const parsedPoliticas = politicas.map((politica) => ({
      ...politica,
      versio: politica.versio ? politica.versio.toString() : null,
      secciones:
        typeof politica.secciones === "string"
          ? JSON.parse(politica.secciones)
          : [],
    }));

    res.json(parsedPoliticas);
  } catch (error) {
    console.error("Error al obtener las políticas:", error);
    res.status(500).json({ message: "No se pudo obtener las políticas." });
  }
});

// Obtener una política para usuarios finales (sin autenticación)
politicasRouter.get("/vigente", async (req, res) => {
  try {
    const [terminos] = await req.db.query(`
      SELECT * 
      FROM politicas 
      WHERE estado = 'vigente' 
        AND CURDATE() <= fechaVigencia 
      ORDER BY versio DESC 
      LIMIT 1
    `);
    if (terminos.length === 0) {
      return res.status(404).json({ error: "No hay Políticas vigentes" });
    }
    res.json(terminos[0]);
  } catch (error) {
    console.error("Error al obtener Política vigente:", error);
    res.status(500).json({ error: "No se pudo obtener la Política vigente" });
  }
});

// Obtener una política por su ID
politicasRouter.get("/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const [termino] = await req.db.query(
      "SELECT * FROM politicas WHERE id = ?",
      [id]
    );

    if (termino.length === 0) {
      return res.status(404).json({ error: "Política no encontrada" });
    }

    res.json(termino[0]);
  } catch (error) {
    console.error("Error al obtener la Política:", error);
    res.status(500).json({ error: "No se pudo obtener la Política" });
  }
});

// Crear una nueva política (versión 1.0 o incrementada)
politicasRouter.post("/", csrfProtection, async (req, res) => {
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res
      .status(400)
      .json({
        error:
          "Los campos título, contenido y fecha de vigencia son obligatorios",
      });
  }

  let connection;

  try {
    // Obtener una conexión para iniciar una transacción
    connection = await req.db.getConnection();
    await connection.beginTransaction();

    // Actualiza cualquier política existente en estado "vigente" a "no vigente"
    await connection.query(
      "UPDATE politicas SET estado = 'no vigente' WHERE estado = 'vigente'"
    );

    // Obtener la versión máxima existente
    const [ultimoRegistro] = await connection.query(
      "SELECT MAX(versio) as ultimaVersion FROM politicas"
    );
    const nuevaVersion = ultimoRegistro[0].ultimaVersion
      ? (parseFloat(ultimoRegistro[0].ultimaVersion) + 1.0).toFixed(1)
      : "1.0";

    // Insertar la nueva política con la nueva versión
    const insertQuery =
      "INSERT INTO politicas (titulo, contenido, fechaVigencia, secciones, versio, estado, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'vigente', NOW(), NOW())";

    await connection.query(insertQuery, [
      titulo,
      contenido,
      fechaVigencia,
      JSON.stringify(secciones || []),
      nuevaVersion,
    ]);

    // Commit de la transacción
    await connection.commit();

    res.status(201).json({ message: "Política creada exitosamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error al crear la política:", error);
    res.status(500).json({ error: "No se pudo crear la política" });
  } finally {
    if (connection) connection.release();
  }
});

// Crear una nueva versión de una política existente
politicasRouter.post("/:id/nueva-version", csrfProtection, async (req, res) => {
  const { id } = req.params;
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res
      .status(400)
      .json({
        error:
          "Los campos título, contenido y fecha de vigencia son obligatorios",
      });
  }

  let connection;

  try {
    // Obtener una conexión para iniciar una transacción
    connection = await req.db.getConnection();
    await connection.beginTransaction();

    // Obtener el término actual y bloquearlo para evitar condiciones de carrera
    const [terminoActual] = await connection.query(
      "SELECT * FROM politicas WHERE id = ? FOR UPDATE",
      [id]
    );

    if (terminoActual.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: "Política no encontrada" });
    }

    const termino = terminoActual[0];

    // Marcar el término actual como 'no vigente'
    await connection.query(
      "UPDATE politicas SET estado = 'no vigente' WHERE id = ?",
      [id]
    );

    // Obtener la versión máxima existente
    const [ultimoRegistro] = await connection.query(
      "SELECT MAX(versio) as ultimaVersion FROM politicas"
    );
    const nuevaVersion = ultimoRegistro[0].ultimaVersion
      ? (parseFloat(ultimoRegistro[0].ultimaVersion) + 1.0).toFixed(1)
      : "1.0";

    // Insertar la nueva versión
    const insertQuery =
      "INSERT INTO politicas (titulo, contenido, fechaVigencia, secciones, versio, estado, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'vigente', NOW(), NOW())";

    await connection.query(insertQuery, [
      titulo,
      contenido,
      fechaVigencia,
      JSON.stringify(secciones || []),
      nuevaVersion,
    ]);

    // Commit de la transacción
    await connection.commit();

    res
      .status(201)
      .json({ message: "Nueva versión de la política creada exitosamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error al crear nueva versión:", error);
    res.status(500).json({ error: "No se pudo crear la nueva versión" });
  } finally {
    if (connection) connection.release();
  }
});

// Eliminar una política
politicasRouter.delete("/:id", csrfProtection, async (req, res) => {
  const { id } = req.params;

  let connection;

  try {
    // Obtener una conexión para iniciar una transacción
    connection = await req.db.getConnection();
    await connection.beginTransaction();

    // Obtener la política a eliminar y bloquearla
    const [politica] = await connection.query(
      "SELECT * FROM politicas WHERE id = ? FOR UPDATE",
      [id]
    );

    if (politica.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: "Política no encontrada" });
    }

    const politicaActual = politica[0];

    // Marcar la política como "eliminada"
    await connection.query(
      "UPDATE politicas SET estado = 'eliminado' WHERE id = ?",
      [id]
    );

    // Si la política eliminada era "vigente", busca la siguiente más reciente y válida
    if (politicaActual.estado === "vigente") {
      const [ultimaPolitica] = await connection.query(`
        SELECT * FROM politicas 
        WHERE estado = 'no vigente' AND fechaVigencia >= CURDATE() 
        ORDER BY fechaVigencia DESC, versio DESC 
        LIMIT 1
      `);

      if (ultimaPolitica.length > 0) {
        await connection.query(
          "UPDATE politicas SET estado = 'vigente' WHERE id = ?",
          [ultimaPolitica[0].id]
        );
      }
    }

    // Commit de la transacción
    await connection.commit();

    res.json({ message: "Política marcada como eliminada exitosamente" });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error al eliminar la política:", error);
    res.status(500).json({ error: "No se pudo eliminar la política" });
  } finally {
    if (connection) connection.release();
  }
});

module.exports = politicasRouter;
