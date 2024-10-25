const express = require('express');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');

const politicasRouter = express.Router();
politicasRouter.use(express.json());

// Protección CSRF, usando cookies
const csrfProtection = csrf({ cookie: true });

// Limitar las solicitudes para evitar abusos (rate limiting)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100,
  message: "Has alcanzado el límite de solicitudes, intenta más tarde.",
});

politicasRouter.use(apiLimiter); // Aplicamos el rate limiter

// Obtener todas las políticas
politicasRouter.get("/", async (req, res) => {
  try {
    const [politicas] = await req.db.query("SELECT * FROM politicas ORDER BY created_at DESC");
    res.json(politicas);
  } catch (error) {
    console.error("Error al obtener las políticas:", error);
    res.status(500).json({ message: "No se pudo obtener las políticas." });
  }
});

// Obtener una política por su ID
politicasRouter.get("/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const [politica] = await req.db.query("SELECT * FROM politicas WHERE id = ?", [id]);

    if (politica.length === 0) {
      return res.status(404).json({ message: "Política no encontrada." });
    }

    res.json(politica[0]);
  } catch (error) {
    console.error("Error al obtener la política:", error);
    res.status(500).json({ message: "No se pudo obtener la política." });
  }
});

// Crear una nueva política (con CSRF y cookies)
politicasRouter.post("/", csrfProtection, async (req, res) => {
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({ message: "Título, contenido y fecha de vigencia son obligatorios." });
  }

  try {
    const query = "INSERT INTO politicas (titulo, contenido, fechaVigencia, secciones) VALUES (?, ?, ?, ?)";
    await req.db.query(query, [titulo, contenido, fechaVigencia, JSON.stringify(secciones)]);
    res.status(201).json({ message: "Política creada exitosamente." });
  } catch (error) {
    console.error("Error al crear la política:", error);
    res.status(500).json({ message: "No se pudo crear la política." });
  }
});

// Actualizar una política existente (con CSRF y cookies)
politicasRouter.put("/:id", csrfProtection, async (req, res) => {
  const { id } = req.params;
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({ message: "Título, contenido y fecha de vigencia son obligatorios." });
  }

  try {
    const query = "UPDATE politicas SET titulo = ?, contenido = ?, fechaVigencia = ?, secciones = ?, updated_at = NOW() WHERE id = ?";
    const [result] = await req.db.query(query, [titulo, contenido, fechaVigencia, JSON.stringify(secciones), id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Política no encontrada." });
    }

    res.json({ message: "Política actualizada exitosamente." });
  } catch (error) {
    console.error("Error al actualizar la política:", error);
    res.status(500).json({ message: "No se pudo actualizar la política." });
  }
});

// Eliminar una política (con CSRF y cookies)
politicasRouter.delete("/:id", csrfProtection, async (req, res) => {
  const { id } = req.params;

  try {
    const query = "DELETE FROM politicas WHERE id = ?";
    const [result] = await req.db.query(query, [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Política no encontrada." });
    }

    res.json({ message: "Política eliminada exitosamente." });
  } catch (error) {
    console.error("Error al eliminar la política:", error);
    res.status(500).json({ message: "No se pudo eliminar la política." });
  }
});


module.exports = politicasRouter;
