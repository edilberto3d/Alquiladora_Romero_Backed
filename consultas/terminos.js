const express = require('express');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');

const terminosRouter = express.Router();
terminosRouter.use(express.json());

// Protección CSRF usando cookies
const csrfProtection = csrf({ cookie: true });

// Limitar las solicitudes para evitar abusos
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100,
  message: "Has alcanzado el límite de solicitudes, intenta más tarde.",
});

terminosRouter.use(apiLimiter); // Aplicamos el rate limiter

// Obtener todos los términos
terminosRouter.get('/', async (req, res) => {
  try {
    const [terminos] = await req.db.query("SELECT * FROM terminos ORDER BY created_at DESC");
    res.json(terminos);
  } catch (error) {
    console.error('Error al obtener términos:', error);
    res.status(500).json({ error: 'No se pudieron obtener los términos' });
  }
});

// Obtener un término por su ID
terminosRouter.get('/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [termino] = await req.db.query("SELECT * FROM terminos WHERE id = ?", [id]);

    if (termino.length === 0) {
      return res.status(404).json({ error: 'Término no encontrado' });
    }

    res.json(termino[0]);
  } catch (error) {
    console.error('Error al obtener el término:', error);
    res.status(500).json({ error: 'No se pudo obtener el término' });
  }
});

// Crear un nuevo término (con CSRF y cookies)
terminosRouter.post('/', csrfProtection, async (req, res) => {
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({ error: 'Los campos título, contenido y fecha de vigencia son obligatorios' });
  }

  try {
    const query = "INSERT INTO terminos (titulo, contenido, fechaVigencia, secciones) VALUES (?, ?, ?, ?)";
    await req.db.query(query, [titulo, contenido, fechaVigencia, JSON.stringify(secciones)]);
    res.status(201).json({ message: 'Término creado exitosamente' });
  } catch (error) {
    console.error('Error al crear término:', error);
    res.status(500).json({ error: 'No se pudo crear el término' });
  }
});

// Actualizar un término existente (con CSRF y cookies)
terminosRouter.put('/:id', csrfProtection, async (req, res) => {
  const { id } = req.params;
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({ error: 'Los campos título, contenido y fecha de vigencia son obligatorios' });
  }

  try {
    const query = "UPDATE terminos SET titulo = ?, contenido = ?, fechaVigencia = ?, secciones = ?, updated_at = NOW() WHERE id = ?";
    const [result] = await req.db.query(query, [titulo, contenido, fechaVigencia, JSON.stringify(secciones), id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Término no encontrado' });
    }

    res.json({ message: 'Término actualizado exitosamente' });
  } catch (error) {
    console.error('Error al actualizar término:', error);
    res.status(500).json({ error: 'No se pudo actualizar el término' });
  }
});

// Eliminar un término (con CSRF y cookies)
terminosRouter.delete('/:id', csrfProtection, async (req, res) => {
  const { id } = req.params;

  try {
    const query = "DELETE FROM terminos WHERE id = ?";
    const [result] = await req.db.query(query, [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Término no encontrado' });
    }

    res.json({ message: 'Término eliminado exitosamente' });
  } catch (error) {
    console.error('Error al eliminar término:', error);
    res.status(500).json({ error: 'No se pudo eliminar el término' });
  }
});


module.exports = terminosRouter;
