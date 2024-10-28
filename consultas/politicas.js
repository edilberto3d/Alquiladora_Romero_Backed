const express = require('express');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');

const politicasRouter = express.Router();
politicasRouter.use(express.json());

// Protección CSRF, usando cookies
const csrfProtection = csrf({ cookie: true });



// Obtener todas las políticas
politicasRouter.get("/", async (req, res) => {
  try {
    // Primero, actualiza todas las políticas con fecha de vigencia expirada
    await req.db.query("UPDATE politicas SET estado = 'no vigente' WHERE fechaVigencia < CURDATE() AND estado = 'vigente'");

    // Verifica que solo una política esté vigente, la más reciente
    const [politicasVigentes] = await req.db.query("SELECT id FROM politicas WHERE estado = 'vigente' ORDER BY created_at DESC");
    if (politicasVigentes.length > 1) {
      for (let i = 1; i < politicasVigentes.length; i++) {
        await req.db.query("UPDATE politicas SET estado = 'no vigente' WHERE id = ?", [politicasVigentes[i].id]);
      }
    }

    const [politicas] = await req.db.query("SELECT * FROM politicas ORDER BY created_at DESC");

    const parsedPoliticas = politicas.map(politica => ({
      ...politica,
      versio: politica.versio ? politica.versio.toString() : null,
      secciones: typeof politica.secciones === 'string' ? JSON.parse(politica.secciones) : []
    }));

    res.json(parsedPoliticas);
  } catch (error) {
    console.error("Error al obtener las políticas:", error);
    res.status(500).json({ message: "No se pudo obtener las políticas." });
  }
});



//====================================================================================================
// Obtener una política para usuarios finales (sin autenticación)
politicasRouter.get("/vigente", async (req, res) => {
  try {
    const [terminos] = await req.db.query("SELECT * FROM politicas WHERE estado = 'vigente' ORDER BY versio DESC LIMIT 1");
    if (terminos.length === 0) {
      return res.status(404).json({ error: 'No hay Poloticas vigentes' });
    }
    res.json(terminos[0]);
  } catch (error) {
    console.error('Error al obtener Politicas vigente:', error);
    res.status(500).json({ error: 'No se pudo obtener el Politicas vigente' });
  }
});

//===================================================================
// Obtener un Politicas por su ID
politicasRouter.get('/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [termino] = await req.db.query("SELECT * FROM politicas WHERE id = ?", [id]);

    if (termino.length === 0) {
      return res.status(404).json({ error: 'Politicas no encontrado' });
    }

    res.json(termino[0]);
  } catch (error) {
    console.error('Error al obtener el Polotica:', error);
    res.status(500).json({ error: 'No se pudo obtener el Polotica' });
  }
});


//===========================================================================================================
// Crear un nuevo término (versión 1.0)
politicasRouter.post('/', csrfProtection, async (req, res) => {
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({ error: 'Los campos título, contenido y fecha de vigencia son obligatorios' });
  }

  try {
    // Actualiza cualquier política existente en estado "vigente" a "no vigente"
    await req.db.query("UPDATE politicas SET estado = 'no vigente' WHERE estado = 'vigente'");

    const [ultimoRegistro] = await req.db.query("SELECT MAX(versio) as ultimaVersion FROM politicas");
    const nuevaVersion = ultimoRegistro.ultimaVersion ? (parseFloat(ultimoRegistro.ultimaVersion) + 1.0).toFixed(1) : '1.0';

    const query = "INSERT INTO politicas (titulo, contenido, fechaVigencia, secciones, versio, estado, created_at) VALUES (?, ?, ?, ?, ?, 'vigente', NOW())";
    await req.db.query(query, [titulo, contenido, fechaVigencia, JSON.stringify(secciones), nuevaVersion]);

    res.status(201).json({ message: 'Política creada exitosamente' });
  } catch (error) {
    console.error('Error al crear la política:', error);
    res.status(500).json({ error: 'No se pudo crear la política' });
  }
});

//===========================================================================================================
// Crear una nueva versión de un término existente
politicasRouter.post('/:id/nueva-version', csrfProtection,  async (req, res) => {
  const { id } = req.params;
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({ error: 'Los campos título, contenido y fecha de vigencia son obligatorios' });
  }

  try {
    // Obtener el término actual
    const [terminoActual] = await req.db.query("SELECT * FROM politicas WHERE id = ?", [id]);

    if (terminoActual.length === 0) {
      return res.status(404).json({ error: 'Término no encontrado' });
    }

    // Marcar el término actual como 'no vigente'
    await req.db.query("UPDATE politicas SET estado = 'no vigente' WHERE id = ?", [id]);

    // Calcular nueva versión
    const versionAnterior = parseFloat(terminoActual[0].versio);
    const nuevaVersion = (versionAnterior + 1.0).toFixed(1); 

    // Insertar nueva versión
    const query = "INSERT INTO politicas (titulo, contenido, fechaVigencia, secciones, versio, estado, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())";
    await req.db.query(query, [titulo, contenido, fechaVigencia, JSON.stringify(secciones), nuevaVersion, 'vigente']);

    res.status(201).json({ message: 'Nueva versión del término creada exitosamente' });
  } catch (error) {
    console.error('Error al crear nueva versión:', error);
    res.status(500).json({ error: 'No se pudo crear la nueva versión' });
  }
});


politicasRouter.delete('/:id', csrfProtection, async (req, res) => {
  const { id } = req.params;

  try {
    const [politica] = await req.db.query("SELECT * FROM politicas WHERE id = ?", [id]);

    if (politica.length === 0) {
      return res.status(404).json({ error: 'Política no encontrada' });
    }

    // Marcar la política como "eliminada"
    await req.db.query("UPDATE politicas SET estado = 'eliminado' WHERE id = ?", [id]);

    // Si la política eliminada era "vigente", busca la siguiente más reciente y válida
    if (politica[0].estado === 'vigente') {
      const [ultimaPolitica] = await req.db.query(`
        SELECT * FROM politicas 
        WHERE estado = 'no vigente' AND fechaVigencia >= CURDATE() 
        ORDER BY fechaVigencia DESC, versio DESC 
        LIMIT 1
      `);

      if (ultimaPolitica.length > 0) {
        await req.db.query("UPDATE politicas SET estado = 'vigente' WHERE id = ?", [ultimaPolitica[0].id]);
      }
    }

    res.json({ message: 'Política marcada como eliminada exitosamente' });
  } catch (error) {
    console.error('Error al eliminar la política:', error);
    res.status(500).json({ error: 'No se pudo eliminar la política' });
  }
});



module.exports = politicasRouter;
