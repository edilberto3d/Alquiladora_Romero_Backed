const express = require('express');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');

const terminosRouter = express.Router();
terminosRouter.use(express.json());

// Protección CSRF usando cookies
const csrfProtection = csrf({ cookie: true });


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

//====================================================================================================
// Obtener la versión vigente para usuarios finales (sin autenticación)
terminosRouter.get('/vigente', async (req, res) => {
  try {
    const [terminos] = await req.db.query("SELECT * FROM terminos WHERE estado = 'vigente' ORDER BY versio DESC LIMIT 1");
    if (terminos.length === 0) {
      return res.status(404).json({ error: 'No hay términos vigentes' });
    }
    res.json(terminos[0]);
  } catch (error) {
    console.error('Error al obtener término vigente:', error);
    res.status(500).json({ error: 'No se pudo obtener el término vigente' });
  }
});
//===================================================================
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
//===========================================================================================================
// Crear un nuevo término (versión 1.0)
terminosRouter.post('/', csrfProtection,  async (req, res) => {
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({ error: 'Los campos título, contenido y fecha de vigencia son obligatorios' });
  }

  try {
     // Obtener el término actual
     const [terminoActual] = await req.db.query("SELECT * FROM terminos WHERE estado = 'vigente' ORDER BY created_at DESC LIMIT 1");
     
     let nuevaVersion;

     if (terminoActual.length === 0) {
      nuevaVersion = '1.0';
     }else{
         // Calcular nueva versión
    const versionAnterior = parseFloat(terminoActual[0].versio);
    nuevaVersion = (versionAnterior + 1.0).toFixed(1); 
     }
     
 
    // Marcar cualquier término vigente existente como 'no vigente'
    await req.db.query("UPDATE terminos SET estado = 'no vigente' WHERE estado = 'vigente'");

    const query = "INSERT INTO terminos (titulo, contenido, fechaVigencia, secciones, versio , estado, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())";
    await req.db.query(query, [titulo, contenido, fechaVigencia, JSON.stringify(secciones), nuevaVersion, 'vigente']);

    res.status(201).json({ message: 'Término creado exitosamente' });
  } catch (error) {
    console.error('Error al crear término:', error);
    res.status(500).json({ error: 'No se pudo crear el término' });
  }
});

//===========================================================================================================

// Crear una nueva versión de un término existente
terminosRouter.post('/:id/nueva-version', csrfProtection,  async (req, res) => {
  const { id } = req.params;
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({ error: 'Los campos título, contenido y fecha de vigencia son obligatorios' });
  }

  try {
    // Obtener el término actual
    const [terminoActual] = await req.db.query("SELECT * FROM terminos WHERE id = ?", [id]);

    if (terminoActual.length === 0) {
      return res.status(404).json({ error: 'Término no encontrado' });
    }

    // Marcar el término actual como 'no vigente'
    await req.db.query("UPDATE terminos SET estado = 'no vigente' WHERE id = ?", [id]);

    // Calcular nueva versión
    const versionAnterior = parseFloat(terminoActual[0].versio);
    const nuevaVersion = (versionAnterior + 1.0).toFixed(1); 

    // Insertar nueva versión
    const query = "INSERT INTO terminos (titulo, contenido, fechaVigencia, secciones, versio, estado, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())";
    await req.db.query(query, [titulo, contenido, fechaVigencia, JSON.stringify(secciones), nuevaVersion, 'vigente']);

    res.status(201).json({ message: 'Nueva versión del término creada exitosamente' });
  } catch (error) {
    console.error('Error al crear nueva versión:', error);
    res.status(500).json({ error: 'No se pudo crear la nueva versión' });
  }
});



// Marcar un término como eliminado (eliminación lógica)
terminosRouter.delete('/:id', csrfProtection, async (req, res) => {
  const { id } = req.params;

  try {
    const [termino] = await req.db.query("SELECT * FROM terminos WHERE id = ?", [id]);

    if (termino.length === 0) {
      return res.status(404).json({ error: 'Término no encontrado' });
    }
    await req.db.query("UPDATE terminos SET estado = 'eliminado' WHERE id = ?", [id]);
    if (termino[0].estado === 'vigente') {
      const [ultimoTermino] = await req.db.query(`
        SELECT * FROM terminos 
        WHERE estado = 'no vigente' 
        AND fechaVigencia >= CURDATE()
        ORDER BY fechaVigencia DESC, versio DESC 
        LIMIT 1
      `);
      if (ultimoTermino.length > 0) {
        await req.db.query("UPDATE terminos SET estado = 'vigente' WHERE id = ?", [ultimoTermino[0].id]);
      }
    }

    res.json({ message: 'Término marcado como eliminado exitosamente' });
  } catch (error) {
    console.error('Error al eliminar término:', error);
    res.status(500).json({ error: 'No se pudo eliminar el término' });
  }
});

module.exports = terminosRouter;
