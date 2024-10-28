const express = require('express');
const csrf = require('csurf');

const deslindeLegalRouter = express.Router();
deslindeLegalRouter.use(express.json());

// Protección CSRF usando cookies
const csrfProtection = csrf({ cookie: true });

// Obtener todos los documentos (historial completo)
deslindeLegalRouter.get('/',  async (req, res) => {
  try {
    const [documentos] = await req.db.query(
      "SELECT * FROM deslinde_legal ORDER BY created_at DESC"
    );
    res.json(documentos);
  } catch (error) {
    console.error('Error al obtener documentos:', error);
    res.status(500).json({ error: 'No se pudieron obtener los documentos' });
  }
});

// Obtener la versión vigente para usuarios finales (sin autenticación)
deslindeLegalRouter.get('/vigente', async (req, res) => {
  try {
    const [documentos] = await req.db.query(
      "SELECT * FROM deslinde_legal WHERE estado = 'vigente' ORDER BY version DESC LIMIT 1"
    );
    if (documentos.length === 0) {
      return res.status(404).json({ error: 'No hay documentos vigentes' });
    }
    res.json(documentos[0]);
  } catch (error) {
    console.error('Error al obtener documento vigente:', error);
    res.status(500).json({ error: 'No se pudo obtener el documento vigente' });
  }
});

// Obtener un documento por su ID
deslindeLegalRouter.get('/:id',  async (req, res) => {
  const { id } = req.params;

  try {
    const [documento] = await req.db.query(
      "SELECT * FROM deslinde_legal WHERE id = ?",
      [id]
    );

    if (documento.length === 0) {
      return res.status(404).json({ error: 'Documento no encontrado' });
    }

    res.json(documento[0]);
  } catch (error) {
    console.error('Error al obtener el documento:', error);
    res.status(500).json({ error: 'No se pudo obtener el documento' });
  }
});

// Crear un nuevo documento (versión 1.0)
deslindeLegalRouter.post('/',  csrfProtection, async (req, res) => {
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({
      error: 'Los campos título, contenido y fecha de vigencia son obligatorios',
    });
  }

  try {

    // Obtener la última versión
    const [ultimaVersion] = await req.db.query(
      "SELECT MAX(version) as maxVersion FROM deslinde_legal"
    );
    const nuevaVersion = ultimaVersion[0].maxVersion
      ? (parseFloat(ultimaVersion[0].maxVersion) + 1.0).toFixed(1)
      : '1.0';

    await req.db.query(
      "UPDATE deslinde_legal SET estado = 'no vigente' WHERE estado = 'vigente'"
    );

    const query =
      "INSERT INTO deslinde_legal (titulo, contenido, fecha_vigencia, secciones, version, estado, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())";
    await req.db.query(query, [
      titulo,
      contenido,
      fechaVigencia,
      JSON.stringify(secciones),
      nuevaVersion,
      'vigente',
    ]);

    res.status(201).json({ message: 'Documento creado exitosamente' });
  } catch (error) {
    console.error('Error al crear documento:', error);
    res.status(500).json({ error: 'No se pudo crear el documento' });
  }
});

// Crear una nueva versión de un documento existente
deslindeLegalRouter.post('/:id/nueva-version',  csrfProtection, async (req, res) => {
  const { id } = req.params;
  const { titulo, contenido, fechaVigencia, secciones } = req.body;

  if (!titulo || !contenido || !fechaVigencia) {
    return res.status(400).json({
      error: 'Los campos título, contenido y fecha de vigencia son obligatorios',
    });
  }

  try {
 
    const [documentoActual] = await req.db.query(
      "SELECT * FROM deslinde_legal WHERE id = ?",
      [id]
    );

    if (documentoActual.length === 0) {
      return res.status(404).json({ error: 'Documento no encontrado' });
    }

   
    await req.db.query(
      "UPDATE deslinde_legal SET estado = 'no vigente' WHERE id = ?",
      [id]
    );

    // Calcular nueva versión
    const versionAnterior = parseFloat(documentoActual[0].version);
    const nuevaVersion = (versionAnterior + 1.0).toFixed(1);

    // Insertar nueva versión
    const query =
      "INSERT INTO deslinde_legal (titulo, contenido, fecha_vigencia, secciones, version, estado, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())";
    await req.db.query(query, [
      titulo,
      contenido,
      fechaVigencia,
      JSON.stringify(secciones),
      nuevaVersion,
      'vigente',
    ]);

    res.status(201).json({ message: 'Nueva versión del documento creada exitosamente' });
  } catch (error) {
    console.error('Error al crear nueva versión:', error);
    res.status(500).json({ error: 'No se pudo crear la nueva versión' });
  }
});

deslindeLegalRouter.delete('/:id',  csrfProtection, async (req, res) => {
  const { id } = req.params;

  try {
    const [documento] = await req.db.query(
      "SELECT * FROM deslinde_legal WHERE id = ?",
      [id]
    );

    if (documento.length === 0) {
      return res.status(404).json({ error: 'Documento no encontrado' });
    }

    await req.db.query(
      "UPDATE deslinde_legal SET estado = 'eliminado' WHERE id = ?",
      [id]
    );

   
    if (documento[0].estado === 'vigente') {
      const [ultimoDocumento] = await req.db.query(`
        SELECT * FROM deslinde_legal
        WHERE estado = 'no vigente' AND fecha_vigencia <= CURDATE()
        ORDER BY fecha_vigencia DESC, version DESC
        LIMIT 1
      `);
      if (ultimoDocumento.length > 0) {
        await req.db.query("UPDATE deslinde_legal SET estado = 'vigente' WHERE id = ?", [
          ultimoDocumento[0].id,
        ]);
      }
    }

    res.json({ message: 'Documento marcado como eliminado exitosamente' });
  } catch (error) {
    console.error('Error al eliminar documento:', error);
    res.status(500).json({ error: 'No se pudo eliminar el documento' });
  }
});

module.exports = deslindeLegalRouter;
