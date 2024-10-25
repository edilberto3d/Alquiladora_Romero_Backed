const express = require("express");
const csrf = require("csurf"); // Protección CSRF para evitar ataques
const router = express.Router();
const csrfProtection = csrf({ cookie: true });

// Middleware para asegurarnos de que las peticiones se hacen con JSON y que usamos cookies
router.use(express.json());

//=====================================================================
// Crear un endpoint para obtener los datos de la empresa
router.get("/", csrfProtection, async (req, res) => {
  try {
    const [empresa] = await req.db.query("SELECT * FROM empresa"); // Solo un registro
    if (empresa.length === 0) {
      return res.status(404).json({ message: "Datos de la empresa no encontrados." });
    }
    res.status(200).json(empresa[0]);
  } catch (error) {
    console.error("Error al obtener los datos de la empresa:", error);
    res.status(500).json({ message: "Error al obtener los datos de la empresa." });
  }
});

//=====================================================================
// Crear un endpoint para insertar o actualizar los datos de la empresa
router.post("/actualizar", csrfProtection, async (req, res) => {
  try {
    const { direccion, correo, telefono, slogan, redes_sociales, logo_url } = req.body;

    const redesSocialesJSON = redes_sociales ? JSON.stringify(redes_sociales) : null;

    // Verificar si los datos ya existen
    const [empresa] = await req.db.query("SELECT id FROM empresa WHERE id = 1");

    if (empresa.length === 0) {
      // Si no existen, insertar nuevos datos
      const queryInsert = `
        INSERT INTO empresa (direccion, correo, telefono, slogan, redes_sociales, logo_url, creado_en, actualizado_en)
        VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
      `;
      await req.db.query(queryInsert, [direccion, correo, telefono, slogan, redesSocialesJSON, logo_url]);
      return res.status(201).json({ message: "Datos de la empresa insertados correctamente." });
    } else {
      // Si ya existen, actualizarlos
      const queryUpdate = `
        UPDATE empresa
        SET direccion = ?, correo = ?, telefono = ?, slogan = ?, redes_sociales = ?, logo_url = ?, actualizado_en = NOW()
        WHERE id = 1
      `;
      await req.db.query(queryUpdate, [direccion, correo, telefono, slogan, redesSocialesJSON, logo_url]);
      return res.status(200).json({ message: "Datos de la empresa actualizados correctamente." });
    }
  } catch (error) {
    console.error("Error al actualizar los datos de la empresa:", error);
    res.status(500).json({ message: "Error al actualizar los datos de la empresa." });
  }
});

//=====================================================================
// Actualizar un campo específico de los datos de la empresa (por ejemplo, solo el logo)
router.patch("/:campo", csrfProtection, async (req, res) => {
  const { campo } = req.params;
  const { valor } = req.body;

  // Lista de campos permitidos
  const camposPermitidos = ['direccion', 'correo', 'telefono', 'slogan', 'logo_url', 'redes_sociales'];

  if (!camposPermitidos.includes(campo)) {
    return res.status(400).json({ message: "Campo no permitido para actualización." });
  }

  try {
    const queryUpdate = `UPDATE empresa SET ${campo} = ?, actualizado_en = NOW() WHERE id = 1`;
    await req.db.query(queryUpdate, [valor]);

    res.status(200).json({ message: `Campo ${campo} actualizado correctamente.` });
  } catch (error) {
    console.error(`Error al actualizar ${campo}:`, error);
    res.status(500).json({ message: `Error al actualizar ${campo}.` });
  }
});

//=====================================================================
module.exports = router;
