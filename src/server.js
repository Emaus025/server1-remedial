const express = require('express');
const cors = require('cors');
const rateLimit = require('./middleware/rateLimit');
const authRoutes = require('./routes/auth');
require('dotenv').config();

const app = express();

// Configura CORS para permitir solicitudes desde el dominio de tu frontend
app.use(cors({
  origin: 'http://localhost:3000', // Solo permitir conexiones locales
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json());
app.use(rateLimit);
app.use('/api', authRoutes);

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Servidor 1 corriendo en puerto ${PORT}`));