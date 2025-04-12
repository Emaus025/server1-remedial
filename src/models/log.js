const db = require('../config/firebase');

const saveLog = async (level, message, details = {}, req = null) => {
  try {
    const logData = {
      level,
      message,
      timestamp: new Date().toISOString(),
      server: 'Servidor 1',
      details: { ...details },
    };

    if (req) {
      logData.method = req.method;
      logData.url = req.url;
      logData.ip = req.ip || req.connection.remoteAddress;
      logData.userAgent = req.get('User-Agent') || 'Desconocido';
      logData.body = req.body ? { ...req.body } : {};
    }

    await db.collection('logs').add(logData);

    console.log(`[${logData.timestamp}] ${level.toUpperCase()} - ${message}`, {
      server: logData.server,
      method: logData.method,
      url: logData.url,
      details: logData.details,
    });

    return logData;
  } catch (error) {
    console.error(`[${new Date().toISOString()}] ERROR - Error al guardar log:`, error);
    throw error;
  }
};

module.exports = { saveLog };
