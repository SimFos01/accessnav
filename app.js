// Enclo Server – Versjon 1
// Oppdatert med ekte database (MariaDB via mysql2)

require('dotenv').config();

const expressOasGenerator = require('express-oas-generator'); // 👈 NYTT
const express = require('express');
const app = express();
const logger = require('./utils/logger');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const { verifyToken } = require('./middleware/authMiddleware');
expressOasGenerator.init(app, {
  writeIntervalMs: 2000,
  specOutputPath: path.join(__dirname, 'oas-doc.json'),
  documentationOutputPath: path.join(__dirname, 'docs.html'),
  swaggerUiServePath: null // Vi bruker ikke innebygget UI
});
const mysql = require('mysql2/promise');
app.use((req, res, next) => {
  const ip =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.connection.remoteAddress ||
    req.socket?.remoteAddress ||
    (req.connection.socket ? req.connection.socket.remoteAddress : null);

  logger.info(`[INNKOMMENDE] IP: ${ip} - ${req.method} ${req.originalUrl}`);
  next();
});
app.use(morgan('dev'));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const fs = require('fs');


// Dynamisk routing: Henter alle routes fra ./routes/
const routesPath = path.join(__dirname, 'routes');
fs.readdirSync(routesPath).forEach(file => {
  if (file.endsWith('Routes.js')) {
    const route = require(path.join(routesPath, file));
    const routeName = '/' + file.replace('Routes.js', '').toLowerCase();
    app.use(routeName, route);
    logger.debug(`🧩 Laster rute: ${routeName} fra ${file}`);
  }
}); 
// Opprett databaseforbindelse
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

// Registrering av bruker
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    const [rows] = await db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hash]);
    res.send('Bruker opprettet');
  } catch (err) {
    console.error(err);
    res.status(500).send('Feil ved opprettelse');
  }
});

// Login og få JWT-token
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send('Feil brukernavn/passord');
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Innlogging feilet');
  }
});

// Beskyttet rute – kun tilgjengelig med gyldig token
app.get('/me', verifyToken, (req, res) => {
  res.json({ message: `Hei ${req.user.email}, du er logget inn!` });
});

// Helsetest
app.get('/health', (req, res) => {
  res.json({ status: 'OK', uptime: process.uptime() });
});

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Keyfree Flow API',
    version: '1.0.0',
    description: 'API-dokumentasjon for Keyfree Flow prototype adgangssystem'
  },
  servers: [
    { url: 'http://localhost:3000' } // tilpass om du bruker reverse proxy
  ]
};

const swaggerOptions = {
  swaggerDefinition,
  apis: ['./routes/*.js'], // 👈 her ligger dine @swagger-kommentarer
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Start server
app.listen(3000, () => logger.info('🔐 Enclo server kjører på http://localhost:3000'));
