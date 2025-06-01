const mysql = require('mysql2');
const logger = require('../utils/logger');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});


logger.info('[DB] config:', {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
});

module.exports = pool.promise(); // 🟢 dette er nøkkelen
