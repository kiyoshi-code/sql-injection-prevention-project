// server.js (secure)
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const helmet = require('helmet');
const winston = require('winston');
const bcrypt = require('bcrypt');

const app = express();
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// simple file logger
const logger = winston.createLogger({
  transports: [ new winston.transports.File({ filename: 'secure.log' }) ]
});

const DB_FILE = path.join(__dirname, 'secure.db');
const db = new sqlite3.Database(DB_FILE);

// Helper: basic username validation (whitelist: letters, numbers, underscore, dash; length limit)
function validateUsername(u) {
  return typeof u === 'string' && /^[A-Za-z0-9_-]{1,50}$/.test(u);
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// SECURE login endpoint (prepared statement + validation)
app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;

  // Validate user input
  if (!validateUsername(username) || typeof password !== 'string' || password.length > 100) {
    logger.warn('Invalid input', { ip: req.ip, username });
    return res.status(400).send('Invalid input');
  }

  // Fetch user and hashed password
  const sql = `SELECT id, username, password FROM users WHERE username = ? LIMIT 1`;
  db.get(sql, [username], (err, row) => {
    if (err) {
      logger.error('DB error', { error: err.message });
      return res.status(500).send('Internal error');
    }
    if (row) {
      bcrypt.compare(password, row.password, (err, result) => {
        if (err) {
          logger.error('Bcrypt error', { error: err.message });
          return res.status(500).send('Internal error');
        }
        if (result) {
          return res.send(`Login success! user: ${row.username}`);
        } else {
          logger.info('Failed login', { ip: req.ip, username });
          return res.send('Login failed');
        }
      });
    } else {
      logger.info('Failed login', { ip: req.ip, username });
      return res.send('Login failed');
    }
  });
});

const PORT = 3002;
app.listen(PORT, () => console.log(`SECURE server running at http://localhost:${PORT}`));
