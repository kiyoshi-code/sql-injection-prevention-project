// init_db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./secure.db');
const bcrypt = require('bcrypt');

db.serialize(() => {
  db.run(`DROP TABLE IF EXISTS users`);
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      password TEXT
    )
  `);

  const users = [
    { username: 'admin', password: 'adminpass' },
    { username: 'alice', password: 'alicepass' }
  ];
  const saltRounds = 10;
  let completed = 0;
  const stmt = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
  users.forEach(user => {
    bcrypt.hash(user.password, saltRounds, (err, hash) => {
      if (err) throw err;
      stmt.run(user.username, hash, () => {
        completed++;
        if (completed === users.length) {
          stmt.finalize();
          console.log("secure.db created and seeded (users: admin/adminpass, alice/alicepass, passwords hashed)");
          db.close();
        }
      });
    });
  });
});
