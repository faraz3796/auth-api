const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

// const pool = mysql.createConnection({
//   host: 'localhost',
//   user: 'root',
//   password: 'password',
//   database: 'passport_auth'
// });
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'fazii401',
    database: 'my_database',
    waitForConnections: true,
    connectionLimit: 3,
    queueLimit: 2
  });

module.exports = function(passport) {
  passport.use(
    new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
      // Match user
      pool.query('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) throw err;
        if (!user[0]) {
          return done(null, false, { message: 'That email is not registered' });
        }

        // Match password
        bcrypt.compare(password, user[0].password, (err, isMatch) => {
          if (err) throw err;
          if (isMatch) {
            return done(null, user[0]);
          } else {
            return done(null, false, { message: 'Password incorrect' });
          }
        });
      });
    })
  );

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    pool.query('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
      done(err, user[0]);
    });
  });
};
