const express = require('express');
const bodyParser = require('body-parser');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('cors');


const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'fazii401',
  database: 'my_database',
  waitForConnections: true,
  connectionLimit: 10,
});


const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(cors());

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});


const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: 'your_jwt_secret',
};

passport.use(new JwtStrategy(jwtOptions, (payload, done) => {

  pool.query('SELECT * FROM users WHERE id = ?', [payload.sub], (err, results) => {
      if (err) {
        console.error(err);
        done(err, false);
      } else if (results.length === 1) {
        const user = results[0];
        done(null, user);
      } else {
        done(null, false);
      }
    });
}));

const requireJwtAuth = passport.authenticate('jwt', { session: false });

app.post('/api/signup', async (req, res) => {
  const {name,email, password } = req.body;
  if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required'});
    }

  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  const [rows, fields] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

  if (rows.length) {
    return res.status(409).json({ success: false, message: 'User already exists' });
  }

  await pool.query('INSERT INTO users (name, email, password) VALUES (?,?,?)',[ name, email, hashedPassword, true]);
  const[userRow] =  await pool.query('SELECT * FROM users WHERE email = ?', [email]);

  res.json({ success: true, data: {
      id : userRow[0].id, name: userRow[0].name, email: userRow[0].email, password : userRow[0].password
  }, message : "Successfully Registered" });

});


app.post('/api/signin', async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  if(rows.length  === 0) {
    return res.status(401).json({ success: false, message: 'Invalid email or password' });
  }

  const isPasswordValid = await bcrypt.compare(password, rows[0].password);
  if (!isPasswordValid) {
    return res.status(401).send({ success: false, message: 'Invalid username or password' });
  }

  const token = jwt.sign({ sub: rows[0].id }, 'your_jwt_secret', { expiresIn: '30d' });

  res.send({ success: true, message: 'Authentication successful', data: {
    id : rows[0].id, name: rows[0].name, email: rows[0].email, password : rows[0].password,  status: rows[0].status, token:token
}});
});

app.post('/api/signout', requireJwtAuth, (req, res) => {
  res.cookie('jwt', '', { maxAge: 0 });
  res.send({ message: 'Signed out successfully' });
});

// all users
app.get('/api/users', async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM users');
res.json({ success: true, data: rows });
});

// admin apis

app.post('/api/admin/signin', async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await pool.query('SELECT * FROM admin WHERE email = ?', [email]);
  if(rows.length  === 0) {
    return res.status(401).json({ success: false, message: 'Invalid email or password' });
  }

  const isPasswordValid = await bcrypt.compare(password, rows[0].password);
  if (!isPasswordValid) {
    return res.status(401).send({ success: false, message: 'Invalid username or password' });
  }

  const token = jwt.sign({ sub: rows[0].id }, 'your_jwt_secret', { expiresIn: '30d' });

  res.send({ success: true, message: 'Authentication successful', data: {
    id : rows[0].id, email: rows[0].email, password : rows[0].password,
    status: rows[0].status, token : token
} 
      
  });
});

app.post('/api/users/block', async (req, res) => {
  const {id, block} = req.body;
await pool.query('UPDATE users SET status = ? WHERE id = ?', [block, id ]);
  res.send({ success: true, message: 'Blocked'
  });
});

app.post('/api/users/reset-pass', async (req, res) => {
  const {id, password} = req.body;
      const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, id ]);
  res.send({ success: true, message: 'Changed Password'
  });
});


// get a user 
app.get('/api/user/:id', async (req, res) => {
const { id } = req.params;

if (!id) {
  res.status(400).json({ success: false, message: 'User ID is required' });
  return;
}

const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);

if (rows.length === 0) {
  res.status(404).json({ success: false, message: 'User not found' });
  return;
}

res.json({ success: true, data: rows[0] });
});
