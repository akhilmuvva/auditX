const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());
app.use(helmet());

// Secure CORS configuration: white-listed domain
app.use(cors({ origin: 'https://auditx.codes' }));

// Secure Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'supersecureadminpassword')");
});

// Secure API Route: Parameterized query (no SQL injection)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;

    db.get(query, [username, password], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (row) {
            res.json({ status: 'success', user: row.username });
        } else {
            res.status(401).json({ status: 'fail' });
        }
    });
});

app.listen(5001, () => {
    console.log("Secure backend server listening on port 5001");
});
