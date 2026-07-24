const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const child_process = require('child_process');

const app = express();
app.use(express.json());

// Vulnerable CORS configuration: wildcard origin
app.use(cors({ origin: '*' }));

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'supersecureadminpassword')");
});

// Vulnerable API Route: SQL Injection via direct concatenation
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.get(query, [], (err, row) => {
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

// Vulnerable: Command Injection via user parameter in child_process exec
app.get('/api/ping', (req, res) => {
    const { host } = req.query;
    child_process.exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
        if (err) {
            return res.status(500).json({ error: err.message, stderr });
        }
        res.json({ output: stdout });
    });
});

// Listen on port 5000 without rate limiter
app.listen(5000, () => {
    console.log("Vulnerable backend server listening on port 5000");
});
