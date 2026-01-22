const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();

app.use(express.urlencoded({ extended: true }));

// This tells the server what to show at http://localhost:3000
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const users = []; 

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.post('/register', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    users.push({ username: req.body.username, password: hashedPassword });
    res.send('Success! <a href="/">Go to Login</a>');
});

app.post('/login', async (req, res) => {
    const user = users.find(u => u.username === req.body.username);
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        res.sendFile(path.join(__dirname, 'dashboard.html'));
    } else {
        res.send('Invalid login. <a href="/">Try again</a>');
    }
});

app.listen(3000, () => console.log('Server started on http://localhost:3000'));