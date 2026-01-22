const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();

// Middleware to parse form data from your HTML pages
app.use(express.urlencoded({ extended: true }));

// Serve static files (like CSS or images) from the current folder
app.use(express.static(__dirname));

// Temporary in-memory database
const users = []; 

// 1. ROUTE: Home Page (Serves the Login page)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. ROUTE: Registration Page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// 3. LOGIC: Handle Registration and go straight to Dashboard
app.post('/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        
        users.push({
            username: req.body.username,
            password: hashedPassword
        });

        // After registration, skip the login page and show the dashboard
        res.sendFile(path.join(__dirname, 'dashboard.html'));
    } catch {
        res.status(500).send('Error creating account. <a href="/register">Try again</a>');
    }
});

// 4. LOGIC: Handle Login
app.post('/login', async (req, res) => {
    const user = users.find(u => u.username === req.body.username);
    
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        res.sendFile(path.join(__dirname, 'dashboard.html'));
    } else {
        res.status(401).send('Invalid login. <a href="/">Back to Login</a>');
    }
});

// 5. SERVER START: Uses Render's dynamic port or 3000 for local testing
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`------------------------------------------`);
    console.log(`Server running on port ${PORT}`);
    console.log(`Local link: http://localhost:${PORT}`);
    console.log(`------------------------------------------`);
});
