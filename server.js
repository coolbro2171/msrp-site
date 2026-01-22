const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();

// This middleware allows the server to read data sent from your HTML forms
app.use(express.urlencoded({ extended: true }));

// This tells the server to look for your CSS/Images in the current folder
app.use(express.static(__dirname));

// Temporary "database" in memory (This clears if the server restarts)
const users = []; 

// 1. ROUTE: Home Page (Login)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. ROUTE: Registration Page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// 3. LOGIC: Handle User Registration
app.post('/register', async (req, res) => {
    try {
        // Encrypt the password before saving it
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        
        users.push({
            username: req.body.username,
            password: hashedPassword
        });

        // Redirect back to login after successful sign-up
        res.send('Account created successfully! <a href="/">Click here to Login</a>');
    } catch {
        res.status(500).send('Error creating account. Please try again.');
    }
});

// 4. LOGIC: Handle User Login
app.post('/login', async (req, res) => {
    const user = users.find(u => u.username === req.body.username);
    
    // Check if user exists and if password matches the hashed version
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        res.sendFile(path.join(__dirname, 'dashboard.html'));
    } else {
        res.status(401).send('Invalid username or password. <a href="/">Try again</a>');
    }
});

// 5. SERVER START: Uses Render's port or 3000 locally
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`------------------------------------------`);
    console.log(`Server is running on port ${PORT}`);
    console.log(`Visit: http://localhost:${PORT}`);
    console.log(`------------------------------------------`);
});
