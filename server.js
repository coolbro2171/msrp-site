const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const app = express();

// Middleware to parse form data
app.use(express.urlencoded({ extended: true }));

// Serve static files from the current directory
app.use(express.static(__dirname));

// Path to your local "database" file
const DATA_FILE = path.join(__dirname, 'users.json');

// Helper function: Reads the users.json file and turns it into a JavaScript list
function loadUsers() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            // If the file doesn't exist yet, create it with an empty list
            fs.writeFileSync(DATA_FILE, JSON.stringify([]));
            return [];
        }
        const data = fs.readFileSync(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error("Error reading users file:", err);
        return [];
    }
}

// Helper function: Saves the JavaScript list back into the users.json file
function saveUsers(users) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
    } catch (err) {
        console.error("Error saving users file:", err);
    }
}

// 1. ROUTE: Home (Login)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. ROUTE: Registration Page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// 3. LOGIC: Register and go straight to Dashboard
app.post('/register', async (req, res) => {
    try {
        const users = loadUsers();
        
        // Check if user already exists
        if (users.find(u => u.username === req.body.username)) {
            return res.send('Username already taken. <a href="/register">Try another</a>');
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        
        users.push({
            username: req.body.username,
            password: hashedPassword
        });

        saveUsers(users); // Permanently save to users.json
        res.sendFile(path.join(__dirname, 'dashboard.html'));
    } catch {
        res.status(500).send('Error during registration.');
    }
});

// 4. LOGIC: Login
app.post('/login', async (req, res) => {
    const users = loadUsers();
    const user = users.find(u => u.username === req.body.username);
    
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        res.sendFile(path.join(__dirname, 'dashboard.html'));
    } else {
        res.status(401).send('Invalid login. <a href="/">Back to Login</a>');
    }
});

// 5. SERVER START: Dynamic port for Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
