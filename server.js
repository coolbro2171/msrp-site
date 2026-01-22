const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const app = express();

// --- DATABASE CONNECTION ---
const MONGODB_URI = "mongodb+srv://cool_bro2171:Leonardo3@msrp-site.axszmf7.mongodb.net/MSRP_Database?retryWrites=true&w=majority&appName=MSRP-Site";

mongoose.connect(MONGODB_URI)
    .then(() => console.log("Connected to Cloud Database successfully"))
    .catch(err => console.error("Database connection error:", err));

// Schema with Owner, Admin, and User roles
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Admin', 'Owner'], default: 'User' }
});
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname));

// Refresh-fix Session Setup
app.use(session({
    secret: 'secure-dev-key-789',
    resave: true,                
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        collectionName: 'sessions'
    }),
    cookie: { 
        maxAge: 3600000,         
        sameSite: 'lax',         
        secure: false            
    }
}));

const protect = (req, res, next) => {
    if (req.session.isLoggedIn) {
        next();
    } else {
        res.redirect('/');
    }
};

// --- ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/dashboard', protect, (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// Admin Route with Ownership Check
app.get('/admin', protect, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.session.username });
        if (user && (user.role === 'Admin' || user.role === 'Owner')) {
            res.sendFile(path.join(__dirname, 'admin.html'));
        } else {
            res.status(403).send('Unauthorized. <a href="/dashboard">Go Back</a>');
        }
    } catch (err) {
        res.redirect('/');
    }
});

// --- OWNER/ADMIN API ---

// Grant Admin Permissions (OWNER ONLY)
app.post('/api/promote-user/:username', protect, async (req, res) => {
    if (req.session.role !== 'Owner') return res.status(403).send('Only the Owner can grant Admin status.');
    
    try {
        await User.findOneAndUpdate({ username: req.params.username }, { role: 'Admin' });
        res.sendStatus(200);
    } catch (err) {
        res.status(500).send('Error promoting user');
    }
});

// Revoke Admin Permissions (OWNER ONLY)
app.post('/api/demote-user/:username', protect, async (req, res) => {
    if (req.session.role !== 'Owner') return res.status(403).send('Only the Owner can revoke Admin status.');
    
    try {
        const target = await User.findOne({ username: req.params.username });
        if (target.role === 'Owner') return res.status(400).send('Cannot demote the Owner.');

        await User.findOneAndUpdate({ username: req.params.username }, { role: 'User' });
        res.sendStatus(200);
    } catch (err) {
        res.status(500).send('Error demoting user');
    }
});

// Delete User (Admins can delete Users, Owner can delete anyone except themselves)
app.delete('/api/delete-user/:username', protect, async (req, res) => {
    const currentUser = await User.findOne({ username: req.session.username });
    if (currentUser.role !== 'Admin' && currentUser.role !== 'Owner') return res.sendStatus(403);

    try {
        const target = await User.findOne({ username: req.params.username });
        if (!target) return res.status(404).send('User not found');
        
        // Prevent deleting the Owner
        if (target.role === 'Owner') return res.status(403).send('The Owner account cannot be deleted.');
        
        // Prevent Admins from deleting other Admins
        if (currentUser.role === 'Admin' && target.role === 'Admin') {
            return res.status(403).send('Admins cannot delete other Admins.');
        }

        await User.findOneAndDelete({ username: req.params.username });
        res.sendStatus(200);
    } catch (err) {
        res.status(500).send('Error deleting user');
    }
});

// Get User List
app.get('/api/users', protect, async (req, res) => {
    if (req.session.role !== 'Admin' && req.session.role !== 'Owner') return res.sendStatus(403);
    const users = await User.find({}, 'username role');
    res.json(users);
});

// --- AUTHENTICATION ---

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // The first user in the database becomes the OWNER
        const userCount = await User.countDocuments();
        const role = (userCount === 0) ? 'Owner' : 'User';

        const newUser = new User({ username, password: hashedPassword, role });
        await newUser.save();

        req.session.isLoggedIn = true;
        req.session.username = username;
        req.session.role = role;
        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send('Error during registration.');
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.isLoggedIn = true;
            req.session.username = username;
            req.session.role = user.role;
            res.redirect((user.role === 'Admin' || user.role === 'Owner') ? '/admin' : '/dashboard');
        } else {
            res.status(401).send('Invalid login.');
        }
    } catch (err) {
        res.status(500).send('Server error.');
    }
});

app.get('/api/me', protect, (req, res) => {
    res.json({ username: req.session.username, role: req.session.role });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
