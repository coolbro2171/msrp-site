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
    .then(() => console.log("Connected to Database Successfully"))
    .catch(err => console.error("Database connection error:", err));

// --- USER SCHEMA ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Staff', 'Admin', 'Owner'], default: 'User' },
    isBanned: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serving static files (Fixes "Cannot GET" errors for HTML and PDFs)
app.use(express.static(__dirname)); 
app.use('/files', express.static(path.join(__dirname, 'files'))); 

app.use(session({
    secret: 'secure-dev-key-789',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGODB_URI }),
    cookie: { maxAge: 3600000, sameSite: 'lax', secure: false }
}));

const protect = (req, res, next) => {
    if (req.session.isLoggedIn) next();
    else res.redirect('/');
};

// --- PAGE ROUTES ---

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

app.get('/dashboard', protect, (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// Documents Route (Staff+)
app.get('/documents', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    if (user && user.role !== 'User') {
        res.sendFile(path.join(__dirname, 'documents.html'));
    } else {
        res.status(403).send('Unauthorized. Staff+ access required.');
    }
});

app.get('/admin', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    if (user && (user.role === 'Admin' || user.role === 'Owner')) {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Unauthorized access.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- MANAGEMENT API ---

// Promotion: Admins can make Users into Staff. Owners can make Staff into Admins.
app.post('/api/promote-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });

        if (!target) return res.status(404).send('User not found');

        if (target.role === 'User' && (currentUser.role === 'Owner' || currentUser.role === 'Admin')) {
            await User.findOneAndUpdate({ username: req.params.username }, { role: 'Staff' });
            res.sendStatus(200);
        } else if (target.role === 'Staff' && currentUser.role === 'Owner') {
            await User.findOneAndUpdate({ username: req.params.username }, { role: 'Admin' });
            res.sendStatus(200);
        } else {
            res.status(403).send('Unauthorized promotion.');
        }
    } catch (err) { res.status(500).send('Error'); }
});

// Demotion: Admins can demote Staff to User. Owners can demote Admins to Staff.
app.post('/api/demote-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });

        if (!target) return res.status(404).send('User not found');

        if (target.role === 'Staff' && (currentUser.role === 'Owner' || currentUser.role === 'Admin')) {
            await User.findOneAndUpdate({ username: req.params.username }, { role: 'User' });
            res.sendStatus(200);
        } else if (target.role === 'Admin' && currentUser.role === 'Owner') {
            await User.findOneAndUpdate({ username: req.params.username }, { role: 'Staff' });
            res.sendStatus(200);
        } else {
            res.status(403).send('Unauthorized demotion.');
        }
    } catch (err) { res.status(500).send('Error'); }
});

app.delete('/api/delete-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });
        if (!target || target.role === 'Owner') return res.sendStatus(403);
        
        if (currentUser.role === 'Owner' || (currentUser.role === 'Admin' && target.role !== 'Admin')) {
            await User.findOneAndDelete({ username: req.params.username });
            res.sendStatus(200);
        } else { res.sendStatus(403); }
    } catch (err) { res.status(500).send('Error'); }
});

// --- AUTHENTICATION ---

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const count = await User.countDocuments();
        const role = count === 0 ? 'Owner' : 'User';
        await new User({ username, password: hashedPassword, role }).save();
        res.redirect('/');
    } catch (err) { res.status(500).send('Registration failed.'); }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
        if (user.isBanned) return res.status(403).send('Your account is banned.');
        
        req.session.isLoggedIn = true;
        req.session.username = username;
        req.session.role = user.role;
        
        // Admins/Owner to Management Panel, Staff/User to Dashboard
        if (user.role === 'Admin' || user.role === 'Owner') {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    } else {
        res.status(401).send('Invalid credentials.');
    }
});

app.get('/api/users', protect, async (req, res) => {
    const users = await User.find({}, 'username role isBanned');
    res.json(users);
});

app.get('/api/me', protect, (req, res) => {
    res.json({ username: req.session.username, role: req.session.role });
});

app.listen(process.env.PORT || 3000, () => console.log("Server Live"));
