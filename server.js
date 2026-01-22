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

// Schema with Banned status and expanded roles
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
app.use(express.static(__dirname));

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
    if (req.session.isLoggedIn) next();
    else res.redirect('/');
};

// --- HTML ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/dashboard', protect, (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/admin', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    if (user && (user.role === 'Admin' || user.role === 'Owner')) {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Unauthorized. Only Admins and the Owner can access this page.');
    }
});

// --- MANAGEMENT API ---

// Promote/Update Role
app.post('/api/promote-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });

        if (!target) return res.status(404).send('User not found');

        if (currentUser.role === 'Owner') {
            await User.findOneAndUpdate({ username: req.params.username }, { role: 'Admin' });
        } else if (currentUser.role === 'Admin' && target.role === 'User') {
            await User.findOneAndUpdate({ username: req.params.username }, { role: 'Staff' });
        } else {
            return res.status(403).send('Unauthorized to promote this user.');
        }
        res.sendStatus(200);
    } catch (err) {
        res.status(500).send('Error updating role');
    }
});

// Demote to User (Owner Only)
app.post('/api/demote-user/:username', protect, async (req, res) => {
    if (req.session.role !== 'Owner') return res.status(403).send('Only the Owner can demote users.');
    try {
        const target = await User.findOne({ username: req.params.username });
        if (target.role === 'Owner') return res.status(400).send('Cannot demote the Owner.');
        await User.findOneAndUpdate({ username: req.params.username }, { role: 'User' });
        res.sendStatus(200);
    } catch (err) {
        res.status(500).send('Error demoting user');
    }
});

// Ban/Unban User
app.post('/api/ban-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });

        if (!target) return res.status(404).send('User not found');
        if (target.role === 'Owner') return res.status(403).send('The Owner cannot be banned.');

        // Owner can ban anyone. Admin can ban Staff and Users.
        const canBan = currentUser.role === 'Owner' || 
                      (currentUser.role === 'Admin' && (target.role === 'User' || target.role === 'Staff'));

        if (canBan) {
            target.isBanned = !target.isBanned;
            await target.save();
            res.sendStatus(200);
        } else {
            res.status(403).send('Unauthorized to ban this user.');
        }
    } catch (err) {
        res.status(500).send('Error toggling ban status');
    }
});

// Delete User
app.delete('/api/delete-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });

        if (!target) return res.status(404).send('User not found');
        if (target.role === 'Owner') return res.status(403).send('Cannot delete the Owner.');

        const canDelete = currentUser.role === 'Owner' || 
                         (currentUser.role === 'Admin' && (target.role === 'User' || target.role === 'Staff'));

        if (canDelete) {
            await User.findOneAndDelete({ username: req.params.username });
            res.sendStatus(200);
        } else {
            res.status(403).send('Unauthorized to delete this user.');
        }
    } catch (err) {
        res.status(500).send('Error deleting user');
    }
});

// --- AUTH & USER DATA ---

app.get('/api/users', protect, async (req, res) => {
    const users = await User.find({}, 'username role isBanned');
    res.json(users);
});

app.get('/api/me', protect, (req, res) => {
    res.json({ username: req.session.username, role: req.session.role });
});

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const userCount = await User.countDocuments();
        const role = (userCount === 0) ? 'Owner' : 'User';

        const newUser = new User({ username, password: hashedPassword, role });
        await newUser.save();
        
        req.session.isLoggedIn = true;
        req.session.username = username;
        req.session.role = role;
        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send('Registration error.');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
        if (user.isBanned) {
            return res.status(403).send('This account has been banned. <a href="/">Back to Home</a>');
        }
        req.session.isLoggedIn = true;
        req.session.username = username;
        req.session.role = user.role;
        res.redirect((user.role === 'Admin' || user.role === 'Owner') ? '/admin' : '/dashboard');
    } else {
        res.status(401).send('Invalid credentials.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.listen(process.env.PORT || 3000, () => console.log("Server Live!"));
