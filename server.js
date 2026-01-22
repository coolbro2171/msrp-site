const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const app = express();

const MONGODB_URI = "mongodb+srv://cool_bro2171:Leonardo3@msrp-site.axszmf7.mongodb.net/MSRP_Database?retryWrites=true&w=majority&appName=MSRP-Site";

mongoose.connect(MONGODB_URI)
    .then(() => console.log("Connected to Cloud Database successfully"))
    .catch(err => console.error("Database connection error:", err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Admin', 'Owner'], default: 'User' }
});
const User = mongoose.model('User', userSchema);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname));

app.use(session({
    secret: 'secure-dev-key-789',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGODB_URI, collectionName: 'sessions' }),
    cookie: { maxAge: 3600000, sameSite: 'lax', secure: false }
}));

const protect = (req, res, next) => {
    if (req.session.isLoggedIn) next();
    else res.redirect('/');
};

// --- ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/dashboard', protect, (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

app.get('/admin', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    if (user && (user.role === 'Admin' || user.role === 'Owner')) {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Unauthorized.');
    }
});

// --- OWNER-ONLY API ---
app.post('/api/promote-user/:username', protect, async (req, res) => {
    // Check DB directly for Owner status to prevent session lag errors
    const currentUser = await User.findOne({ username: req.session.username });
    if (!currentUser || currentUser.role !== 'Owner') return res.status(403).send('Only the Owner can promote.');
    
    await User.findOneAndUpdate({ username: req.params.username }, { role: 'Admin' });
    res.sendStatus(200);
});

app.post('/api/demote-user/:username', protect, async (req, res) => {
    const currentUser = await User.findOne({ username: req.session.username });
    if (!currentUser || currentUser.role !== 'Owner') return res.status(403).send('Only the Owner can demote.');
    
    await User.findOneAndUpdate({ username: req.params.username }, { role: 'User' });
    res.sendStatus(200);
});

app.delete('/api/delete-user/:username', protect, async (req, res) => {
    const currentUser = await User.findOne({ username: req.session.username });
    const target = await User.findOne({ username: req.params.username });

    if (target.role === 'Owner') return res.status(403).send('Cannot delete Owner.');
    if (currentUser.role === 'Admin' && target.role === 'Admin') return res.status(403).send('Admins cannot delete Admins.');

    await User.findOneAndDelete({ username: req.params.username });
    res.sendStatus(200);
});

app.get('/api/users', protect, async (req, res) => {
    const users = await User.find({}, 'username role');
    res.json(users);
});

// --- AUTH ---
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const userCount = await User.countDocuments();
        
        // The first person to register in the empty database becomes Owner
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
        req.session.isLoggedIn = true;
        req.session.username = username;
        req.session.role = user.role;
        res.redirect((user.role === 'Admin' || user.role === 'Owner') ? '/admin' : '/dashboard');
    } else {
        res.status(401).send('Invalid login.');
    }
});

app.get('/api/me', protect, (req, res) => {
    res.json({ username: req.session.username, role: req.session.role });
});

app.listen(process.env.PORT || 3000, () => console.log("Server Live!"));
