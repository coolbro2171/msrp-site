const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const { Client, GatewayIntentBits } = require('discord.js');

const app = express();

// --- DISCORD CONFIGURATION ---
const DISCORD_CLIENT_ID = '1465834442043031614';
const DISCORD_CLIENT_SECRET = 'kRzCCJlwHV6VKtZwUYP4tKZoVdBP-0eK';
const DISCORD_BOT_TOKEN = 'MTQ2NTgzNDQ0MjA0MzAzMTYxNA.GQHDVS.TZS06hvH4_5SdialpqCVAht5hxkkT6h4o_IxBU';
const GUILD_ID = '1198422904178749500'; // Replace with your Discord Server ID

const bot = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });
bot.login(DISCORD_BOT_TOKEN).catch(err => console.error("Discord Bot Login Failed:", err));

// --- DATABASE CONNECTION ---
const MONGODB_URI = "mongodb+srv://cool_bro2171:Leonardo3@msrp-site.axszmf7.mongodb.net/MSRP_Database?retryWrites=true&w=majority&appName=MSRP-Site";

mongoose.connect(MONGODB_URI)
    .then(() => console.log("Database Connected Successfully"))
    .catch(err => console.error("Database connection error:", err));

// --- USER SCHEMA (Updated with all Badge fields) ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Staff', 'Admin', 'Management', 'Owner'], default: 'User' },
    isBanned: { type: Boolean, default: false },
    // Badge Fields from your image
    isDeveloper: { type: Boolean, default: false },
    isDatabaseAccess: { type: Boolean, default: false },
    isStaffTrainer: { type: Boolean, default: false },
    // Discord Integration
    discordId: { type: String, default: null },
    // 2FA Fields
    twoFactorSecret: { type: String },
    twoFactorEnabled: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// --- PASSPORT / DISCORD OAUTH CONFIG ---
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) { done(err); }
});

passport.use(new DiscordStrategy({
    clientID: DISCORD_CLIENT_ID,
    clientSecret: DISCORD_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/discord/callback',
    scope: ['identify']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ discordId: profile.id });
        if (user) return done(null, user);
        return done(null, false, { message: 'Discord account not linked to an MSRP account.' });
    } catch (err) { return done(err); }
}));

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(session({
    secret: 'secure-dev-key-789',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGODB_URI }),
    cookie: { maxAge: 3600000, secure: false } 
}));

app.use(passport.initialize());
app.use(passport.session());

// --- DISCORD ROLE SYNC LOGIC ---
async function syncDiscordRoles(user) {
    if (!user.discordId) return;
    try {
        const guild = await bot.guilds.fetch(GUILD_ID);
        const member = await guild.members.fetch(user.discordId);
        
        // PASTE YOUR DISCORD ROLE IDs HERE
        const roleMapping = {
            'Owner': '1395978500468637909,1396254329647923430',
            'Management': '1385417365067399208',
            'Admin': '1198422904308772926',
            'Staff': '1198422904266821640',
            'isDeveloper': '1396254329647923430',
            'isDatabaseAccess': '0',
            'isStaffTrainer': '1397763310279069886',
        };

        let rolesToAssign = [];
        if (roleMapping[user.role]) rolesToAssign.push(roleMapping[user.role]);
        if (user.isDeveloper) rolesToAssign.push(roleMapping.isDeveloper);
        if (user.isDatabaseAccess) rolesToAssign.push(roleMapping.isDatabaseAccess);
        if (user.isStaffTrainer) rolesToAssign.push(roleMapping.isStaffTrainer);
        if (user.isFounder) rolesToAssign.push(roleMapping.isFounder);

        await member.roles.set(rolesToAssign);
    } catch (err) {
        console.error(`Failed to sync roles for ${user.username}:`, err);
    }
}

// --- AUTH ROUTES ---
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => {
    req.session.username = req.user.username;
    req.session.isLoggedIn = true;
    res.redirect('/dashboard');
});

// --- API ROUTES ---
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find({}, 'username role isBanned isDeveloper isDatabaseAccess isStaffTrainer isFounder discordId twoFactorEnabled');
        const rankOrder = { 'Owner': 1, 'Management': 2, 'Admin': 3, 'Staff': 4, 'User': 5 };
        users.sort((a, b) => (rankOrder[a.role] || 99) - (rankOrder[b.role] || 99));
        res.json(users);
    } catch (err) { res.status(500).send('Error loading users'); }
});

app.post('/api/promote-user/:username', async (req, res) => {
    try {
        const target = await User.findOne({ username: req.params.username });
        if (!target) return res.status(404).send('User not found');
        
        target.role = req.body.newRole;
        await target.save();
        await syncDiscordRoles(target); // Sync Discord roles immediately
        res.sendStatus(200);
    } catch (err) { res.status(500).send('Promotion failed'); }
});

// --- LOGIN & REGISTER ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        if (user.isBanned) return res.status(403).send('Account Banned');
        req.session.username = username;
        req.session.isLoggedIn = true;
        res.redirect('/dashboard');
    } else { res.status(401).send('Invalid Login'); }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- PAGE NAVIGATION ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/dashboard', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'dashboard.html')) : res.redirect('/'));
app.get('/admin', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'admin.html')) : res.redirect('/'));

app.listen(3000, () => console.log("MSRP Server Live on Port 3000"));



