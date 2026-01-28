const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const { Client, GatewayIntentBits } = require('discord.js');

const app = express();

// --- DISCORD CONFIGURATION ---
const DISCORD_CLIENT_ID = '1465834442043031614';
const DISCORD_CLIENT_SECRET = 'kRzCCJlwHV6VKtZwUYP4tKZoVdBP-0eK';
const DISCORD_BOT_TOKEN = 'MTQ2NTgzNDQ0MjA0MzAzMTYxNA.GQHDVS.TZS06hvH4_5SdialpqCVAht5hxkkT6h4o_IxBU';
const GUILD_ID = '1198422904178749500'; // Found from your discord icon link

const bot = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });
bot.login(DISCORD_BOT_TOKEN).catch(err => console.error("Discord Bot Error:", err));

// --- DATABASE CONNECTION ---
const MONGODB_URI = "mongodb+srv://cool_bro2171:Leonardo3@msrp-site.axszmf7.mongodb.net/MSRP_Database?retryWrites=true&w=majority&appName=MSRP-Site";

mongoose.connect(MONGODB_URI)
    .then(() => {
        console.log("Database Connected");
        startDatabaseWatcher(); 
    })
    .catch(err => console.error("Database Connection Error:", err));

// --- USER SCHEMA ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Staff', 'Admin', 'Management', 'Owner'], default: 'User' },
    isBanned: { type: Boolean, default: false },
    isDeveloper: { type: Boolean, default: false },
    isDatabaseAccess: { type: Boolean, default: false }, // Manual Badge
    isStaffTrainer: { type: Boolean, default: false },
    discordId: { type: String, default: null }
});
const User = mongoose.model('User', userSchema);

// --- DISCORD ROLE SYNC LOGIC ---
async function syncDiscordRoles(user) {
    if (!user.discordId) return;
    try {
        const guild = await bot.guilds.fetch(GUILD_ID);
        const member = await guild.members.fetch(user.discordId);
        
        const roleMapping = {
            'Owner': '1395978500468637909',
            'Management': '1385417365067399208',
            'Admin': '1198422904308772926',
            'Staff': '1198422904266821640',
            'isDeveloper': '1396254329647923430',
            'isStaffTrainer': '1397763310279069886',
            'isDatabaseAccess': '',
        };

        let rolesToAssign = [];
        if (roleMapping[user.role]) rolesToAssign.push(roleMapping[user.role]);
        if (user.isDeveloper) rolesToAssign.push(roleMapping.isDeveloper);
        if (user.isStaffTrainer) rolesToAssign.push(roleMapping.isStaffTrainer);
        if (user.isDatabaseAccess && roleMapping.isDatabaseAccess !== '') {
            rolesToAssign.push(roleMapping.isDatabaseAccess);
        }

        await member.roles.set(rolesToAssign);
        console.log(`Synced roles for ${user.username}`);
    } catch (err) {
        console.error(`Sync Error for ${user.username}:`, err);
    }
}

// --- DATABASE WATCHER ---
function startDatabaseWatcher() {
    const changeStream = User.watch([], { fullDocument: 'updateLookup' });
    changeStream.on('change', async (change) => {
        if (change.operationType === 'update' || change.operationType === 'replace') {
            const user = change.fullDocument;
            await syncDiscordRoles(user);
        }
    });
}

// --- PASSPORT CONFIG ---
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { const user = await User.findById(id); done(null, user); } catch (err) { done(err); }
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
        return done(null, false, { message: 'Discord not linked.' });
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
    cookie: { maxAge: 3600000 }
}));
app.use(passport.initialize());
app.use(passport.session());

// --- ROUTES ---
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => {
    req.session.username = req.user.username;
    req.session.isLoggedIn = true;
    res.redirect('/dashboard');
});

app.get('/api/users', async (req, res) => {
    const users = await User.find({}, '-password');
    res.json(users);
});

app.post('/api/promote-user/:username', async (req, res) => {
    const target = await User.findOne({ username: req.params.username });
    if (target) {
        target.role = req.body.newRole;
        await target.save();
        await syncDiscordRoles(target);
        res.sendStatus(200);
    }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/dashboard', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'dashboard.html')) : res.redirect('/'));
app.get('/admin', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'admin.html')) : res.redirect('/'));

app.listen(process.env.PORT || 3000, () => console.log("MSRP Server Live"));
