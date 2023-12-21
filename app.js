// Load environment variables from .env file
require('dotenv').config();

// Use require for packages
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

// Create a PostgreSQL pool for database connections
const dbPool = new Pool({
    user: "postgres",
    host: "localhost",
    database: "userDB",
    password: process.env.PASSWORD,
    port: 5433,
});

// Function to execute SQL queries on the database
async function query(sql, params) {
    const client = await dbPool.connect();
    try {
        return await client.query(sql, params);
    } finally {
        client.release();
    }
}

// Create an Express application
const app = express();
const port = 3000;

// Set up middleware for parsing URL-encoded request bodies and serving static files
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Configure session handling using express-session
app.use(
    session({
        secret: process.env.SESSION_SECRET, // Secret used to sign the session ID cookie
        resave: false, // Do not save session if unmodified
        saveUninitialized: false, // Do not create a session until something is stored
        cookie: {
            maxAge: 3600000, // Session expiration time in milliseconds
            // secure: true, // Only transmit over HTTPS
            // httpOnly: true, // Restrict access from JavaScript
            // sameSite: 'strict' // Control cross-origin cookie usage
        },
    })
);

// Initialize Passport and use Passport sessions
app.use(passport.initialize());
app.use(passport.session());

// Check if username exists in the database
const usernameExists = async (username) => {
    // Query the database to check if the username exists
    const data = await query("SELECT * FROM users WHERE username=$1", [username]);

    // Return the user data if found, otherwise return false
    if (data.rowCount == 0) return false;
    return data.rows[0];
};

// Create a new user in the database
const createUser = async (username, password) => {
    try {
        // Generate a salt and hash the password
        const salt = await bcrypt.genSalt(10); // Set the number of salt rounds for password hashing
        const hash = await bcrypt.hash(password, salt);

        // Convert the hash buffer to a string
        const hashString = hash.toString('utf-8');

        // Insert the new user into the database and return the user data
        const data = await query(
            "INSERT INTO users(username, password) VALUES ($1, $2) RETURNING id, username, password",
            [username, hashString]
        );

        // Return the newly created user
        if (data.rowCount == 0) return false;
        return data.rows[0];
    } catch (error) {
        console.error("Error during user creation:", error);
        throw error;
    }
};

// Match entered password with the hashed password from the database
const matchPassword = (password, hashPassword) => {
    // Convert the hashPassword buffer to a string
    const hashString = hashPassword.toString('utf-8');
    // Use compare for asynchronous password comparison
    return bcrypt.compare(password, hashString);
};

// Passport strategy for user registration
passport.use(
    "local-register",
    new LocalStrategy(async (username, password, done) => {
        try {
            // Check if the user already exists
            const userExists = await usernameExists(username);

            // If user exists, return false
            if (userExists) {
                return done(null, false);
            }

            // Create a new user and return the user object
            const user = await createUser(username, password);
            return done(null, user);
        } catch (error) {
            done(error);
        }
    })
);

// Passport strategy for user login
passport.use(
    "local-login",
    new LocalStrategy(async (username, password, done) => {
        try {
            // Find the user in the database
            const user = await usernameExists(username);

            // If user doesn't exist, return false
            if (!user) {
                console.log("User not found");
                return done(null, false);
            }

            // Check user data before password comparison (debugging)
            console.log("User data before password comparison:", user);

            // Check if the password matches
            const isMatch = await matchPassword(password, user.password);

            // Return user object if password matches, otherwise return false
            if (isMatch) {
                console.log("Login successful");
                return done(null, user);
            } else {
                console.log("Password does not match");
                return done(null, false);
            }
        } catch (error) {
            console.error("Error during login:", error);
            return done(error, false);
        }
    })
);

// Serialize and deserialize user information for session management
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        // Find the user by ID and return the user object
        const response = await query('SELECT * FROM users WHERE id = $1', [id]);
        const user = response.rows[0];
        done(null, user);
    } catch (error) {
        done(error, false);
    }
});

// Routes for different endpoints

// Home page route
app.get("/", async (req, res) => {
    res.render("home.ejs");
});

// Register page route
app.get("/register", async (req, res) => {
    res.render("register.ejs");
});

// Login page route
app.get("/login", async (req, res) => {
    res.render("login.ejs");
});

// Login form submission route
app.post('/login', passport.authenticate('local-login', {
    failureRedirect: '/login', // Redirect on failure
    successRedirect: '/secrets', // Redirect on success
}));

// Registration form submission route
app.post("/register", passport.authenticate("local-register", {
    failureRedirect: '/register', // Redirect if registration fails
    successRedirect: '/secrets', // Redirect on successful registration
}));

// Secrets page route
app.get('/secrets', (req, res) => {
    // Check if the user is authenticated
    if (req.isAuthenticated()) {
        res.render('secrets.ejs');
    } else {
        // Redirect to login page if the user is not authenticated
        res.redirect('/login');
    }
});

// Logout route
app.get("/logout", (req, res) => {
    res.clearCookie("connect.sid"); // Clear the cookies left on the client-side
    req.logOut(() => {
        res.redirect("/"); // Redirect to the home page after logout
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
