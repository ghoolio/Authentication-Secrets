//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const port = 3000;
const pg = require('pg');
const SHA256 = require("crypto-js/sha256");
const bcrypt = require("bcrypt");
 
const saltRounds = 10;
const app = express();
 
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "userDB",
    password: process.env.PASSWORD,
    port: 5433,
});
db.connect();

app.get("/", async (req, res) => {
    res.render("home.ejs");
});

app.get("/register", async (req, res) => {
    res.render("register.ejs");
});

app.get("/login", async (req, res) => {
    res.render("login.ejs");
});

const secretKey = process.env.SECRETKEY;

app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;  // Note: Do not hash the password here with bcrypt
    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        console.log(hashedPassword);
        await db.query("INSERT INTO users (username, password) VALUES ($1, $2)", [email, hashedPassword]);
        res.render("secrets.ejs");
    } catch (err) {
        console.log(err.message);
    };
});

app.post("/login", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const result = await db.query("SELECT username, password FROM users WHERE username=($1)", [email]);
        const user = result.rows[0];
        if (user) {
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                res.render("secrets.ejs");
                return;
            }
        }
        // Incorrect username or password
        res.redirect("/login");
    } catch (err) {
        console.log(err.message);
    };
});




app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});