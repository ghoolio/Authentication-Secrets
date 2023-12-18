//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const port = 3000;
const pg = require('pg');
 
const app = express();

console.log(process.env.BLA);
 
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "userDB",
    password: "9WzQueG&ZM",
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
    const password = req.body.password;
    try {
        await db.query("INSERT INTO users (username, password) VALUES ($1, pgp_sym_encrypt(($2), ($3)))", [email, password, secretKey]);
        res.render("secrets.ejs");
    } catch (err) {
        console.log(err.message);
    };
});
 
app.post("/login", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
    try {
        const result = await db.query("SELECT username, pgp_sym_decrypt(password, ($1)) AS password FROM users WHERE username=($2)", [secretKey, email]);
        const user = result.rows[0];
        console.log(user);
        if (user.password == password) {
            res.render("secrets.ejs");
        };
    } catch (err) {
        console.log(err.message);
    };
});

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
