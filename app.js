require("dotenv").config();
const express = require("express");
const DBConnect = require("./src/config/dbconnect");
const AuthEJSController = require("./src/controller/authEJSController");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const path = require('path');

DBConnect();

const app = express();

const Port = process.env.PORT || 3007;

app.use(cors());

app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
    },
  }),
);

// =====================================================
// STATIC FILES
// =====================================================

app.use(express.static(path.join(__dirname, "public")));

// =====================================================
// EJS
// =====================================================

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "src", "views"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authRouter = require("./src/router/authRouter");
app.use("/api/blog", authRouter);

const authEjsRouter = require("./src/router/authEJSRouter");
app.use("/ejs", authEjsRouter);

app.get("/", AuthEJSController.landingPage);

app.listen(Port, () => {
  console.log(`Server is running on port: ${Port}`);
});
