require("dotenv").config();
const express = require("express");
const DBConnect = require("./src/config/dbconnect");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("express-session");

DBConnect();

const app = express();

const Port = process.env.PORT || 3007;

app.use(cors());

app.use(cookieParser());
app.use(
  session({
    secret: process.env.BLOG_SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
    },
  }),
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authRouter = require("./src/router/authRouter");
app.use('/api/blog', authRouter);


app.listen(Port, () => {
  console.log(`Server is running on port: ${Port}`);
});