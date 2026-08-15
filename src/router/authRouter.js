const express = require("express");
const router = express.Router();

const AuthController = require("../controller/authController");
// const AuthMiddleware = require("../middleware/authMiddleware");

// SINGLE BLOG API
router.all("/", AuthController.blogHandler);



module.exports = router;
