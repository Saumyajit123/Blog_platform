const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const User = require("../models/User");

class AuthMiddleware {
  static verifyToken(req, res) {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader) {
        return {
          success: false,
          status: 401,
          message: "Authorization token required",
        };
      }

      const parts = authHeader.split(" ");

      // Check if the authorization header is in the correct format (Bearer <token>)
      if (parts.length !== 2 || parts[0] !== "Bearer") {
        return {
          success: false,
          status: 401,
          message: "Invalid authorization format",
        };
      }

      // Extract the token from the authorization header
      const token = parts[1];

      const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

      req.user = decoded;

      return {
        success: true,
      };
    } catch (error) {
      return {
        success: false,
        status: 401,
        message: "Invalid or expired access token",
      };
    }
  }

  static async verifySecretKey(req) {
    try {
      const secretKey = req.headers["x-secret-key"];

      if (!secretKey) {
        return {
          success: false,
          status: 401,
          message: "Secret key required",
        };
      }

      if (!req.user || !req.user.id) {
        return {
          success: false,
          status: 401,
          message: "User information missing from token",
        };
      }

      const user = await User.findById(req.user.id);

      if (!user) {
        return {
          success: false,
          status: 404,
          message: "User not found",
        };
      }

      if (!user.secretKeyHash) {
        return {
          success: false,
          status: 403,
          message: "Secret key is not configured for this user",
        };
      }

      const isValid = await bcryptjs.compare(secretKey, user.secretKeyHash);

      if (!isValid) {
        return {
          success: false,
          status: 403,
          message: "Invalid secret key",
        };
      }

      return {
        success: true,
      };
    } catch (error) {
      console.error("Secret key verification error:", error);

      return {
        success: false,
        status: 500,
        message: "Secret key verification failed",
      };
    }
  }
}

module.exports = AuthMiddleware;
