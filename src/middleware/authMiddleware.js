const jwt = require("jsonwebtoken");

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

  static verifySecretKey(req) {
    const secretKey = req.headers["x-secret-key"];

    if (!secretKey) {
      return {
        success: false,
        status: 401,
        message: "Blog secret key required",
      };
    }

    if (secretKey !== process.env.BLOG_SECRET_KEY) {
      return {
        success: false,
        status: 403,
        message: "Invalid blog secret key",
      };
    }

    return {
      success: true,
    };
  }
}

module.exports = AuthMiddleware;
