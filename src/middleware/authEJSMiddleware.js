const User = require("../models/user");

class AuthEJSMiddleware {
  static async requireLogin(req, res, next) {
    try {
      if (!req.session.userId) {
        return res.redirect("/ejs/login");
      }

      const user = await User.findById(req.session.userId);

      if (!user) {
        req.session.destroy(() => {});
        return res.redirect("/ejs/login");
      }

      req.ejsUser = user;

      next();
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "Authentication error",
      });
    }
  }

  static allowRoles(...roles) {
    return (req, res, next) => {
        if(!req.ejsUser) {
            return res.redirect("/ejs/login");
        }

        if(!roles.includes(req.ejsUser.role)) {
            return res.status(403).json({
                success: false,
                message: "Access denied"
            });
        }

        next()
    };
  }
}

module.exports = AuthEJSMiddleware;
