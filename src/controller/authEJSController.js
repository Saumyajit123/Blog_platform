const bcryptjs = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const User = require("../models/user");
const Blog = require("../models/blog");
const Category = require("../models/category");
const sendMail = require("../config/mail");
const userSchema = require("../validate/userSchema");

class AuthEJSController {
  // ================================
  // Login
  // ================================

  static loginPage(req, res) {
    const resetSuccess = req.query.reset === "success";

    res.render("auth/login", {
      error: null,
      success: resetSuccess
        ? "Password changed successfully. Please login."
        : null,
    });
  }

  static async login(req, res) {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({
        email: email.toLowerCase(),
      });

      if (!user) {
        return res.status(401).render("auth/login", {
          error: "Invalid email or password",
          success: null,
        });
      }

      const passwordMatch = await bcryptjs.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).render("auth/login", {
          error: "Invalid email or password",
          success: null,
        });
      }

      // Session based authentication for EJS UI
      req.session.userId = user._id.toString();

      req.session.role = user.role;

      return res.redirect("/ejs/dashboard");
    } catch (error) {
      console.error("EJS login error:", error);

      return res.status(500).render("auth/login", {
        error: "Something went wrong",
        success: null,
      });
    }
  }

  // ======================================
  // Logout
  // ======================================

  static logout(req, res) {
    req.session.destroy((error) => {
      if (error) {
        return res.sattus(500).json({
          success: false,
          message: "Logout failed",
        });
      }

      res.clearCookie("connect.sid");

      return res.redirect("/ejs/login");
    });
  }

  // =================================
  // Dashboard
  // =================================

  static async dashboard(req, res) {
    try {
      const user = req.ejsUser;

      // Admin Dashboard
      if (user.role === "admin") {
        const totalUsers = await User.countDocuments();
        const totalWriters = await User.countDocuments({
          role: "writer",
        });
        const totalNormalUsers = await User.countDocuments({
          role: "user",
        });
        const totalBlogs = await Blog.countDocuments();
        const publishedBlogs = await Blog.countDocuments({
          status: "approved",
          isPublished: true,
        });
        const pendingBlogs = await Blog.countDocuments({
          status: "pending",
        });
        const rejectedBlogs = await Blog.countDocuments({
          status: "rejected",
        });
        const totalCategories = await Category.countDocuments();
        return res.render("dashboard/admin", {
          user,
          totalUsers,
          totalWriters,
          totalNormalUsers,
          totalBlogs,
          publishedBlogs,
          pendingBlogs,
          rejectedBlogs,
          totalCategories,
        });
      }

      // Writer dashboard:
      if (user.role === "writer") {
        const totalBlogs = await Blog.countDocuments({
          author: user._id,
        });

        const publishedBlogs = await Blog.countDocuments({
          author: user._id,
          status: "approved",
          isPublished: true,
        });

        const pendingBlogs = await Blog.countDocuments({
          author: user._id,
          status: "rejected",
        });

        const rejectedBlogs = await Blog.countDocuments({
          author: user._id,
          status: "rejected",
        });

        return res.render("dashboard/writer", {
          user,
          totalBlogs,
          publishedBlogs,
          pendingBlogs,
          rejectedBlogs,
        });
      }

      //User dashboard:
      const publishedBlogs = await Blog.countDocuments({
        status: "approved",
        isPublished: true,
      });

      return res.render("dashboard/user", {
        user,
        publishedBlogs,
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }

  // ===================================
  // Change Password Page
  // ===================================

  static changePasswordPage(req, res) {
    res.render("password/change", {
      user: req.ejsUser,
      error: null,
      success: null,
    });
  }

  // =====================================
  // Change password
  // =====================================

  static async changePassword(req, res) {
    try {
      const { currentpassword, newPassword } = req.body;
      const user = req.ejsUser;

      //Verify current password:
      const passwordMatch = await bcryptjs.compare(
        currentpassword,
        user.password,
      );

      if (!passwordMatch) {
        return res.status(400).render("password/change", {
          user,
          error: "Current password is incorrect",
          success: null,
        });
      }

      const samePassword = await bcryptjs.compare(newPassword, user.password);

      if (samePassword) {
        return res.status(400).render("password/change", {
          user,
          error: "New password must be different from current password",
          success: null,
        });
      }

      user.password = await bcryptjs.hash(newPassword, 10);

      //Invalidate existing api refresh token:
      user.refreshToken = null;

      // Invalidate existing secret key:
      if (Object.prototype.hasOwnProperty.call(user, "secretKeyHash")) {
        user.secretKeyHash = null;
      }

      await user.save();

      //Destroy Ejs session so user logs in again:
      req.session.destroy((sessionError) => {
        if (sessionError) {
          console.error("Session destroy error:", sessionError);
        }

        res.clearCookie("connect.sid");

        return res.redirect("/ejs/login?reset=success");
      });
    } catch (error) {
      console.error(error);
      return res.status(500).render("password/change", {
        user: req.ejsUser,
        error: "Password change failed",
        success: null,
      });
    }
  }

  //=================================
  // Forgot password page
  //=================================

  static forgotPasswordPage(req, res) {
    res.render("password/forgot", {
      error: null,
      success: null,
    });
  }

  //=====================================
  // Forgot password
  //=====================================

  static async forgotPassword(req, res) {
    try {
      const { email } = req.body;
      const user = await User.findOne({
        email: email.toLowerCase(),
      });

      if (!user) {
        return res.render("password/forgot", {
          error: null,
          success:
            "If an account exists with this email, a password reset link has been sent.",
        });
      }

      //Generate random token:
      const resetToken = crypto.randomBytes(32).toString("hex");

      //Store only hash in database:
      const resetTokenHash = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

      user.resetTokenHash = resetTokenHash;

      user.resetTokenExpires = Date.now() + 1000 * 60 * 30;

      await user.save();

      const resetLink = `${process.env.APP_URL}/ejs/reset-password?token=${resetToken}`;

      await sendMail({
        to: user.email,
        subject: "Blog Platform - Reset password",
        html: `<div style="font-family: Arial, sans-serif;">
            <h2>Reset Your Password</h2>

            <p>Hello ${user.name},</p>

            <p>
              We received a request to reset
              your Blog Platform password.
            </p>

            <p>
              Click the button below to create
              a new password.
            </p>

            <p>
              <a
                href="${resetLink}"
                style="
                  display:inline-block;
                  padding:12px 20px;
                  background:#111827;
                  color:#ffffff;
                  text-decoration:none;
                  border-radius:6px;
                "
              >
                Reset Password
              </a>
            </p>

            <p>
              This link expires in 30 minutes.
            </p>

            <p>
              If you did not request this,
              you can ignore this email.
            </p>
          </div>`,
      });

      return res.render("password/forgot", {
        error: null,
        success:
          "If an account exists with this email, a password reset link has been sent.",
      });
    } catch (error) {
      console.error("Forgot password error:", error);

      return res.status(500).render("password/forgot", {
        error: "Unable to process forgot password request.",
        success: null,
      });
    }
  }

  //=====================================
  // Reset password page
  //=====================================

  static resetPasswordPage(req, res) {
    const { token } = req.query;

    if (!token) {
      return res.status(400).send("Reset token is required");
    }

    return res.render("password/reset", {
      token,
      error: null,
      success: null,
    });
  }

  //=======================================
  // Reset password
  //=======================================

  static async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body;

      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
      const user = await User.findOne({
        resetTokenHash: tokenHash,
        resetTokenExpires: {
          $gt: Date.now(),
        },
      });

      if (!user) {
        return res.status(400).render("password/reset", {
          token,
          error: "Reset link is invalid or expired.",
          success: null,
        });
      }

      //Prevent reusing same password:
      const samePassword = await bcryptjs.compare(newPassword, user.password);

      if (samePassword) {
        return res.status(400).render("password/reset", {
          token,
          error: "New password must be different from current password.",
          success: null,
        });
      }

      user.password = await bcryptjs.hash(newPassword, 10);

      // Delete reset token
      user.resetTokenHash = null;
      user.resetTokenExpires = null;

      // Invalidate existing API credentials
      user.refreshToken = null;

      if (Object.prototype.hasOwnProperty.call(user, "secretKeyHash")) {
        user.secretKeyHash = null;
      }

      await user.save();

      return res.redirect("/ejs/login?reset=success");
    } catch (error) {
      console.error("Reset password error:", error);
      return res.status(500).render("password/reset", {
        token: req.body.token,
        error: "Unable to reset password.",
        success: null,
      });
    }
  }

  // =================================================
  // Admin gets user list
  //==================================================

  static async users(req, res) {
    try {
      const users = await User.find()
        .select(
          "-password " +
            "-refreshToken " +
            "-secretKeyhash " +
            "-resetTokenHash " +
            "-resetTokenExpires ",
        )
        .sort({
          createdAt: -1,
        });
      return res.render("admin/users", {
        user: req.ejsUser,
        users,
        message:
          req.query.mail === "sent"
            ? "Password change email sent successfully."
            : null,
      });
    } catch (error) {
      console.error("Users list error:", error);
      return res.status(500).json({
        success: false,
        message: "Server Error",
      });
    }
  }

  //==============================================
  // Admin create user page
  //==============================================

  static createUserPage(req, res) {
    return res.render("admin/create-user", {
      user: req.ejsUser,
      error: null,
      success: null,
    });
  }

  //================================================
  // Admin can create writer/user :
  //================================================

  static async createUser(req, res) {
    try {
      const { name, email, password, role } = req.body;

      if (!["writer", "user"].includes(role)) {
        return res.status(400).render("admin/create-user", {
          user: req.ejsUser,
          error: "Only writer and user accounts can be created here.",
          success: null,
        });
      }

      const existingUser = await User.findOne({
        email: email.toLowerCase(),
      });

      if (existingUser) {
        return res.status(409).render("admin/create-user", {
          user: req.ejsUser,
          error: "Email already exists",
          success: null,
        });
      }

      const hashedPassword = await bcryptjs.hash(password, 10);

      const newUser = await User.create({
        name,
        email: email.toLowerCase(),
        password: hashedPassword,
        role,
      });

      // REDIRECT TO USER MANAGEMENT PAGE
      return res.redirect("/ejs/admin/users?created=success");

      //Admin sends the password change email:
      return res.render("admin/create-user", {
        user: req.ejsUser,
        error: null,
        success: `${role} created successfully.`,
        createdUserId: newUser._id.toString(),
      });
    } catch (error) {
      console.error("Create user error:", error);

      return res.status(500).render("admin/create-user", {
        user: req.ejsUser,
        error: "Unable to create user",
        success: null,
      });
    }
  }

  //========================================================
  //Admin sends password change email to writer/user:
  //========================================================

  static async sendPasswordChangeEmail(req, res) {
    try {
      const { userId } = req.body;

      const targetUser = await User.findById(userId);

      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      if (!["writer", "user"].includes(targetUser.role)) {
        return res.status(403).json({
          success: false,
          message: "Password change email can only be sent to writer or user.",
        });
      }

      const resetToken = crypto.randomBytes(32).toString("hex");

      const resetTokenHash = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

      targetUser.resetTokenHash = resetTokenHash;
      targetUser.resetTokenExpires = Date.now() + 1000 * 60 * 30;

      await targetUser.save();

      const resetLink = `${process.env.APP_URL}/ejs/reset-password?token=${resetToken}`;

      await sendMail({
        to: targetUser.email,
        subject: "Blog Platform - Password Change Required",
        html: `<div style="font-family:Arial,sans-serif;">
            <h2>Password Change Required</h2>

            <p>
              Hello ${targetUser.name},
            </p>

            <p>
              The administrator has requested
              that you change your password.
            </p>

            <p>
              Click the button below to set
              a new password.
            </p>

            <p>
              <a
                href="${resetLink}"
                style="
                  display:inline-block;
                  padding:12px 20px;
                  background:#111827;
                  color:#ffffff;
                  text-decoration:none;
                  border-radius:6px;
                "
              >
                Change Password
              </a>
            </p>

            <p>
              This link expires in 30 minutes.
            </p>
          </div>`,
      });

      return res.redirect("/ejs/admin/users?mail=sent");
    } catch (error) {
      console.error("Send password email error:", error);
      return res.status(500).json({
        success: false,
        message: "Unable to send password-change email",
      });
    }
  }

  //======================================================
  // Create category page
  //======================================================

  static async createCategoryPage(req, res) {
    return res.render(`${req.ejsUser.role}/create-category`, {
      user: req.ejsUser,
      error: null,
      success: null,
    });
  }

  //======================================================
  // Create category
  //======================================================

  static async createCategory(req, res) {
    try {
      const { name } = req.body;

      const existingCategory = await Category.findOne({
        name: name.trim(),
      });

      if (existingCategory) {
        return res.status(409).render(`${req.ejsUser.role}/create-category`, {
          user: req.ejsUser,
          error: "Category already exists",
          success: null,
        });
      }

      await Category.create({
        name: name.trim(),
      });

      return res.render(`${req.ejsUser.role}/create-category`, {
        user: req.ejsUser,
        error: null,
        success: "Category created successfully",
      });
    } catch (error) {
      console.error("Create category error:", error);

      return res.status(500).render(`${req.ejsUser.role}/create-category`, {
        user: req.ejsUser,
        error: "Category creation failed",
        success: null,
      });
    }
  }

  //======================================
  // Create blog page
  //======================================

  static async createBlogPage(req, res) {
    try {
      const categories = await Category.find().sort({ name: 1 });

      const view =
        req.ejsUser.role === "admin"
          ? "admin/create-blog"
          : "writer/create-blog";

      return res.render(view, {
        user: req.ejsUser,
        categories,
        error: null,
        success: null,
      });
    } catch (error) {
      console.error("Create blog page error:", error);
      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }

  //===========================================
  //Create blog
  //===========================================

  static async createBlog(req, res) {
    try {
      const { title, content, category } = req.body;
      const blog = await Blog.create({
        title,
        content,
        category,
        author: req.ejsUser._id,
        status: req.ejsUser.role === "admin" ? "approved" : "pending",
        isPublished: req.ejsUser.role === "admin",
      });

      const categories = await Category.find().sort({
        name: 1,
      });

      return res.render(`${req.ejsUser.role}/create-blog`, {
        user: req.ejsUser,
        categories,
        error: null,
        success:
          req.ejsUser.role === "admin"
            ? "Blog created and published successfully."
            : "Blog created and submitted for approval.",
        blog,
      });
    } catch (error) {
      console.error("Create blog error:", error);

      const categories = await Category.find().sort({
        name: 1,
      });

      return res.status(500).render(`${req.ejsUser.role}/create-blog`, {
        user: req.ejsUser,
        categories,
        error: "Blog creation failed",
        success: null,
      });
    }
  }

  //======================================
  //Blog list
  //======================================

  static async blogs(req, res) {
    try {
      let blogs;

      //Admin
      if (req.ejsUser.role === "admin") {
        blogs = await Blog.find()
          .populate("author", "name email role")
          .populate("category", "name")
          .sort({
            createdAt: -1,
          });
      }

      //Writer
      else if (req.ejsUser.role === "writer") {
        blogs = await Blog.find({
          author: req.ejsUser._id,
        })
          .populate("author", "name email role")
          .populate("category", "name")
          .sort({ createdAt: -1 });
      }

      //User
      else {
        blogs = await blog
          .find({
            status: "approved",
            isPublished: true,
          })
          .populate("author", "name")
          .populate("category", "name")
          .sort({ createdAt: -1 });
      }

      return res.render("blog/list", {
        user: req.ejsUser,
        blogs,
      });
    } catch (error) {
      console.error("Blog list error:", error);

      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }

  //======================================
  // Blog details
  //======================================

  static async blogDetail(req, res) {
    try {
      const blog = await Blog.findById(req.params.id)
        .populate("author", "name email role")
        .populate("category", "name")
        .populate("comments.user", "name email");

      if (!blog) {
        return res.status(404).send("Blog not found");
      }

      // User can see only published blogs
      if (req.ejsUser.role === "user") {
        if (blog.status !== "approved" || !blog.isPublished) {
          return res.status(403).send("This blog is not available.");
        }
      }

      // Writer can see own blogs
      if (req.ejsUser.role === "writer") {
        const ownBlog =
          blog.author &&
          blog.author._id.toString() === req.ejsUser._id.toString();

        const publicBlog =
          blog.status === "approved" && blog.isPublished === true;

        if (!ownBlog && !publicBlog) {
          return res.status(403).send("This blog is not available.");
        }
      }

      return res.render("blog/detail", {
        user: req.ejsUser,
        blog,
      });
    } catch (error) {
      console.error("Blog detail error:", error);

      return res.status(500).send("Unable to load blog");
    }
  }

  //=======================================
  //Update blog page
  //=======================================

  static async updateBlogPage(req, res) {
    try {
      const blogId = req.params.id;

      console.log("Edit Blog ID:", blogId);
      console.log("Logged in user:", req.ejsUser.email);
      console.log("Logged in role:", req.ejsUser.role);

      // -------------------------------------------------
      // Validate MongoDB ID
      // -------------------------------------------------

      // const mongoose = require("mongoose");

      if (!mongoose.Types.ObjectId.isValid(blogId)) {
        return res.status(400).send("Invalid blog ID");
      }

      // -------------------------------------------------
      // Find blog
      // -------------------------------------------------

      const blog = await Blog.findById(blogId);

      if (!blog) {
        return res.status(404).send("Blog not found");
      }

      // -------------------------------------------------
      // Writer can edit only own blog
      // -------------------------------------------------

      if (req.ejsUser.role === "writer") {
        if (blog.author.toString() !== req.ejsUser._id.toString()) {
          return res.status(403).send("You can edit only your own blog.");
        }
      }

      // -------------------------------------------------
      // Get categories
      // -------------------------------------------------

      const categories = await Category.find().sort({
        name: 1,
      });

      // -------------------------------------------------
      // Select EJS view according to role
      // -------------------------------------------------

      const view =
        req.ejsUser.role === "admin" ? "admin/edit-blog" : "writer/edit-blog";

      console.log("Rendering view:", view);

      // -------------------------------------------------
      // Render
      // -------------------------------------------------

      return res.render(view, {
        user: req.ejsUser,
        blog,
        categories,
        error: null,
        success: null,
      });
    } catch (error) {
      console.error("EDIT BLOG PAGE ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Server error",
        error: error.message,
      });
    }
  }

  //===================================
  //Update blog
  //===================================

  static async updateBlog(req, res) {
    try {
      const blogId = req.params.id;

      const { title, content, category } = req.body;

      const blog = await Blog.findById(blogId);

      if (!blog) {
        return res.status(404).send("Blog not found");
      }

      // -------------------------------------------------
      // WRITER OWNERSHIP
      // -------------------------------------------------

      if (req.ejsUser.role === "writer") {
        if (blog.author.toString() !== req.ejsUser._id.toString()) {
          return res.status(403).send("You can update only your own blog.");
        }
      }

      // -------------------------------------------------
      // UPDATE
      // -------------------------------------------------

      blog.title = title;
      blog.content = content;
      blog.category = category;

      // -------------------------------------------------
      // WRITER NEEDS APPROVAL AGAIN
      // -------------------------------------------------

      if (req.ejsUser.role === "writer") {
        blog.status = "pending";

        blog.isPublished = false;
      }

      await blog.save();

      return res.redirect(`/ejs/blog/${blog._id}`);
    } catch (error) {
      console.error("UPDATE BLOG ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Server error",
        error: error.message,
      });
    }
  }

  //==============================================
  // Delete Blog
  //==============================================

  static async deleteBlog(req, res) {
    try {
      const blog = await Blog.findById(req.params.id);

      if (!blog) {
        return res.status(404).send("Blog not found");
      }

      // Writer can delete only own blog
      if (req.ejsUser.role === "writer") {
        if (blog.author.toString() !== req.ejsUser._id.toString()) {
          return res.status(403).send("You can delete only your own blog.");
        }
      }

      await Blog.findByIdAndDelete(req.params.id);

      return res.redirect("/ejs/blogs");
    } catch (error) {
      console.error("Delete blog error:", error);

      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }

  //===============================
  // Like blog
  //===============================

  static async likeBlog(req, res) {
    try {
      const blog = await Blog.findById(req.params.id);

      if (!blog) {
        return res.status(404).json({
          success: false,
          message: "Blog not found",
        });
      }

      //User can loke only published blogs
      if (req.ejsUser.role === "user") {
        if (blog.status !== "approved" || !blog.isPublished) {
          return res.status(403).json({
            success: false,
            message: "You can like only published blog.",
          });
        }
      }

      const userId = req.ejsUser._id.toString();

      const alradyLiked = blog.likes.some((id) => id.toString() === userId);

      if (alradyLiked) {
        blog.likes = blog.likes.filter((id) => id.toString() !== userId);
      } else {
        blog.likes.push(req.ejsUser._id);
      }

      await blog.save();

      return res.redirect(`/ejs/blog/${blog._id}`);
    } catch (error) {
      console.error("Like blog error:", error);

      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }

  //=======================================
  //Comment blog
  //=======================================

  static async commentBlog(req, res) {
    try {
      const { comment } = req.body;

      const blog = await Blog.findById(req.params.id);

      if (!blog) {
        return res.status(404).send("Blog not found");
      }

      // User can comment only published blogs
      if (req.ejsUser.role === "user") {
        if (blog.status !== "approved" || !blog.isPublished) {
          return res.status(403).send("You cannot comment on this blog.");
        }
      }

      blog.comments.push({
        user: req.ejsUser._id,
        comment: comment.trim(),
      });

      await blog.save();

      return res.redirect(`/ejs/blog/${blog._id}`);
    } catch (error) {
      console.error("Comment blog error:", error);

      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }

  //========================================
  // Admin approve blog
  //========================================

  static async approveBlog(req, res) {
    try {
      const blog = await Blog.findById(req.params.id);

      if (!blog) {
        return res.status(404).send("Blog not found");
      }

      blog.status = "approved";

      blog.isPublished = true;

      await blog.save();

      return res.redirect("/ejs/blogs");
    } catch (error) {
      console.error("Approve blog error:", error);

      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }

  // =====================================================
  // Admin rejects blog
  // =====================================================

  static async rejectBlog(req, res) {
    try {
      const blog = await Blog.findById(req.params.id);

      if (!blog) {
        return res.status(404).send("Blog not found");
      }

      blog.status = "rejected";

      blog.isPublished = false;

      await blog.save();

      return res.redirect("/ejs/blogs");
    } catch (error) {
      console.error("Reject blog error:", error);

      return res.status(500).json({
        success: false,
        message: "Server error",
      });
    }
  }
}

module.exports = AuthEJSController;
