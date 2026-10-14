const bcryptjs = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const User = require("../models/User");
const Blog = require("../models/blog");
const Category = require("../models/category");
const sendMail = require("../config/mail");
const userSchema = require("../validate/userSchema");
const uploadCloudinary = require("../utils/uploadCloudinary");
const deleteCloudinary = require("../utils/deleteCloudinary");

class AuthEJSController {
  // ================================
  // Register
  // ================================
  static registerPage(req, res) {
    return res.render("auth/register", {
      title: "Join the Blog Platform",
      error: null,
      success: null,
    });
  }

  static async register(req, res) {
    try {
      const { name, email, password, role } = req.body;
      const requestedRole = String(role || "").toLowerCase();

      if (!["writer", "user"].includes(requestedRole)) {
        return res.status(400).render("auth/register", {
          title: "Join the Blog Platform",
          error: "Choose either Writer or User",
          success: null,
        });
      }

      const normalizedEmail = String(email || "")
        .trim()
        .toLowerCase();

      const existingUser = await User.findOne({
        email: normalizedEmail,
      });

      if (existingUser) {
        return res.status(409).render("auth/register", {
          title: "Join the Blog Platform",
          error: "An account with this email already exists.",
          success: null,
        });
      }

      if (!name || name.trim().length < 2) {
        return res.status(400).render("auth/register", {
          title: "Join the Blog Platform",
          error: "Name must contain at least 2 characters.",
          success: null,
        });
      }

      if (!password || password.length < 8) {
        return res.status(400).render("auth/register", {
          title: "Join the Blog Platform",
          error: "Password must contain at least 8 characters.",
          success: null,
        });
      }

      const hashedPassword = await bcryptjs.hash(password, 10);

      const isWriter = requestedRole === "writer";

      await User.create({
        name: name.trim(),
        email: normalizedEmail,
        password: hashedPassword,
        role: isWriter ? "user" : "user",
        requestedRole,
        approvalStatus: isWriter ? "pending" : "approved",
        approvedAt: isWriter ? null : new Date(),
      });

      if (isWriter) {
        return res.status(201).render("auth/register", {
          title: "Join the Blog Platform",
          error: null,
          success:
            "Your Writer application has been submitted. " +
            "You can log in as a Writer after an administrator approves it.",
        });
      }

      return res.status(201).render("auth/register", {
        title: "Join the Blog Platform",
        error: null,
        success: "Your User account has been created. You can now log in.",
      });
    } catch (error) {
      console.error("Registration error:", error);

      return res.status(500).render("auth/register", {
        title: "Join the Blog Platform",
        error: "Unable to create your account. Please try again.",
        success: null,
      });
    }
  }

  // ================================
  // Login
  // ================================

  static loginPage(req, res) {
    const resetSuccess = req.query.reset === "success";

    return res.render("auth/login", {
      title: "Blog Platform - Login",
      error: null,
      success: resetSuccess
        ? "Password changed successfully. Please log in."
        : null,
    });
  }

  static async login(req, res) {
    try {
      const { email, password, role } = req.body;

      const selectedRole = String(role || "").toLowerCase();

      if (!["admin", "writer", "user"].includes(selectedRole)) {
        return res.status(400).render("auth/login", {
          title: "Blog Platform - Login",
          error: "Please select Admin, Writer or User login.",
          success: null,
        });
      }

      const user = await User.findOne({
        email: String(email || "")
          .trim()
          .toLowerCase(),
      });

      if (!user) {
        return res.status(401).render("auth/login", {
          title: "Blog Platform - Login",
          error: "Invalid email or password.",
          success: null,
        });
      }

      const passwordMatch = await bcryptjs.compare(
        password || "",
        user.password,
      );

      if (!passwordMatch) {
        return res.status(401).render("auth/login", {
          title: "Blog Platform - Login",
          error: "Invalid email or password.",
          success: null,
        });
      }

      if (selectedRole === "admin" && user.role !== "admin") {
        return res.status(403).render("auth/login", {
          title: "Blog Platform - Login",
          error: "This account does not have administrator access.",
          success: null,
        });
      }

      if (selectedRole === "writer") {
        if (user.requestedRole !== "writer" && user.role !== "writer") {
          return res.status(403).render("auth/login", {
            title: "Blog Platform - Login",
            error: "This account was not registered as a Writer.",
            success: null,
          });
        }

        if (user.approvalStatus === "pending") {
          return res.status(403).render("auth/login", {
            title: "Blog Platform - Login",
            error: "Your Writer application is awaiting admin approval.",
            success: null,
          });
        }

        if (user.approvalStatus === "rejected") {
          return res.status(403).render("auth/login", {
            title: "Blog Platform - Login",
            error:
              "Your Writer application was rejected. " +
              (user.rejectionReason || "Please contact the administrator."),
            success: null,
          });
        }

        if (user.role !== "writer") {
          return res.status(403).render("auth/login", {
            title: "Blog Platform - Login",
            error: "Writer access has not been granted to this account.",
            success: null,
          });
        }
      }

      if (selectedRole === "user") {
        if (user.role !== "user" || user.requestedRole === "writer") {
          return res.status(403).render("auth/login", {
            title: "Blog Platform - Login",
            error:
              "This account cannot log in using the User option. " +
              "Choose its registered role.",
            success: null,
          });
        }
      }

      req.session.regenerate((sessionError) => {
        if (sessionError) {
          console.error(sessionError);

          return res.status(500).render("auth/login", {
            title: "Blog Platform - Login",
            error: "Unable to create a secure session.",
            success: null,
          });
        }

        req.session.userId = user._id.toString();
        req.session.role = user.role;

        return req.session.save((saveError) => {
          if (saveError) {
            console.error(saveError);

            return res.status(500).render("auth/login", {
              title: "Blog Platform - Login",
              error: "Unable to save your session.",
              success: null,
            });
          }

          return res.redirect("/ejs/dashboard");
        });
      });
    } catch (error) {
      console.error("EJS login error:", error);

      return res.status(500).render("auth/login", {
        title: "Blog Platform - Login",
        error: "Something went wrong. Please try again.",
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
          title: "Admin dashboard",
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
          title: "Writer Dashboard",
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
        title: "User Dashboard",
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
      title: "Change Password",
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
      title: "Forgot Password Page",
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
      title: "Reset Password Page",
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
          "-password -refreshToken -secretKeyHash " +
            "-resetTokenHash -resetTokenExpires",
        )
        .sort({
          createdAt: -1,
        })
        .lean();

      const messages = {
        approved: "Writer application approved successfully.",
        rejected: "Writer application rejected.",
        pending: "Application returned to pending review.",
      };
      return res.render("admin/users", {
        title: "Manage Users",
        user: req.ejsUser,
        users,
        message:
          messages[req.query.approval] ||
          (req.query.mail === "sent"
            ? "Password change email sent successfully."
            : req.query.created === "success"
              ? "Account created successfully."
              : null),
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
      title: "Create User",
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
        name: name.trim(),
        email: email.trim().toLowerCase(),
        password: hashedPassword,
        role,
        requestedRole: role,
        approvalStatus: "approved",
        approvedBy: req.ejsUser._id,
        approvedAt: new Date(),
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
      title: "Create Category",
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
        title: "Create Blog",
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
    let uploadedImage = null;

    try {
      const { title, content, category } = req.body;

      if (!title || !content || !category) {
        return res
          .status(400)
          .send("Title, content and category are required.");
      }

      // Upload the selected cover image to Cloudinary.
      if (req.file) {
        uploadedImage = await uploadCloudinary(req.file.buffer, "blog-images");
      }

      await Blog.create({
        title,
        content,
        category,
        author: req.ejsUser._id,

        image: uploadedImage
          ? {
              url: uploadedImage.url,
              public_id: uploadedImage.public_id,
            }
          : {
              url: "",
              public_id: "",
            },

        status: req.ejsUser.role === "admin" ? "approved" : "pending",

        isPublished: req.ejsUser.role === "admin",
      });

      const categories = await Category.find().sort({ name: 1 });

      return res.render(`${req.ejsUser.role}/create-blog`, {
        title: "Create Blog",
        user: req.ejsUser,
        categories,
        error: null,
        success:
          req.ejsUser.role === "admin"
            ? "Blog created and published successfully."
            : "Blog created and submitted for approval.",
      });
    } catch (error) {
      // Remove the new upload if blog creation fails.
      if (uploadedImage?.public_id) {
        try {
          await deleteCloudinary(uploadedImage.public_id);
        } catch (cleanupError) {
          console.error("Image cleanup failed:", cleanupError);
        }
      }

      console.error("Create blog error:", error);
      return res.status(500).send("Blog creation failed.");
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
        blogs = await Blog
          .find({
            status: "approved",
            isPublished: true,
          })
          .populate("author", "name")
          .populate("category", "name")
          .sort({ createdAt: -1 });
      }

      return res.render("blog/list", {
        title: "Blogs",
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
        title: "Blog Details",
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

      // console.log("Edit Blog ID:", blogId);
      // console.log("Logged in user:", req.ejsUser.email);
      // console.log("Logged in role:", req.ejsUser.role);
    
      if (!mongoose.Types.ObjectId.isValid(blogId)) {
        return res.status(400).send("Invalid blog ID");
      }

      const blog = await Blog.findById(blogId);

      if (!blog) {
        return res.status(404).send("Blog not found");
      }

      if (req.ejsUser.role === "writer") {
        if (blog.author.toString() !== req.ejsUser._id.toString()) {
          return res.status(403).send("You can edit only your own blog.");
        }
      }

      const categories = await Category.find().sort({
        name: 1,
      });

      const view =
        req.ejsUser.role === "admin" ? "admin/edit-blog" : "writer/edit-blog";

      // console.log("Rendering view:", view);

      return res.render(view, {
        title: "Edit Blog",
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
    let newImage = null;

    try {
      const { title, content, category } = req.body;
      const blog = await Blog.findById(req.params.id);

      if (!blog) {
        return res.status(404).send("Blog not found.");
      }

      // Preserve the existing writer ownership rule.
      if (req.ejsUser.role === "writer") {
        if (blog.author.toString() !== req.ejsUser._id.toString()) {
          return res.status(403).send("You can update only your own blog.");
        }
      }

      if (!title || !content || !category) {
        return res
          .status(400)
          .send("Title, content and category are required.");
      }

      // Save the old Cloudinary ID before replacing the image.
      const oldPublicId = blog.image?.public_id || null;

      // Upload the replacement only if a new file was selected.
      if (req.file) {
        newImage = await uploadCloudinary(req.file.buffer, "blog-images");
      }

      blog.title = title;
      blog.content = content;
      blog.category = category;

      // If no new image was selected, retain the existing image.
      if (newImage) {
        blog.image = {
          url: newImage.url,
          public_id: newImage.public_id,
        };
      }

      // Writers must submit edited blogs for approval again.
      if (req.ejsUser.role === "writer") {
        blog.status = "pending";
        blog.isPublished = false;
      }

      await blog.save();

      // Delete the old image only after MongoDB saves successfully.
      if (newImage && oldPublicId && oldPublicId !== newImage.public_id) {
        try {
          await deleteCloudinary(oldPublicId);
        } catch (deleteError) {
          console.error("Unable to delete old Cloudinary image:", deleteError);
        }
      }

      return res.redirect(`/ejs/blog/${blog._id}`);
    } catch (error) {
      // Avoid leaving the new upload behind if saving fails.
      if (newImage?.public_id) {
        try {
          await deleteCloudinary(newImage.public_id);
        } catch (cleanupError) {
          console.error("New image cleanup failed:", cleanupError);
        }
      }

      console.error("Update blog error:", error);
      return res.status(500).send("Unable to update blog.");
    }
  }

  //==============================================
  // Delete Blog
  //==============================================

  static async deleteBlog(req, res) {
    try {
      const blog = await Blog.findById(req.params.id);

      if (!blog) {
        return res.status(404).send("Blog not found.");
      }

      if (req.ejsUser.role === "writer") {
        if (blog.author.toString() !== req.ejsUser._id.toString()) {
          return res.status(403).send("You can delete only your own blog.");
        }
      }

      const publicId = blog.image?.public_id;

      await Blog.findByIdAndDelete(blog._id);

      // Delete the image after the blog is successfully removed.
      if (publicId) {
        try {
          await deleteCloudinary(publicId);
        } catch (deleteError) {
          console.error(
            "Blog deleted, but Cloudinary cleanup failed:",
            deleteError,
          );
        }
      }

      return res.redirect("/ejs/blogs");
    } catch (error) {
      console.error("Delete blog error:", error);
      return res.status(500).send("Unable to delete blog.");
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

  // ======================================================
  // Admin approval for writer and user
  // ======================================================

  static async userApproval(req, res) {
    try {
      const { id } = req.params;
      const { action, reason } = req.body;

      const applicant = await User.findById(id);

      if (!applicant) {
        return res.status(404).send("Applicant not found");
      }

      const requestedRole = applicant.requestedRole;

      if (!["user", "writer"].includes(requestedRole)) {
        return res
          .status(400)
          .send("this account does not have an eligible application");
      }

      if (action === "approve") {
        ((applicant.role = requestedRole),
          (applicant.approvalStatus = "approved"),
          (applicant.approvedBy = req.ejsUser._id));
        applicant.approvedAt = new Date();
        applicant.rejectionReason = null;
      } else if (action === "reject") {
        applicant.role = "user";
        applicant.approvalStatus = "rejected";
        applicant.approvedBy = req.ejsUser._id;
        applicant.approvedAt = new Date();
        applicant.rejectionReason = String(
          reason || "Application rejected by admin",
        )
          .trim()
          .slice(0, 300);
      } else if (action === "reconsider") {
        if (applicant.approvalStatus !== "rejected") {
          return res
            .status(400)
            .send("Only rejected applications can be reconsidered.");
        }

        applicant.role = "user";
        applicant.approvalStatus = "pending";
        applicant.approvedBy = null;
        applicant.approvedAt = null;
        applicant.rejectionReason = null;
      } else {
        return res
          .status(400)
          .send("Invalid action. Use approve, reject, or reconsider.");
      }

      await applicant.save();

      return res.redirect(
        `/ejs/admin/users?approval=${action === "reconsider" ? "pending" : action === "approve" ? "approved" : "rejected"}`,
      );
    } catch (error) {
      console.error("User approval update error:", error);

      return res.status(500).send("Unable to update application status.");
    }
  }

  // =========================================
  // Landing Page
  // =========================================

  static async landingPage(req, res) {
    try {
      const blogs = await Blog.find({
        status: "approved",
        isPublished: true,
      })
        .sort({ createdAt: -1 })
        .limit(6)
        .lean();

      return res.render("landing", {
        title: "Golden Pages | Stories Worth Sharing",
        blogs,
      });
    } catch (error) {
      console.error("Landing page error:", error);

      return res.status(500).send("Unable to load the landing page.");
    }
  }
}

module.exports = AuthEJSController;
