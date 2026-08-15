const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Blog = require("../models/blog");
const User = require("../models/User");
const Category = require("../models/category");
const AuthMiddleware = require("../middleware/authMiddleware");
const Validation = require("../validate/index");



class BlogController {
  static async blogHandler(req, res) {
    try {
      const method = req.method;
      const action = req.body?.action;

      // =====================================================
      // JOI VALIDATION
      // =====================================================

      const schema = Validation.getSchema(method, action);

      if (schema) {
        const result = Validation.run(schema, req.body);

        if (!result.success) {
          return res.status(400).json({
            success: false,
            errors: result.errors,
          });
        }

        // Joi cleaned the request body
        req.body = result.value;
      }

      // =====================================================
      // REGISTER
      // =====================================================

      if (method === "POST" && action === "register") {
        const { name, email, password } = req.body;

        const existingUser = await User.findOne({
          email,
        });

        if (existingUser) {
          return res.status(409).json({
            success: false,
            message: "Email already registered",
          });
        }

        const hashedPassword = await bcryptjs.hash(password, 10);

        const user = await User.create({
          name,
          email,
          password: hashedPassword,
          role: "user",
        });

        return res.status(201).json({
          success: true,
          message: "Registration successful",

          data: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
          },
        });
      }

      // =====================================================
      // CREATE ADMIN
      // =====================================================

      if (method === "POST" && action === "create-admin") {
        const { name, email, password, setupKey } = req.body;

        if (setupKey !== process.env.ADMIN_SETUP_KEY) {
          return res.status(403).json({
            success: false,
            message: "Invalid admin setup key",
          });
        }

        const existingUser = await User.findOne({
          email,
        });

        if (existingUser) {
          return res.status(409).json({
            success: false,
            message: "Email already registered",
          });
        }

        const hashedPassword = await bcryptjs.hash(password, 10);

        const admin = await User.create({
          name,
          email,
          password: hashedPassword,
          role: "admin",
        });

        return res.status(201).json({
          success: true,
          message: "Admin created successfully",

          data: {
            id: admin._id,
            name: admin.name,
            email: admin.email,
            role: admin.role,
          },
        });
      }

      // =====================================================
      // CREATE WRITER
      // =====================================================

      if (method === "POST" && action === "create-writer") {
        const { name, email, password, setupKey } = req.body;

        if (setupKey !== process.env.WRITER_SETUP_KEY) {
          return res.status(403).json({
            success: false,
            message: "Invalid writer setup key",
          });
        }

        const existingUser = await User.findOne({
          email,
        });

        if (existingUser) {
          return res.status(409).json({
            success: false,
            message: "Email already registered",
          });
        }

        const hashedPassword = await bcryptjs.hash(password, 10);

        const writer = await User.create({
          name,
          email,
          password: hashedPassword,
          role: "writer",
        });

        return res.status(201).json({
          success: true,
          message: "Writer created successfully",

          data: {
            id: writer._id,
            name: writer.name,
            email: writer.email,
            role: writer.role,
          },
        });
      }

      // =====================================================
      // CREATE CATEGORY
      // =====================================================

      if (method === "POST" && action === "create-category") {
        const { name } = req.body;

        const existingCategory = await Category.findOne({
          name,
        });

        if (existingCategory) {
          return res.status(409).json({
            success: false,
            message: "Category already exists",
          });
        }

        const category = await Category.create({
          name,
        });

        return res.status(201).json({
          success: true,
          message: "Category created successfully",
          data: category,
        });
      }

      // =====================================================
      // LOGIN
      // =====================================================

      if (method === "POST" && action === "login") {
        const { email, password } = req.body;

        const user = await User.findOne({
          email,
        });

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        const passwordMatch = await bcryptjs.compare(password, user.password);

        if (!passwordMatch) {
          return res.status(401).json({
            success: false,
            message: "Invalid email or password",
          });
        }

        // ACCESS TOKEN

        const accessToken = jwt.sign(
          {
            id: user._id,
            email: user.email,
            role: user.role,
          },
          process.env.JWT_SECRET_KEY,
          {
            expiresIn: "1h",
          },
        );

        // REFRESH TOKEN

        const refreshToken = jwt.sign(
          {
            id: user._id,
          },
          process.env.REFRESH_TOKEN,
          {
            expiresIn: "7d",
          },
        );

        user.refreshToken = refreshToken;

        await user.save();

        return res.status(200).json({
          success: true,
          message: "Login successful",

          accessToken,

          refreshToken,

          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
          },
        });
      }

      // =====================================================
      // REFRESH TOKEN
      // =====================================================

      if (method === "POST" && action === "refresh") {
        const { refreshToken } = req.body;

        let decoded;

        try {
          decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN);
        } catch (error) {
          return res.status(401).json({
            success: false,
            message: "Invalid or expired refresh token",
          });
        }

        const user = await User.findById(decoded.id);

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        if (user.refreshToken !== refreshToken) {
          return res.status(401).json({
            success: false,
            message: "Invalid refresh token",
          });
        }

        const newAccessToken = jwt.sign(
          {
            id: user._id,
            email: user.email,
            role: user.role,
          },
          process.env.JWT_SECRET_KEY,
          {
            expiresIn: "1h",
          },
        );

        return res.status(200).json({
          success: true,
          message: "Access token refreshed",

          accessToken: newAccessToken,
        });
      }

      // =====================================================
      // LOGOUT
      // =====================================================

      if (method === "POST" && action === "logout") {
        const authResult = AuthMiddleware.verifyToken(req);

        if (!authResult.success) {
          return res.status(authResult.status).json({
            success: false,
            message: authResult.message,
          });
        }

        const user = await User.findById(req.user.id);

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        user.refreshToken = null;

        await user.save();

        return res.status(200).json({
          success: true,
          message: "Logout successful",
        });
      }

      // =====================================================
      // AUTHENTICATE NORMAL BLOG REQUEST
      // =====================================================

      const authResult = AuthMiddleware.verifyToken(req);

      if (!authResult.success) {
        return res.status(authResult.status).json({
          success: false,
          message: authResult.message,
        });
      }

      // =====================================================
      // SECRET KEY
      // =====================================================

      const secretResult = AuthMiddleware.verifySecretKey(req);

      if (!secretResult.success) {
        return res.status(secretResult.status).json({
          success: false,
          message: secretResult.message,
        });
      }

      const { id, role } = req.user;

      // =====================================================
      // POST
      // CREATE / LIKE / COMMENT
      // =====================================================

      if (method === "POST") {
        // -------------------------------------------------
        // LIKE
        // -------------------------------------------------

        if (action === "like") {
          const { blogId } = req.body;

          const blog = await Blog.findById(blogId);

          if (!blog) {
            return res.status(404).json({
              success: false,
              message: "Blog not found",
            });
          }

          const alreadyLiked = blog.likes.some(
            (userId) => userId.toString() === id.toString(),
          );

          if (alreadyLiked) {
            blog.likes = blog.likes.filter(
              (userId) => userId.toString() !== id.toString(),
            );

            await blog.save();

            return res.status(200).json({
              success: true,
              message: "Blog unliked",
              likes: blog.likes.length,
            });
          }

          blog.likes.push(id);

          await blog.save();

          return res.status(200).json({
            success: true,
            message: "Blog liked",
            likes: blog.likes.length,
          });
        }

        // -------------------------------------------------
        // COMMENT
        // -------------------------------------------------

        if (action === "comment") {
          const { blogId, comment } = req.body;

          const blog = await Blog.findById(blogId);

          if (!blog) {
            return res.status(404).json({
              success: false,
              message: "Blog not found",
            });
          }

          blog.comments.push({
            user: id,
            comment,
          });

          await blog.save();

          return res.status(200).json({
            success: true,
            message: "Comment added successfully",
            data: blog,
          });
        }

        // -------------------------------------------------
        // CREATE BLOG
        // -------------------------------------------------

        if (role !== "admin" && role !== "writer") {
          return res.status(403).json({
            success: false,
            message: "You are not allowed to create blogs",
          });
        }

        const { title, content, category } = req.body;

        const blog = await Blog.create({
          title,
          content,
          category,
          author: id,

          status: role === "admin" ? "approved" : "pending",

          isPublished: role === "admin",
        });

        return res.status(201).json({
          success: true,

          message:
            role === "admin"
              ? "Blog created and published"
              : "Blog created and sent for approval",

          data: blog,
        });
      }

      // =====================================================
      // GET
      // =====================================================

      if (method === "GET") {
        let blogs;

        if (role === "admin") {
          blogs = await Blog.find()
            .populate("author", "name email role")
            .populate("category")
            .sort({
              createdAt: -1,
            });
        } else if (role === "writer") {
          blogs = await Blog.find({
            author: id,
          })
            .populate("author", "name email role")
            .populate("category")
            .sort({
              createdAt: -1,
            });
        } else {
          blogs = await Blog.find({
            status: "approved",
            isPublished: true,
          })
            .populate("author", "name")
            .populate("category")
            .sort({
              createdAt: -1,
            });
        }

        return res.status(200).json({
          success: true,
          count: blogs.length,
          data: blogs,
        });
      }

      // =====================================================
      // PUT
      // UPDATE / APPROVE / REJECT
      // =====================================================

      if (method === "PUT") {
        const putAction = req.body.action;

        // -------------------------------------------------
        // APPROVE / REJECT
        // -------------------------------------------------

        if (putAction === "approve" || putAction === "reject") {
          const { blogId } = req.body;

          if (role !== "admin") {
            return res.status(403).json({
              success: false,
              message: "Only admin can perform this action",
            });
          }

          const blog = await Blog.findById(blogId);

          if (!blog) {
            return res.status(404).json({
              success: false,
              message: "Blog not found",
            });
          }

          if (putAction === "approve") {
            blog.status = "approved";

            blog.isPublished = true;
          } else {
            blog.status = "rejected";

            blog.isPublished = false;
          }

          await blog.save();

          return res.status(200).json({
            success: true,
            message:
              putAction === "approve"
                ? "Blog approved successfully"
                : "Blog rejected successfully",
            data: blog,
          });
        }

        // -------------------------------------------------
        // UPDATE BLOG
        // -------------------------------------------------

        const { blogId, title, content, category } = req.body;

        const blog = await Blog.findById(blogId);

        if (!blog) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        // ADMIN

        if (role === "admin") {
          if (title !== undefined) {
            blog.title = title;
          }

          if (content !== undefined) {
            blog.content = content;
          }

          if (category !== undefined) {
            blog.category = category;
          }

          await blog.save();

          return res.status(200).json({
            success: true,
            message: "Blog updated successfully",
            data: blog,
          });
        }

        // WRITER

        if (role === "writer") {
          if (blog.author.toString() !== id.toString()) {
            return res.status(403).json({
              success: false,
              message: "You can update only your own blog",
            });
          }

          if (title !== undefined) {
            blog.title = title;
          }

          if (content !== undefined) {
            blog.content = content;
          }

          if (category !== undefined) {
            blog.category = category;
          }

          blog.status = "pending";

          blog.isPublished = false;

          await blog.save();

          return res.status(200).json({
            success: true,
            message: "Blog updated and sent for approval",
            data: blog,
          });
        }

        return res.status(403).json({
          success: false,
          message: "You are not allowed to update blogs",
        });
      }

      // =====================================================
      // DELETE
      // =====================================================

      if (method === "DELETE") {
        const { blogId } = req.body;

        const blog = await Blog.findById(blogId);

        if (!blog) {
          return res.status(404).json({
            success: false,
            message: "Blog not found",
          });
        }

        // ADMIN

        if (role === "admin") {
          await Blog.findByIdAndDelete(blogId);

          return res.status(200).json({
            success: true,
            message: "Blog deleted successfully",
          });
        }

        // WRITER

        if (role === "writer") {
          if (blog.author.toString() !== id.toString()) {
            return res.status(403).json({
              success: false,
              message: "You can delete only your own blog",
            });
          }

          await Blog.findByIdAndDelete(blogId);

          return res.status(200).json({
            success: true,
            message: "Blog deleted successfully",
          });
        }

        return res.status(403).json({
          success: false,
          message: "You are not allowed to delete blogs",
        });
      }

    } catch (error) {
      console.error(error);

      return res.status(500).json({
        success: false,
        message: "Something went wrong",
        error: error.message,
      });
    }
  }
}

module.exports = BlogController;
