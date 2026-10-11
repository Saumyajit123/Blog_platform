const express = require("express");
const router = express.Router();

const AuthEjsController = require("../controller/authEJSController");
const EjsAuthMiddleware = require("../middleware/authEJSMiddleware");
const Validation = require("../validate");
const userSchema = require("../validate/userSchema");

// ====================================================
// REGISTER
// ====================================================
router.get("/register", AuthEjsController.registerPage);

router.post("/register", AuthEjsController.register);

// =====================================================
// LOGIN
// =====================================================

router.get("/login", AuthEjsController.loginPage);

router.post("/login", AuthEjsController.login);

// =====================================================
// LOGOUT
// =====================================================

router.get("/logout", AuthEjsController.logout);

// =====================================================
// DASHBOARD
// =====================================================

router.get(
  "/dashboard",
  EjsAuthMiddleware.requireLogin,
  AuthEjsController.dashboard,
);

// =====================================================
// FORGOT PASSWORD
// =====================================================

router.get("/forgot-password", AuthEjsController.forgotPasswordPage);

router.post(
  "/forgot-password",
  Validation.validate(userSchema.forgotPassword),
  AuthEjsController.forgotPassword,
);

// =====================================================
// RESET PASSWORD
// =====================================================

router.get("/reset-password", AuthEjsController.resetPasswordPage);

router.post(
  "/reset-password",
  Validation.validate(userSchema.resetPassword),
  AuthEjsController.resetPassword,
);

// =====================================================
// CHANGE PASSWORD
// =====================================================

router.get(
  "/change-password",
  EjsAuthMiddleware.requireLogin,
  AuthEjsController.changePasswordPage,
);

router.post(
  "/change-password",
  EjsAuthMiddleware.requireLogin,
  Validation.validate(userSchema.changePassword),
  AuthEjsController.changePassword,
);

// =====================================================
// ADMIN - USERS
// =====================================================

router.get(
  "/admin/users",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin"),
  AuthEjsController.users,
);

router.get(
  "/admin/users/create",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin"),
  Validation.validate(userSchema.ejsCreateUser),
  AuthEjsController.createUserPage,
);

router.post(
  "/admin/users/create",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin"),
  Validation.validate(userSchema.ejsCreateUser),
  AuthEjsController.createUser,
);

// =====================================================
// ADMIN - SEND PASSWORD EMAIL
// =====================================================

router.post(
  "/admin/users/send-password-email",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin"),
  Validation.validate(userSchema.ejsUserId),
  AuthEjsController.sendPasswordChangeEmail,
);

// =====================================================
// BLOG LIST
// =====================================================

router.get("/blogs", EjsAuthMiddleware.requireLogin, AuthEjsController.blogs);

// =====================================================
// CREATE BLOG
// =====================================================

router.get(
  "/blog/create",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin", "writer"),
  AuthEjsController.createBlogPage,
);

router.post(
  "/blog/create",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin", "writer"),
  Validation.validate(userSchema.ejsCreateBlog),
  AuthEjsController.createBlog,
);

// =====================================================
// EDIT BLOG
// =====================================================

router.get(
  "/blog/:id/edit",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin", "writer"),
  AuthEjsController.updateBlogPage,
);

router.post(
  "/blog/:id/edit",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin", "writer"),
  Validation.validate(userSchema.ejsUpdateBlog),
  AuthEjsController.updateBlog,
);

// =====================================================
// DELETE BLOG
// =====================================================

router.post(
  "/blog/:id/delete",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin", "writer"),
  AuthEjsController.deleteBlog,
);

// =====================================================
// LIKE
// =====================================================

router.post(
  "/blog/:id/like",
  EjsAuthMiddleware.requireLogin,
  AuthEjsController.likeBlog,
);

// =====================================================
// COMMENT
// =====================================================

router.post(
  "/blog/:id/comment",
  EjsAuthMiddleware.requireLogin,
  Validation.validate(userSchema.ejsCommentBlog),
  AuthEjsController.commentBlog,
);

// =====================================================
// APPROVE
// =====================================================

router.post(
  "/blog/:id/approve",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin"),
  AuthEjsController.approveBlog,
);

// =====================================================
// REJECT
// =====================================================

router.post(
  "/blog/:id/reject",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin"),
  AuthEjsController.rejectBlog,
);

// =====================================================
// BLOG DETAIL
// =====================================================

router.get(
  "/blog/:id",
  EjsAuthMiddleware.requireLogin,
  AuthEjsController.blogDetail,
);

// =====================================================
// CREATE CATEGORY
// =====================================================

router.get(
  "/category/create",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin", "writer"),
  AuthEjsController.createCategoryPage,
);

router.post(
  "/category/create",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin", "writer"),
  Validation.validate(userSchema.ejsCreateCategory),
  AuthEjsController.createCategory,
);

// ====================================================
// ADMIN APPROVE USER/WRITER
// ====================================================

router.post(
  "/admin/users/:id/approval",
  EjsAuthMiddleware.requireLogin,
  EjsAuthMiddleware.allowRoles("admin"),
  AuthEjsController.userApproval,
);

module.exports = router;
