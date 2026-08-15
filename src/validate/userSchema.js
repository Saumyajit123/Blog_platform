const Joi = require("joi");

const objectId = Joi.string()
  .pattern(/^[0-9a-fA-F]{24}$/)
  .messages({
    "string.pattern.base": "Invalid ID format",
  });

const passwordSchema = Joi.string().min(8).max(30).required().messages({
  "string.empty": "Password is required",
  "string.min": "Password must be at least 8 characters",
  "string.max": "Password must not exceed 30 characters",
  "any.required": "Password is required",
});

const userSchema = {
  //Register
  register: Joi.object({
    action: Joi.string().valid("register").required(),

    name: Joi.string().trim().min(2).max(50).required().messages({
      "string.empty": "Name is required",
      "string.min": "Name must be at least 2 characters",
      "string.max": "Name must not exceed 50 characters",
      "any.required": "Name is required",
    }),

    email: Joi.string().trim().lowercase().email().required().messages({
      "string.empty": "Email is required",
      "string.email": "Please enter a valid email",
      "any.required": "Email is required",
    }),

    password: passwordSchema,
  }),

  //Create Admin:
  createAdmin: Joi.object({
    action: Joi.string().valid("create-admin").required(),

    name: Joi.string().trim().min(2).max(50).required().messages({
      "string.empty": "Name is required",
      "string.min": "Name must be at least 2 characters",
      "string.max": "Name must not exceed 50 characters",
      "any.required": "Name is required",
    }),

    email: Joi.string().trim().lowercase().email().required().messages({
      "string.empty": "Email is required",
      "string.email": "Please enter a valid email",
      "any.required": "Email is required",
    }),

    password: passwordSchema,

    setupKey: Joi.string().trim().required().messages({
      "string.empty": "Admin setup key is required",
      "any.required": "Admin setup key is required",
    }),
  }),

  //Create Writer
  createWriter: Joi.object({
    action: Joi.string().valid("create-writer").required(),

    name: Joi.string().trim().min(2).max(50).required().messages({
      "string.empty": "Name is required",
      "string.min": "Name must be at least 2 characters",
      "string.max": "Name must not exceed 50 characters",
      "any.required": "Name is required",
    }),

    email: Joi.string().trim().lowercase().email().required().messages({
      "string.empty": "Email is required",
      "string.email": "Please enter a valid email",
      "any.required": "Email is required",
    }),

    password: passwordSchema,

    setupKey: Joi.string().trim().required().messages({
      "string.empty": "Writer setup key is required",
      "any.required": "Writer setup key is required",
    }),
  }),

  //Login:
  login: Joi.object({
    action: Joi.string().valid("login").required(),

    email: Joi.string().trim().lowercase().email().required().messages({
      "string.empty": "Email is required",
      "string.email": "Please enter a valid email",
      "any.required": "Email is required",
    }),

    password: Joi.string().required().messages({
      "string.empty": "Password is required",
      "any.required": "Password is required",
    }),
  }),

  //Refresh token:
  refresh: Joi.object({
    action: Joi.string().valid("refresh").required(),

    refreshToken: Joi.string().required().messages({
      "string.empty": "Refresh token is required",
      "any.required": "Refresh token is required",
    }),
  }),

  //Logout:
  logout: Joi.object({
    action: Joi.string().valid("logout").required(),
  }),

  //Create category:
  createCategory: Joi.object({
    action: Joi.string().valid("create-category").required(),

    name: Joi.string().trim().min(2).max(50).required().messages({
      "string.empty": "Category name is required",
      "string.min": "Category name must be at least 2 characters",
      "string.max": "Category name must not exceed 50 characters",
      "any.required": "Category name is required",
    }),
  }),

  //Create blog:
  createBlog: Joi.object({
    title: Joi.string().trim().min(3).max(200).required().messages({
      "string.empty": "Title is required",
      "string.min": "Title must be at least 3 characters",
      "string.max": "Title must not exceed 200 characters",
      "any.required": "Title is required",
    }),

    content: Joi.string().trim().min(10).required().messages({
      "string.empty": "Content is required",
      "string.min": "Content must be at least 10 characters",
      "any.required": "Content is required",
    }),

    category: objectId.required().messages({
      "any.required": "Category is required",
    }),
  }),

  //Like:
  likeBlog: Joi.object({
    action: Joi.string().valid("like").required(),

    blogId: objectId.required().messages({
      "any.required": "Blog ID is required",
    }),
  }),

  //Comment:
  commentBlog: Joi.object({
    action: Joi.string().valid("comment").required(),

    blogId: objectId.required().messages({
      "any.required": "Blog ID is required",
    }),

    comment: Joi.string().trim().min(1).max(1000).required().messages({
      "string.empty": "Comment is required",
      "string.max": "Comment must not exceed 1000 characters",
      "any.required": "Comment is required",
    }),
  }),

  //Update blog:
  updateBlog: Joi.object({
    blogId: objectId.required().messages({
      "any.required": "Blog ID is required",
    }),

    title: Joi.string().trim().min(3).max(200).optional(),

    content: Joi.string().trim().min(10).optional(),

    category: objectId.optional(),

    action: Joi.string().optional(),
  }),

  //Delete blog:
  deleteBlog: Joi.object({
    blogId: objectId.required().messages({
      "any.required": "Blog ID is required",
    }),
  }),

  //Approve blog:
  blogAction: Joi.object({
    action: Joi.string().valid("approve", "reject").required(),

    blogId: objectId.required().messages({
      "any.required": "Blog ID is required",
    }),
  }),
};

module.exports = userSchema;
