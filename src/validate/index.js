const userSchema = require("../validate/userSchema");

class Validation {
  static getSchema(method, action) {
    let schema = null;

    // POST
    if (method === "POST") {
      if (action === "register") {
        schema = userSchema.register;
      } else if (action === "create-admin") {
        schema = userSchema.createAdmin;
      } else if (action === "create-writer") {
        schema = userSchema.createWriter;
      } else if (action === "login") {
        schema = userSchema.login;
      } else if (action === "refresh") {
        schema = userSchema.refresh;
      } else if (action === "logout") {
        schema = userSchema.logout;
      } else if (action === "create-category") {
        schema = userSchema.createCategory;
      } else if (action === "like") {
        schema = userSchema.likeBlog;
      } else if (action === "comment") {
        schema = userSchema.commentBlog;
      } else {
        // Normal POST = create blog
        schema = userSchema.createBlog;
      }
    }

    // PUT
    else if (method === "PUT") {
      if (action === "approve" || action === "reject") {
        schema = userSchema.blogAction;
      } else {
        schema = userSchema.updateBlog;
      }
    }

    // DELETE
    else if (method === "DELETE") {
      schema = userSchema.deleteBlog;
    }

    return schema;
  }

  static run(schema, data) {
    const { error, value } = schema.validate(data, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      return {
        success: false,

        errors: error.details.map((err) => ({
          field: err.path.join("."),
          message: err.message,
        })),
      };
    }

    return {
      success: true,
      value,
    };
  }

  static validate(schema) {
    return (req, res, next) => {
      const { error, value } = schema.validate(req.body, {
        abortEarly: false, //Without this option, Joi stops at the first validation error. (//You get all errors:["Email is required", "Password must be at least 6 characters" ] This provides better feedback to API consumers.)
        stripUnknown: true, //Removes properties that are not defined in the Joi schema. (Then after validation:removed automatically.)
      });

      if (error) {
        return res.status(400).json({
          success: false,
          errors: error.details.map((err) => ({
            field: err.path.join("."),
            message: err.message,
          })),
        });
      }

      req.body = value;
      next();
    };
  }
}

module.exports = Validation;
