const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
    },

    role: {
      type: String,
      enum: ["admin", "writer", "user"],
      default: "user",
    },

    requestedRole: {
      type: String,
      enum: ["writer", "user"],
      default: "user",
    },

    approvalStatus: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "approved",
    },

    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    approvedAt: {
      type: Date,
      default: null,
    },

    rejectionReason: {
      type: String,
      default: null,
      trim: true,
    },

    refreshToken: {
      type: String,
      default: null,
    },

    resetTokenHash: {
      type: String,
      default: null,
    },

    resetTokenExpires: {
      type: Date,
      default: null,
    },

    secretKeyHash: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

const UserModel = mongoose.models.User || mongoose.model("User", userSchema);

module.exports = UserModel;
