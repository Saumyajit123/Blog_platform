const cloudinary = require("../config/cloudinary");

const deleteCloudinary = async (publicId) => {
  if (!publicId || typeof publicId !== "string") {
    throw new Error("A valid Cloudinary public_id is required.");
  }

  const result = await cloudinary.uploader.destroy(publicId, {
    resource_type: "image",
    invalidate: true,
  });

  if (!["ok", "not found"].includes(result.result)) {
    throw new Error(`Cloudinary image deletion failed: ${result.result}`);
  }

  return result;
};

module.exports = deleteCloudinary;
