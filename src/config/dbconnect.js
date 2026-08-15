const mongoose = require("mongoose");

const dns = require("dns");
 
// Force public DNS
dns.setServers(["8.8.8.8", "1.1.1.1"]);

const DBConnect = async() => {
  try {
    const connection = await mongoose.connect(process.env.MONGO_URL);
    if (connection) {
      console.log("Mongodb connected successfully");
    } else {
      console.log("MongoDB connection failed");
    }
  } catch (err) {
    console.log(err);
  }
};

module.exports = DBConnect;
