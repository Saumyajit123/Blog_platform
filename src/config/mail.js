const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT),
  secure: false,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

const sendMail = async ({ to, subject, html }) => {
  return transporter.sendMail({
    from: `"Blog Platform" <${process.env.MAIL_USER}>`,
    to,
    subject,
    html,
  });
};

module.exports = sendMail;
