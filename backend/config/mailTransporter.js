import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
	service: "gmail",
	auth: {
		user: "secureshop.crypto@gmail.com",
		pass: "xzyhwtlhhgvpebrh",
	},
});

export default transporter;