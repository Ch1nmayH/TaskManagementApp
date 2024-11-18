import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import "dotenv/config";
import userRouter from "./routes/userRoute.js";
import connectDB from "./config/db.js";
import cookieParser from "cookie-parser";

const app = express();
const port = process.env.PORT || 6000;

app.use(cors({
	origin: "http://localhost:3000", // Replace * with the specific origin
	credentials: true, // Allow sending of credentials (cookies)
  }));


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.get("/", (req, res) => {
	res.send("server is running...");
});

app.use("/api/user", userRouter);

app.listen(port, () => {
	try {
		connectDB();
		console.log(`Server is running on port ${port}`);
	} catch (error) {
		console.error(`Error: ${error.message}`);
	}
});