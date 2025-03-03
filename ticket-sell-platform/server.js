const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error(err));

const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model("User", UserSchema);

const secretKey = process.env.JWT_SECRET;

// Register Route
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();
  res.json({ message: "User registered successfully!" });
});

// Login Route
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) return res.status(400).json({ error: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: "1h" });
  res.json({ token });
});

// Protected Route
app.get("/api/protected", (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    res.json({ message: "Welcome to the protected route!", user: decoded });
  });
});

app.listen(5000, () => console.log("Server running on port 5000"));
