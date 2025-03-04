const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");

dotenv.config();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

//Alternate way to handle CORS
app.use((req, res, next) => {
    console.log('Incoming Request:', {
      method: req.method,
      path: req.path,
      origin: req.headers.origin
    });
  
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader(
      'Access-Control-Allow-Headers', 
      'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    );
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
      }
    
      next();
});

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error(err));

const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  events: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Event' }]
});

const EventSchema = new mongoose.Schema({
  name: String,
  date: String,
  location: String,
  price: Number
});

const User = mongoose.model("User", UserSchema);
const Event = mongoose.model("Event", EventSchema);

const secretKey = process.env.JWT_SECRET;

// User Register Route
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();
  res.json({ message: "User registered successfully!" });
});

// Create new Event Route
app.post("/api/events", async (req, res) => {
    try {
      const { name, date, location, price } = req.body;
      const newEvent = new Event({ name, date, location, price });
      await newEvent.save();
      res.json({ message: "Event created successfully!", event: newEvent });
    } catch (error) {
      console.error("Error creating event:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  });
  

// List All teh Events Route
app.get("/api/events", async (req, res) => {
  const events = await Event.find();
  res.json(events);
});

//User Login Route
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) return res.status(400).json({ error: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: "1h" });
  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ message: "Login successful" });
});

// Get User Details including if any tickets purchased Route
app.get("/api/user", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, secretKey, async (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });

    const user = await User.findById(decoded.userId).populate('events');
    res.json(user);
  });
});

// User Buys Ticket Route
app.post("/api/buy-ticket", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, secretKey, async (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });

    const { eventId } = req.body;
    const event = await Event.findById(eventId);
    if (!event) return res.status(404).json({ error: "Event not found" });

    const user = await User.findById(decoded.userId);
    user.events.push(event);
    await user.save();

    res.json({ message: "Ticket purchased successfully", event });
  });
});

app.listen(5000, () => console.log("Server running on port 5000"));