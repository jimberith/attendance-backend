import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();

app.use(cors({
  origin: "*",
  methods: ["GET","POST","PUT","DELETE"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.use(express.json({ limit: "5mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";

// ✅ TEST ROUTE
app.get("/", (req, res) => {
  res.send("✅ ATTENDIFY Backend Running");
});

// ✅ MongoDB connect
mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

// ✅ User schema
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  rollNumber: { type: String, unique: true },
  passwordHash: String,
  role: { type: String, enum: ["owner", "student"], default: "student" }
});
const User = mongoose.model("User", UserSchema);

// ✅ Check email exists
app.post("/auth/check-email", async (req, res) => {
  try {
    const { email } = req.body;
    if(!email) return res.status(400).json({ success:false, message:"Email required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    res.json({ success:true, exists: !!user });
  } catch (err) {
    res.status(500).json({ success:false, message: err.message });
  }
});

// ✅ Signup
app.post("/signup", async (req, res) => {
  try {
    const { name, email, rollNumber, password } = req.body;
    if(!name || !email || !rollNumber || !password) {
      return res.status(400).json({ success:false, message:"Missing fields" });
    }

    const emailExists = await User.findOne({ email: email.toLowerCase() });
    if(emailExists) return res.json({ success:false, message:"Email already exists" });

    const rollExists = await User.findOne({ rollNumber });
    if(rollExists) return res.json({ success:false, message:"Roll number already exists" });

    const count = await User.countDocuments();
    const role = count === 0 ? "owner" : "student";

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email: email.toLowerCase(),
      rollNumber,
      passwordHash,
      role
    });

    const token = jwt.sign({ id:user._id, role:user.role, rollNumber:user.rollNumber }, JWT_SECRET, { expiresIn:"7d" });

    res.json({
      success:true,
      token,
      user: { name:user.name, role:user.role, rollNumber:user.rollNumber }
    });

  } catch (err) {
    res.status(500).json({ success:false, message: err.message });
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  try {
    const { loginId, password } = req.body;
    if(!loginId || !password) return res.status(400).json({ success:false, message:"Missing fields" });

    const user = await User.findOne({
      $or: [
        { email: loginId.toLowerCase() },
        { rollNumber: loginId },
        { name: loginId }
      ]
    });

    if(!user) return res.json({ success:false, message:"Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.json({ success:false, message:"Invalid credentials" });

    const token = jwt.sign({ id:user._id, role:user.role, rollNumber:user.rollNumber }, JWT_SECRET, { expiresIn:"7d" });

    res.json({
      success:true,
      token,
      user: { name:user.name, role:user.role, rollNumber:user.rollNumber }
    });

  } catch (err) {
    res.status(500).json({ success:false, message: err.message });
  }
});

// ✅ Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("✅ Server running on port " + PORT));
