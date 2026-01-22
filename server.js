import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();

/* ✅ CORS */
app.use(cors({
  origin: "*",
  methods: ["GET","POST","PUT","DELETE"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.use(express.json({ limit: "8mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const MONGO_URI = process.env.MONGO_URI;

/* ✅ IMPORTANT: Must include /ATTENDIFY in URI */
mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => console.log("✅ MongoDB Connected to DB:", mongoose.connection.name))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

/* ===============================
   SCHEMAS
================================ */
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  rollNumber: String,
  passwordHash: String,
  role: String,
  enrolledClass: String,
  gender: String,
  phone: String,
  dob: String,
  address: String,
  profilePic: String
}, { timestamps: true });

const AttendanceSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  date: String,
  status: String
}, { timestamps: true });

const MarksSchema = new mongoose.Schema({
  rollNumber: String,
  subject: String,
  marks: Number
}, { timestamps: true });

const ClassSchema = new mongoose.Schema({
  name: String
}, { timestamps: true });

const SubjectSchema = new mongoose.Schema({
  name: String
}, { timestamps: true });

/* ✅ CRITICAL: Force collection names EXACTLY */
const User = mongoose.model("User", UserSchema, "users");
const Attendance = mongoose.model("Attendance", AttendanceSchema, "attendance");
const Marks = mongoose.model("Marks", MarksSchema, "marks");
const ClassModel = mongoose.model("Class", ClassSchema, "classes");
const SubjectModel = mongoose.model("Subject", SubjectSchema, "subjects");

/* ===============================
   HELPERS
================================ */
function safeUser(u){
  return {
    name: u.name,
    role: u.role,
    rollNumber: u.rollNumber,
    enrolledClass: u.enrolledClass,
    gender: u.gender || "",
    phone: u.phone || "",
    dob: u.dob || "",
    address: u.address || "",
    profilePic: u.profilePic || ""
  };
}

function createToken(u){
  return jwt.sign(
    { id: u._id, role: u.role, rollNumber: u.rollNumber },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next){
  const header = req.headers.authorization;
  if(!header) return res.status(401).json({ success:false, message:"Missing token" });

  const token = header.split(" ")[1];
  if(!token) return res.status(401).json({ success:false, message:"Invalid token" });

  try{
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  }catch{
    return res.status(401).json({ success:false, message:"Token expired/invalid" });
  }
}

/* ===============================
   ROUTES
================================ */
app.get("/", (req, res) => {
  res.send("✅ ATTENDIFY Backend Running");
});

/* ✅ Debug: confirms DB name + collection counts */
app.get("/debug/db-check", async (req, res) => {
  try{
    res.json({
      success: true,
      connectedDB: mongoose.connection.name,
      collections: (await mongoose.connection.db.listCollections().toArray()).map(c => c.name),
      counts: {
        users: await User.countDocuments(),
        attendance: await Attendance.countDocuments(),
        marks: await Marks.countDocuments(),
        classes: await ClassModel.countDocuments(),
        subjects: await SubjectModel.countDocuments()
      }
    });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Signup */
app.post("/signup", async (req, res) => {
  try{
    const { name, email, rollNumber, password } = req.body;
    if(!name || !email || !rollNumber || !password){
      return res.status(400).json({ success:false, message:"Fill all fields" });
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
      role,
      enrolledClass: null
    });

    const token = createToken(user);
    res.json({ success:true, token, user: safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Login (Name/Email/Roll) */
app.post("/login", async (req, res) => {
  try{
    const { loginId, password } = req.body;
    if(!loginId || !password) return res.status(400).json({ success:false, message:"Fill all fields" });

    const user = await User.findOne({
      $or: [
        { email: loginId.toLowerCase() },
        { rollNumber: loginId },
        { name: loginId }
      ]
    });

    if(!user) return res.json({ success:false, message:"Invalid credentials" });
    if(!user.passwordHash) return res.json({ success:false, message:"User exists but password not set in DB" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.json({ success:false, message:"Invalid credentials" });

    const token = createToken(user);
    res.json({ success:true, token, user: safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Me */
app.get("/me", auth, async (req, res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });
  if(!user) return res.status(404).json({ success:false, message:"User not found" });
  res.json({ success:true, user: safeUser(user) });
});

/* ✅ Attendance (student) */
app.get("/attendance", auth, async (req, res) => {
  const records = await Attendance.find({ rollNumber: req.user.rollNumber }).sort({ date: -1 });
  res.json({ success:true, records });
});

/* ✅ Marks (student) */
app.get("/marks", auth, async (req, res) => {
  const records = await Marks.find({ rollNumber: req.user.rollNumber }).sort({ createdAt: -1 });
  res.json({ success:true, records });
});

/* ✅ Get Classes */
app.get("/classes", auth, async (req, res) => {
  const classes = await ClassModel.find().sort({ name: 1 });
  res.json({ success:true, classes });
});

/* ✅ Get Subjects */
app.get("/subjects", auth, async (req, res) => {
  const subjects = await SubjectModel.find().sort({ name: 1 });
  res.json({ success:true, subjects });
});

/* ✅ Start */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("✅ Server running on port", PORT));
