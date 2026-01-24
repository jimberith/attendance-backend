import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";

dotenv.config();
const app = express();

app.use(cors({
  origin: "*",
  methods: ["GET","POST","PUT","DELETE"],
  allowedHeaders: ["Content-Type","Authorization"]
}));

app.use(express.json({ limit: "12mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => console.log("✅ MongoDB Connected:", mongoose.connection.name))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  rollNumber: String,
  passwordHash: String,
  role: { type:String, default:"student" },
  enrolledClass: { type:String, default:null },
  gender: String,
  phone: String,
  dob: String,
  address: String,
  profilePic: String,
  faceImage: String,
  faceUpdatedAt: String
}, { timestamps:true });

const AttendanceSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  date: String,
  status: String,
  markedBy: String
}, { timestamps:true });

const ClassSchema = new mongoose.Schema({
  name: String
},{ timestamps:true });

const SubjectSchema = new mongoose.Schema({
  name: String
},{ timestamps:true });

const User = mongoose.model("User", UserSchema, "users");
const Attendance = mongoose.model("Attendance", AttendanceSchema, "attendance");
const ClassModel = mongoose.model("Class", ClassSchema, "classes");
const SubjectModel = mongoose.model("Subject", SubjectSchema, "subjects");

function safeUser(u){
  return {
    name: u.name,
    email: u.email,
    role: u.role,
    rollNumber: u.rollNumber,
    enrolledClass: u.enrolledClass,
    gender: u.gender || "",
    phone: u.phone || "",
    dob: u.dob || "",
    address: u.address || "",
    profilePic: u.profilePic || "",
    faceRegistered: !!u.faceImage
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

function ownerOrStaff(req, res, next){
  if(req.user.role === "owner" || req.user.role === "staff") return next();
  return res.status(403).json({ success:false, message:"Not allowed" });
}

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }
});

app.get("/", (req, res) => {
  res.json({ success:true, message:"ATTENDIFY Backend Running" });
});

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

app.post("/login", async (req, res) => {
  try{
    const { loginId, password } = req.body;
    if(!loginId || !password){
      return res.status(400).json({ success:false, message:"Fill all fields" });
    }

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

    const token = createToken(user);
    res.json({ success:true, token, user: safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

app.get("/me", auth, async (req, res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });
  if(!user) return res.status(404).json({ success:false, message:"User not found" });
  res.json({ success:true, user: safeUser(user) });
});

app.post("/enroll", auth, async (req, res) => {
  try{
    const { className } = req.body;
    if(!className) return res.json({ success:false, message:"Missing className" });

    const user = await User.findOneAndUpdate(
      { rollNumber: req.user.rollNumber },
      { enrolledClass: className },
      { new: true }
    );

    res.json({ success:true, user: safeUser(user) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

app.get("/classes", auth, async (req, res) => {
  const classes = await ClassModel.find().sort({ name:1 });
  res.json({ success:true, classes });
});

app.get("/subjects", auth, async (req, res) => {
  const subjects = await SubjectModel.find().sort({ name:1 });
  res.json({ success:true, subjects });
});

app.get("/attendance", auth, async (req, res) => {
  const records = await Attendance.find({ rollNumber: req.user.rollNumber }).sort({ date:-1 });
  res.json({ success:true, records });
});

app.post("/profile", auth, async (req, res) => {
  try{
    const update = req.body || {};
    delete update.role;

    if(update.password && update.password.trim()){
      update.passwordHash = await bcrypt.hash(update.password.trim(), 10);
    }
    delete update.password;

    const user = await User.findOneAndUpdate(
      { rollNumber: req.user.rollNumber },
      { $set: update },
      { new:true }
    );

    res.json({ success:true, user: safeUser(user) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

app.post("/face/enroll", auth, upload.single("image"), async (req, res) => {
  try{
    if(!req.file){
      return res.status(400).json({ success:false, message:"No image uploaded" });
    }

    const base64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;
    const now = new Date().toISOString();

    const user = await User.findOneAndUpdate(
      { rollNumber: req.user.rollNumber },
      { faceImage: base64, faceUpdatedAt: now },
      { new:true }
    );

    res.json({ success:true, user: safeUser(user) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

app.get("/owner/users", auth, ownerOrStaff, async (req, res) => {
  const users = await User.find().sort({ createdAt:-1 });
  res.json({ success:true, users: users.map(safeUser) });
});

app.post("/owner/attendance", auth, ownerOrStaff, async (req, res) => {
  try{
    const { rollNumber, className, status, date } = req.body;
    if(!rollNumber || !className || !status || !date){
      return res.status(400).json({ success:false, message:"Missing fields" });
    }

    const rec = await Attendance.findOneAndUpdate(
      { rollNumber, className, date },
      { status, markedBy: req.user.role },
      { upsert:true, new:true }
    );

    res.json({ success:true, record: rec });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

app.post("/owner/attendance/by-date", auth, ownerOrStaff, async (req, res) => {
  try{
    const { className, date } = req.body;
    if(!className || !date){
      return res.json({ success:false, message:"Missing className/date" });
    }

    const records = await Attendance.find({ className, date });
    res.json({ success:true, records });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("✅ Server running on port", PORT));
