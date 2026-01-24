import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";

import * as faceapi from "@vladmandic/face-api";
import canvas from "canvas";

dotenv.config();
const app = express();

/* ✅ CORS */
app.use(cors({
  origin: "*",
  methods: ["GET","POST","PUT","DELETE"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.use(express.json({ limit: "12mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const MONGO_URI = process.env.MONGO_URI;

/* ✅ Mongo Connect */
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
  profilePic: String,

  // ✅ face data
  faceDescriptors: { type: [Array], default: [] }
}, { timestamps: true });

const AttendanceSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  date: String,
  status: String,
  markedBy: String
}, { timestamps: true });

const ClassSchema = new mongoose.Schema({ name: String }, { timestamps: true });

/* ✅ Models */
const User = mongoose.model("User", UserSchema, "users");
const Attendance = mongoose.model("Attendance", AttendanceSchema, "attendance");
const ClassModel = mongoose.model("Class", ClassSchema, "classes");

/* ===============================
   HELPERS
================================ */
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
   FACE API SETUP
================================ */
const { Canvas, Image, ImageData } = canvas;
faceapi.env.monkeyPatch({ Canvas, Image, ImageData });

async function loadModels(){
  try{
    await faceapi.nets.ssdMobilenetv1.loadFromDisk("./models");
    await faceapi.nets.faceLandmark68Net.loadFromDisk("./models");
    await faceapi.nets.faceRecognitionNet.loadFromDisk("./models");
    console.log("✅ Face models loaded");
  }catch(err){
    console.log("❌ Face model load error:", err.message);
  }
}
loadModels();

/* Multer image upload */
const upload = multer({ storage: multer.memoryStorage() });

function euclideanDistance(a, b){
  let sum = 0;
  for(let i=0;i<a.length;i++){
    sum += (a[i] - b[i]) ** 2;
  }
  return Math.sqrt(sum);
}

async function getFaceDescriptorFromBuffer(buffer){
  const img = await canvas.loadImage(buffer);
  const detection = await faceapi
    .detectSingleFace(img)
    .withFaceLandmarks()
    .withFaceDescriptor();

  if(!detection) return null;
  return Array.from(detection.descriptor);
}

/* ===============================
   ROUTES
================================ */
app.get("/", (req,res) => res.send("✅ ATTENDIFY Backend Running"));

/* Signup */
app.post("/signup", async (req,res) => {
  try{
    const { name, email, rollNumber, password } = req.body;
    if(!name || !email || !rollNumber || !password)
      return res.status(400).json({ success:false, message:"Fill all fields" });

    const exists = await User.findOne({ email: email.toLowerCase() });
    if(exists) return res.json({ success:false, message:"Email already exists" });

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

/* Login */
app.post("/login", async (req,res) => {
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

    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.json({ success:false, message:"Invalid credentials" });

    const token = createToken(user);
    res.json({ success:true, token, user: safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* Me */
app.get("/me", auth, async (req,res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });
  if(!user) return res.json({ success:false, message:"User not found" });
  res.json({ success:true, user: safeUser(user) });
});

/* Enroll */
app.post("/enroll", auth, async (req,res) => {
  try{
    const { className } = req.body;
    if(!className) return res.json({ success:false, message:"Class required" });

    const user = await User.findOne({ rollNumber: req.user.rollNumber });
    if(!user) return res.json({ success:false, message:"User not found" });

    user.enrolledClass = className;
    await user.save();

    res.json({ success:true, message:"Enrolled ✅", user: safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* Classes */
app.get("/classes", auth, async (req,res) => {
  const classes = await ClassModel.find().sort({ name: 1 });
  res.json({ success:true, classes });
});

/* Attendance */
app.get("/attendance", auth, async (req,res) => {
  const records = await Attendance.find({ rollNumber: req.user.rollNumber }).sort({ date: -1 });
  res.json({ success:true, records });
});

/* ====================================================
   ✅ FACE ENROLL (APP)
==================================================== */
app.post("/face/enroll", auth, upload.single("image"), async (req,res) => {
  try{
    if(!req.file) return res.json({ success:false, message:"No image uploaded" });

    const descriptor = await getFaceDescriptorFromBuffer(req.file.buffer);
    if(!descriptor) return res.json({ success:false, message:"No face detected. Try again." });

    const user = await User.findOne({ rollNumber: req.user.rollNumber });
    if(!user) return res.json({ success:false, message:"User not found" });

    user.faceDescriptors.push(descriptor);
    await user.save();

    res.json({ success:true, message:"Face enrolled ✅", faceCount: user.faceDescriptors.length });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ====================================================
   ✅ ESP32 MARK ATTENDANCE
==================================================== */
app.post("/face/mark-attendance", upload.single("image"), async (req,res) => {
  try{
    const { className } = req.body;
    if(!className) return res.json({ success:false, message:"className required" });
    if(!req.file) return res.json({ success:false, message:"No image uploaded" });

    const descriptor = await getFaceDescriptorFromBuffer(req.file.buffer);
    if(!descriptor) return res.json({ success:false, message:"No face detected" });

    const users = await User.find({ enrolledClass: className });

    let bestMatch = null;
    let bestDist = 999;

    for(const u of users){
      for(const d of (u.faceDescriptors || [])){
        const dist = euclideanDistance(descriptor, d);
        if(dist < bestDist){
          bestDist = dist;
          bestMatch = u;
        }
      }
    }

    if(!bestMatch || bestDist > 0.55){
      return res.json({ success:false, message:"Face not recognized", distance: bestDist });
    }

    const today = new Date().toISOString().split("T")[0];

    const record = await Attendance.findOneAndUpdate(
      { rollNumber: bestMatch.rollNumber, className, date: today },
      { status: "Present", markedBy: "esp32" },
      { upsert: true, new: true }
    );

    res.json({
      success:true,
      message:`Attendance marked ✅ for ${bestMatch.name}`,
      rollNumber: bestMatch.rollNumber,
      name: bestMatch.name,
      distance: bestDist,
      record
    });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Start */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("✅ Server running on port", PORT));
