import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import canvas from "canvas";
import * as faceapi from "@vladmandic/face-api";

dotenv.config();
const app = express();
const upload = multer({ limits:{ fileSize: 5 * 1024 * 1024 } });

app.use(cors({ origin:"*", methods:["GET","POST"], allowedHeaders:["Content-Type","Authorization"] }));
app.use(express.json({ limit:"8mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "SECRET";
mongoose.connect(process.env.MONGO_URI);

const { Canvas, Image, ImageData } = canvas;
faceapi.env.monkeyPatch({ Canvas, Image, ImageData });

await faceapi.nets.ssdMobilenetv1.loadFromDisk("./models");
await faceapi.nets.faceLandmark68Net.loadFromDisk("./models");
await faceapi.nets.faceRecognitionNet.loadFromDisk("./models");

/* ================= SCHEMAS ================= */
const User = mongoose.model("User", new mongoose.Schema({
  name:String,
  email:String,
  rollNumber:String,
  passwordHash:String,
  role:String,
  enrolledClass:String,
  faceDescriptor:[Number],
  profilePic:String
}));

const ClassModel = mongoose.model("Class", new mongoose.Schema({
  name:String,
  latitude:Number,
  longitude:Number,
  radius:Number
}));

const Attendance = mongoose.model("Attendance", new mongoose.Schema({
  rollNumber:String,
  className:String,
  date:String,
  status:String,
  markedBy:String
}));

const AttendanceRequest = mongoose.model("AttendanceRequest", new mongoose.Schema({
  rollNumber:String,
  className:String,
  date:String,
  latitude:Number,
  longitude:Number,
  status:String
}));

/* ================= AUTH ================= */
function auth(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({success:false});
  try{
    req.user = jwt.verify(h.split(" ")[1], JWT_SECRET);
    next();
  }catch{ return res.status(401).json({success:false}); }
}

function token(u){
  return jwt.sign({ rollNumber:u.rollNumber, role:u.role }, JWT_SECRET);
}

function dist(a,b){
  return Math.sqrt(a.reduce((s,v,i)=>s+(v-b[i])**2,0));
}

function geo(lat1,lon1,lat2,lon2){
  const R=6371000;
  const dLat=(lat2-lat1)*Math.PI/180;
  const dLon=(lon2-lon1)*Math.PI/180;
  const a=Math.sin(dLat/2)**2+
    Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*
    Math.sin(dLon/2)**2;
  return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
}

/* ================= ROUTES ================= */
app.post("/signup", async(req,res)=>{
  const { name,email,rollNumber,password } = req.body;
  const count = await User.countDocuments();
  const user = await User.create({
    name,email,rollNumber,
    passwordHash: await bcrypt.hash(password,10),
    role: count===0 ? "owner" : "student"
  });
  res.json({ success:true, token:token(user), user });
});

app.post("/login", async(req,res)=>{
  const { loginId,password } = req.body;
  const u = await User.findOne({
    $or:[{email:loginId},{rollNumber:loginId},{name:loginId}]
  });
  if(!u || !await bcrypt.compare(password,u.passwordHash))
    return res.json({success:false});
  res.json({ success:true, token:token(u), user:u });
});

app.get("/me", auth, async(req,res)=>{
  const u = await User.findOne({ rollNumber:req.user.rollNumber });
  res.json({ success:true, user:u });
});

/* ========== FACE REGISTER ========== */
app.post("/face/register", auth, upload.single("image"), async(req,res)=>{
  const img = await canvas.loadImage(req.file.buffer);
  const det = await faceapi.detectSingleFace(img).withFaceLandmarks().withFaceDescriptor();
  if(!det) return res.json({success:false});
  await User.updateOne(
    { rollNumber:req.user.rollNumber },
    { faceDescriptor:Array.from(det.descriptor) }
  );
  res.json({ success:true });
});

/* ========== AUTO ATTENDANCE ========== */
app.post("/attendance/auto", auth, upload.single("image"), async(req,res)=>{
  const { latitude,longitude } = req.body;
  const date = new Date().toISOString().split("T")[0];
  const u = await User.findOne({ rollNumber:req.user.rollNumber });
  const cls = await ClassModel.findOne({ name:u.enrolledClass });
  if(!u.faceDescriptor) return res.json({success:false});

  const img = await canvas.loadImage(req.file.buffer);
  const det = await faceapi.detectSingleFace(img).withFaceLandmarks().withFaceDescriptor();
  if(!det || dist(det.descriptor,u.faceDescriptor)>0.55)
    return res.json({success:false});

  const meters = geo(latitude,longitude,cls.latitude,cls.longitude);

  if(meters<=cls.radius){
    await Attendance.findOneAndUpdate(
      { rollNumber:u.rollNumber,date },
      { rollNumber:u.rollNumber,className:u.enrolledClass,date,status:"Present",markedBy:"auto" },
      { upsert:true }
    );
    return res.json({ success:true, auto:true });
  }

  await AttendanceRequest.create({
    rollNumber:u.rollNumber,
    className:u.enrolledClass,
    date,latitude,longitude,status:"pending"
  });
  res.json({ success:true, auto:false });
});

/* ========== REQUESTS ========== */
app.get("/owner/attendance/requests", auth, async(req,res)=>{
  if(!["owner","staff"].includes(req.user.role)) return res.json({success:false});
  res.json({ success:true, requests: await AttendanceRequest.find({status:"pending"}) });
});

app.post("/owner/attendance/decision", auth, async(req,res)=>{
  if(!["owner","staff"].includes(req.user.role)) return res.json({success:false});
  const { requestId,approve } = req.body;
  const r = await AttendanceRequest.findById(requestId);
  if(!r) return res.json({success:false});
  r.status = approve ? "approved":"rejected";
  await r.save();
  await Attendance.findOneAndUpdate(
    { rollNumber:r.rollNumber,date:r.date },
    {
      rollNumber:r.rollNumber,
      className:r.className,
      date:r.date,
      status: approve?"Present":"Absent",
      markedBy:req.user.role
    },
    { upsert:true }
  );
  res.json({ success:true });
});

app.listen(10000);
