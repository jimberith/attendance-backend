import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";

dotenv.config();
const app = express();
const upload = multer();

app.use(cors());
app.use(express.json({ limit: "10mb" }));

/* =======================
   DB
======================= */
mongoose.connect(process.env.MONGO_URI)
  .then(()=>console.log("MongoDB connected"))
  .catch(err=>console.log(err));

/* =======================
   MODELS
======================= */
const UserSchema = new mongoose.Schema({
  name:String,
  email:String,
  rollNumber:String,
  passwordHash:String,
  role:{ type:String, default:"student" },
  enrolledClass:String,
  profilePic:String,
  faceImage:String
});
const AttendanceSchema = new mongoose.Schema({
  rollNumber:String,
  className:String,
  date:String,
  status:String
});
const RequestSchema = new mongoose.Schema({
  rollNumber:String,
  className:String,
  date:String,
  latitude:Number,
  longitude:Number,
  status:{ type:String, default:"pending" }
});

const User = mongoose.model("User",UserSchema);
const Attendance = mongoose.model("Attendance",AttendanceSchema);
const Request = mongoose.model("Request",RequestSchema);

/* =======================
   AUTH
======================= */
function auth(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({success:false});
  try{
    req.user = jwt.verify(h.split(" ")[1],process.env.JWT_SECRET);
    next();
  }catch{
    res.status(401).json({success:false});
  }
}

function token(user){
  return jwt.sign(
    { rollNumber:user.rollNumber, role:user.role },
    process.env.JWT_SECRET,
    { expiresIn:"7d" }
  );
}

/* =======================
   ROUTES
======================= */

/* Signup */
app.post("/signup",async(req,res)=>{
  const {name,email,rollNumber,password}=req.body;
  if(!name||!email||!rollNumber||!password)
    return res.json({success:false,message:"Missing fields"});

  if(await User.findOne({$or:[{email},{rollNumber}]}))
    return res.json({success:false,message:"User exists"});

  const count = await User.countDocuments();
  const role = count===0?"owner":"student";

  const user = await User.create({
    name,email,rollNumber,
    passwordHash:await bcrypt.hash(password,10),
    role
  });

  res.json({success:true,token:token(user)});
});

/* Login */
app.post("/login",async(req,res)=>{
  const {loginId,password}=req.body;
  const user = await User.findOne({
    $or:[{email:loginId},{rollNumber:loginId},{name:loginId}]
  });
  if(!user) return res.json({success:false,message:"Invalid"});

  if(!await bcrypt.compare(password,user.passwordHash))
    return res.json({success:false,message:"Invalid"});

  res.json({success:true,token:token(user)});
});

/* Me */
app.get("/me",auth,async(req,res)=>{
  const user = await User.findOne({rollNumber:req.user.rollNumber});
  res.json({success:true,user});
});

/* =======================
   PROFILE
======================= */
app.post("/profile",auth,async(req,res)=>{
  const user = await User.findOne({rollNumber:req.user.rollNumber});
  Object.assign(user,req.body);
  await user.save();
  res.json({success:true,user});
});

/* =======================
   FACE REGISTER
======================= */
app.post("/face/register",auth,upload.single("image"),async(req,res)=>{
  const user = await User.findOne({rollNumber:req.user.rollNumber});
  user.faceImage = req.file.buffer.toString("base64");
  await user.save();
  res.json({success:true});
});

/* =======================
   ATTENDANCE
======================= */
function distance(lat1,lon1,lat2,lon2){
  const R=6371000;
  const dLat=(lat2-lat1)*Math.PI/180;
  const dLon=(lon2-lon1)*Math.PI/180;
  return R*2*Math.asin(Math.sqrt(
    Math.sin(dLat/2)**2+
    Math.cos(lat1*Math.PI/180)*
    Math.cos(lat2*Math.PI/180)*
    Math.sin(dLon/2)**2
  ));
}

/* Auto attendance */
app.post("/attendance/auto",auth,upload.single("image"),async(req,res)=>{
  const user = await User.findOne({rollNumber:req.user.rollNumber});
  const {latitude,longitude}=req.body;
  const date=new Date().toISOString().split("T")[0];

  const CLASS_LAT=11.0168;
  const CLASS_LON=76.9558;

  if(distance(latitude,longitude,CLASS_LAT,CLASS_LON)<=50){
    await Attendance.create({
      rollNumber:user.rollNumber,
      className:user.enrolledClass,
      date,
      status:"Present"
    });
    return res.json({success:true,auto:true});
  }

  await Request.create({
    rollNumber:user.rollNumber,
    className:user.enrolledClass,
    date,
    latitude,longitude
  });
  res.json({success:true,auto:false});
});

/* Requests */
app.get("/owner/attendance/requests",auth,async(req,res)=>{
  if(req.user.role==="student") return res.json({success:false});
  const r = await Request.find({status:"pending"});
  res.json({success:true,requests:r});
});

/* Decision */
app.post("/owner/attendance/decision",auth,async(req,res)=>{
  if(req.user.role==="student") return res.json({success:false});
  const {requestId,approve}=req.body;
  const r = await Request.findById(requestId);
  await Attendance.create({
    rollNumber:r.rollNumber,
    className:r.className,
    date:r.date,
    status:approve?"Present":"Absent"
  });
  r.status="done";
  await r.save();
  res.json({success:true});
});

/* =======================
   SERVER
======================= */
app.listen(10000,()=>console.log("Server running on 10000"));
