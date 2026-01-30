document.addEventListener("DOMContentLoaded", () => {

const API_BASE = "https://attendance-backend-7m9r.onrender.com";
const TARGET = { lat:11.2742, lng:77.6049, radius:50 };

const $ = id => document.getElementById(id);

/* =======================
   POPUP
======================= */
function msg(m,t="Message"){
  popupTitle.textContent=t;
  popupMessage.textContent=m;
  popupOverlay.classList.remove("hidden");
}
popupOkBtn.onclick=()=>popupOverlay.classList.add("hidden");

/* =======================
   AUTH STORAGE
======================= */
const setToken=t=>localStorage.setItem("token",t);
const getToken=()=>localStorage.getItem("token");
const clearToken=()=>localStorage.removeItem("token");

const setUser=u=>localStorage.setItem("user",JSON.stringify(u));
const getUser=()=>JSON.parse(localStorage.getItem("user")||"null");
const clearUser=()=>localStorage.removeItem("user");

/* =======================
   API
======================= */
async function apiFetch(path,opt={}){
  const h=opt.headers||{};
  if(!(opt.body instanceof FormData)) h["Content-Type"]="application/json";
  if(getToken()) h.Authorization="Bearer "+getToken();
  const r=await fetch(API_BASE+path,{...opt,headers:h});
  return r.json();
}

/* =======================
   AUTH UI
======================= */
let authMode="login";

function setAuthMode(m){
  authMode=m;
  showLoginTab.classList.toggle("active",m==="login");
  showSignupTab.classList.toggle("active",m==="signup");
  signupFields.classList.toggle("hidden",m!=="signup");
  loginFields.classList.toggle("hidden",m!=="login");
  submitAuthBtn.textContent=m==="login"?"Login":"Signup";
}

showLoginTab.onclick=()=>setAuthMode("login");
showSignupTab.onclick=()=>setAuthMode("signup");

/* =======================
   AUTH ACTIONS
======================= */
submitAuthBtn.onclick=async()=>{
  if(authMode==="login"){
    const loginId=$("loginId").value.trim();
    const password=$("password").value.trim();
    if(!loginId||!password) return msg("Fill all fields");

    const d=await apiFetch("/login",{
      method:"POST",
      body:JSON.stringify({loginId,password})
    });

    if(!d.success) return msg(d.message||"Login failed");
    setToken(d.token);
    loadApp();
  }else{
    const name=$("name").value.trim();
    const email=$("email").value.trim();
    const rollNumber=$("rollNumber").value.trim();
    const password=$("password").value.trim();

    if(!name||!email||!rollNumber||!password)
      return msg("Fill all fields");

    const d=await apiFetch("/signup",{
      method:"POST",
      body:JSON.stringify({name,email,rollNumber,password})
    });

    if(!d.success) return msg(d.message||"Signup failed");
    setToken(d.token);
    loadApp();
  }
};

/* =======================
   LOGOUT
======================= */
logoutBtn.onclick=()=>{
  clearToken();
  clearUser();
  authSection.classList.remove("hidden");
  homeSection.classList.add("hidden");
};

/* =======================
   NAVIGATION
======================= */
function openPage(id){
  document.querySelectorAll(".page").forEach(p=>p.classList.add("hidden"));
  $(id).classList.remove("hidden");

  document.querySelectorAll(".nav-item").forEach(b=>b.classList.remove("active"));
  document.querySelector(`.nav-item[data-page="${id}"]`)?.classList.add("active");
}

document.querySelectorAll(".nav-item").forEach(btn=>{
  btn.onclick=()=>{
    openPage(btn.dataset.page);
    if(btn.dataset.page==="attendanceRequestsPage") loadRequests();
  };
});

/* =======================
   LOAD APP
======================= */
async function loadApp(){
  if(!getToken()){
    authSection.classList.remove("hidden");
    homeSection.classList.add("hidden");
    return;
  }

  const me=await apiFetch("/me");
  if(!me.success){
    clearToken();
    return;
  }

  setUser(me.user);
  authSection.classList.add("hidden");
  homeSection.classList.remove("hidden");

  welcomeText.textContent=`Welcome, ${me.user.name}`;
  roleText.textContent=`Role: ${me.user.role.toUpperCase()}`;
  enrolledPill.textContent=me.user.enrolledClass||"Not Enrolled";

  if(me.user.role!=="student"){
    adminNavBlock.classList.remove("hidden");
    document.querySelectorAll(".admin-only").forEach(x=>x.classList.remove("hidden"));
  }

  openPage("dashboardPage");
}

/* =======================
   FACE + GEO ATTENDANCE
======================= */
function dist(a,b,c,d){
  const R=6371000,toRad=x=>x*Math.PI/180;
  const dLat=toRad(c-a),dLon=toRad(d-b);
  return R*2*Math.asin(Math.sqrt(
    Math.sin(dLat/2)**2+
    Math.cos(toRad(a))*Math.cos(toRad(c))*Math.sin(dLon/2)**2));
}

async function captureFace(){
  const s=await navigator.mediaDevices.getUserMedia({video:true});
  const v=document.createElement("video");
  v.srcObject=s;await v.play();
  await new Promise(r=>setTimeout(r,600));
  const c=document.createElement("canvas");
  c.width=v.videoWidth;c.height=v.videoHeight;
  c.getContext("2d").drawImage(v,0,0);
  s.getTracks().forEach(t=>t.stop());
  return await new Promise(r=>c.toBlob(r,"image/jpeg",0.95));
}

$("faceAttendanceBtn")?.onclick=()=>{
navigator.geolocation.getCurrentPosition(async p=>{
  const {latitude,longitude}=p.coords;
  const d=dist(latitude,longitude,TARGET.lat,TARGET.lng);
  locationStatus.textContent=`Distance: ${Math.round(d)} m`;

  const img=await captureFace();
  const fd=new FormData();
  fd.append("image",img);
  fd.append("lat",latitude);
  fd.append("lng",longitude);

  const ep=d<=TARGET.radius?"/attendance/face":"/attendance/request";
  const r=await apiFetch(ep,{method:"POST",body:fd});
  msg(r.message,r.success?"Done":"Error");
});
};

/* =======================
   REQUESTS
======================= */
async function loadRequests(){
  const d=await apiFetch("/owner/attendance/requests");
  attendanceRequestsView.innerHTML=d.requests.map(r=>`
    <div class="user-card">
      <b>${r.rollNumber}</b> (${Math.round(r.distance)}m)
      <div class="user-actions">
        <button class="btn btn-main" onclick="decision('${r._id}',true)">Approve</button>
        <button class="btn btn-danger" onclick="decision('${r._id}',false)">Reject</button>
      </div>
    </div>`).join("");
}

window.decision=async(id,ok)=>{
  await apiFetch(
    ok?"/owner/attendance/request/approve":"/owner/attendance/request/reject",
    {method:"POST",body:JSON.stringify({requestId:id})}
  );
  loadRequests();
};

loadApp();
});
