// ========= DOM ELEMENTS =========
const drop = document.getElementById("drop");
const fileInput = document.getElementById("file");
const fileNameEl = document.getElementById("fileName");
const fileHashEl = document.getElementById("fileHash");
const scanMeta = document.getElementById("scanMeta");
const progressBar = document.getElementById("progressBar");
const btnAnalyze = document.getElementById("btnAnalyze");
const btnReset = document.getElementById("btnReset");
const btnExport = document.getElementById("btnExport");

const riskBadge = document.getElementById("riskBadge");
const riskScoreEl = document.getElementById("riskScore");
const riskSummary = document.getElementById("riskSummary");
const indicatorsTable = document.querySelector("#indicators tbody");
const feedTable = document.querySelector("#feed tbody");
const distText = document.getElementById("distText");

// ========= STATE =========
let selectedFile = null;
let analysisResult = null;

// ========= HELPERS =========
function sha256(buffer) {
  return crypto.subtle.digest("SHA-256", buffer).then(hash => {
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  });
}

function setProgress(percent) {
  progressBar.style.width = percent + "%";
}

function resetUI() {
  selectedFile = null;
  analysisResult = null;
  setProgress(0);
  scanMeta.style.display = "none";
  riskScoreEl.textContent = "–";
  riskSummary.textContent = "Awaiting file…";
  riskBadge.className = "badge b-warn";
  indicatorsTable.innerHTML = "";
}

// ========= FILE HANDLING =========
drop.addEventListener("dragover", e => {
  e.preventDefault();
  drop.classList.add("drag");
});

drop.addEventListener("dragleave", () => drop.classList.remove("drag"));

drop.addEventListener("drop", async e => {
  e.preventDefault();
  drop.classList.remove("drag");
  if (e.dataTransfer.files.length > 0) {
    await handleFile(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener("change", async e => {
  if (e.target.files.length > 0) {
    await handleFile(e.target.files[0]);
  }
});

async function handleFile(file) {
  if (!file.name.endsWith(".apk")) {
    alert("Only .apk files allowed (demo).");
    return;
  }
  selectedFile = file;
  fileNameEl.textContent = file.name;

  const buffer = await file.arrayBuffer();
  const hash = await sha256(buffer);
  fileHashEl.textContent = hash.substring(0, 32) + "…"; // shortened

  scanMeta.style.display = "block";
}

// ========= ANALYSIS =========
btnAnalyze.addEventListener("click", async () => {
  if (!selectedFile) {
    alert("Select an APK first.");
    return;
  }
  setProgress(0);
  indicatorsTable.innerHTML = "";
  riskSummary.textContent = "Analyzing…";

  // Fake progress animation
  for (let i = 0; i <= 100; i += 10) {
    await new Promise(r => setTimeout(r, 120));
    setProgress(i);
  }

  // Simulated result
  const score = Math.floor(Math.random() * 100);
  const indicators = [
    {
      name: "Suspicious Permission",
      value: "READ_SMS",
      weight: 15,
      status: score > 60 ? "Triggered" : "OK"
    },
    {
      name: "Package Spoofing",
      value: "com.abcbank.mobile",
      weight: 20,
      status: score > 70 ? "Triggered" : "OK"
    },
    {
      name: "Hardcoded URL",
      value: "hxxp://phish-login[.]com",
      weight: 25,
      status: score > 50 ? "Triggered" : "OK"
    }
  ];

  analysisResult = { score, indicators };

  // Update UI
  riskScoreEl.textContent = score;
  if (score >= 80) {
    riskBadge.className = "badge b-bad";
    riskSummary.textContent = "High risk: likely malicious.";
  } else if (score >= 60) {
    riskBadge.className = "badge b-warn";
    riskSummary.textContent = "Suspicious: investigate further.";
  } else {
    riskBadge.className = "badge b-ok";
    riskSummary.textContent = "Low risk: likely clean.";
  }

  indicators.forEach(ind => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${ind.name}</td>
      <td>${ind.value}</td>
      <td>${ind.weight}</td>
      <td>${ind.status}</td>
    `;
    indicatorsTable.appendChild(row);
  });

  updateFeed(selectedFile.name, score);
});

btnReset.addEventListener("click", resetUI);

// ========= EXPORT =========
btnExport.addEventListener("click", () => {
  if (!analysisResult) {
    alert("No analysis result yet.");
    return;
  }
  const blob = new Blob([JSON.stringify(analysisResult, null, 2)], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "analysis.json";
  a.click();
  URL.revokeObjectURL(url);
});

// ========= FEED =========
function updateFeed(pkgName, score) {
  const row = document.createElement("tr");
  row.innerHTML = `
    <td>${pkgName.replace(".apk", "")}</td>
    <td>${Math.random().toString(16).substring(2, 10)}</td>
    <td>${score}</td>
    <td>domain[.]com</td>
    <td>${score >= 80 ? "Malicious" : score >= 60 ? "Suspicious" : "Clean"}</td>
  `;
  feedTable.prepend(row);

  // Update legit/malicious counter
  const parts = distText.textContent.split("/");
  let legit = parseInt(parts[0]) || 0;
  let bad = parseInt(parts[1]) || 0;
  if (score >= 60) bad++;
  else legit++;
  distText.textContent = `${legit} / ${bad}`;
}

// ========= INIT =========
resetUI();