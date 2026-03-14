// ────────── DOM ELEMENTS ──────────
const els = {
  threatCount: document.getElementById('threatCount'),
  valCPU: document.getElementById('valCPU'),
  valRAM: document.getElementById('valRAM'),
  valDISK: document.getElementById('valDISK'),
  valNET: document.getElementById('valNET'),
  logs: {
    anomaly: document.getElementById('log-anomaly'),
    portscan: document.getElementById('log-portscan'),
    kernel: document.getElementById('log-kernel'),
    packet: document.getElementById('log-packet'),
    attack: document.getElementById('log-attack')
  }
};

// ────────── SPARKLINE GRAPHS (using Canvas) ──────────
// Store last 60 seconds of history 
const MAX_POINTS = 60;
const historyData = {
  cpu: Array(MAX_POINTS).fill(0),
  ram: Array(MAX_POINTS).fill(0),
  disk: Array(MAX_POINTS).fill(0),
  net: Array(MAX_POINTS).fill(0)
};

const colors = {
  cpu: '#eab308',   // yellow
  ram: '#3b82f6',  // blue
  disk: '#06b6d4', // cyan
  net: '#10b981'   // emerald
};

function drawSparkline(canvasId, dataArr, color, maxValOverride = 100) {
  const canvas = document.getElementById(canvasId);
  if(!canvas) return;
  
  // Handle high-DPI displays for crisp lines
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * 2;
  canvas.height = rect.height * 2;
  
  const ctx = canvas.getContext('2d');
  ctx.scale(2, 2);
  
  const w = rect.width;
  const h = rect.height;
  
  ctx.clearRect(0, 0, w, h);
  
  // Find dynamic max for Network, use 100 for percentages
  let maxVal = maxValOverride;
  if(maxValOverride === 'auto') {
    maxVal = Math.max(...dataArr, 10); // at least 10 so it's not a flat line when 0
  }
  
  const step = w / (MAX_POINTS - 1);
  
  // Gradient fill under the line
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, color + '66'); // 40% opacity
  grad.addColorStop(1, color + '00'); // 0% opacity
  
  ctx.beginPath();
  ctx.moveTo(0, h);
  
  for(let i=0; i<MAX_POINTS; i++) {
    const p = Math.min(1, Math.max(0, dataArr[i] / maxVal)); // normalize 0-1
    const x = i * step;
    const y = h - (p * h * 0.9); // 0.9 padding top
    ctx.lineTo(x, y);
  }
  
  ctx.lineTo(w, h);
  ctx.fillStyle = grad;
  ctx.fill();
  
  // Draw the bright line
  ctx.beginPath();
  for(let i=0; i<MAX_POINTS; i++) {
    const p = Math.min(1, Math.max(0, dataArr[i] / maxVal));
    const x = i * step;
    const y = h - (p * h * 0.9);
    if(i===0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.stroke();
  
  // Draw a dot on the last data point
  const lastVal = Math.min(1, Math.max(0, dataArr[MAX_POINTS-1] / maxVal));
  ctx.beginPath();
  ctx.arc(w - 2, h - (lastVal * h * 0.9), 2.5, 0, Math.PI*2);
  ctx.fillStyle = '#fff';
  ctx.fill();
}

function updateMetrics(metrics, threats) {
  // Update texts
  els.threatCount.textContent = threats;
  els.valCPU.textContent = metrics.cpu.toFixed(0) + '%';
  els.valRAM.textContent = metrics.ram.toFixed(0) + '%';
  els.valDISK.textContent = metrics.disk.toFixed(0) + '%';
  els.valNET.textContent = metrics.net.toFixed(0) + ' KB/s';
  
  // Shift array and append new
  historyData.cpu.shift(); historyData.cpu.push(metrics.cpu);
  historyData.ram.shift(); historyData.ram.push(metrics.ram);
  historyData.disk.shift(); historyData.disk.push(metrics.disk);
  historyData.net.shift(); historyData.net.push(metrics.net);
  
  // Draw Graph
  drawSparkline('canvasCPU', historyData.cpu, colors.cpu, 100);
  drawSparkline('canvasRAM', historyData.ram, colors.ram, 100);
  drawSparkline('canvasDISK', historyData.disk, colors.disk, 100);
  drawSparkline('canvasNET', historyData.net, colors.net, 'auto');
}

// ────────── LOG HANDLING ──────────
function appendLogs(logs) {
  logs.forEach(item => {
    const container = els.logs[item.panel];
    if(!container) return;
    
    const div = document.createElement('div');
    div.className = 'log-line ' + (item.alert ? 'alert' : '');
    div.innerText = `[${item.timestamp}] ${item.text}`;
    
    container.appendChild(div);
    
    // Auto-scroll logic: keep last 100 nodes to prevent DOM bloat
    if(container.childNodes.length > 200) {
      container.removeChild(container.firstChild);
    }
    container.scrollTop = container.scrollHeight;
  });
}

// ────────── SSE CONNECTION ──────────
function connectStream() {
  const evtSource = new EventSource("/stream");
  
  evtSource.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    if(data.type === 'metrics') {
      updateMetrics(data.data, data.threats);
    } 
    else if(data.type === 'logs') {
      appendLogs(data.logs);
    }
  };
  
  evtSource.onerror = function() {
    console.error("SSE Connection lost. Reconnecting...");
  };
}

// ────────── BUTTON TRIGGERS ──────────
function triggerAttack(type) {
  const targetIp = document.getElementById('targetIp').value;
  let url = `/attack/${type}?target=${targetIp}`;
  
  fetch(url, { method: 'POST' })
    .then(res => res.json())
    .catch(err => console.error("Attack trigger error:", err));
}

// Init
window.onload = () => {
  // Pre-draw empty canvases
  drawSparkline('canvasCPU', historyData.cpu, colors.cpu, 100);
  drawSparkline('canvasRAM', historyData.ram, colors.ram, 100);
  drawSparkline('canvasDISK', historyData.disk, colors.disk, 100);
  drawSparkline('canvasNET', historyData.net, colors.net, 'auto');
  
  connectStream();
};
