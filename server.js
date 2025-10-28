const express = require('express');
const cors = require('cors');
const path = require('path');
const { Server } = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Mock ML models data
const mockTrafficData = {
  totalPackets: 0,
  anomalies: 0,
  threats: [],
  devices: [],
  protocols: { 'TCP': 0, 'UDP': 0, 'ICMP': 0 },
  topSources: [],
  alerts: []
};

// Generate mock data
function generateMockData() {
  mockTrafficData.totalPackets += Math.floor(Math.random() * 10) + 1;
  
  // Generate random anomalies
  if (Math.random() < 0.1) {
    mockTrafficData.anomalies++;
    mockTrafficData.alerts.push({
      id: Date.now(),
      timestamp: new Date().toISOString(),
      type: ['Port Scan', 'DDoS', 'Suspicious Traffic', 'Data Exfiltration'][Math.floor(Math.random() * 4)],
      severity: ['Low', 'Medium', 'High'][Math.floor(Math.random() * 3)],
      source: `192.168.1.${Math.floor(Math.random() * 255)}`,
      destination: `8.8.8.${Math.floor(Math.random() * 255)}`,
      score: Math.floor(Math.random() * 40) + 60
    });
  }
  
  // Update protocols
  mockTrafficData.protocols.TCP += Math.floor(Math.random() * 5);
  mockTrafficData.protocols.UDP += Math.floor(Math.random() * 3);
  mockTrafficData.protocols.ICMP += Math.floor(Math.random() * 2);
  
  // Update top sources
  const newSource = `192.168.1.${Math.floor(Math.random() * 255)}`;
  const existingSource = mockTrafficData.topSources.find(s => s.ip === newSource);
  if (existingSource) {
    existingSource.count++;
  } else {
    mockTrafficData.topSources.push({ ip: newSource, count: 1 });
  }
  
  // Keep only top 10 sources
  mockTrafficData.topSources.sort((a, b) => b.count - a.count);
  mockTrafficData.topSources = mockTrafficData.topSources.slice(0, 10);
}

// Routes
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: 'Network Security Dashboard API is running'
  });
});

app.get('/api/dashboard', (req, res) => {
  res.json(mockTrafficData);
});

app.get('/api/alerts', (req, res) => {
  res.json(mockTrafficData.alerts);
});

app.get('/api/stats', (req, res) => {
  res.json({
    totalPackets: mockTrafficData.totalPackets,
    anomalies: mockTrafficData.anomalies,
    anomalyRate: mockTrafficData.totalPackets > 0 ? 
      (mockTrafficData.anomalies / mockTrafficData.totalPackets * 100).toFixed(2) : 0,
    protocols: mockTrafficData.protocols,
    topSources: mockTrafficData.topSources.slice(0, 5)
  });
});

// Serve the main dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.io for real-time updates
io.on('connection', (socket) => {
  console.log('Client connected');
  
  // Send initial data
  socket.emit('dashboard-update', mockTrafficData);
  
  // Send periodic updates
  const interval = setInterval(() => {
    generateMockData();
    socket.emit('dashboard-update', mockTrafficData);
  }, 2000);
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
    clearInterval(interval);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Network Security Dashboard Server running on port ${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}`);
  console.log(`🔗 API Health: http://localhost:${PORT}/api/health`);
});

// Generate initial data
setInterval(generateMockData, 1000);
