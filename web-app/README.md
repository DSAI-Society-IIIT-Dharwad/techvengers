# Network Traffic Analyzer - Web Application

A modern React-based web dashboard for the Network Traffic Analyzer system, replacing the Streamlit interface with a more professional and customizable web application.

## 🚀 Features

- **Modern React UI** with Material-UI components
- **Real-time Data Updates** every 30 seconds
- **Interactive Charts** using Recharts library
- **Responsive Design** for desktop and mobile
- **Dark Theme** optimized for security monitoring
- **RESTful API** built with Flask
- **Geographic Visualization** for external IP connections

## 📊 Dashboard Components

### 1. Main Dashboard
- Real-time statistics cards
- Traffic over time line chart
- Protocol distribution pie chart
- Top source IPs bar chart
- Alert summary with risk levels

### 2. Alerts Page
- Filterable alerts table
- Risk level filtering (High/Medium/Low)
- Recent alerts toggle (24h)
- Detailed alert information

### 3. Network Map
- Geographic distribution of external IPs
- Connection statistics
- Country-based grouping
- Interactive location data

## 🛠️ Technology Stack

### Frontend
- **React 18** - Modern React with hooks
- **Material-UI** - Professional UI components
- **Recharts** - Interactive charts and graphs
- **Axios** - HTTP client for API calls
- **React Router** - Client-side routing

### Backend
- **Flask** - Lightweight Python web framework
- **Flask-CORS** - Cross-origin resource sharing
- **Pandas** - Data manipulation and analysis
- **NumPy** - Numerical computing

## 📁 Project Structure

```
web-app/
├── api_server.py              # Flask API server
├── start_web_app.py          # Startup script
├── network-dashboard/         # React application
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.js   # Main dashboard component
│   │   │   ├── Alerts.js      # Alerts management
│   │   │   └── NetworkMap.js  # Geographic visualization
│   │   ├── App.js            # Main app component
│   │   └── App.css           # Custom styles
│   ├── package.json          # Node.js dependencies
│   └── public/               # Static assets
└── README.md                 # This file
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm or yarn

### Installation

1. **Install Python dependencies:**
   ```bash
   pip install flask flask-cors pandas numpy
   ```

2. **Install Node.js dependencies:**
   ```bash
   cd network-dashboard
   npm install
   ```

3. **Start the application:**
   ```bash
   python start_web_app.py
   ```

### Manual Startup

If you prefer to start services manually:

1. **Start API server:**
   ```bash
   python api_server.py
   ```

2. **Start React app (in another terminal):**
   ```bash
   cd network-dashboard
   npm start
   ```

## 🌐 Access URLs

- **React Dashboard**: http://localhost:3000
- **API Server**: http://localhost:5000
- **API Documentation**: http://localhost:5000/api/health

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/stats` | GET | Overall statistics |
| `/api/packets` | GET | Packet data with filtering |
| `/api/alerts` | GET | Alert data with filtering |
| `/api/traffic-over-time` | GET | Traffic aggregated by time |
| `/api/top-ips` | GET | Top source IPs by traffic |
| `/api/protocol-distribution` | GET | Protocol distribution |
| `/api/geographic-data` | GET | Geographic IP data |

### Query Parameters

- **packets**: `?limit=1000&protocol=TCP&src_ip=192.168.1.1`
- **alerts**: `?limit=100&risk_level=High&recent_only=true`

## 🎨 Customization

### Themes
The app uses Material-UI's dark theme. To customize:

1. Edit `src/App.js` theme configuration
2. Modify color palette and typography
3. Update `src/App.css` for custom styles

### Charts
Charts are built with Recharts. To modify:

1. Edit components in `src/components/`
2. Change chart types, colors, and data formatting
3. Add new chart types as needed

### API Integration
To connect to different data sources:

1. Modify `api_server.py` data loading functions
2. Update API endpoints as needed
3. Change data processing logic

## 🔧 Development

### Adding New Components

1. Create component file in `src/components/`
2. Import and use in `App.js`
3. Add routing if needed

### Extending API

1. Add new endpoints in `api_server.py`
2. Update frontend to call new endpoints
3. Add error handling and validation

## 🐛 Troubleshooting

### Common Issues

1. **API Connection Failed**
   - Ensure Flask server is running on port 5000
   - Check CORS configuration
   - Verify data files exist

2. **React App Won't Start**
   - Run `npm install` in network-dashboard directory
   - Check Node.js version compatibility
   - Clear npm cache: `npm cache clean --force`

3. **Charts Not Loading**
   - Verify data format matches chart expectations
   - Check browser console for errors
   - Ensure API returns valid JSON

### Debug Mode

- **API Server**: Runs with `debug=True` by default
- **React App**: Use browser dev tools for debugging
- **Logs**: Check terminal output for error messages

## 📈 Performance

- **Data Refresh**: 30 seconds for dashboard, 60 seconds for map
- **Caching**: API caches data in memory
- **Pagination**: Large datasets are paginated
- **Responsive**: Optimized for mobile and desktop

## 🔒 Security

- **CORS**: Configured for localhost development
- **Data Validation**: Input sanitization on API endpoints
- **Error Handling**: Graceful error responses
- **Rate Limiting**: Consider adding for production use

## 🚀 Production Deployment

For production deployment:

1. **Build React app:**
   ```bash
   cd network-dashboard
   npm run build
   ```

2. **Configure Flask for production:**
   - Use production WSGI server (Gunicorn)
   - Set up reverse proxy (Nginx)
   - Configure HTTPS
   - Add authentication/authorization

3. **Environment variables:**
   - Set `FLASK_ENV=production`
   - Configure database connections
   - Set up monitoring and logging

## 📝 License

This project is part of the Network Traffic Analyzer system. See main project README for license information.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

## 📞 Support

For issues and questions:
- Check troubleshooting section
- Review API documentation
- Open GitHub issue
- Contact project maintainers
