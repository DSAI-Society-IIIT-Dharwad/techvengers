import React, { useState, useEffect } from 'react';
import {
  Paper,
  Typography,
  Box,
  Alert,
  CircularProgress,
  Card,
  CardContent,
  Grid
} from '@mui/material';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const NetworkMap = () => {
  const [locations, setLocations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchGeographicData();
    const interval = setInterval(fetchGeographicData, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, []);

  const fetchGeographicData = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API_BASE_URL}/geographic-data`);
      setLocations(response.data.locations);
      setError(null);
    } catch (err) {
      setError('Failed to fetch geographic data. Make sure the API server is running.');
      console.error('Error fetching geographic data:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Loading network map...
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Network Geographic Map
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Map Placeholder */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 2, height: 500 }}>
            <Typography variant="h6" gutterBottom>
              World Map Visualization
            </Typography>
            <Box 
              display="flex" 
              justifyContent="center" 
              alignItems="center" 
              height="100%"
              sx={{ 
                backgroundColor: '#f5f5f5', 
                borderRadius: 1,
                border: '2px dashed #ccc'
              }}
            >
              <Box textAlign="center">
                <Typography variant="h6" color="textSecondary">
                  🌍 Interactive World Map
                </Typography>
                <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                  This would show a world map with markers for external IP connections
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  Total external IPs: {locations.length}
                </Typography>
              </Box>
            </Box>
          </Paper>
        </Grid>

        {/* Location List */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2, height: 500 }}>
            <Typography variant="h6" gutterBottom>
              External Connections
            </Typography>
            <Box sx={{ maxHeight: 400, overflowY: 'auto' }}>
              {locations.length === 0 ? (
                <Typography variant="body2" color="textSecondary">
                  No external connections detected
                </Typography>
              ) : (
                locations.map((location, index) => (
                  <Card key={index} sx={{ mb: 1 }}>
                    <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
                      <Typography variant="body2" fontFamily="monospace">
                        {location.ip}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {location.country} • {location.count} packets
                      </Typography>
                      <Typography variant="caption" color="textSecondary" display="block">
                        Lat: {location.lat.toFixed(2)}, Lng: {location.lng.toFixed(2)}
                      </Typography>
                    </CardContent>
                  </Card>
                ))
              )}
            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* Statistics */}
      <Paper sx={{ p: 2, mt: 3 }}>
        <Typography variant="h6" gutterBottom>
          Geographic Statistics
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  External IPs
                </Typography>
                <Typography variant="h4">
                  {locations.length}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Countries
                </Typography>
                <Typography variant="h4">
                  {new Set(locations.map(l => l.country)).size}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total Packets
                </Typography>
                <Typography variant="h4">
                  {locations.reduce((sum, l) => sum + l.count, 0)}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Avg Packets/IP
                </Typography>
                <Typography variant="h4">
                  {locations.length > 0 
                    ? Math.round(locations.reduce((sum, l) => sum + l.count, 0) / locations.length)
                    : 0
                  }
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
};

export default NetworkMap;
