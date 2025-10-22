// server.js - Vercel-compatible backend
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// SECURE: Store credentials in environment variables
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const SHEET_ID = process.env.SHEET_ID;

// Cache to improve performance
let cachedData = {};
let lastFetchTime = {};
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// API endpoint to fetch sheet data
app.get('/api/sheets/data', async (req, res) => {
    const sheetName = req.query.sheet || 'Sheet1'; // Default to Sheet1

    try {
        // Check if cached data for the specific sheet is still valid
        if (cachedData[sheetName] && lastFetchTime[sheetName] && (Date.now() - lastFetchTime[sheetName] < CACHE_DURATION)) {
            console.log(`Serving cached data for ${sheetName}`);
            return res.json(cachedData[sheetName]);
        }

        // Validate environment variables
        if (!GOOGLE_API_KEY || !SHEET_ID) {
            return res.status(500).json({ 
                error: 'Server configuration error: Missing API credentials' 
            });
        }

        // Fetch data from Google Sheets API
        const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${sheetName}?key=${GOOGLE_API_KEY}`;
        
        const response = await fetch(url);
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error?.message || 'Failed to fetch from Google Sheets');
        }

        const data = await response.json();
        
        if (!data.values || data.values.length === 0) {
            return res.status(404).json({ error: 'No data found in sheet' });
        }

        // Convert to array of objects
        const headers = data.values[0];
        const rows = data.values.slice(1).map(row => {
            const obj = {};
            headers.forEach((header, index) => {
                obj[header] = row[index] || '';
            });
            return obj;
        });

        // Update cache for the specific sheet
        cachedData[sheetName] = rows;
        lastFetchTime[sheetName] = Date.now();

        console.log(`Fetched ${rows.length} rows from Google Sheets (${sheetName})`);
        res.json(rows);

    } catch (error) {
        console.error(`Error fetching sheet data for ${sheetName}:`, error);
        res.status(500).json({ 
            error: 'Failed to fetch data', 
            message: error.message 
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Clear cache endpoint (optional - for manual refresh)
app.post('/api/sheets/clear-cache', (req, res) => {
    cachedData = {};
    lastFetchTime = {};
    res.json({ message: 'Cache cleared successfully' });
});

// Export the app handler for Vercel
module.exports = app;

