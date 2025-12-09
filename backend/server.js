/**
 * API Security Scanner - Backend Server
 * Express server with scanning endpoints
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const scanner = require('../scanner');

const app = express();
const PORT = process.env.PORT || 5000;

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/json' || file.originalname.endsWith('.json')) {
      cb(null, true);
    } else {
      cb(new Error('Only JSON files are allowed'), false);
    }
  }
});

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Store active scans for progress tracking
const activeScans = new Map();

/**
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

/**
 * Get available vulnerability types
 */
app.get('/api/scan-types', (req, res) => {
  const types = scanner.scanners.map(s => ({
    type: s.getType(),
    severity: s.getSeverity(),
    payloadCount: s.getPayloads().length
  }));
  res.json(types);
});

/**
 * Parse Postman collection endpoint
 */
app.post('/api/parse/postman', upload.single('collection'), (req, res) => {
  try {
    let collection;
    
    if (req.file) {
      // File upload
      collection = JSON.parse(req.file.buffer.toString());
    } else if (req.body.collection) {
      // JSON body
      collection = typeof req.body.collection === 'string' 
        ? JSON.parse(req.body.collection) 
        : req.body.collection;
    } else {
      return res.status(400).json({ 
        error: 'No collection provided',
        message: 'Please upload a file or provide collection in request body'
      });
    }

    const envVars = req.body.envVars || {};
    const endpoints = scanner.parsePostmanCollection(collection, envVars);

    res.json({
      success: true,
      endpointCount: endpoints.length,
      endpoints: endpoints.map(e => ({
        name: e.name,
        method: e.method,
        url: e.url,
        hasBody: !!e.body,
        hasHeaders: Object.keys(e.headers || {}).length > 0,
        queryParamCount: Object.keys(e.queryParams || {}).length
      }))
    });
  } catch (error) {
    console.error('Parse error:', error);
    res.status(400).json({
      error: 'Failed to parse collection',
      message: error.message
    });
  }
});

/**
 * Parse CURL command endpoint
 */
app.post('/api/parse/curl', (req, res) => {
  try {
    const { curl } = req.body;

    if (!curl) {
      return res.status(400).json({
        error: 'No CURL command provided',
        message: 'Please provide a curl command in the request body'
      });
    }

    // Handle multiple CURL commands
    const curlCommands = curl.split(/\n(?=curl)/i).filter(c => c.trim());
    const endpoints = curlCommands.map(c => scanner.parseCurl(c));

    res.json({
      success: true,
      endpointCount: endpoints.length,
      endpoints: endpoints.map(e => ({
        name: e.name,
        method: e.method,
        url: e.url,
        hasBody: !!e.body,
        hasHeaders: Object.keys(e.headers || {}).length > 0,
        queryParamCount: Object.keys(e.queryParams || {}).length
      }))
    });
  } catch (error) {
    console.error('CURL parse error:', error);
    res.status(400).json({
      error: 'Failed to parse CURL command',
      message: error.message
    });
  }
});

/**
 * Main scan endpoint
 */
app.post('/api/scan', upload.single('collection'), async (req, res) => {
  const scanId = uuidv4();
  
  try {
    let endpoints = [];
    let envVars = {};

    // Parse environment variables
    if (req.body.envVars) {
      envVars = typeof req.body.envVars === 'string' 
        ? JSON.parse(req.body.envVars) 
        : req.body.envVars;
    }

    // Parse input based on type
    if (req.file) {
      // Postman collection file
      const collection = JSON.parse(req.file.buffer.toString());
      endpoints = scanner.parsePostmanCollection(collection, envVars);
    } else if (req.body.collection) {
      // Postman collection JSON
      const collection = typeof req.body.collection === 'string'
        ? JSON.parse(req.body.collection)
        : req.body.collection;
      endpoints = scanner.parsePostmanCollection(collection, envVars);
    } else if (req.body.curl) {
      // CURL commands
      const curlCommands = req.body.curl.split(/\n(?=curl)/i).filter(c => c.trim());
      endpoints = curlCommands.map(c => scanner.parseCurl(c));
    } else if (req.body.endpoints) {
      // Direct endpoint list
      endpoints = typeof req.body.endpoints === 'string'
        ? JSON.parse(req.body.endpoints)
        : req.body.endpoints;
    } else {
      return res.status(400).json({
        error: 'No input provided',
        message: 'Please provide a Postman collection, CURL commands, or endpoint list'
      });
    }

    if (endpoints.length === 0) {
      return res.status(400).json({
        error: 'No endpoints found',
        message: 'Could not extract any API endpoints from the provided input'
      });
    }

    // Parse scan options
    let scanTypes = null;
    if (req.body.scanTypes) {
      try {
        scanTypes = typeof req.body.scanTypes === 'string' 
          ? JSON.parse(req.body.scanTypes)
          : req.body.scanTypes;
        if (!Array.isArray(scanTypes)) {
          scanTypes = [scanTypes];
        }
      } catch (e) {
        scanTypes = [req.body.scanTypes];
      }
    }
    
    const options = {
      scanTypes: scanTypes,
      maxPayloads: parseInt(req.body.maxPayloads) || 5,
      injectLocation: req.body.injectLocation || 'all'
    };
    
    console.log('Scan options:', JSON.stringify(options));

    // Initialize progress tracking
    activeScans.set(scanId, {
      status: 'running',
      progress: { current: 0, total: endpoints.length },
      startTime: Date.now()
    });

    console.log(`Starting scan ${scanId} with ${endpoints.length} endpoints`);
    console.log('Endpoints to scan:', endpoints.map(e => `${e.method} ${e.url}`).join(', '));

    // Run the scan
    const results = await scanner.runScan(
      endpoints, 
      options,
      (progress) => {
        const scanInfo = activeScans.get(scanId);
        if (scanInfo) {
          scanInfo.progress = progress;
        }
      }
    );

    // Update scan status
    activeScans.set(scanId, {
      status: 'completed',
      results: results
    });

    // Clean up after 1 hour
    setTimeout(() => activeScans.delete(scanId), 3600000);

    console.log(`Scan ${scanId} completed in ${results.duration}ms`);

    res.json({
      success: true,
      scanId: scanId,
      results: results
    });

  } catch (error) {
    console.error('Scan error:', error);
    
    activeScans.set(scanId, {
      status: 'error',
      error: error.message
    });

    res.status(500).json({
      error: 'Scan failed',
      message: error.message,
      scanId: scanId
    });
  }
});

/**
 * Get scan progress/status
 */
app.get('/api/scan/:scanId', (req, res) => {
  const { scanId } = req.params;
  const scanInfo = activeScans.get(scanId);

  if (!scanInfo) {
    return res.status(404).json({
      error: 'Scan not found',
      message: 'The specified scan ID was not found'
    });
  }

  res.json(scanInfo);
});

/**
 * Quick scan single endpoint
 */
app.post('/api/scan/quick', async (req, res) => {
  try {
    const { url, method = 'GET', headers = {}, body = null } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'URL required',
        message: 'Please provide a URL to scan'
      });
    }

    const endpoint = {
      name: url,
      method: method.toUpperCase(),
      url: url,
      headers: headers,
      body: body,
      queryParams: {}
    };

    // Parse query params from URL
    try {
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((value, key) => {
        endpoint.queryParams[key] = value;
      });
      endpoint.url = `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`;
    } catch (e) {
      // Keep URL as is
    }

    const options = {
      maxPayloads: 3,
      injectLocation: 'all'
    };

    const results = await scanner.scanEndpoint(endpoint, options);

    res.json({
      success: true,
      results: results
    });

  } catch (error) {
    console.error('Quick scan error:', error);
    res.status(500).json({
      error: 'Quick scan failed',
      message: error.message
    });
  }
});

/**
 * Test connectivity to an endpoint
 */
app.post('/api/test-connection', async (req, res) => {
  try {
    const { url, method = 'GET', headers = {} } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'URL required',
        message: 'Please provide a URL to test'
      });
    }

    const endpoint = {
      url: url,
      method: method,
      headers: headers,
      body: null,
      queryParams: {}
    };

    const result = await scanner.sendRequest(endpoint);

    res.json({
      success: result.success,
      status: result.response?.status,
      responseTime: result.responseTime,
      error: result.error
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: 'File upload error',
      message: err.message
    });
  }

  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: `Endpoint ${req.method} ${req.path} not found`
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   🔒 API Security Scanner - Backend Server                 ║
║                                                            ║
║   Server running on http://localhost:${PORT}                 ║
║                                                            ║
║   Endpoints:                                               ║
║   - GET  /api/health          Health check                 ║
║   - GET  /api/scan-types      Available scan types         ║
║   - POST /api/parse/postman   Parse Postman collection     ║
║   - POST /api/parse/curl      Parse CURL commands          ║
║   - POST /api/scan            Run security scan            ║
║   - POST /api/scan/quick      Quick single endpoint scan   ║
║   - GET  /api/scan/:id        Get scan status              ║
║   - POST /api/test-connection Test endpoint connectivity   ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;

