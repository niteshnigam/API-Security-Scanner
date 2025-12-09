/**
 * Security Scanner Engine
 * Main orchestrator for all security tests
 */

const axios = require('axios');

// Original 4 scanners
const sqlScanner = require('./sql');
const xssScanner = require('./xss');
const commandInjectionScanner = require('./commandInjection');
const pathTraversalScanner = require('./pathTraversal');

// New 6 scanners
const nosqlInjectionScanner = require('./nosqlInjection');
const headerInjectionScanner = require('./headerInjection');
const rateLimitingScanner = require('./rateLimiting');
const malformedPayloadScanner = require('./malformedPayload');
const httpMethodScanner = require('./httpMethodTest');
const payloadSizeScanner = require('./payloadSize');

// All scanner modules - 10 total vulnerability types
const scanners = [
  sqlScanner,              // SQL Injection
  xssScanner,              // Cross-Site Scripting
  commandInjectionScanner, // OS Command Injection
  pathTraversalScanner,    // Path Traversal / LFI
  nosqlInjectionScanner,   // NoSQL / JSON Injection
  headerInjectionScanner,  // Header Manipulation
  rateLimitingScanner,     // Rate Limiting Test
  malformedPayloadScanner, // Malformed Input Test
  httpMethodScanner,       // HTTP Method Test
  payloadSizeScanner       // Payload Size Test
];

// Enable detailed logging
const DEBUG = true;
const log = (...args) => DEBUG && console.log('[Scanner]', ...args);

/**
 * Parse Postman collection and extract API endpoints
 * @param {Object} collection - Postman collection JSON
 * @param {Object} envVars - Environment variables
 * @returns {Array} Array of API endpoints
 */
function parsePostmanCollection(collection, envVars = {}) {
  const endpoints = [];

  // Replace environment variables in string
  const replaceEnvVars = (str) => {
    if (!str) return str;
    let result = str;
    Object.entries(envVars).forEach(([key, value]) => {
      result = result.replace(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), value);
    });
    return result;
  };

  // Recursively parse items
  const parseItems = (items, parentAuth = null) => {
    if (!items || !Array.isArray(items)) return;

    items.forEach(item => {
      if (item.item) {
        // This is a folder, recurse
        parseItems(item.item, item.auth || parentAuth);
      } else if (item.request) {
        // This is a request
        const request = item.request;
        let url = '';

        if (typeof request.url === 'string') {
          url = request.url;
        } else if (request.url && request.url.raw) {
          url = request.url.raw;
        } else if (request.url && request.url.host) {
          const host = Array.isArray(request.url.host) 
            ? request.url.host.join('.') 
            : request.url.host;
          const path = request.url.path 
            ? (Array.isArray(request.url.path) ? request.url.path.join('/') : request.url.path)
            : '';
          const protocol = request.url.protocol || 'http';
          url = `${protocol}://${host}/${path}`;
        }

        url = replaceEnvVars(url);

        // Parse headers
        const headers = {};
        if (request.header && Array.isArray(request.header)) {
          request.header.forEach(h => {
            if (!h.disabled) {
              headers[h.key] = replaceEnvVars(h.value);
            }
          });
        }

        // Parse body
        let body = null;
        if (request.body) {
          if (request.body.mode === 'raw') {
            body = replaceEnvVars(request.body.raw);
            try {
              body = JSON.parse(body);
            } catch (e) {
              // Keep as string if not JSON
            }
          } else if (request.body.mode === 'urlencoded') {
            body = {};
            (request.body.urlencoded || []).forEach(param => {
              if (!param.disabled) {
                body[param.key] = replaceEnvVars(param.value);
              }
            });
          } else if (request.body.mode === 'formdata') {
            body = {};
            (request.body.formdata || []).forEach(param => {
              if (!param.disabled && param.type !== 'file') {
                body[param.key] = replaceEnvVars(param.value);
              }
            });
          }
        }

        // Parse query params
        const queryParams = {};
        if (request.url && request.url.query) {
          request.url.query.forEach(q => {
            if (!q.disabled) {
              queryParams[q.key] = replaceEnvVars(q.value);
            }
          });
        }

        endpoints.push({
          name: item.name || url,
          method: (request.method || 'GET').toUpperCase(),
          url: url,
          headers: headers,
          body: body,
          queryParams: queryParams
        });
      }
    });
  };

  // Handle both v2.0 and v2.1 collection formats
  const items = collection.item || collection.items || [];
  parseItems(items, collection.auth);

  return endpoints;
}

/**
 * Parse CURL command and extract API endpoint
 * @param {string} curlCommand - CURL command string
 * @returns {Object} API endpoint object
 */
function parseCurl(curlCommand) {
  const endpoint = {
    name: 'CURL Request',
    method: 'GET',
    url: '',
    headers: {},
    body: null,
    queryParams: {}
  };

  // Clean the command - normalize line continuations
  let cmd = curlCommand
    .replace(/\\\s*\n/g, ' ')  // Remove line continuations
    .replace(/\s+/g, ' ')       // Normalize whitespace
    .trim();
  
  // Remove 'curl' prefix if present
  if (cmd.toLowerCase().startsWith('curl')) {
    cmd = cmd.substring(4).trim();
  }

  // Parse URL - look for https:// or http:// URLs
  const urlPatterns = [
    /['"]?(https?:\/\/[^\s'"\\]+)['"]?/i,
  ];

  for (const pattern of urlPatterns) {
    const match = cmd.match(pattern);
    if (match) {
      // Clean up the URL - remove any trailing quotes or backslashes
      endpoint.url = match[1].replace(/['"\\\s]+$/, '');
      break;
    }
  }

  // Parse method (-X or --request)
  const methodMatch = cmd.match(/(?:-X|--request)\s+['"]?(\w+)['"]?/i);
  if (methodMatch) {
    endpoint.method = methodMatch[1].toUpperCase();
  }
  // Note: We'll determine POST method later based on actual data content

  // Parse headers (-H or --header)
  const headerRegex = /(?:-H|--header)\s+['"]([^'"]+)['"]/gi;
  let headerMatch;
  while ((headerMatch = headerRegex.exec(cmd)) !== null) {
    const [key, ...valueParts] = headerMatch[1].split(':');
    if (key && valueParts.length > 0) {
      endpoint.headers[key.trim()] = valueParts.join(':').trim();
    }
  }

  // Parse data (-d or --data or --data-raw)
  const dataPatterns = [
    /(?:-d|--data|--data-raw|--data-binary)\s+'([^']*)'/i,   // Single quotes (capture can be empty)
    /(?:-d|--data|--data-raw|--data-binary)\s+"([^"]*)"/i,   // Double quotes (capture can be empty)
  ];

  let hasActualData = false;
  let rawDataValue = null;
  
  for (const pattern of dataPatterns) {
    const dataMatch = cmd.match(pattern);
    if (dataMatch) {
      rawDataValue = dataMatch[1];
      break;
    }
  }
  
  // Only process if we have non-empty data
  if (rawDataValue && rawDataValue.trim().length > 0) {
    hasActualData = true;
    try {
      endpoint.body = JSON.parse(rawDataValue);
    } catch (e) {
      // Try URL encoded format
      const params = {};
      rawDataValue.split('&').forEach(pair => {
        const [key, value] = pair.split('=');
        if (key && key.trim()) {
          params[decodeURIComponent(key)] = value ? decodeURIComponent(value) : '';
        }
      });
      endpoint.body = Object.keys(params).length > 0 ? params : rawDataValue;
    }
  }
  
  // Set method to POST only if there's actual data AND no explicit method was set
  if (hasActualData && !methodMatch) {
    endpoint.method = 'POST';
  }

  // Parse query params from URL
  try {
    const urlObj = new URL(endpoint.url);
    urlObj.searchParams.forEach((value, key) => {
      endpoint.queryParams[key] = value;
    });
    // Store base URL without query params
    endpoint.url = `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`;
  } catch (e) {
    // Invalid URL, keep as is
  }

  return endpoint;
}

/**
 * Inject payload into different parts of the request
 * @param {Object} endpoint - Original endpoint
 * @param {string} payload - Payload to inject
 * @param {string} location - Where to inject ('query', 'body', 'header', 'path')
 * @returns {Array} Array of modified endpoints
 */
function injectPayload(endpoint, payload, location) {
  const injectedEndpoints = [];

  if (location === 'query' || location === 'all') {
    // Inject into existing query parameters
    Object.keys(endpoint.queryParams || {}).forEach(key => {
      const modified = JSON.parse(JSON.stringify(endpoint));
      modified.queryParams[key] = payload;
      modified.injectionPoint = `Query param: ${key}`;
      injectedEndpoints.push(modified);
    });

    // Always add payload as new query param for testing
    const modified = JSON.parse(JSON.stringify(endpoint));
    modified.queryParams = modified.queryParams || {};
    modified.queryParams['q'] = payload;
    modified.injectionPoint = 'Query param: q (injected)';
    injectedEndpoints.push(modified);
  }

  if (location === 'body' || location === 'all') {
    // Inject into existing body parameters
    if (endpoint.body && typeof endpoint.body === 'object') {
      Object.keys(endpoint.body).forEach(key => {
        const modified = JSON.parse(JSON.stringify(endpoint));
        modified.body[key] = payload;
        modified.injectionPoint = `Body param: ${key}`;
        injectedEndpoints.push(modified);
      });
    }
    
    // Always add a body injection for POST/PUT/PATCH
    if (['POST', 'PUT', 'PATCH'].includes(endpoint.method)) {
      const modified = JSON.parse(JSON.stringify(endpoint));
      modified.body = modified.body || {};
      if (typeof modified.body === 'object') {
        modified.body['input'] = payload;
      } else {
        modified.body = { input: payload };
      }
      modified.injectionPoint = 'Body param: input (injected)';
      injectedEndpoints.push(modified);
    }
  }

  if (location === 'header' || location === 'all') {
    // Inject into a test header
    const modified = JSON.parse(JSON.stringify(endpoint));
    modified.headers = modified.headers || {};
    modified.headers['X-Test-Input'] = payload;
    modified.injectionPoint = 'Header: X-Test-Input (injected)';
    injectedEndpoints.push(modified);
  }

  if (location === 'path' || location === 'all') {
    // Inject into URL path - add as path parameter
    const modified = JSON.parse(JSON.stringify(endpoint));
    const urlBase = modified.url.endsWith('/') ? modified.url : modified.url + '/';
    modified.url = urlBase + encodeURIComponent(payload);
    modified.injectionPoint = 'URL path (appended)';
    injectedEndpoints.push(modified);
  }

  // Ensure we always have at least one injection point
  if (injectedEndpoints.length === 0) {
    const modified = JSON.parse(JSON.stringify(endpoint));
    modified.queryParams = modified.queryParams || {};
    modified.queryParams['test'] = payload;
    modified.injectionPoint = 'Query param: test (fallback)';
    injectedEndpoints.push(modified);
  }

  return injectedEndpoints;
}

/**
 * Send HTTP request and measure response time
 * @param {Object} endpoint - Endpoint to test
 * @returns {Object} Response and timing info
 */
async function sendRequest(endpoint) {
  const startTime = Date.now();
  
  try {
    // Build URL with query params
    let url = endpoint.url;
    
    // Ensure URL has protocol
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    
    if (endpoint.queryParams && Object.keys(endpoint.queryParams).length > 0) {
      const separator = url.includes('?') ? '&' : '?';
      const params = new URLSearchParams(endpoint.queryParams);
      url = `${url}${separator}${params.toString()}`;
    }

    log(`Sending ${endpoint.method} request to: ${url}`);

    const config = {
      method: endpoint.method || 'GET',
      url: url,
      headers: {
        'User-Agent': 'API-Security-Scanner/1.0',
        'Accept': '*/*',
        ...endpoint.headers
      },
      timeout: 15000,
      validateStatus: () => true, // Accept any status code
      maxRedirects: 5
    };

    if (endpoint.body && ['POST', 'PUT', 'PATCH'].includes(endpoint.method)) {
      config.data = endpoint.body;
      if (!config.headers['Content-Type']) {
        config.headers['Content-Type'] = typeof endpoint.body === 'object' 
          ? 'application/json' 
          : 'application/x-www-form-urlencoded';
      }
    }

    const response = await axios(config);
    const endTime = Date.now();

    log(`Response received: ${response.status} in ${endTime - startTime}ms`);

    return {
      success: true,
      response: response,
      responseTime: endTime - startTime,
      error: null
    };
  } catch (error) {
    const endTime = Date.now();
    log(`Request error: ${error.message}`);
    
    // Even on error, we can learn from the response
    return {
      success: false,
      response: {
        status: error.response?.status || 0,
        data: error.response?.data || error.message,
        headers: error.response?.headers || {}
      },
      responseTime: endTime - startTime,
      error: error.code === 'ECONNREFUSED' 
        ? 'Connection refused - server may be down'
        : error.code === 'ETIMEDOUT'
        ? 'Request timed out'
        : error.message
    };
  }
}

/**
 * Get baseline response for an endpoint
 * @param {Object} endpoint - Endpoint to test
 * @returns {Object} Baseline response info
 */
async function getBaseline(endpoint) {
  const result = await sendRequest(endpoint);
  return {
    status: result.response.status,
    responseTime: result.responseTime,
    contentLength: result.response.headers?.['content-length'] || 0
  };
}

/**
 * Run security tests on a single endpoint
 * @param {Object} endpoint - Endpoint to test
 * @param {Object} options - Scan options
 * @returns {Object} Test results
 */
async function scanEndpoint(endpoint, options = {}) {
  log(`Starting scan for endpoint: ${endpoint.method} ${endpoint.url}`);
  
  const results = {
    api: endpoint.name || endpoint.url,
    method: endpoint.method,
    url: endpoint.url,
    tests: [],
    summary: {
      total: 0,
      passed: 0,
      failed: 0,
      errors: 0
    }
  };

  // Get baseline response
  let baseline = null;
  try {
    log('Getting baseline response...');
    baseline = await getBaseline(endpoint);
    log(`Baseline: status=${baseline.status}, time=${baseline.responseTime}ms`);
  } catch (e) {
    log(`Could not get baseline for ${endpoint.url}: ${e.message}`);
  }

  // Determine which scanners to use
  const scannersToUse = options.scanTypes && options.scanTypes.length > 0
    ? scanners.filter(s => options.scanTypes.includes(s.getType()))
    : scanners;

  log(`Using ${scannersToUse.length} scanners: ${scannersToUse.map(s => s.getType()).join(', ')}`);

  // Limit payloads if specified
  const maxPayloads = options.maxPayloads || 5;

  // Run each scanner
  for (const scanner of scannersToUse) {
    const payloads = scanner.getPayloads().slice(0, maxPayloads);
    log(`Running ${scanner.getType()} scanner with ${payloads.length} payloads`);
    
    for (const payload of payloads) {
      // Inject payload into different locations
      const injectedEndpoints = injectPayload(endpoint, payload, options.injectLocation || 'all');
      log(`Injecting payload into ${injectedEndpoints.length} locations`);

      // Test each injection point (limit to prevent too many requests)
      const endpointsToTest = injectedEndpoints.slice(0, 2);
      
      for (const injectedEndpoint of endpointsToTest) {
        results.summary.total++;
        log(`Test #${results.summary.total}: ${scanner.getType()} @ ${injectedEndpoint.injectionPoint}`);

        try {
          const requestStart = Date.now();
          const { response, responseTime, error, success } = await sendRequest(injectedEndpoint);
          
          log(`Response: status=${response?.status || 'N/A'}, time=${responseTime}ms, success=${success}`);

          // Create detailed test result
          const testResult = {
            type: scanner.getType(),
            severity: scanner.getSeverity(),
            payload: payload,
            injectionPoint: injectedEndpoint.injectionPoint,
            requestUrl: injectedEndpoint.url,
            requestMethod: injectedEndpoint.method,
            responseCode: response?.status || 0,
            responseTime: responseTime,
            responseSize: typeof response?.data === 'string' 
              ? response.data.length 
              : JSON.stringify(response?.data || '').length,
            responsePreview: truncateResponse(response?.data),
            testedAt: new Date().toISOString()
          };

          if (error && !success) {
            testResult.result = 'ERROR';
            testResult.notes = `Request failed: ${error}`;
            testResult.indicators = ['Request could not be completed'];
            results.tests.push(testResult);
            results.summary.errors++;
            continue;
          }

          // Analyze response for vulnerabilities
          const analysis = scanner.analyzeResponse(
            response, 
            payload, 
            baseline?.status,
            responseTime
          );

          testResult.result = analysis.vulnerable ? 'FAIL' : 'PASS';
          testResult.confidence = analysis.confidence || 'low';
          testResult.indicators = analysis.indicators || [];
          testResult.notes = analysis.notes || (analysis.vulnerable 
            ? 'Potential vulnerability detected based on response analysis'
            : 'No vulnerability indicators found in response');

          // Add baseline comparison info
          if (baseline) {
            testResult.baselineStatus = baseline.status;
            testResult.statusChanged = response.status !== baseline.status;
          }

          results.tests.push(testResult);

          if (analysis.vulnerable) {
            results.summary.failed++;
            log(`⚠️ VULNERABILITY FOUND: ${scanner.getType()} - ${payload.substring(0, 30)}...`);
          } else {
            results.summary.passed++;
          }

        } catch (error) {
          log(`Error during test: ${error.message}`);
          results.tests.push({
            type: scanner.getType(),
            severity: scanner.getSeverity(),
            payload: payload,
            injectionPoint: injectedEndpoint.injectionPoint,
            result: 'ERROR',
            responseCode: 0,
            responseTime: 0,
            notes: `Scan error: ${error.message}`,
            indicators: ['Test execution failed'],
            testedAt: new Date().toISOString()
          });
          results.summary.errors++;
        }

        // Small delay to avoid overwhelming target
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    }
  }

  log(`Scan complete for ${endpoint.url}: ${results.summary.total} tests, ${results.summary.failed} vulnerabilities`);
  return results;
}

/**
 * Truncate response for preview
 */
function truncateResponse(data) {
  if (!data) return '[No response body]';
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  if (str.length <= 200) return str;
  return str.substring(0, 200) + '... [truncated]';
}

/**
 * Run security scan on multiple endpoints
 * @param {Array} endpoints - Array of endpoints to scan
 * @param {Object} options - Scan options
 * @param {Function} progressCallback - Progress callback function
 * @returns {Object} Complete scan results
 */
async function runScan(endpoints, options = {}, progressCallback = null) {
  log(`\n${'='.repeat(60)}`);
  log('STARTING SECURITY SCAN');
  log(`${'='.repeat(60)}`);
  log(`Endpoints: ${endpoints.length}`);
  log(`Options: ${JSON.stringify(options)}`);
  
  const startTime = Date.now();
  const results = {
    scanId: require('uuid').v4(),
    timestamp: new Date().toISOString(),
    options: options,
    endpoints: [],
    summary: {
      totalEndpoints: endpoints.length,
      totalTests: 0,
      passed: 0,
      failed: 0,
      errors: 0,
      vulnerabilities: []
    }
  };

  for (let i = 0; i < endpoints.length; i++) {
    const endpoint = endpoints[i];
    log(`\n--- Scanning endpoint ${i + 1}/${endpoints.length}: ${endpoint.method} ${endpoint.url} ---`);
    
    if (progressCallback) {
      progressCallback({
        current: i + 1,
        total: endpoints.length,
        endpoint: endpoint.name || endpoint.url
      });
    }

    try {
      const endpointResults = await scanEndpoint(endpoint, options);
      results.endpoints.push(endpointResults);

      // Update summary
      results.summary.totalTests += endpointResults.summary.total;
      results.summary.passed += endpointResults.summary.passed;
      results.summary.failed += endpointResults.summary.failed;
      results.summary.errors += endpointResults.summary.errors;

      log(`Endpoint complete: ${endpointResults.summary.total} tests, ${endpointResults.summary.failed} vulnerabilities`);

      // Track vulnerabilities
      const vulns = endpointResults.tests.filter(t => t.result === 'FAIL');
      vulns.forEach(v => {
        results.summary.vulnerabilities.push({
          endpoint: endpointResults.api,
          type: v.type,
          severity: v.severity,
          payload: v.payload,
          confidence: v.confidence
        });
      });
    } catch (error) {
      log(`ERROR scanning endpoint: ${error.message}`);
      results.endpoints.push({
        api: endpoint.name || endpoint.url,
        method: endpoint.method,
        url: endpoint.url,
        error: error.message,
        tests: [],
        summary: { total: 0, passed: 0, failed: 0, errors: 1 }
      });
      results.summary.errors++;
    }
  }

  results.duration = Date.now() - startTime;
  
  log(`\n${'='.repeat(60)}`);
  log('SCAN COMPLETE');
  log(`Duration: ${results.duration}ms`);
  log(`Total Tests: ${results.summary.totalTests}`);
  log(`Passed: ${results.summary.passed}`);
  log(`Failed: ${results.summary.failed}`);
  log(`Errors: ${results.summary.errors}`);
  log(`${'='.repeat(60)}\n`);
  
  return results;
}

module.exports = {
  parsePostmanCollection,
  parseCurl,
  scanEndpoint,
  runScan,
  scanners,
  injectPayload,
  sendRequest
};

