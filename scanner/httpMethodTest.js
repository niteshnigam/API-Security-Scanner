/**
 * HTTP Method Testing Scanner Module
 * Tests for improper HTTP method handling
 */

const payloads = {
  httpMethods: [
    'TRACE',
    'OPTIONS', 
    'PUT',
    'DELETE',
    'PATCH',
    'CONNECT',
    'PROPFIND',
    'DEBUG',
  ]
};

function analyzeResponse(response, payload, originalStatus = null) {
  const result = {
    vulnerable: false,
    confidence: 'low',
    indicators: [],
    notes: ''
  };

  const responseBody = typeof response.data === 'string' 
    ? response.data 
    : JSON.stringify(response.data || '');
  const responseHeaders = response.headers || {};
  
  const testedMethod = payload;

  // Check for proper method rejection (405 Method Not Allowed)
  if (response.status === 405) {
    result.vulnerable = false;
    result.indicators.push(`✅ Server properly rejects ${testedMethod} with 405`);
    result.notes = 'GOOD: Server enforces allowed HTTP methods';
    
    // Check for Allow header
    if (responseHeaders['allow']) {
      result.indicators.push(`Allowed methods: ${responseHeaders['allow']}`);
    }
    return result;
  }

  // Check for TRACE/TRACK (Cross-Site Tracing vulnerability)
  if (testedMethod === 'TRACE' || testedMethod === 'TRACK') {
    if (response.status === 200) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push(`⚠️ ${testedMethod} method is enabled`);
      result.notes = 'VULNERABLE: TRACE enabled - Cross-Site Tracing (XST) possible';
      return result;
    }
  }

  // Check for OPTIONS response (info disclosure)
  if (testedMethod === 'OPTIONS') {
    if (response.status === 200 || response.status === 204) {
      result.indicators.push('ℹ️ OPTIONS method is allowed');
      
      if (responseHeaders['allow']) {
        result.indicators.push(`Allowed: ${responseHeaders['allow']}`);
        
        // Check for dangerous methods in Allow header
        const dangerousMethods = ['TRACE', 'TRACK', 'DEBUG'];
        const allowedDangerous = dangerousMethods.filter(m => 
          responseHeaders['allow'].toUpperCase().includes(m)
        );
        
        if (allowedDangerous.length > 0) {
          result.vulnerable = true;
          result.confidence = 'medium';
          result.indicators.push(`⚠️ Dangerous methods allowed: ${allowedDangerous.join(', ')}`);
          result.notes = 'WARNING: Review allowed HTTP methods';
        }
      }
      
      result.notes = result.notes || 'INFO: OPTIONS reveals allowed methods';
    }
  }

  // Check for WebDAV methods being enabled
  const webdavMethods = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE'];
  if (webdavMethods.includes(testedMethod)) {
    if (response.status === 200 || response.status === 207) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push(`⚠️ WebDAV method ${testedMethod} is enabled`);
      result.notes = 'VULNERABLE: WebDAV methods should be disabled';
    }
  }

  // Check for DEBUG method
  if (testedMethod === 'DEBUG' && response.status === 200) {
    result.vulnerable = true;
    result.confidence = 'high';
    result.indicators.push('⚠️ DEBUG method is enabled');
    result.notes = 'VULNERABLE: Debug endpoint exposed';
  }

  // Default - method was rejected or handled safely
  if (!result.indicators.length) {
    result.indicators.push(`${testedMethod} method returned ${response.status}`);
    result.notes = 'SAFE: Server handled HTTP method appropriately';
  }

  return result;
}

function getPayloads() {
  return payloads.httpMethods;
}

function getType() {
  return 'HTTP Method';
}

function getSeverity() {
  return 'Medium';
}

module.exports = {
  getPayloads,
  analyzeResponse,
  getType,
  getSeverity
};

