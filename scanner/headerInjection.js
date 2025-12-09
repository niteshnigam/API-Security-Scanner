/**
 * Header Injection / Manipulation Scanner Module
 * Tests for header-based vulnerabilities
 */

const payloads = {
  headerInjection: [
    // XSS in Headers
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    
    // SQL Injection in Headers
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "7.0.1; DROP TABLE users",
    
    // CRLF Injection (HTTP Response Splitting)
    'test\r\nSet-Cookie: malicious=value',
    'test%0d%0aSet-Cookie: evil=true',
    '%0d%0aLocation: http://evil.com',
    
    // Host Header Injection values
    'evil.com',
    '127.0.0.1',
    'localhost',
  ]
};

function isWAFBlocked(response, responseBody) {
  const status = response.status;
  const bodyLower = responseBody.toLowerCase();
  
  const wafIndicators = [
    'you have been blocked', 'access denied', 'forbidden', 'firewall',
    'cloudflare', 'waf', 'attack detected', 'malicious'
  ];
  
  if (status === 403 || status === 406 || status === 429) {
    if (wafIndicators.some(ind => bodyLower.includes(ind))) return true;
  }
  if (bodyLower.includes('cloudflare ray id')) return true;
  return false;
}

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

  // Check WAF
  if (isWAFBlocked(response, responseBody)) {
    result.indicators.push('✅ WAF/Firewall blocked the request');
    result.notes = 'PROTECTED: Header manipulation was blocked';
    return result;
  }

  // Check for CRLF injection (response splitting)
  if (payload.includes('%0d%0a') || payload.includes('\r\n')) {
    const setCookie = responseHeaders['set-cookie'];
    if (setCookie && (setCookie.includes('malicious') || setCookie.includes('evil'))) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ CRLF Injection - Response splitting successful');
      result.notes = 'VULNERABLE: Attacker can inject arbitrary headers';
    }
  }

  // Check for XSS reflection from headers
  if (payload.includes('<script>') || payload.includes('onerror=')) {
    if (responseBody.includes(payload)) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ Header value reflected in response (XSS)');
      result.notes = 'VULNERABLE: Header value reflected without sanitization';
    }
  }

  // Check for Host header injection
  if (payload === 'evil.com' || payload.includes('127.0.0.1')) {
    if (responseBody.includes(payload)) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ Host header value reflected in response');
      result.notes = 'VULNERABLE: Host header is used unsafely in response';
    }
  }

  if (!result.vulnerable) {
    result.indicators.push('Header injection payload rejected or not reflected');
    result.notes = 'SAFE: No header injection vulnerabilities detected';
  }

  return result;
}

function getPayloads() {
  return payloads.headerInjection;
}

function getType() {
  return 'Header Injection';
}

function getSeverity() {
  return 'High';
}

module.exports = {
  getPayloads,
  analyzeResponse,
  getType,
  getSeverity
};

