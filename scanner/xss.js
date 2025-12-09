/**
 * XSS (Cross-Site Scripting) Scanner Module
 * Tests for XSS vulnerabilities in API endpoints
 */

const payloads = require('./payloads');

// Patterns indicating XSS vulnerability (payload reflection)
const reflectionPatterns = [
  /<script[^>]*>.*<\/script>/gi,
  /<img[^>]*onerror[^>]*>/gi,
  /<svg[^>]*onload[^>]*>/gi,
  /<body[^>]*onload[^>]*>/gi,
  /<input[^>]*onfocus[^>]*>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,  // Event handlers
  /<iframe[^>]*>/gi,
  /<object[^>]*>/gi,
  /<embed[^>]*>/gi,
  /<link[^>]*>/gi,
  /<meta[^>]*http-equiv/gi,
];

// Dangerous patterns that should be escaped
const dangerousPatterns = [
  '<script>',
  '</script>',
  'javascript:',
  'onerror=',
  'onload=',
  'onclick=',
  'onmouseover=',
  'onfocus=',
  'onblur=',
  '<img',
  '<svg',
  '<iframe',
];

/**
 * Check if payload is reflected in response
 * @param {string} responseBody - Response body
 * @param {string} payload - Original payload
 * @returns {boolean} Whether payload is reflected
 */
function isPayloadReflected(responseBody, payload) {
  // Check exact reflection
  if (responseBody.includes(payload)) {
    return true;
  }

  // Check for decoded reflection (URL encoded payloads)
  try {
    const decoded = decodeURIComponent(payload);
    if (responseBody.includes(decoded)) {
      return true;
    }
  } catch (e) {
    // Invalid encoding, skip
  }

  // Check for HTML entity decoded reflection
  const htmlDecoded = payload
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
  
  if (responseBody.includes(htmlDecoded)) {
    return true;
  }

  return false;
}

/**
 * Check if dangerous content is present unescaped
 * @param {string} responseBody - Response body
 * @param {string} payload - Original payload
 * @returns {Object} Analysis of dangerous content
 */
function checkDangerousContent(responseBody, payload) {
  const found = [];
  
  for (const pattern of dangerousPatterns) {
    if (payload.toLowerCase().includes(pattern.toLowerCase())) {
      // Check if the dangerous pattern exists unescaped in response
      if (responseBody.toLowerCase().includes(pattern.toLowerCase())) {
        found.push(pattern);
      }
    }
  }

  return found;
}

/**
 * Check if response is from a WAF/firewall blocking the request
 * @param {Object} response - Response object
 * @param {string} responseBody - Response body as string
 * @returns {boolean} True if WAF blocked the request
 */
function isWAFBlocked(response, responseBody) {
  const status = response.status;
  const bodyLower = responseBody.toLowerCase();
  
  // Common WAF block indicators
  const wafIndicators = [
    'you have been blocked',
    'access denied',
    'forbidden',
    'request blocked',
    'security block',
    'firewall',
    'cloudflare',
    'akamai',
    'imperva',
    'incapsula',
    'sucuri',
    'mod_security',
    'web application firewall',
    'waf',
    'attack detected',
    'malicious request',
    'sql injection',
    'cross-site scripting',
    'xss detected',
    'invalid request',
    'request rejected'
  ];
  
  // 403 or 406 with WAF indicators = blocked
  if (status === 403 || status === 406 || status === 429) {
    if (wafIndicators.some(indicator => bodyLower.includes(indicator))) {
      return true;
    }
  }
  
  // Check for Cloudflare Ray ID (specific to Cloudflare WAF)
  if (bodyLower.includes('cloudflare ray id') || bodyLower.includes('cf-ray')) {
    return true;
  }
  
  return false;
}

/**
 * Analyze response for XSS indicators
 * @param {Object} response - Axios response object
 * @param {string} payload - The payload that was sent
 * @param {number} originalStatus - Original response status (baseline)
 * @returns {Object} Analysis result
 */
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

  // FIRST: Check if WAF/Firewall blocked the request - this means PROTECTED!
  if (isWAFBlocked(response, responseBody)) {
    result.vulnerable = false;
    result.confidence = 'high';
    result.indicators.push('✅ WAF/Firewall blocked the malicious request');
    result.indicators.push(`Response status: ${response.status}`);
    result.notes = 'PROTECTED: Web Application Firewall detected and blocked the XSS attempt. The application is secured by WAF.';
    return result;
  }

  // Check for 4xx/5xx error responses (not vulnerable, request was rejected)
  if (response.status >= 400 && response.status < 600) {
    // Error response - check if it's a security rejection
    const errorIndicators = ['invalid', 'error', 'bad request', 'not allowed', 'rejected'];
    if (errorIndicators.some(ind => responseBody.toLowerCase().includes(ind))) {
      result.vulnerable = false;
      result.indicators.push(`Request rejected with status ${response.status}`);
      result.notes = 'Request was rejected by the server - input validation may be in place';
      return result;
    }
  }

  // Check for direct payload reflection - THE KEY CHECK
  if (isPayloadReflected(responseBody, payload)) {
    // Check if it's reflected in a dangerous context
    const dangerousContent = checkDangerousContent(responseBody, payload);
    
    if (dangerousContent.length > 0) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ Payload reflected without sanitization');
      result.indicators.push(`Dangerous content found: ${dangerousContent.join(', ')}`);
      result.notes = 'VULNERABLE: XSS payload was reflected in the response without proper encoding. This could allow script execution.';
    } else {
      result.vulnerable = true;
      result.confidence = 'medium';
      result.indicators.push('Payload reflected in response');
      result.notes = 'Payload found in response - verify if properly escaped in browser context';
    }
  } else {
    // Payload NOT reflected - this is safe
    result.vulnerable = false;
    result.indicators.push('Payload was not reflected in response');
    result.notes = 'SAFE: The XSS payload was not reflected in the server response';
  }

  // Only check for dangerous patterns if we haven't already determined safety
  // AND only if these patterns match the actual payload we sent
  if (!result.vulnerable && response.status === 200) {
    // Check if exact payload appears in response
    const exactPayloadInResponse = responseBody.includes(payload);
    if (exactPayloadInResponse) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ Exact payload found in 200 OK response');
      result.notes = 'VULNERABLE: The exact XSS payload appears in a successful response';
    }
  }

  // Check for missing security headers (informational only, not vulnerability)
  const securityHeaders = {
    'x-xss-protection': response.headers['x-xss-protection'],
    'content-security-policy': response.headers['content-security-policy'],
    'x-content-type-options': response.headers['x-content-type-options']
  };

  const missingHeaders = Object.entries(securityHeaders)
    .filter(([, value]) => !value)
    .map(([key]) => key);

  if (missingHeaders.length > 0 && result.vulnerable) {
    result.indicators.push(`Missing security headers: ${missingHeaders.join(', ')}`);
  }

  return result;
}

/**
 * Get XSS payloads
 * @returns {Array} Array of XSS payloads
 */
function getPayloads() {
  return payloads.xss;
}

/**
 * Get vulnerability type name
 * @returns {string} Vulnerability type
 */
function getType() {
  return 'XSS';
}

/**
 * Get severity level
 * @returns {string} Severity level
 */
function getSeverity() {
  return 'High';
}

module.exports = {
  getPayloads,
  analyzeResponse,
  getType,
  getSeverity,
  isPayloadReflected,
  checkDangerousContent
};

