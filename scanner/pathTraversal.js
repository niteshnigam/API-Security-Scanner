/**
 * Path Traversal Scanner Module
 * Tests for path traversal / LFI vulnerabilities in API endpoints
 */

const payloads = require('./payloads');

// Patterns indicating successful path traversal
const fileContentPatterns = [
  // Unix system files
  /root:.*:0:0:/,  // /etc/passwd
  /daemon:.*:1:1:/,
  /nobody:.*:65534:/,
  /shadow:.*:\*:/,
  /bin\/bash/,
  /bin\/sh/,
  /localhost/,  // /etc/hosts
  /127\.0\.0\.1/,
  /nameserver/,  // /etc/resolv.conf
  /\[global\]/i,  // Samba config
  
  // Windows system files
  /\[boot loader\]/i,  // boot.ini
  /\[operating systems\]/i,
  /\[fonts\]/i,  // win.ini
  /\[extensions\]/i,
  /\[Mail\]/i,
  /; for 16-bit app support/i,  // system.ini
  /\[drivers\]/i,
  /\[386Enh\]/i,
  /MSDOS\.SYS/i,
  /IO\.SYS/i,
  
  // Common config files
  /DB_PASSWORD/i,
  /DB_HOST/i,
  /API_KEY/i,
  /SECRET_KEY/i,
  /AWS_ACCESS/i,
  /MYSQL_PASSWORD/i,
  /POSTGRES_PASSWORD/i,
  
  // Application files
  /<?php/,
  /<?xml/,
  /<\?xml version/,
  /<!DOCTYPE/,
  /package\.json/,
  /"dependencies"/,
  /"devDependencies"/,
];

// Error patterns that indicate path traversal attempts are being processed
const errorPatterns = [
  /No such file or directory/i,
  /File not found/i,
  /Cannot find the file/i,
  /Access denied/i,
  /Permission denied/i,
  /failed to open stream/i,
  /include\(\): Failed opening/i,
  /require\(\): Failed opening/i,
  /fopen\(\): failed/i,
  /file_get_contents\(\): failed/i,
  /is not a valid path/i,
  /Invalid file path/i,
  /Directory traversal/i,
  /Path traversal/i,
];

// Null byte injection indicators
const nullBytePatterns = [
  /%00/,
  /\x00/,
  /\\x00/,
  /\\0/,
];

/**
 * Check if response is from a WAF/firewall blocking the request
 */
function isWAFBlocked(response, responseBody) {
  const status = response.status;
  const bodyLower = responseBody.toLowerCase();
  
  const wafIndicators = [
    'you have been blocked', 'access denied', 'forbidden', 'request blocked',
    'firewall', 'cloudflare', 'akamai', 'imperva', 'waf', 'attack detected',
    'malicious request', 'path traversal', 'directory traversal', 'invalid request'
  ];
  
  if (status === 403 || status === 406 || status === 429) {
    if (wafIndicators.some(indicator => bodyLower.includes(indicator))) {
      return true;
    }
  }
  
  if (bodyLower.includes('cloudflare ray id')) return true;
  return false;
}

/**
 * Analyze response for path traversal indicators
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

  // FIRST: Check for WAF blocking
  if (isWAFBlocked(response, responseBody)) {
    result.vulnerable = false;
    result.confidence = 'high';
    result.indicators.push('✅ WAF/Firewall blocked the malicious request');
    result.notes = 'PROTECTED: WAF detected and blocked the path traversal attempt.';
    return result;
  }

  // Check for 4xx errors (request rejected)
  if (response.status === 400 || response.status === 403 || response.status === 404) {
    result.vulnerable = false;
    result.indicators.push(`Request rejected/not found with status ${response.status}`);
    result.notes = 'SAFE: Path traversal was blocked or file not found';
    return result;
  }

  // Check for system file contents - REAL VULNERABILITY
  for (const pattern of fileContentPatterns) {
    if (pattern.test(responseBody)) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ System/config file content detected');
      result.notes = `VULNERABLE: System file content found - ${pattern.toString().slice(0, 50)}`;
      break;
    }
  }

  // Check for traversal error messages (information disclosure)
  for (const pattern of errorPatterns) {
    if (pattern.test(responseBody)) {
      if (!result.vulnerable) {
        result.indicators.push('ℹ️ Path-related error message detected');
        result.notes = 'INFO: Error messages may indicate file system interaction';
      }
      break;
    }
  }

  // Check for binary content (potential file disclosure)
  const contentType = response.headers['content-type'] || '';
  if (response.status === 200 && (
      contentType.includes('octet-stream') || 
      contentType.includes('application/pdf') ||
      contentType.includes('image/'))) {
    result.vulnerable = true;
    result.confidence = 'medium';
    result.indicators.push('⚠️ Binary file content returned');
    result.notes = 'SUSPICIOUS: Binary content returned - possible file disclosure';
  }

  // Behavior change detection
  if (originalStatus !== null) {
    if (response.status === 200 && originalStatus === 404) {
      result.vulnerable = true;
      result.confidence = 'medium';
      result.indicators.push('⚠️ File found after path traversal');
      result.notes = 'VULNERABLE: Traversal payload changed 404 to 200';
    }
  }

  // If no vulnerability found
  if (!result.vulnerable) {
    result.indicators.push('No path traversal indicators found');
    result.notes = 'SAFE: No system file content detected in response';
  }

  return result;
}

/**
 * Get path traversal payloads
 * @returns {Array} Array of path traversal payloads
 */
function getPayloads() {
  return payloads.pathTraversal;
}

/**
 * Get vulnerability type name
 * @returns {string} Vulnerability type
 */
function getType() {
  return 'Path Traversal';
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
  fileContentPatterns
};

