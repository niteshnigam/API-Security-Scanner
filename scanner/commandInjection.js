/**
 * Command Injection Scanner Module
 * Tests for OS command injection vulnerabilities in API endpoints
 */

const payloads = require('./payloads');

// Patterns indicating command execution
const commandOutputPatterns = [
  // Unix patterns
  /root:.*:0:0:/i,  // /etc/passwd content
  /bin\/bash/i,
  /bin\/sh/i,
  /nobody:.*:65534/i,
  /daemon:.*:1:1/i,
  /uid=\d+.*gid=\d+/i,  // id command output
  /Linux.*\d+\.\d+\.\d+/i,  // uname output
  /total \d+\s+drwx/i,  // ls -la output
  /drwxr-xr-x/i,  // directory listing
  /-rw-r--r--/i,  // file listing
  /\/home\/\w+/i,  // home directory
  /\/usr\/bin/i,
  /\/var\/log/i,
  
  // Windows patterns
  /Volume Serial Number/i,
  /Directory of/i,
  /\d{2}\/\d{2}\/\d{4}/i,  // Windows date format in dir
  /Windows IP Configuration/i,
  /Ethernet adapter/i,
  /C:\\Windows/i,
  /C:\\Users/i,
  /Program Files/i,
  /SYSTEM32/i,
  /\[boot loader\]/i,  // boot.ini
  /\[operating systems\]/i,
  /\[fonts\]/i,  // win.ini
  /\[extensions\]/i,
  /COMPUTERNAME=/i,
  /USERNAME=/i,
  /USERDOMAIN=/i,
  
  // Command error patterns that still indicate execution
  /command not found/i,
  /not recognized as an internal or external command/i,
  /No such file or directory/i,
  /Permission denied/i,
  /Access is denied/i,
  /cannot find the path/i,
  /is not recognized as a cmdlet/i,
];

// Time-based detection patterns
const timingKeywords = ['sleep', 'WAITFOR', 'ping -c', 'ping -n'];

/**
 * Check if response is from a WAF/firewall blocking the request
 */
function isWAFBlocked(response, responseBody) {
  const status = response.status;
  const bodyLower = responseBody.toLowerCase();
  
  const wafIndicators = [
    'you have been blocked', 'access denied', 'forbidden', 'request blocked',
    'firewall', 'cloudflare', 'akamai', 'imperva', 'waf', 'attack detected',
    'malicious request', 'command injection', 'invalid request'
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
 * Analyze response for command injection indicators
 * @param {Object} response - Axios response object
 * @param {string} payload - The payload that was sent
 * @param {number} originalStatus - Original response status (baseline)
 * @param {number} responseTime - Response time in milliseconds
 * @returns {Object} Analysis result
 */
function analyzeResponse(response, payload, originalStatus = null, responseTime = null) {
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
    result.notes = 'PROTECTED: WAF detected and blocked the command injection attempt.';
    return result;
  }

  // Check for 4xx errors (request rejected)
  if (response.status >= 400 && response.status < 500) {
    result.vulnerable = false;
    result.indicators.push(`Request rejected with status ${response.status}`);
    result.notes = 'Request was rejected - input validation may be in place';
    return result;
  }

  // Check for command output patterns - REAL VULNERABILITY
  for (const pattern of commandOutputPatterns) {
    if (pattern.test(responseBody)) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ Command output detected in response');
      result.notes = `VULNERABLE: System command output found - ${pattern.toString().slice(0, 50)}`;
      break;
    }
  }

  // Check for time-based injection
  if (responseTime !== null) {
    const isTimingPayload = timingKeywords.some(kw => 
      payload.toLowerCase().includes(kw.toLowerCase())
    );
    
    if (isTimingPayload && responseTime > 4500) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ Time-based command injection detected');
      result.notes = `VULNERABLE: Response delayed by ${responseTime}ms - command executed`;
    }
  }

  // Check for command error messages (indicates command was attempted)
  const errorPatterns = [
    /sh: .*: not found/i,
    /bash: .*: command not found/i,
    /cmd\.exe.*is not recognized/i,
    /\/bin\/.*: No such file/i,
    /cannot execute binary file/i,
    /syntax error near unexpected token/i,
  ];

  for (const pattern of errorPatterns) {
    if (pattern.test(responseBody)) {
      result.vulnerable = true;
      result.confidence = 'medium';
      result.indicators.push('⚠️ Shell error message in response');
      result.notes = 'VULNERABLE: Shell error indicates command was processed';
      break;
    }
  }

  // If no vulnerability found
  if (!result.vulnerable) {
    result.indicators.push('No command injection indicators found');
    result.notes = 'SAFE: No command execution indicators detected in response';
  }

  return result;
}

/**
 * Get command injection payloads
 * @returns {Array} Array of command injection payloads
 */
function getPayloads() {
  return payloads.commandInjection;
}

/**
 * Get vulnerability type name
 * @returns {string} Vulnerability type
 */
function getType() {
  return 'Command Injection';
}

/**
 * Get severity level
 * @returns {string} Severity level
 */
function getSeverity() {
  return 'Critical';
}

module.exports = {
  getPayloads,
  analyzeResponse,
  getType,
  getSeverity,
  commandOutputPatterns
};

