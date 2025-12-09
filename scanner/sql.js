/**
 * SQL Injection Scanner Module
 * Tests for SQL injection vulnerabilities in API endpoints
 */

const payloads = require('./payloads');

// SQL error patterns that indicate potential vulnerability
const sqlErrorPatterns = [
  /sql syntax/i,
  /mysql_fetch/i,
  /mysql_num_rows/i,
  /mysql_query/i,
  /pg_query/i,
  /pg_exec/i,
  /sqlite_/i,
  /ORA-\d{5}/i,
  /Oracle error/i,
  /ODBC SQL Server Driver/i,
  /SQLServer JDBC Driver/i,
  /Microsoft OLE DB Provider/i,
  /Incorrect syntax near/i,
  /Unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /syntax error at or near/i,
  /unexpected end of SQL command/i,
  /invalid column name/i,
  /unknown column/i,
  /no such column/i,
  /column.*does not exist/i,
  /table.*doesn't exist/i,
  /no such table/i,
  /division by zero/i,
  /You have an error in your SQL syntax/i,
  /Warning.*mysql_/i,
  /valid MySQL result/i,
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /Warning.*sqlite_/i,
  /SQLite\/JDBCDriver/i,
  /SQLite.Exception/i,
  /System.Data.SQLite.SQLiteException/i,
  /SQLITE_ERROR/i,
  /SQL Server.*Driver/i,
  /SQL Server.*Error/i,
  /Access.*Driver/i,
  /Jet Database Engine/i,
  /Driver.*SQL[-_ ]*Server/i,
  /SQLSTATE/i,
  /psycopg2/i,
  /mysqli/i,
  /PDOException/i,
  /db2_/i,
  /ifx_/i,
  /sybase/i,
];

// Patterns indicating successful injection
const successPatterns = [
  /root:.*:0:0/i,  // passwd file content
  /admin.*password/i,
  /user.*password/i,
  /login.*success.*true/i,
  /authentication.*bypass/i,
];

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
    'invalid request',
    'request rejected'
  ];
  
  // 403 or 406 with WAF indicators = blocked
  if (status === 403 || status === 406 || status === 429) {
    if (wafIndicators.some(indicator => bodyLower.includes(indicator))) {
      return true;
    }
  }
  
  // Check for Cloudflare Ray ID
  if (bodyLower.includes('cloudflare ray id') || bodyLower.includes('cf-ray')) {
    return true;
  }
  
  return false;
}

/**
 * Analyze response for SQL injection indicators
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
    result.notes = 'PROTECTED: Web Application Firewall detected and blocked the SQL injection attempt. The application is secured by WAF.';
    return result;
  }

  // Check for 4xx error responses (generally safe - request rejected)
  if (response.status >= 400 && response.status < 500 && response.status !== 401) {
    result.vulnerable = false;
    result.indicators.push(`Request rejected with status ${response.status}`);
    result.notes = 'Request was rejected - server may have input validation';
    return result;
  }

  // Check for SQL error messages - indicates vulnerability
  for (const pattern of sqlErrorPatterns) {
    if (pattern.test(responseBody)) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ SQL error message detected in response');
      result.notes = `VULNERABLE: SQL error exposed - ${pattern.toString().slice(0, 50)}`;
      break;
    }
  }

  // Check for success patterns (data leakage)
  for (const pattern of successPatterns) {
    if (pattern.test(responseBody)) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ Potential data leakage detected');
      result.notes = `VULNERABLE: Sensitive data pattern found in response`;
      break;
    }
  }

  // Check for authentication bypass (unexpected 200 with auth-bypass payloads)
  if (payload.includes("OR '1'='1") || payload.includes('OR "1"="1')) {
    if (response.status === 200) {
      // Check if response suggests successful login/access
      if (/success|authenticated|welcome|token|session|jwt|bearer/i.test(responseBody)) {
        result.vulnerable = true;
        result.confidence = 'high';
        result.indicators.push('⚠️ Potential authentication bypass');
        result.notes = 'VULNERABLE: SQL injection payload resulted in successful authentication';
      }
    }
  }

  // Check for behavior change from baseline
  if (originalStatus !== null && response.status !== originalStatus) {
    if (response.status === 200 && originalStatus >= 400) {
      result.vulnerable = true;
      result.confidence = 'medium';
      result.indicators.push('⚠️ Status code changed from error to success');
      result.notes = 'SUSPICIOUS: Injection changed response from error to success';
    }
  }

  // If no vulnerability found, mark as safe
  if (!result.vulnerable) {
    result.indicators.push('No SQL injection indicators found');
    result.notes = 'SAFE: No SQL error messages or injection indicators detected in response';
  }

  // Check for verbose error messages (information disclosure - lower severity)
  if (/stack trace|exception|error.*line \d+/i.test(responseBody)) {
    result.indicators.push('ℹ️ Verbose error messages detected (info disclosure)');
  }

  return result;
}

/**
 * Get SQL injection payloads
 * @returns {Array} Array of SQL injection payloads
 */
function getPayloads() {
  return payloads.sqlInjection;
}

/**
 * Get vulnerability type name
 * @returns {string} Vulnerability type
 */
function getType() {
  return 'SQL Injection';
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
  sqlErrorPatterns,
  successPatterns
};

