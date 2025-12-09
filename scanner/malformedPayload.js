/**
 * Malformed Payload Scanner Module
 * Tests for improper input validation and error handling
 */

const payloads = {
  malformedPayloads: [
    // Invalid JSON
    '{ "name": 123,, "xyz": }',
    '{"unclosed": "string',
    '{name: "no quotes"}',
    '{"trailing": "comma",}',
    
    // Empty/Null payloads
    '',
    '{}',
    '[]',
    'null',
    
    // Type confusion
    '{"name": 12345}',
    '{"age": "twenty"}',
    '{"active": "yes"}',
    '{"items": "not-array"}',
    
    // Boundary values
    '{"count": -1}',
    '{"count": 999999999999}',
    '{"id": -999999}',
    
    // Special characters
    '{"name": "\\u0000\\u0001"}',
    '{"name": "test\\ninjection"}',
    
    // Unicode edge cases
    '{"name": "😀🎉🔥"}',
    '{"name": "中文测试"}',
    
    // Deeply nested
    '{"a":{"b":{"c":{"d":{"e":{"f":"deep"}}}}}}',
  ]
};

// Error patterns that indicate poor error handling
const verboseErrorPatterns = [
  /stack\s*trace/i,
  /at\s+\w+\s+\(/i,
  /exception/i,
  /error.*line\s*\d+/i,
  /syntax.*error/i,
  /undefined.*property/i,
  /cannot\s+read/i,
  /type.*error/i,
  /internal\s+server\s+error/i,
  /\.js:\d+:\d+/i,
  /node_modules/i,
];

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

  // Good: Server returns proper error codes for malformed data
  if (response.status === 400) {
    result.vulnerable = false;
    result.indicators.push('✅ Server returns 400 Bad Request for malformed data');
    result.notes = 'GOOD: Server properly validates input';
    
    // But check if error is too verbose
    for (const pattern of verboseErrorPatterns) {
      if (pattern.test(responseBody)) {
        result.indicators.push('⚠️ Error response contains verbose debug information');
        result.notes = 'WARNING: Error messages may leak implementation details';
        break;
      }
    }
    return result;
  }

  // Check for 500 errors (poor error handling)
  if (response.status === 500) {
    result.vulnerable = true;
    result.confidence = 'medium';
    result.indicators.push('⚠️ Server crashed with 500 error');
    result.notes = 'VULNERABLE: Malformed input causes server error';
    
    // Check for verbose errors
    for (const pattern of verboseErrorPatterns) {
      if (pattern.test(responseBody)) {
        result.confidence = 'high';
        result.indicators.push('⚠️ Stack trace or debug info exposed');
        result.notes = 'VULNERABLE: Server exposes internal error details';
        break;
      }
    }
    return result;
  }

  // Check for verbose error patterns in any response
  for (const pattern of verboseErrorPatterns) {
    if (pattern.test(responseBody)) {
      result.vulnerable = true;
      result.confidence = 'medium';
      result.indicators.push('⚠️ Verbose error information detected');
      result.notes = 'VULNERABLE: Server exposes implementation details';
      break;
    }
  }

  if (!result.vulnerable) {
    result.indicators.push('Server handled malformed payload gracefully');
    result.notes = `SAFE: Server responded with ${response.status}`;
  }

  return result;
}

function getPayloads() {
  return payloads.malformedPayloads;
}

function getType() {
  return 'Malformed Payload';
}

function getSeverity() {
  return 'Low';
}

module.exports = {
  getPayloads,
  analyzeResponse,
  getType,
  getSeverity
};

