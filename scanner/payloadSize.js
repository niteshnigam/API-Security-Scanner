/**
 * Payload Size / Buffer Overflow Scanner Module
 * Tests for input size limits and buffer handling
 */

function generateLargePayload(size) {
  return 'A'.repeat(size);
}

const payloads = {
  sizeTests: [
    // These represent different size tests
    '500_chars',
    '1000_chars', 
    '5000_chars',
    '10000_chars',
    '50000_chars',
  ]
};

// Get actual payload value based on size description
function getPayloadValue(sizeDesc) {
  const sizeMap = {
    '500_chars': generateLargePayload(500),
    '1000_chars': generateLargePayload(1000),
    '5000_chars': generateLargePayload(5000),
    '10000_chars': generateLargePayload(10000),
    '50000_chars': generateLargePayload(50000),
  };
  return JSON.stringify({ data: sizeMap[sizeDesc] || generateLargePayload(1000) });
}

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

  // Check for proper size limit rejection
  if (response.status === 413) {
    result.vulnerable = false;
    result.indicators.push('✅ Server returns 413 Payload Too Large');
    result.notes = 'GOOD: Server enforces payload size limits';
    return result;
  }

  // Check for 400 Bad Request (also acceptable)
  if (response.status === 400) {
    result.vulnerable = false;
    result.indicators.push('✅ Server rejects oversized payload with 400');
    result.notes = 'GOOD: Server validates input size';
    return result;
  }

  // Check for timeout
  if (response.status === 408 || response.status === 504) {
    result.vulnerable = true;
    result.confidence = 'medium';
    result.indicators.push('⚠️ Request timed out with large payload');
    result.notes = 'VULNERABLE: Large payloads may cause DoS';
    return result;
  }

  // Check for server crash (500)
  if (response.status === 500 || response.status === 502 || response.status === 503) {
    result.vulnerable = true;
    result.confidence = 'high';
    result.indicators.push('⚠️ Server error with large payload');
    result.notes = 'VULNERABLE: Large payload causes server error - DoS vector';
    return result;
  }

  // Check for slow response (potential DoS)
  if (responseTime && responseTime > 10000) {
    result.vulnerable = true;
    result.confidence = 'medium';
    result.indicators.push(`⚠️ Very slow response: ${responseTime}ms`);
    result.notes = 'VULNERABLE: Large payloads cause significant slowdown';
  } else if (responseTime && responseTime > 5000) {
    result.indicators.push(`ℹ️ Slow response: ${responseTime}ms`);
    result.notes = 'WARNING: Large payloads cause noticeable slowdown';
  }

  // If 200 OK with large payload
  if (response.status === 200) {
    result.indicators.push(`Server accepted ${payload} payload`);
    result.notes = 'SAFE: Server handled large payload';
  }

  return result;
}

function getPayloads() {
  return payloads.sizeTests;
}

function getType() {
  return 'Payload Size';
}

function getSeverity() {
  return 'Medium';
}

module.exports = {
  getPayloads,
  analyzeResponse,
  getType,
  getSeverity,
  getPayloadValue
};

