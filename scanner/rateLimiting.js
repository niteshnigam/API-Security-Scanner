/**
 * Rate Limiting / Bot Simulation Scanner Module
 * Tests for rate limiting and anti-bot protection
 */

function isWAFBlocked(response, responseBody) {
  const status = response.status;
  const bodyLower = responseBody.toLowerCase();
  
  const wafIndicators = [
    'you have been blocked', 'access denied', 'forbidden', 'firewall',
    'cloudflare', 'waf', 'rate limit', 'too many requests', 'throttle',
    'slow down', 'try again later'
  ];
  
  if (status === 403 || status === 429 || status === 503) {
    return true;
  }
  if (wafIndicators.some(ind => bodyLower.includes(ind))) {
    return true;
  }
  return false;
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

  // Check if rate limiting kicked in
  if (response.status === 429) {
    result.vulnerable = false;
    result.confidence = 'high';
    result.indicators.push('✅ Rate limiting is active (429 Too Many Requests)');
    result.notes = 'PROTECTED: Server properly implements rate limiting';
    return result;
  }

  // Check WAF/Bot protection
  if (isWAFBlocked(response, responseBody)) {
    result.vulnerable = false;
    result.confidence = 'high';
    result.indicators.push('✅ Bot/DDoS protection is active');
    result.notes = 'PROTECTED: Server has anti-bot/rate limiting measures';
    return result;
  }

  // Check for rate limit headers
  const rateLimitHeaders = [
    'x-ratelimit-limit',
    'x-ratelimit-remaining',
    'x-ratelimit-reset',
    'retry-after',
    'x-rate-limit-limit',
    'ratelimit-limit'
  ];

  const foundRateLimitHeaders = rateLimitHeaders.filter(h => 
    response.headers && response.headers[h.toLowerCase()]
  );

  if (foundRateLimitHeaders.length > 0) {
    result.indicators.push(`ℹ️ Rate limit headers present: ${foundRateLimitHeaders.join(', ')}`);
    
    const remaining = response.headers['x-ratelimit-remaining'] || 
                      response.headers['x-rate-limit-remaining'];
    if (remaining !== undefined) {
      result.indicators.push(`Remaining requests: ${remaining}`);
    }
    result.notes = 'INFO: Rate limiting headers detected - server may have protection';
  } else if (response.status === 200) {
    result.indicators.push('⚠️ No rate limit headers in response');
    result.notes = 'WARNING: Consider implementing rate limiting for this endpoint';
  }

  return result;
}

function getPayloads() {
  // Simple payloads - actual rate limit testing happens at scan level
  return ['rate_limit_test_1', 'rate_limit_test_2', 'rate_limit_test_3'];
}

function getType() {
  return 'Rate Limiting';
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

