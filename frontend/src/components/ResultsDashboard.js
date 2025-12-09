import React, { useState, useMemo, useEffect } from 'react';
import './ResultsDashboard.css';

function ResultsDashboard({ results, downloadResults, onNewScan }) {
  const [selectedEndpoint, setSelectedEndpoint] = useState(0); // Default open first
  const [filter, setFilter] = useState('all'); // 'all', 'failed', 'passed'
  const [typeFilter, setTypeFilter] = useState('all');
  const [expandedTests, setExpandedTests] = useState({});
  
  // Auto-expand first endpoint on load
  useEffect(() => {
    if (results?.endpoints?.length > 0) {
      setSelectedEndpoint(0);
    }
  }, [results]);

  // Calculate statistics
  const stats = useMemo(() => {
    const vulnBySeverity = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    };

    const vulnByType = {};
    
    results.summary.vulnerabilities.forEach(v => {
      vulnBySeverity[v.severity] = (vulnBySeverity[v.severity] || 0) + 1;
      vulnByType[v.type] = (vulnByType[v.type] || 0) + 1;
    });

    return {
      ...results.summary,
      vulnBySeverity,
      vulnByType,
      successRate: results.summary.totalTests > 0 
        ? ((results.summary.passed / results.summary.totalTests) * 100).toFixed(1)
        : 0
    };
  }, [results]);

  // Filter endpoints
  const filteredEndpoints = useMemo(() => {
    return results.endpoints.filter(ep => {
      if (filter === 'failed') return ep.summary?.failed > 0;
      if (filter === 'passed') return ep.summary?.failed === 0;
      return true;
    });
  }, [results.endpoints, filter]);

  // Get unique vulnerability types
  const vulnTypes = useMemo(() => {
    const types = new Set();
    results.endpoints.forEach(ep => {
      ep.tests?.forEach(t => types.add(t.type));
    });
    return ['all', ...Array.from(types)];
  }, [results.endpoints]);

  const toggleTestExpand = (testId) => {
    setExpandedTests(prev => ({
      ...prev,
      [testId]: !prev[testId]
    }));
  };

  const getSeverityColor = (severity) => {
    const colors = {
      Critical: '#ff1744',
      High: '#f72585',
      Medium: '#ffab00',
      Low: '#00b0ff'
    };
    return colors[severity] || '#9090a8';
  };

  const formatDuration = (ms) => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  return (
    <div className="results-dashboard animate-fadeIn">
      {/* Header Actions */}
      <div className="results-header">
        <div className="results-title">
          <h2>
            <span>📊</span> Scan Results
          </h2>
          <p className="scan-meta">
            Scan ID: {results.scanId?.slice(0, 8)} | 
            Duration: {formatDuration(results.duration)} | 
            {new Date(results.timestamp).toLocaleString()}
          </p>
        </div>
        <div className="results-actions">
          <button className="btn btn-secondary" onClick={downloadResults}>
            <span>📥</span> Download JSON
          </button>
          <button className="btn btn-primary" onClick={onNewScan}>
            <span>🔄</span> New Scan
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>
            {stats.totalEndpoints}
          </div>
          <div className="stat-label">Endpoints Tested</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>
            {stats.totalTests}
          </div>
          <div className="stat-label">Total Tests</div>
        </div>
        <div className="stat-card success">
          <div className="stat-value" style={{ color: 'var(--success)' }}>
            {stats.passed}
          </div>
          <div className="stat-label">Passed</div>
        </div>
        <div className="stat-card danger">
          <div className="stat-value" style={{ color: 'var(--danger)' }}>
            {stats.failed}
          </div>
          <div className="stat-label">Vulnerabilities Found</div>
        </div>
      </div>

      {/* Vulnerability Breakdown */}
      {stats.failed > 0 && (
        <div className="vuln-breakdown card">
          <div className="card-header">
            <h3 className="card-title">
              <span>⚠️</span> Vulnerability Breakdown
            </h3>
          </div>
          <div className="card-body">
            <div className="breakdown-grid">
              <div className="breakdown-section">
                <h4>By Severity</h4>
                <div className="breakdown-bars">
                  {Object.entries(stats.vulnBySeverity).map(([severity, count]) => (
                    count > 0 && (
                      <div key={severity} className="breakdown-bar-item">
                        <div className="bar-label">
                          <span style={{ color: getSeverityColor(severity) }}>{severity}</span>
                          <span>{count}</span>
                        </div>
                        <div className="bar-track">
                          <div 
                            className="bar-fill"
                            style={{ 
                              width: `${(count / stats.failed) * 100}%`,
                              background: getSeverityColor(severity)
                            }}
                          ></div>
                        </div>
                      </div>
                    )
                  ))}
                </div>
              </div>
              <div className="breakdown-section">
                <h4>By Type</h4>
                <div className="breakdown-bars">
                  {Object.entries(stats.vulnByType).map(([type, count]) => (
                    <div key={type} className="breakdown-bar-item">
                      <div className="bar-label">
                        <span>{type}</span>
                        <span>{count}</span>
                      </div>
                      <div className="bar-track">
                        <div 
                          className="bar-fill"
                          style={{ 
                            width: `${(count / stats.failed) * 100}%`,
                            background: 'var(--accent-tertiary)'
                          }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="results-filters">
        <div className="filter-group">
          <label>Status:</label>
          <div className="filter-buttons">
            <button 
              className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
              onClick={() => setFilter('all')}
            >
              All ({results.endpoints.length})
            </button>
            <button 
              className={`filter-btn danger ${filter === 'failed' ? 'active' : ''}`}
              onClick={() => setFilter('failed')}
            >
              Vulnerable ({results.endpoints.filter(e => e.summary?.failed > 0).length})
            </button>
            <button 
              className={`filter-btn success ${filter === 'passed' ? 'active' : ''}`}
              onClick={() => setFilter('passed')}
            >
              Secure ({results.endpoints.filter(e => e.summary?.failed === 0).length})
            </button>
          </div>
        </div>
        <div className="filter-group">
          <label>Type:</label>
          <select 
            className="select-field"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            {vulnTypes.map(type => (
              <option key={type} value={type}>
                {type === 'all' ? 'All Types' : type}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Endpoints List */}
      <div className="endpoints-results">
        {filteredEndpoints.map((endpoint, index) => (
          <div 
            key={index} 
            className={`endpoint-result-card ${endpoint.summary?.failed > 0 ? 'vulnerable' : 'secure'}`}
          >
            <div 
              className="endpoint-result-header"
              onClick={() => setSelectedEndpoint(selectedEndpoint === index ? null : index)}
            >
              <div className="endpoint-info">
                <span className={`badge badge-method badge-${endpoint.method?.toLowerCase()}`}>
                  {endpoint.method}
                </span>
                <span className="endpoint-api">{endpoint.api}</span>
                {endpoint.summary?.failed > 0 ? (
                  <span className="badge badge-danger">
                    {endpoint.summary.failed} vulnerabilities
                  </span>
                ) : (
                  <span className="badge badge-success">Secure</span>
                )}
              </div>
              <div className="endpoint-stats">
                <span className="stat-mini">
                  <span className="stat-mini-label">Tests:</span>
                  {endpoint.summary?.total || 0}
                </span>
                <span className="stat-mini success">
                  <span className="stat-mini-label">Pass:</span>
                  {endpoint.summary?.passed || 0}
                </span>
                <span className="stat-mini danger">
                  <span className="stat-mini-label">Fail:</span>
                  {endpoint.summary?.failed || 0}
                </span>
                <span className={`expand-icon ${selectedEndpoint === index ? 'open' : ''}`}>
                  ▼
                </span>
              </div>
            </div>

            {selectedEndpoint === index && (
              <div className="endpoint-result-details">
                {(!endpoint.tests || endpoint.tests.length === 0) ? (
                  <div className="no-tests-message">
                    <span>⚠️</span> No tests were executed for this endpoint. 
                    This may happen if the target URL is unreachable.
                  </div>
                ) : (
                  <div className="table-container">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Status</th>
                          <th>Type</th>
                          <th>Severity</th>
                          <th>Injection Point</th>
                          <th>Response</th>
                          <th>Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {endpoint.tests
                          ?.filter(t => typeFilter === 'all' || t.type === typeFilter)
                          .map((test, testIndex) => {
                            const testId = `${index}-${testIndex}`;
                            const isExpanded = expandedTests[testId];
                            
                            return (
                              <React.Fragment key={testIndex}>
                                <tr className={test.result === 'FAIL' ? 'row-fail' : test.result === 'ERROR' ? 'row-error' : ''}>
                                  <td>
                                    <span className={`badge badge-${test.result === 'FAIL' ? 'danger' : test.result === 'PASS' ? 'success' : 'warning'}`}>
                                      {test.result}
                                    </span>
                                  </td>
                                  <td>
                                    <span className="type-badge">{test.type}</span>
                                  </td>
                                  <td>
                                    <span className="severity-badge" style={{ color: getSeverityColor(test.severity) }}>
                                      {test.severity}
                                    </span>
                                  </td>
                                  <td>
                                    <code className="code-inline">{test.injectionPoint}</code>
                                  </td>
                                  <td>
                                    <div className="response-info">
                                      <span className={`response-code ${test.responseCode >= 200 && test.responseCode < 300 ? 'success' : test.responseCode >= 400 ? 'error' : test.responseCode === 0 ? 'none' : ''}`}>
                                        {test.responseCode || 'N/A'}
                                      </span>
                                      {test.responseTime > 0 && (
                                        <span className="response-time">{test.responseTime}ms</span>
                                      )}
                                      {test.responseSize > 0 && (
                                        <span className="response-size">{test.responseSize}B</span>
                                      )}
                                    </div>
                                  </td>
                                  <td>
                                    <button 
                                      className="btn btn-sm btn-secondary"
                                      onClick={() => toggleTestExpand(testId)}
                                    >
                                      {isExpanded ? '▲ Hide' : '▼ View'}
                                    </button>
                                  </td>
                                </tr>
                                {isExpanded && (
                                  <tr className="expanded-row">
                                    <td colSpan="6">
                                      <div className="test-details">
                                        <div className="detail-grid">
                                          <div className="detail-section">
                                            <strong>🎯 Payload Injected:</strong>
                                            <code className="code-block payload-block">{test.payload}</code>
                                          </div>
                                          
                                          <div className="detail-section">
                                            <strong>📍 Request Info:</strong>
                                            <div className="request-info">
                                              <p><span>Method:</span> {test.requestMethod || endpoint.method}</p>
                                              <p><span>URL:</span> <code>{test.requestUrl || endpoint.url}</code></p>
                                              <p><span>Tested At:</span> {test.testedAt || 'N/A'}</p>
                                            </div>
                                          </div>
                                        </div>
                                        
                                        <div className="detail-section">
                                          <strong>📊 Analysis Result:</strong>
                                          <div className="analysis-result">
                                            <div className="analysis-item">
                                              <span className="label">Verdict:</span>
                                              <span className={`verdict verdict-${test.result?.toLowerCase()}`}>
                                                {test.result === 'FAIL' ? '⚠️ VULNERABLE' : test.result === 'PASS' ? '✅ SECURE' : '❓ ERROR'}
                                              </span>
                                            </div>
                                            {test.confidence && (
                                              <div className="analysis-item">
                                                <span className="label">Confidence:</span>
                                                <span className={`confidence confidence-${test.confidence}`}>
                                                  {test.confidence.toUpperCase()}
                                                </span>
                                              </div>
                                            )}
                                            {test.baselineStatus && (
                                              <div className="analysis-item">
                                                <span className="label">Baseline Status:</span>
                                                <span>{test.baselineStatus}</span>
                                                {test.statusChanged && <span className="status-changed">(Changed!)</span>}
                                              </div>
                                            )}
                                          </div>
                                        </div>
                                        
                                        {test.indicators?.length > 0 && (
                                          <div className="detail-section">
                                            <strong>🔍 Detection Indicators:</strong>
                                            <ul className="indicators-list">
                                              {test.indicators.map((ind, i) => (
                                                <li key={i}>{ind}</li>
                                              ))}
                                            </ul>
                                          </div>
                                        )}
                                        
                                        {test.responsePreview && (
                                          <div className="detail-section">
                                            <strong>📄 Response Preview:</strong>
                                            <code className="code-block response-preview">{test.responsePreview}</code>
                                          </div>
                                        )}
                                        
                                        {test.notes && (
                                          <div className="detail-section">
                                            <strong>📝 Notes:</strong>
                                            <p className="notes-text">{test.notes}</p>
                                          </div>
                                        )}
                                      </div>
                                    </td>
                                  </tr>
                                )}
                              </React.Fragment>
                            );
                          })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Vulnerabilities List */}
      {stats.vulnerabilities.length > 0 && (
        <div className="card vuln-list">
          <div className="card-header">
            <h3 className="card-title">
              <span>🔥</span> All Vulnerabilities ({stats.vulnerabilities.length})
            </h3>
          </div>
          <div className="card-body">
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Payload</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.vulnerabilities.map((vuln, index) => (
                    <tr key={index}>
                      <td>
                        <code className="code-inline">{vuln.endpoint}</code>
                      </td>
                      <td>{vuln.type}</td>
                      <td>
                        <span style={{ color: getSeverityColor(vuln.severity) }}>
                          {vuln.severity}
                        </span>
                      </td>
                      <td>
                        <span className={`confidence confidence-${vuln.confidence}`}>
                          {vuln.confidence?.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <code className="code-inline payload-cell">{vuln.payload}</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ResultsDashboard;

