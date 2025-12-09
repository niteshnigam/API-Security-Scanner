import React, { useRef, useState } from 'react';
import './InputPanel.css';

function InputPanel({
  inputType,
  setInputType,
  collection,
  curlInput,
  setCurlInput,
  envVars,
  setEnvVars,
  parsedEndpoints,
  parsePostman,
  parseCurl,
  scanOptions,
  setScanOptions,
  runScan,
  isScanning,
  isParsing,
  scanProgress
}) {
  const fileInputRef = useRef(null);
  const [dragActive, setDragActive] = useState(false);
  const [newEnvKey, setNewEnvKey] = useState('');
  const [newEnvValue, setNewEnvValue] = useState('');
  const [showOptions, setShowOptions] = useState(false);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      parsePostman(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      parsePostman(e.target.files[0]);
    }
  };

  const handleCurlPaste = (e) => {
    const text = e.target.value;
    setCurlInput(text);
    if (text.trim()) {
      parseCurl(text);
    }
  };

  const addEnvVar = () => {
    if (newEnvKey && newEnvValue) {
      setEnvVars({ ...envVars, [newEnvKey]: newEnvValue });
      setNewEnvKey('');
      setNewEnvValue('');
    }
  };

  const removeEnvVar = (key) => {
    const updated = { ...envVars };
    delete updated[key];
    setEnvVars(updated);
  };

  const toggleScanType = (type) => {
    const types = scanOptions.scanTypes.includes(type)
      ? scanOptions.scanTypes.filter(t => t !== type)
      : [...scanOptions.scanTypes, type];
    setScanOptions({ ...scanOptions, scanTypes: types });
  };

  const vulnerabilityTypes = [
    // Original 4
    { id: 'SQL Injection', icon: '💉', description: 'Database injection' },
    { id: 'XSS', icon: '🎭', description: 'Cross-site scripting' },
    { id: 'Command Injection', icon: '⚡', description: 'OS command execution' },
    { id: 'Path Traversal', icon: '📁', description: 'File system access' },
    // New 6
    { id: 'NoSQL Injection', icon: '🍃', description: 'MongoDB/JSON injection' },
    { id: 'Header Injection', icon: '📋', description: 'Header manipulation' },
    { id: 'Rate Limiting', icon: '⏱️', description: 'Bot/DDoS protection' },
    { id: 'Malformed Payload', icon: '🔧', description: 'Input validation' },
    { id: 'HTTP Method', icon: '🔀', description: 'Method tampering' },
    { id: 'Payload Size', icon: '📦', description: 'Buffer overflow test' }
  ];

  return (
    <div className="input-panel animate-fadeIn">
      {/* Input Type Selection */}
      <div className="tabs">
        <button 
          className={`tab ${inputType === 'postman' ? 'active' : ''}`}
          onClick={() => setInputType('postman')}
        >
          <span>📦</span> Postman Collection
        </button>
        <button 
          className={`tab ${inputType === 'curl' ? 'active' : ''}`}
          onClick={() => setInputType('curl')}
        >
          <span>⌨️</span> CURL Commands
        </button>
      </div>

      <div className="grid-2">
        {/* Left Column - Input */}
        <div className="input-section">
          {inputType === 'postman' ? (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">
                  <span>📤</span> Upload Collection
                </h3>
              </div>
              <div className="card-body">
                <div 
                  className={`drop-zone ${dragActive ? 'active' : ''} ${collection ? 'has-file' : ''}`}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".json"
                    onChange={handleFileChange}
                    style={{ display: 'none' }}
                  />
                  {collection ? (
                    <div className="drop-zone-success">
                      <span className="success-icon">✅</span>
                      <p className="file-name">{collection.name}</p>
                      <p className="file-info">{parsedEndpoints.length} endpoints found</p>
                    </div>
                  ) : (
                    <div className="drop-zone-prompt">
                      <span className="upload-icon">📁</span>
                      <p>Drag & drop your Postman collection here</p>
                      <p className="drop-hint">or click to browse</p>
                    </div>
                  )}
                </div>
                {isParsing && (
                  <div className="parsing-indicator">
                    <div className="spinner"></div>
                    <span>Parsing collection...</span>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">
                  <span>⌨️</span> Paste CURL Commands
                </h3>
              </div>
              <div className="card-body">
                <textarea
                  className="input-field curl-input"
                  placeholder={`Paste one or more CURL commands here...

Example:
curl -X POST https://api.example.com/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"test","password":"test123"}'`}
                  value={curlInput}
                  onChange={handleCurlPaste}
                />
                {isParsing && (
                  <div className="parsing-indicator">
                    <div className="spinner"></div>
                    <span>Parsing CURL...</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Environment Variables */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">
                <span>🔑</span> Environment Variables
              </h3>
            </div>
            <div className="card-body">
              <div className="env-vars-list">
                {Object.entries(envVars).map(([key, value]) => (
                  <div key={key} className="env-var-item">
                    <span className="env-var-key">{key}</span>
                    <span className="env-var-value">{value}</span>
                    <button 
                      className="env-var-remove"
                      onClick={() => removeEnvVar(key)}
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
              <div className="env-var-add">
                <input
                  type="text"
                  className="input-field"
                  placeholder="Variable name"
                  value={newEnvKey}
                  onChange={(e) => setNewEnvKey(e.target.value)}
                />
                <input
                  type="text"
                  className="input-field"
                  placeholder="Value"
                  value={newEnvValue}
                  onChange={(e) => setNewEnvValue(e.target.value)}
                />
                <button 
                  className="btn btn-secondary btn-sm"
                  onClick={addEnvVar}
                  disabled={!newEnvKey || !newEnvValue}
                >
                  Add
                </button>
              </div>
              <p className="env-hint">
                Variables will replace {'{{variableName}}'} in your requests
              </p>
            </div>
          </div>
        </div>

        {/* Right Column - Preview & Options */}
        <div className="preview-section">
          {/* Endpoint Preview */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">
                <span>🔗</span> Endpoints Preview
                {parsedEndpoints.length > 0 && (
                  <span className="endpoint-count">{parsedEndpoints.length}</span>
                )}
              </h3>
            </div>
            <div className="card-body">
              {parsedEndpoints.length > 0 ? (
                <div className="endpoints-list">
                  {parsedEndpoints.map((endpoint, index) => (
                    <div key={index} className="endpoint-item animate-slideIn" style={{ animationDelay: `${index * 0.05}s` }}>
                      <span className={`badge badge-method badge-${endpoint.method.toLowerCase()}`}>
                        {endpoint.method}
                      </span>
                      <span className="endpoint-url">{endpoint.url || endpoint.name}</span>
                      <div className="endpoint-meta">
                        {endpoint.hasBody && <span className="meta-badge">Body</span>}
                        {endpoint.hasHeaders && <span className="meta-badge">Headers</span>}
                        {endpoint.queryParamCount > 0 && (
                          <span className="meta-badge">Params: {endpoint.queryParamCount}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon">📋</div>
                  <p className="empty-state-text">
                    No endpoints yet. Upload a collection or paste CURL commands.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Scan Options */}
          <div className="card">
            <div 
              className="card-header clickable"
              onClick={() => setShowOptions(!showOptions)}
            >
              <h3 className="card-title">
                <span>⚙️</span> Scan Options
                <span className={`toggle-icon ${showOptions ? 'open' : ''}`}>▼</span>
              </h3>
            </div>
            {showOptions && (
              <div className="card-body">
                <div className="option-group">
                  <label className="input-label">Vulnerability Types</label>
                  <div className="vuln-type-grid">
                    {vulnerabilityTypes.map(type => (
                      <div 
                        key={type.id}
                        className={`vuln-type-card ${scanOptions.scanTypes.includes(type.id) ? 'selected' : ''}`}
                        onClick={() => toggleScanType(type.id)}
                      >
                        <span className="vuln-type-icon">{type.icon}</span>
                        <span className="vuln-type-name">{type.id}</span>
                        <span className="vuln-type-desc">{type.description}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="option-row">
                  <div className="option-group">
                    <label className="input-label">Payloads per Type</label>
                    <select 
                      className="select-field"
                      value={scanOptions.maxPayloads}
                      onChange={(e) => setScanOptions({ ...scanOptions, maxPayloads: parseInt(e.target.value) })}
                    >
                      <option value={3}>3 (Fast)</option>
                      <option value={5}>5 (Balanced)</option>
                      <option value={10}>10 (Thorough)</option>
                      <option value={20}>20 (Comprehensive)</option>
                    </select>
                  </div>

                  <div className="option-group">
                    <label className="input-label">Injection Location</label>
                    <select 
                      className="select-field"
                      value={scanOptions.injectLocation}
                      onChange={(e) => setScanOptions({ ...scanOptions, injectLocation: e.target.value })}
                    >
                      <option value="all">All Locations</option>
                      <option value="query">Query Parameters Only</option>
                      <option value="body">Request Body Only</option>
                      <option value="header">Headers Only</option>
                      <option value="path">URL Path Only</option>
                    </select>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Scan Button */}
      <div className="scan-action">
        <button 
          className="btn btn-primary btn-lg scan-button"
          onClick={runScan}
          disabled={isScanning || parsedEndpoints.length === 0}
        >
          {isScanning ? (
            <>
              <div className="spinner"></div>
              Scanning... ({scanProgress.current}/{scanProgress.total})
            </>
          ) : (
            <>
              <span>🚀</span>
              Run Security Tests
            </>
          )}
        </button>
        
        {isScanning && (
          <div className="scan-progress">
            <div className="progress-bar">
              <div 
                className="progress-fill"
                style={{ width: `${(scanProgress.current / scanProgress.total) * 100}%` }}
              ></div>
            </div>
            <p className="progress-text">
              Testing endpoint {scanProgress.current} of {scanProgress.total}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default InputPanel;

