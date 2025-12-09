import React, { useState, useCallback } from 'react';
import './App.css';
import Header from './components/Header';
import InputPanel from './components/InputPanel';
import ResultsDashboard from './components/ResultsDashboard';
import axios from 'axios';

const API_BASE = 'http://localhost:5000/api';

function App() {
  const [inputType, setInputType] = useState('postman'); // 'postman' or 'curl'
  const [collection, setCollection] = useState(null);
  const [curlInput, setCurlInput] = useState('');
  const [envVars, setEnvVars] = useState({});
  const [parsedEndpoints, setParsedEndpoints] = useState([]);
  const [scanResults, setScanResults] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isParsing, setIsParsing] = useState(false);
  const [error, setError] = useState(null);
  const [scanProgress, setScanProgress] = useState({ current: 0, total: 0 });
  const [scanOptions, setScanOptions] = useState({
    scanTypes: [
      'SQL Injection', 
      'XSS', 
      'Command Injection', 
      'Path Traversal',
      'NoSQL Injection',
      'Header Injection',
      'Rate Limiting',
      'Malformed Payload',
      'HTTP Method',
      'Payload Size'
    ],
    maxPayloads: 5,
    injectLocation: 'all'
  });

  // Parse Postman collection
  const parsePostman = useCallback(async (file) => {
    setIsParsing(true);
    setError(null);
    
    try {
      const formData = new FormData();
      formData.append('collection', file);
      formData.append('envVars', JSON.stringify(envVars));
      
      const response = await axios.post(`${API_BASE}/parse/postman`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      setParsedEndpoints(response.data.endpoints);
      setCollection(file);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to parse Postman collection');
      setParsedEndpoints([]);
    } finally {
      setIsParsing(false);
    }
  }, [envVars]);

  // Parse CURL commands
  const parseCurl = useCallback(async (curlText) => {
    if (!curlText.trim()) {
      setParsedEndpoints([]);
      return;
    }
    
    setIsParsing(true);
    setError(null);
    
    try {
      const response = await axios.post(`${API_BASE}/parse/curl`, {
        curl: curlText
      });
      
      setParsedEndpoints(response.data.endpoints);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to parse CURL commands');
      setParsedEndpoints([]);
    } finally {
      setIsParsing(false);
    }
  }, []);

  // Run security scan
  const runScan = useCallback(async () => {
    if (parsedEndpoints.length === 0) {
      setError('No endpoints to scan. Please add a Postman collection or CURL commands first.');
      return;
    }
    
    setIsScanning(true);
    setError(null);
    setScanResults(null);
    setScanProgress({ current: 0, total: parsedEndpoints.length });
    
    try {
      // Build request body as JSON for better handling
      const requestBody = {
        envVars: envVars,
        scanTypes: scanOptions.scanTypes,
        maxPayloads: scanOptions.maxPayloads,
        injectLocation: scanOptions.injectLocation
      };
      
      if (inputType === 'postman' && collection) {
        // For file upload, use FormData
        const formData = new FormData();
        formData.append('collection', collection);
        formData.append('envVars', JSON.stringify(envVars));
        formData.append('scanTypes', JSON.stringify(scanOptions.scanTypes));
        formData.append('maxPayloads', scanOptions.maxPayloads);
        formData.append('injectLocation', scanOptions.injectLocation);
        
        const response = await axios.post(`${API_BASE}/scan`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
        setScanResults(response.data.results);
      } else if (inputType === 'curl') {
        // For CURL, send as JSON
        requestBody.curl = curlInput;
        
        const response = await axios.post(`${API_BASE}/scan`, requestBody, {
          headers: { 'Content-Type': 'application/json' }
        });
        setScanResults(response.data.results);
      }
    } catch (err) {
      console.error('Scan error:', err);
      setError(err.response?.data?.message || 'Scan failed. Please try again.');
    } finally {
      setIsScanning(false);
    }
  }, [parsedEndpoints, inputType, collection, curlInput, envVars, scanOptions]);

  // Download results as JSON
  const downloadResults = useCallback(() => {
    if (!scanResults) return;
    
    const blob = new Blob([JSON.stringify(scanResults, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-results-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [scanResults]);

  // Reset everything
  const resetAll = useCallback(() => {
    setCollection(null);
    setCurlInput('');
    setEnvVars({});
    setParsedEndpoints([]);
    setScanResults(null);
    setError(null);
  }, []);

  return (
    <div className="app">
      <Header />
      
      <main className="main-content">
        <div className="container">
          {error && (
            <div className="error-banner animate-fadeIn">
              <span className="error-icon">⚠️</span>
              <span>{error}</span>
              <button onClick={() => setError(null)} className="error-close">×</button>
            </div>
          )}
          
          {!scanResults ? (
            <InputPanel
              inputType={inputType}
              setInputType={setInputType}
              collection={collection}
              curlInput={curlInput}
              setCurlInput={setCurlInput}
              envVars={envVars}
              setEnvVars={setEnvVars}
              parsedEndpoints={parsedEndpoints}
              parsePostman={parsePostman}
              parseCurl={parseCurl}
              scanOptions={scanOptions}
              setScanOptions={setScanOptions}
              runScan={runScan}
              isScanning={isScanning}
              isParsing={isParsing}
              scanProgress={scanProgress}
            />
          ) : (
            <ResultsDashboard
              results={scanResults}
              downloadResults={downloadResults}
              onNewScan={resetAll}
            />
          )}
        </div>
      </main>
      
      <footer className="footer">
        <p>🔒 API Security Scanner v1.0 | Built for secure API testing</p>
      </footer>
    </div>
  );
}

export default App;

