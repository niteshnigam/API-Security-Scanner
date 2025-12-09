import React from 'react';
import './Header.css';

function Header() {
  return (
    <header className="header">
      <div className="header-content">
        <div className="logo">
          <span className="logo-icon">🔒</span>
          <div className="logo-text">
            <h1>API Security Scanner</h1>
            <p className="tagline">Detect vulnerabilities before attackers do</p>
          </div>
        </div>
        
        <nav className="header-nav">
          <a href="https://owasp.org/www-project-api-security/" target="_blank" rel="noopener noreferrer" className="nav-link">
            OWASP API Top 10
          </a>
          <span className="version-badge">v1.0</span>
        </nav>
      </div>
      
      <div className="header-glow"></div>
    </header>
  );
}

export default Header;

