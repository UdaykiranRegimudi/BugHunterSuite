import https from 'https';
import { URL } from 'url';
import { IncomingMessage } from 'http';

interface SecurityCheckResult {
  valid?: boolean;
  secure?: boolean;
  vulnerable?: boolean;
  issues?: string[];
  missing?: string[];
  endpoints?: string[];
  severity?: 'low' | 'medium' | 'high' | 'critical';
  description?: string;
  remediation?: string;
}

interface SecurityScanResults {
  ssl: SecurityCheckResult;
  headers: SecurityCheckResult;
  xss: SecurityCheckResult;
  sql: SecurityCheckResult;
  accessControl: SecurityCheckResult;
  cryptography: SecurityCheckResult;
  insecureDesign: SecurityCheckResult;
  securityConfig: SecurityCheckResult;
  vulnerableComponents: SecurityCheckResult;
  authentication: SecurityCheckResult;
  integrityFailures: SecurityCheckResult;
  logging: SecurityCheckResult;
  ssrf: SecurityCheckResult;
}

export async function performSecurityCheck(targetUrl: string, updateProgress: (progress: number) => void): Promise<SecurityScanResults> {
  const url = new URL(targetUrl);
  if (!url.protocol.startsWith('http')) {
    throw new Error('Invalid URL protocol. Only HTTP/HTTPS URLs are supported.');
  }

  const results: SecurityScanResults = {
    ssl: { valid: false, issues: [] },
    headers: { secure: false, missing: [] },
    xss: { vulnerable: false, endpoints: [] },
    sql: { vulnerable: false, endpoints: [] },
    accessControl: { vulnerable: false, issues: [] },
    cryptography: { secure: false, issues: [] },
    insecureDesign: { vulnerable: false, issues: [] },
    securityConfig: { secure: false, issues: [] },
    vulnerableComponents: { vulnerable: false, issues: [] },
    authentication: { secure: false, issues: [] },
    integrityFailures: { vulnerable: false, issues: [] },
    logging: { secure: false, issues: [] },
    ssrf: { vulnerable: false, endpoints: [] }
  };

  const totalChecks = 13;
  let completedChecks = 0;

  // Existing checks
  try {
    await checkSSL(url, results.ssl);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.ssl.issues?.push(`SSL Error: ${error.message}`);
  }

  try {
    await checkHeaders(url, results.headers);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.headers.missing?.push(`Headers Error: ${error.message}`);
  }

  try {
    await checkXSS(url, results.xss);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.xss.endpoints?.push(`XSS Error: ${error.message}`);
  }

  try {
    await checkSQLInjection(url, results.sql);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.sql.endpoints?.push(`SQL Error: ${error.message}`);
  }

  // New OWASP Top 10 checks
  try {
    await checkAccessControl(url, results.accessControl);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.accessControl.issues?.push(`Access Control Error: ${error.message}`);
  }

  try {
    await checkCryptography(url, results.cryptography);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.cryptography.issues?.push(`Cryptography Error: ${error.message}`);
  }

  try {
    await checkInsecureDesign(url, results.insecureDesign);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.insecureDesign.issues?.push(`Design Error: ${error.message}`);
  }

  try {
    await checkSecurityConfig(url, results.securityConfig);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.securityConfig.issues?.push(`Configuration Error: ${error.message}`);
  }

  try {
    await checkVulnerableComponents(url, results.vulnerableComponents);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.vulnerableComponents.issues?.push(`Component Error: ${error.message}`);
  }

  try {
    await checkAuthentication(url, results.authentication);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.authentication.issues?.push(`Authentication Error: ${error.message}`);
  }

  try {
    await checkIntegrityFailures(url, results.integrityFailures);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.integrityFailures.issues?.push(`Integrity Error: ${error.message}`);
  }

  try {
    await checkLogging(url, results.logging);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.logging.issues?.push(`Logging Error: ${error.message}`);
  }

  try {
    await checkSSRF(url, results.ssrf);
    updateProgress(++completedChecks * (100 / totalChecks));
  } catch (error) {
    results.ssrf.endpoints?.push(`SSRF Error: ${error.message}`);
  }

  return results;
}

async function checkSSL(url: URL, result: SecurityCheckResult): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method: 'HEAD',
      rejectUnauthorized: true,
    }, (res) => {
      const protocol = res.socket?.getPeerCertificate()?.protocol;
      if (protocol && ['TLSv1.2', 'TLSv1.3'].includes(protocol)) {
        result.valid = true;
      } else {
        result.valid = false;
        result.issues?.push('Outdated SSL/TLS protocol version');
      }
      resolve();
    });

    req.on('error', (error) => {
      result.valid = false;
      result.issues?.push(`SSL Error: ${error.message}`);
      resolve();
    });

    req.end();
  });
}

async function checkHeaders(url: URL, result: SecurityCheckResult): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: 'HEAD' }, (res) => {
      const headers = res.headers;
      const requiredHeaders = [
        'strict-transport-security',
        'x-content-type-options',
        'x-frame-options',
        'content-security-policy',
      ];

      result.missing = requiredHeaders.filter(header => !headers[header]);
      result.secure = result.missing.length === 0;
      resolve();
    });

    req.on('error', (error) => {
      result.secure = false;
      result.missing?.push(`Headers Error: ${error.message}`);
      resolve();
    });

    req.end();
  });
}

async function checkXSS(url: URL, result: SecurityCheckResult): Promise<void> {
  const testPayloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
  ];

  // Test common entry points
  const endpoints = ['/search', '/comment', '/feedback'];
  result.vulnerable = false;
  result.endpoints = [];

  for (const endpoint of endpoints) {
    const testUrl = new URL(endpoint, url);
    testUrl.searchParams.set('q', testPayloads[0]);

    try {
      const response = await fetch(testUrl.toString());
      const text = await response.text();

      if (testPayloads.some(payload => text.includes(payload))) {
        result.vulnerable = true;
        result.endpoints?.push(endpoint);
      }
    } catch (error) {
      // Skip failed endpoints
      continue;
    }
  }
}

async function checkSQLInjection(url: URL, result: SecurityCheckResult): Promise<void> {
  const sqlPayloads = [
    "' OR '1'='1",
    "1' OR '1'='1",
    "1; DROP TABLE users--",
  ];

  // Test common entry points
  const endpoints = ['/login', '/search', '/profile'];
  result.vulnerable = false;
  result.endpoints = [];

  for (const endpoint of endpoints) {
    const testUrl = new URL(endpoint, url);
    testUrl.searchParams.set('id', sqlPayloads[0]);

    try {
      const response = await fetch(testUrl.toString());
      const text = await response.text();

      // Check for common SQL error messages
      const sqlErrorPatterns = [
        'sql syntax',
        'mysql error',
        'postgresql error',
        'ORA-',
        'SQL Server error'
      ];

      if (sqlErrorPatterns.some(pattern => text.toLowerCase().includes(pattern))) {
        result.vulnerable = true;
        result.endpoints?.push(endpoint);
      }
    } catch (error) {
      // Skip failed endpoints
      continue;
    }
  }
}

async function checkAccessControl(url: URL, result: SecurityCheckResult): Promise<void> {
  result.vulnerable = false;
  result.issues = [];
  result.severity = 'high';

  const sensitiveEndpoints = [
    '/admin',
    '/api/users',
    '/dashboard',
    '/settings'
  ];

  for (const endpoint of sensitiveEndpoints) {
    try {
      const response = await fetch(new URL(endpoint, url).toString());
      if (response.status !== 401 && response.status !== 403) {
        result.vulnerable = true;
        result.issues.push(`Endpoint ${endpoint} accessible without authentication`);
      }
    } catch (error) {
      // Skip failed endpoints
      continue;
    }
  }
}

async function checkCryptography(url: URL, result: SecurityCheckResult): Promise<void> {
  result.secure = false;
  result.issues = [];
  result.severity = 'critical';

  const response = await fetch(url.toString());
  const headers = response.headers;

  // Check for secure cookie attributes
  const cookies = headers.get('set-cookie');
  if (cookies) {
    if (!cookies.includes('Secure') || !cookies.includes('HttpOnly')) {
      result.issues.push('Cookies missing Secure or HttpOnly flags');
    }
    if (!cookies.includes('SameSite')) {
      result.issues.push('Cookies missing SameSite attribute');
    }
  }

  // Check TLS version
  const tlsVersion = headers.get('server-timing')?.includes('tls=1.3') ? '1.3' : '1.2';
  if (tlsVersion !== '1.3') {
    result.issues.push('Not using latest TLS version (1.3)');
  }

  result.secure = result.issues.length === 0;
}

async function checkInsecureDesign(url: URL, result: SecurityCheckResult): Promise<void> {
  result.vulnerable = false;
  result.issues = [];
  result.severity = 'high';

  const designPatterns = [
    { path: '/reset-password', method: 'POST' },
    { path: '/api/export', method: 'GET' },
    { path: '/api/bulk-update', method: 'POST' }
  ];

  for (const pattern of designPatterns) {
    try {
      const response = await fetch(new URL(pattern.path, url).toString(), {
        method: pattern.method
      });

      // Check for rate limiting headers
      if (!response.headers.get('x-ratelimit-limit')) {
        result.issues.push(`No rate limiting on ${pattern.path}`);
        result.vulnerable = true;
      }
    } catch {
      continue;
    }
  }
}

async function checkSecurityConfig(url: URL, result: SecurityCheckResult): Promise<void> {
  result.secure = false;
  result.issues = [];
  result.severity = 'high';

  const response = await fetch(url.toString());
  const headers = response.headers;

  // Check security headers
  const securityHeaders = {
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': '',
    'cross-origin-opener-policy': 'same-origin'
  };

  for (const [header, value] of Object.entries(securityHeaders)) {
    if (!headers.get(header) || (value && headers.get(header) !== value)) {
      result.issues.push(`Missing or incorrect security header: ${header}`);
    }
  }

  result.secure = result.issues.length === 0;
}

async function checkVulnerableComponents(url: URL, result: SecurityCheckResult): Promise<void> {
  result.vulnerable = false;
  result.issues = [];
  result.severity = 'critical';

  // Check for common vulnerable technology signatures
  const response = await fetch(url.toString());
  const headers = response.headers;

  const serverHeader = headers.get('server');
  if (serverHeader) {
    // Check for known vulnerable versions
    const vulnerableVersions = [
      { pattern: /Apache\/2\.4\.(2[0-9]|3[0-9])/, name: 'Apache < 2.4.40' },
      { pattern: /nginx\/1\.[0-9]\.[0-9]/, name: 'nginx < 1.14.0' },
      { pattern: /PHP\/[1-6]/, name: 'PHP < 7.0' }
    ];

    for (const version of vulnerableVersions) {
      if (version.pattern.test(serverHeader)) {
        result.vulnerable = true;
        result.issues.push(`Potentially vulnerable ${version.name} detected`);
      }
    }
  }
}

async function checkAuthentication(url: URL, result: SecurityCheckResult): Promise<void> {
  result.secure = false;
  result.issues = [];
  result.severity = 'critical';

  const authEndpoints = [
    { path: '/login', method: 'POST' },
    { path: '/register', method: 'POST' },
    { path: '/reset-password', method: 'POST' }
  ];

  for (const endpoint of authEndpoints) {
    try {
      const response = await fetch(new URL(endpoint.path, url).toString(), {
        method: endpoint.method
      });

      // Check for basic security headers
      if (!response.headers.get('x-frame-options')) {
        result.issues.push(`Missing X-Frame-Options header on ${endpoint.path}`);
      }

      // Check for rate limiting
      if (!response.headers.get('x-ratelimit-limit')) {
        result.issues.push(`No rate limiting on ${endpoint.path}`);
      }
    } catch {
      continue;
    }
  }

  result.secure = result.issues.length === 0;
}

async function checkIntegrityFailures(url: URL, result: SecurityCheckResult): Promise<void> {
  result.vulnerable = false;
  result.issues = [];
  result.severity = 'high';

  const response = await fetch(url.toString());
  const headers = response.headers;

  // Check for Subresource Integrity
  const html = await response.text();
  const scriptTags = html.match(/<script[^>]*>/g) || [];

  for (const tag of scriptTags) {
    if (!tag.includes('integrity=')) {
      result.vulnerable = true;
      result.issues.push('Script tag missing Subresource Integrity (SRI) hash');
    }
  }

  // Check for Content Security Policy
  if (!headers.get('content-security-policy')) {
    result.vulnerable = true;
    result.issues.push('Missing Content Security Policy');
  }
}

async function checkLogging(url: URL, result: SecurityCheckResult): Promise<void> {
  result.secure = false;
  result.issues = [];
  result.severity = 'medium';

  // Attempt some suspicious activities
  const suspiciousActions = [
    { path: '/login', method: 'POST', payload: { username: "admin'--" } },
    { path: '/api/data', method: 'GET', params: '?id=1 OR 1=1' },
    { path: '/upload', method: 'POST', payload: { file: 'test.php' } }
  ];

  for (const action of suspiciousActions) {
    try {
      const actionUrl = new URL(action.path, url);
      if (action.params) {
        actionUrl.search = action.params;
      }

      const response = await fetch(actionUrl.toString(), {
        method: action.method,
        body: action.payload ? JSON.stringify(action.payload) : undefined,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      // Check for security headers that indicate logging
      if (!response.headers.get('x-request-id')) {
        result.issues.push(`No request tracking on ${action.path}`);
      }
    } catch {
      continue;
    }
  }

  result.secure = result.issues.length === 0;
}

async function checkSSRF(url: URL, result: SecurityCheckResult): Promise<void> {
  result.vulnerable = false;
  result.endpoints = [];
  result.severity = 'critical';

  const ssrfEndpoints = [
    '/api/fetch',
    '/api/proxy',
    '/api/import',
    '/api/webhook'
  ];

  // Test URLs that shouldn't be accessible
  const testUrls = [
    'http://169.254.169.254/latest/meta-data/', // AWS metadata
    'http://localhost/',
    'http://127.0.0.1/',
    'file:///etc/passwd'
  ];

  for (const endpoint of ssrfEndpoints) {
    for (const testUrl of testUrls) {
      try {
        const response = await fetch(new URL(endpoint, url).toString(), {
          method: 'POST',
          body: JSON.stringify({ url: testUrl }),
          headers: {
            'Content-Type': 'application/json'
          }
        });

        if (response.status !== 403 && response.status !== 400) {
          result.vulnerable = true;
          result.endpoints?.push(`${endpoint} might be vulnerable to SSRF`);
        }
      } catch {
        continue;
      }
    }
  }
}