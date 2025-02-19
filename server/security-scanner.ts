import https from 'https';
import { URL } from 'url';

interface SecurityCheckResult {
  valid?: boolean;
  secure?: boolean;
  vulnerable?: boolean;
  issues?: string[];
  missing?: string[];
  endpoints?: string[];
}

interface SecurityScanResults {
  ssl: SecurityCheckResult;
  headers: SecurityCheckResult;
  xss: SecurityCheckResult;
  sql: SecurityCheckResult;
}

export async function performSecurityCheck(targetUrl: string, updateProgress: (progress: number) => void): Promise<SecurityScanResults> {
  // Validate URL
  const url = new URL(targetUrl);
  if (!url.protocol.startsWith('http')) {
    throw new Error('Invalid URL protocol. Only HTTP/HTTPS URLs are supported.');
  }

  const results: SecurityScanResults = {
    ssl: { valid: false, issues: [] },
    headers: { secure: false, missing: [] },
    xss: { vulnerable: false, endpoints: [] },
    sql: { vulnerable: false, endpoints: [] }
  };

  // Check SSL/TLS (25%)
  try {
    await checkSSL(url, results.ssl);
    updateProgress(25);
  } catch (error) {
    results.ssl.issues?.push(`SSL Error: ${error.message}`);
  }

  // Check Security Headers (50%)
  try {
    await checkHeaders(url, results.headers);
    updateProgress(50);
  } catch (error) {
    results.headers.missing?.push(`Headers Error: ${error.message}`);
  }

  // Check for XSS Vulnerabilities (75%)
  try {
    await checkXSS(url, results.xss);
    updateProgress(75);
  } catch (error) {
    results.xss.endpoints?.push(`XSS Error: ${error.message}`);
  }

  // Check for SQL Injection (100%)
  try {
    await checkSQLInjection(url, results.sql);
    updateProgress(100);
  } catch (error) {
    results.sql.endpoints?.push(`SQL Error: ${error.message}`);
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
