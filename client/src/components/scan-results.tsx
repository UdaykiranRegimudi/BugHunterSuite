import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Check, X } from "lucide-react";

interface ScanResult {
  valid?: boolean;
  secure?: boolean;
  vulnerable?: boolean;
  issues?: string[];
  missing?: string[];
  endpoints?: string[];
}

interface VulnerabilityResult {
  ssl: ScanResult;
  headers: ScanResult;
  xss: ScanResult;
  sql: ScanResult;
}

interface ScanResultsProps {
  results: VulnerabilityResult;
}

export default function ScanResults({ results }: ScanResultsProps) {
  return (
    <div className="grid md:grid-cols-2 gap-8">
      {/* SSL/TLS Security */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            SSL/TLS Security
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 mb-4">
            {results.ssl.valid ? (
              <Check className="h-5 w-5 text-green-500" />
            ) : (
              <X className="h-5 w-5 text-red-500" />
            )}
            <span>
              {results.ssl.valid
                ? "SSL configuration is secure"
                : "SSL configuration issues found"}
            </span>
          </div>
          {results.ssl.issues && results.ssl.issues.length > 0 && (
            <Alert variant="destructive">
              <AlertTitle>Issues Found</AlertTitle>
              <AlertDescription>
                <ul className="list-disc pl-4 mt-2">
                  {results.ssl.issues.map((issue) => (
                    <li key={issue}>{issue}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* HTTP Headers */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            HTTP Headers
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 mb-4">
            {results.headers.secure ? (
              <Check className="h-5 w-5 text-green-500" />
            ) : (
              <X className="h-5 w-5 text-red-500" />
            )}
            <span>
              {results.headers.secure
                ? "Security headers are properly configured"
                : "Missing security headers"}
            </span>
          </div>
          {results.headers.missing && results.headers.missing.length > 0 && (
            <Alert variant="destructive">
              <AlertTitle>Missing Headers</AlertTitle>
              <AlertDescription>
                <ul className="list-disc pl-4 mt-2">
                  {results.headers.missing.map((header) => (
                    <li key={header}>{header}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* XSS Vulnerabilities */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            XSS Vulnerabilities
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 mb-4">
            {!results.xss.vulnerable ? (
              <Check className="h-5 w-5 text-green-500" />
            ) : (
              <X className="h-5 w-5 text-red-500" />
            )}
            <span>
              {!results.xss.vulnerable
                ? "No XSS vulnerabilities detected"
                : "XSS vulnerabilities found"}
            </span>
          </div>
          {results.xss.endpoints && results.xss.endpoints.length > 0 && (
            <Alert variant="destructive">
              <AlertTitle>Vulnerable Endpoints</AlertTitle>
              <AlertDescription>
                <ul className="list-disc pl-4 mt-2">
                  {results.xss.endpoints.map((endpoint) => (
                    <li key={endpoint}>{endpoint}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* SQL Injection */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            SQL Injection
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 mb-4">
            {!results.sql.vulnerable ? (
              <Check className="h-5 w-5 text-green-500" />
            ) : (
              <X className="h-5 w-5 text-red-500" />
            )}
            <span>
              {!results.sql.vulnerable
                ? "No SQL injection vulnerabilities detected"
                : "SQL injection vulnerabilities found"}
            </span>
          </div>
          {results.sql.endpoints && results.sql.endpoints.length > 0 && (
            <Alert variant="destructive">
              <AlertTitle>Vulnerable Endpoints</AlertTitle>
              <AlertDescription>
                <ul className="list-disc pl-4 mt-2">
                  {results.sql.endpoints.map((endpoint) => (
                    <li key={endpoint}>{endpoint}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
