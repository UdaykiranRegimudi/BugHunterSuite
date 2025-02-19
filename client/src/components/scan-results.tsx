import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Check, X, AlertTriangle } from "lucide-react";

interface ScanResult {
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

interface VulnerabilityResult {
  ssl: ScanResult;
  headers: ScanResult;
  xss: ScanResult;
  sql: ScanResult;
  accessControl: ScanResult;
  cryptography: ScanResult;
  insecureDesign: ScanResult;
  securityConfig: ScanResult;
  vulnerableComponents: ScanResult;
  authentication: ScanResult;
  integrityFailures: ScanResult;
  logging: ScanResult;
  ssrf: ScanResult;
}

interface ScanResultsProps {
  results: VulnerabilityResult;
}

function SeverityBadge({ severity }: { severity?: string }) {
  const colors = {
    low: "bg-yellow-100 text-yellow-800",
    medium: "bg-orange-100 text-orange-800",
    high: "bg-red-100 text-red-800",
    critical: "bg-red-200 text-red-900",
  };

  if (!severity) return null;

  return (
    <span className={`text-xs px-2 py-1 rounded-full ${colors[severity as keyof typeof colors]}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function VulnerabilityCard({
  title,
  result,
  icon = Shield,
}: {
  title: string;
  result: ScanResult;
  icon?: typeof Shield;
}) {
  const Icon = icon;
  const hasIssues = result.issues?.length > 0 || result.endpoints?.length > 0 || result.missing?.length > 0;
  const isSecure = result.secure || !result.vulnerable || result.valid;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Icon className="h-5 w-5" />
          <span className="flex-1">{title}</span>
          {result.severity && <SeverityBadge severity={result.severity} />}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-2 mb-4">
          {isSecure ? (
            <Check className="h-5 w-5 text-green-500" />
          ) : (
            <X className="h-5 w-5 text-red-500" />
          )}
          <span>
            {isSecure ? "No vulnerabilities detected" : "Issues found"}
          </span>
        </div>

        {hasIssues && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Issues Found</AlertTitle>
            <AlertDescription>
              <ul className="list-disc pl-4 mt-2">
                {result.issues?.map((issue, index) => (
                  <li key={index}>{issue}</li>
                ))}
                {result.endpoints?.map((endpoint, index) => (
                  <li key={`endpoint-${index}`}>{endpoint}</li>
                ))}
                {result.missing?.map((item, index) => (
                  <li key={`missing-${index}`}>{item}</li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        )}

        {result.description && (
          <p className="mt-4 text-sm text-muted-foreground">
            {result.description}
          </p>
        )}

        {result.remediation && (
          <Alert className="mt-4">
            <AlertTitle>Remediation</AlertTitle>
            <AlertDescription>
              {result.remediation}
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

export default function ScanResults({ results }: ScanResultsProps) {
  return (
    <div className="grid gap-8">
      <div className="grid md:grid-cols-2 gap-8">
        {/* Core Security */}
        <VulnerabilityCard
          title="SSL/TLS Security"
          result={results.ssl}
        />
        <VulnerabilityCard
          title="HTTP Security Headers"
          result={results.headers}
        />
      </div>

      <h2 className="text-2xl font-bold mt-8 mb-4">OWASP Top 10 Vulnerabilities</h2>

      <div className="grid md:grid-cols-2 gap-8">
        {/* A01:2021 - Broken Access Control */}
        <VulnerabilityCard
          title="Access Control"
          result={results.accessControl}
        />

        {/* A02:2021 - Cryptographic Failures */}
        <VulnerabilityCard
          title="Cryptographic Security"
          result={results.cryptography}
        />

        {/* A03:2021 - Injection */}
        <VulnerabilityCard
          title="SQL Injection"
          result={results.sql}
        />
        <VulnerabilityCard
          title="Cross-Site Scripting (XSS)"
          result={results.xss}
        />

        {/* A04:2021 - Insecure Design */}
        <VulnerabilityCard
          title="Insecure Design"
          result={results.insecureDesign}
        />

        {/* A05:2021 - Security Misconfiguration */}
        <VulnerabilityCard
          title="Security Configuration"
          result={results.securityConfig}
        />

        {/* A06:2021 - Vulnerable Components */}
        <VulnerabilityCard
          title="Vulnerable Components"
          result={results.vulnerableComponents}
        />

        {/* A07:2021 - Authentication Failures */}
        <VulnerabilityCard
          title="Authentication Security"
          result={results.authentication}
        />

        {/* A08:2021 - Software and Data Integrity Failures */}
        <VulnerabilityCard
          title="Integrity Checks"
          result={results.integrityFailures}
        />

        {/* A09:2021 - Security Logging and Monitoring */}
        <VulnerabilityCard
          title="Security Logging"
          result={results.logging}
        />

        {/* A10:2021 - SSRF */}
        <VulnerabilityCard
          title="Server-Side Request Forgery"
          result={results.ssrf}
        />
      </div>
    </div>
  );
}