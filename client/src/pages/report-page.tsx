import { useQuery } from "@tanstack/react-query";
import { useParams } from "wouter";
import { Scan } from "@shared/schema";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Shield, AlertTriangle, Check, X, Loader2, ArrowLeft } from "lucide-react";
import { Link } from "wouter";

export default function ReportPage() {
  const { id } = useParams<{ id: string }>(); // Ensure this line is correct
  console.log(id)

  const { data: scan, isLoading, error } = useQuery<Scan>({
    queryKey: [`/api/scans/${id}`], // Use the `id` from useParams
    refetchInterval: (data) =>
      data && (data.status === "completed" || data.status === "failed")
        ? false
        : 1000, // Poll every second while scan is running
  });

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!scan || error) {
    let errorMessage = "Unknown error";

    if (error instanceof Error) {
      // Simplify error message display
      const match = error.message.match(/\{.*?\}/);
      if (match) {
        try {
          const errorObj = JSON.parse(match[0]);
          errorMessage = errorObj.error;
        } catch {
          errorMessage = error.message;
        }
      }
    }

    return (
      <div className="min-h-screen flex items-center justify-center p-4">
        <Alert variant="destructive" className="w-full max-w-md">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>
            {errorMessage}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  const results = scan.results as any;

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <Link href="/">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Dashboard
            </Button>
          </Link>
        </div>

        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Security Scan Report</h1>
          <p className="text-muted-foreground">
            Target: {scan.url}
          </p>
          <p className="text-sm text-muted-foreground">
            Scan started: {new Date(scan.createdAt!).toLocaleString()}
          </p>
        </div>

        {scan.status === "running" ? (
          <Card>
            <CardContent className="p-8">
              <div className="text-center mb-4">
                <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-muted-foreground" />
                <p className="mb-4">Scan in progress...</p>
              </div>
              <Progress value={scan.progress} className="w-full" />
              <p className="text-sm text-muted-foreground text-center mt-2">
                {scan.progress}% complete
              </p>
            </CardContent>
          </Card>
        ) : scan.status === "completed" && results ? (
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
                        {results.ssl.issues.map((issue: string) => (
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
                {results.headers.missing &&
                  results.headers.missing.length > 0 && (
                    <Alert variant="destructive">
                      <AlertTitle>Missing Headers</AlertTitle>
                      <AlertDescription>
                        <ul className="list-disc pl-4 mt-2">
                          {results.headers.missing.map((header: string) => (
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
                {results.xss.endpoints &&
                  results.xss.endpoints.length > 0 && (
                    <Alert variant="destructive">
                      <AlertTitle>Vulnerable Endpoints</AlertTitle>
                      <AlertDescription>
                        <ul className="list-disc pl-4 mt-2">
                          {results.xss.endpoints.map((endpoint: string) => (
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
                {results.sql.endpoints &&
                  results.sql.endpoints.length > 0 && (
                    <Alert variant="destructive">
                      <AlertTitle>Vulnerable Endpoints</AlertTitle>
                      <AlertDescription>
                        <ul className="list-disc pl-4 mt-2">
                          {results.sql.endpoints.map((endpoint: string) => (
                            <li key={endpoint}>{endpoint}</li>
                          ))}
                        </ul>
                      </AlertDescription>
                    </Alert>
                  )}
              </CardContent>
            </Card>
          </div>
        ) : (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>Scan failed to complete</AlertDescription>
          </Alert>
        )}
      </div>
    </div>
  );
}