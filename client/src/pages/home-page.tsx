import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import ScanForm from "@/components/scan-form";
import { useQuery } from "@tanstack/react-query";
import { Scan } from "@shared/schema";
import { LogOut, Loader2, Shield, Check, X } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function HomePage() {
  const { user, logoutMutation } = useAuth();
  const { data: scans, isLoading } = useQuery<Scan[]>({
    queryKey: ["/api/scans"],
    refetchInterval: 1000,
  });

  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <h1 className="text-xl font-bold">Security Scanner</h1>
          <div className="flex items-center gap-4">
            <span className="text-sm text-muted-foreground">{user?.username}</span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => logoutMutation.mutate()}
              disabled={logoutMutation.isPending}
            >
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="grid md:grid-cols-2 gap-8">
          <div>
            <h2 className="text-2xl font-bold mb-4">Start New Scan</h2>
            <ScanForm />
          </div>

          <div>
            <h2 className="text-2xl font-bold mb-4">Recent Scans</h2>
            {scans && scans.length > 0 ? (
              <div className="space-y-4">
                {scans.map((scan) => (
                  <div
                    key={scan.id}
                    onClick={() => setSelectedScan(scan)}
                    className="block p-4 rounded-lg border bg-card hover:bg-accent transition-colors cursor-pointer"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium truncate">{scan.url}</span>
                      <span className="text-sm text-muted-foreground">
                        {new Date(scan.createdAt!).toLocaleString()}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`text-sm px-2 py-1 rounded-full ${
                        scan.status === "completed" ? "bg-green-100 text-green-800" :
                        scan.status === "failed" ? "bg-red-100 text-red-800" :
                        "bg-yellow-100 text-yellow-800"
                      }`}>
                        {scan.status}
                        {scan.status === "running" && ` (${scan.progress}%)`}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground">No scans yet</p>
            )}
          </div>
        </div>

        {selectedScan && (
          <div className="mt-8">
            <h2 className="text-2xl font-bold mb-4">Scan Report</h2>
            <div className="grid md:grid-cols-2 gap-8">
              {Object.entries(selectedScan.results).map(([key, result]) => (
                <Card key={key}>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="h-5 w-5" />
                      {key.replace(/([A-Z])/g, ' $1').toUpperCase()}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center gap-2 mb-4">
                      {result.vulnerable || result.secure === false ? (
                        <X className="h-5 w-5 text-red-500" />
                      ) : (
                        <Check className="h-5 w-5 text-green-500" />
                      )}
                      <span>
                        {result.vulnerable || result.secure === false
                          ? `${key} vulnerabilities found`
                          : `${key} is secure`}
                      </span>
                    </div>
                    {result.issues && result.issues.length > 0 && (
                      <Alert variant="destructive">
                        <AlertTitle>Issues Found</AlertTitle>
                        <AlertDescription>
                          <ul className="list-disc pl-4 mt-2">
                            {result.issues.map((issue, index) => (
                              <li key={index}>{issue}</li>
                            ))}
                          </ul>
                        </AlertDescription>
                      </Alert>
                    )}
                    {result.endpoints && result.endpoints.length > 0 && (
                      <Alert variant="destructive">
                        <AlertTitle>Vulnerable Endpoints</AlertTitle>
                        <AlertDescription>
                          <ul className="list-disc pl-4 mt-2">
                            {result.endpoints.map((endpoint, index) => (
                              <li key={index}>{endpoint}</li>
                            ))}
                          </ul>
                        </AlertDescription>
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
