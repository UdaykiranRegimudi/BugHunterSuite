import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import ScanForm from "@/components/scan-form";
import { useQuery } from "@tanstack/react-query";
import { Scan } from "@shared/schema";
import { LogOut, Loader2 } from "lucide-react";
import { Link } from "wouter";

export default function HomePage() {
  const { user, logoutMutation } = useAuth();
  const { data: scans, isLoading } = useQuery<Scan[]>({
    queryKey: ["/api/scans"],
  });

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <h1 className="text-xl font-bold">Security Scanner</h1>
          <div className="flex items-center gap-4">
            <span className="text-sm text-muted-foreground">
              {user?.username}
            </span>
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
            {isLoading ? (
              <div className="flex items-center justify-center p-8">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : scans && scans.length > 0 ? (
              <div className="space-y-4">
                {scans.map((scan) => (
                  <Link key={scan.id} href={`/report/${scan.id}`}>
                    <div className="block p-4 rounded-lg border bg-card hover:bg-accent transition-colors cursor-pointer">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium truncate">{scan.url}</span>
                        <span className="text-sm text-muted-foreground">
                          {new Date(scan.createdAt!).toLocaleString()}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-sm px-2 py-1 rounded-full ${
                            scan.status === "completed"
                              ? "bg-green-100 text-green-800"
                              : scan.status === "failed"
                              ? "bg-red-100 text-red-800"
                              : "bg-yellow-100 text-yellow-800"
                          }`}
                        >
                          {scan.status}
                        </span>
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground">No scans yet</p>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}