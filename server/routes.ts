import type { Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth } from "./auth";
import { storage } from "./storage";
import { insertScanSchema, urlSchema } from "@shared/schema";

async function mockSecurityCheck(url: string, updateProgress: (progress: number) => void) {
  const steps = [
    { name: 'SSL Check', weight: 25 },
    { name: 'Headers Check', weight: 25 },
    { name: 'XSS Check', weight: 25 },
    { name: 'SQL Injection Check', weight: 25 }
  ];

  let currentProgress = 0;
  for (const step of steps) {
    await new Promise(resolve => setTimeout(resolve, 500)); // Simulate work
    currentProgress += step.weight;
    updateProgress(currentProgress);
  }

  return {
    ssl: {
      valid: Math.random() > 0.3,
      issues: Math.random() > 0.7 ? ["Outdated SSL version"] : [],
    },
    headers: {
      secure: Math.random() > 0.4,
      missing: Math.random() > 0.6 ? ["X-Frame-Options"] : [],
    },
    xss: {
      vulnerable: Math.random() > 0.8,
      endpoints: Math.random() > 0.7 ? ["/search", "/comment"] : [],
    },
    sql: {
      vulnerable: Math.random() > 0.9,
      endpoints: Math.random() > 0.8 ? ["/login"] : [],
    }
  };
}

export async function registerRoutes(app: Express): Promise<Server> {
  setupAuth(app);

  app.post("/api/scans", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);

    try {
      const data = insertScanSchema.parse(req.body);
      urlSchema.parse(data.url);

      const scan = await storage.createScan(req.user!.id, data);

      // Start mock security check with progress updates
      mockSecurityCheck(data.url, async (progress) => {
        await storage.updateScanProgress(scan.id, progress);
      }).then(results => {
        storage.updateScanResults(scan.id, results);
      });

      res.status(201).json(scan);
    } catch (error) {
      res.status(400).json({ error: String(error) });
    }
  });

  app.get("/api/scans", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    const scans = await storage.getUserScans(req.user!.id);
    res.json(scans);
  });

  app.get("/api/scans/:id", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    const scan = await storage.getScan(Number(req.params.id));
    if (!scan) return res.sendStatus(404);
    if (scan.userId !== req.user!.id) return res.sendStatus(403);
    res.json(scan);
  });

  const httpServer = createServer(app);
  return httpServer;
}