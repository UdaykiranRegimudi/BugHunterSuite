import type { Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth } from "./auth";
import { storage } from "./storage";
import { insertScanSchema, urlSchema } from "@shared/schema";
import { performSecurityCheck } from "./security-scanner";

export async function registerRoutes(app: Express): Promise<Server> {
  setupAuth(app);

  app.post("/api/scans", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);

    try {
      const data = insertScanSchema.parse(req.body);
      urlSchema.parse(data.url);

      const scan = await storage.createScan(req.user!.id, data);

      // Start security check with progress updates
      performSecurityCheck(data.url, async (progress) => {
        await storage.updateScanProgress(scan.id, progress);
      }).then(async (results) => {
        await storage.updateScanResults(scan.id, results);
      }).catch(async (error) => {
        const scan = await storage.getScan(scan.id);
        if (scan) {
          await storage.updateScanResults(scan.id, {
            error: error.message,
            ssl: { valid: false, issues: [error.message] },
            headers: { secure: false, missing: [] },
            xss: { vulnerable: false, endpoints: [] },
            sql: { vulnerable: false, endpoints: [] }
          });
        }
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