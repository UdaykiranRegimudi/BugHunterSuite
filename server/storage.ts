import { User, InsertUser, Scan, InsertScan } from "@shared/schema";
import session from "express-session";
import createMemoryStore from "memorystore";
import { randomBytes } from "crypto";

const MemoryStore = createMemoryStore(session);

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  createScan(userId: number, scan: InsertScan): Promise<Scan>;
  getScan(id: number): Promise<Scan | undefined>;
  getUserScans(userId: number): Promise<Scan[]>;
  updateScanResults(id: number, results: any): Promise<void>;
  updateScanProgress(id: number, progress: number): Promise<void>;
  sessionStore: session.Store;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private scans: Map<number, Scan>;
  private currentUserId: number;
  private currentScanId: number;
  sessionStore: session.Store;

  constructor() {
    this.users = new Map();
    this.scans = new Map();
    this.currentUserId = 1;
    this.currentScanId = 1;
    this.sessionStore = new MemoryStore({
      checkPeriod: 86400000,
    });
  }

  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserId++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async createScan(userId: number, scan: InsertScan): Promise<Scan> {
    const id = this.currentScanId++;
    const newScan: Scan = {
      id,
      userId,
      ...scan,
      status: 'running',
      progress: 0,
      results: null,
      createdAt: new Date(),
    };
    this.scans.set(id, newScan);
    return newScan;
  }

  async getScan(id: number): Promise<Scan | undefined> {
    return this.scans.get(id);
  }

  async getUserScans(userId: number): Promise<Scan[]> {
    return Array.from(this.scans.values()).filter(
      (scan) => scan.userId === userId,
    );
  }

  async updateScanResults(id: number, results: any): Promise<void> {
    const scan = await this.getScan(id);
    if (scan) {
      this.scans.set(id, { ...scan, status: 'completed', progress: 100, results });
    }
  }

  async updateScanProgress(id: number, progress: number): Promise<void> {
    const scan = await this.getScan(id);
    if (scan) {
      this.scans.set(id, { ...scan, progress });
    }
  }
}

export const storage = new MemStorage();