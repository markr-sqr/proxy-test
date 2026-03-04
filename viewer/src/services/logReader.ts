import { readFile, stat } from "fs/promises";
import { LogEntry, LogQuery, LogResponse } from "../types";

const LOG_FILE = process.env.PROXY_LOG_FILE || "/tmp/proxy.log";

let cachedEntries: LogEntry[] = [];
let cachedMtimeMs = 0;
let cachedSize = 0;

async function parseLogFile(): Promise<LogEntry[]> {
  let fileStat;
  try {
    fileStat = await stat(LOG_FILE);
  } catch {
    return [];
  }

  // Return cache if file hasn't changed
  if (fileStat.mtimeMs === cachedMtimeMs && fileStat.size === cachedSize) {
    return cachedEntries;
  }

  const content = await readFile(LOG_FILE, "utf-8");
  const entries: LogEntry[] = [];

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      entries.push(JSON.parse(trimmed) as LogEntry);
    } catch {
      // skip malformed lines
    }
  }

  cachedEntries = entries;
  cachedMtimeMs = fileStat.mtimeMs;
  cachedSize = fileStat.size;

  return entries;
}

function matchesQuery(entry: LogEntry, query: LogQuery): boolean {
  if (query.start) {
    const startTime = new Date(query.start).getTime();
    if (isNaN(startTime)) return true;
    if (new Date(entry.timestamp).getTime() < startTime) return false;
  }

  if (query.end) {
    const endTime = new Date(query.end).getTime();
    if (isNaN(endTime)) return true;
    if (new Date(entry.timestamp).getTime() > endTime) return false;
  }

  if (query.method) {
    if (entry.method.toUpperCase() !== query.method.toUpperCase()) return false;
  }

  if (query.url) {
    if (!entry.target.toLowerCase().includes(query.url.toLowerCase()))
      return false;
  }

  if (query.severity) {
    const sev = query.severity.toUpperCase();
    if (!entry.risks.some((r) => r.severity.toUpperCase() === sev))
      return false;
  }

  return true;
}

export async function queryLogs(query: LogQuery): Promise<LogResponse> {
  const all = await parseLogFile();
  const filtered = all.filter((e) => matchesQuery(e, query));
  const total = filtered.length;

  const start = (query.page - 1) * query.limit;
  const entries = filtered.slice(start, start + query.limit);

  return { page: query.page, limit: query.limit, total, entries };
}
