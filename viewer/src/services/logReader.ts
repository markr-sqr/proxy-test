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

interface PreparedFilter {
  startTime: number | null;
  endTime: number | null;
  method: string | null;
  urlLower: string | null;
  severity: string | null;
}

function prepareFilter(query: LogQuery): PreparedFilter {
  let startTime: number | null = null;
  if (query.start) {
    const t = new Date(query.start).getTime();
    if (!isNaN(t)) startTime = t;
  }
  let endTime: number | null = null;
  if (query.end) {
    const t = new Date(query.end).getTime();
    if (!isNaN(t)) endTime = t;
  }
  return {
    startTime,
    endTime,
    method: query.method ? query.method.toUpperCase() : null,
    urlLower: query.url ? query.url.toLowerCase() : null,
    severity: query.severity ? query.severity.toUpperCase() : null,
  };
}

function matchesFilter(entry: LogEntry, f: PreparedFilter): boolean {
  if (f.startTime !== null) {
    if (new Date(entry.timestamp).getTime() < f.startTime) return false;
  }

  if (f.endTime !== null) {
    if (new Date(entry.timestamp).getTime() > f.endTime) return false;
  }

  if (f.method) {
    if (entry.method.toUpperCase() !== f.method) return false;
  }

  if (f.urlLower) {
    if (!entry.target.toLowerCase().includes(f.urlLower)) return false;
  }

  if (f.severity) {
    if (!entry.risks.some((r) => r.severity.toUpperCase() === f.severity))
      return false;
  }

  return true;
}

export async function queryLogs(query: LogQuery): Promise<LogResponse> {
  const all = await parseLogFile();
  const pf = prepareFilter(query);
  const filtered = all.filter((e) => matchesFilter(e, pf));
  const total = filtered.length;

  const start = (query.page - 1) * query.limit;
  const entries = filtered.slice(start, start + query.limit);

  return { page: query.page, limit: query.limit, total, entries };
}
