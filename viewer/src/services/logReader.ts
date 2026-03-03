import { readFileSync, existsSync } from "fs";
import { LogEntry, LogQuery, LogResponse } from "../types";

const LOG_FILE = process.env.PROXY_LOG_FILE || "/tmp/proxy.log";

function parseLogFile(): LogEntry[] {
  if (!existsSync(LOG_FILE)) {
    return [];
  }

  const content = readFileSync(LOG_FILE, "utf-8");
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

export function queryLogs(query: LogQuery): LogResponse {
  const all = parseLogFile();
  const filtered = all.filter((e) => matchesQuery(e, query));
  const total = filtered.length;

  const start = (query.page - 1) * query.limit;
  const entries = filtered.slice(start, start + query.limit);

  return { page: query.page, limit: query.limit, total, entries };
}
