export interface Risk {
  severity: string;
  description: string;
}

export interface Payload {
  request_line: string;
  headers: [string, string][];
  body: string;
  body_is_binary: boolean;
  body_truncated: boolean;
}

export interface LogEntry {
  timestamp: string;
  client_ip: string;
  client_port: number;
  method: string;
  target: string;
  status: string;
  risks: Risk[];
  payload?: Payload;
}

export interface LogQuery {
  page: number;
  limit: number;
  start?: string;
  end?: string;
  method?: string;
  url?: string;
  severity?: string;
}

export interface LogResponse {
  page: number;
  limit: number;
  total: number;
  entries: LogEntry[];
}
