import express from "express";
import path from "path";
import logsRouter from "./routes/logs";

const PORT = parseInt(process.env.VIEWER_PORT || "9999", 10);

const app = express();

app.get("/", (_req, res) => {
  res.json({
    endpoints: {
      "GET /api/logs": "Paginated proxy logs (query: page, limit, start, end, method, url, severity)",
      "GET /ui/logs": "Log viewer UI",
      "GET /health": "Health check",
    },
  });
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/api/logs", logsRouter);

app.get("/ui/logs", (_req, res) => {
  res.sendFile(path.join(__dirname, "../public/logs.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[viewer] Listening on 0.0.0.0:${PORT}`);
});
