import { Router, Request, Response } from "express";
import { LogQuery } from "../types";
import { queryLogs } from "../services/logReader";

const router = Router();

router.get("/", async (req: Request, res: Response) => {
  const page = Math.max(1, parseInt(req.query.page as string) || 1);
  const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit as string) || 50));

  const query: LogQuery = {
    page,
    limit,
    start: (req.query.start as string) || undefined,
    end: (req.query.end as string) || undefined,
    method: (req.query.method as string) || undefined,
    url: (req.query.url as string) || undefined,
    severity: (req.query.severity as string) || undefined,
  };

  res.json(await queryLogs(query));
});

export default router;
