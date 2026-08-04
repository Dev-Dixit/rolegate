import express from "express";
import type { Request, RequestHandler } from "express";

import { createRBAC, type RBACSubject } from "@rolegate/core";
import { createExpressRBAC } from "@rolegate/express";

const rbac = createRBAC({
  permissions: ["articles:read", "articles:create", "articles:update", "articles:delete"] as const,
  roles: {
    viewer: {
      permissions: ["articles:read"],
    },
    editor: {
      extends: ["viewer"],
      permissions: ["articles:create", "articles:update"],
    },
    admin: {
      permissions: ["*"],
    },
  },
});

type Role = "viewer" | "editor" | "admin";
type DemoRequest = Request & {
  demoSubject?: RBACSubject<Role>;
};

const authenticateDemoUser: RequestHandler = (request, _response, next) => {
  const user = request.header("x-demo-user");
  if (user === "viewer" || user === "editor" || user === "admin") {
    (request as DemoRequest).demoSubject = { roles: [user] };
  }
  next();
};

const { authorize } = createExpressRBAC({
  rbac,
  getSubject: (request) => (request as DemoRequest).demoSubject ?? null,
});

const app = express();
app.use(express.json());
app.use(authenticateDemoUser);

app.get("/health", (_request, response) => {
  response.json({ ok: true });
});

app.get("/articles", authorize("articles:read"), (_request, response) => {
  response.json({ articles: [] });
});

app.post("/articles", authorize("articles:create"), (_request, response) => {
  response.status(201).json({ id: "article-1" });
});

app.patch("/articles/:id", authorize("articles:update"), (request, response) => {
  response.json({ id: request.params.id, updated: true });
});

app.delete("/articles/:id", authorize("articles:delete"), (_request, response) => {
  response.status(204).end();
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  console.log(`RoleGate example listening on http://localhost:${port}`);
  console.log("Use x-demo-user: viewer, editor, or admin to authenticate demo requests.");
});
