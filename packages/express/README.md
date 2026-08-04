# @rolegate/express

Express 4 and 5 authorization middleware powered by `@rolegate/core`.

## Usage

```ts
import { createExpressRBAC } from "@rolegate/express";

const { authorize, authorizeAny, authorizeAll } = createExpressRBAC({
  rbac,
  getSubject: async (request) => {
    const user = await loadAuthenticatedUser(request);
    return user ? { roles: user.roles } : null;
  },
});

app.get("/articles", authorize("articles:read"), listArticles);
app.post("/articles", authorizeAny("articles:create", "articles:publish"), createArticle);
app.patch("/articles/:id", authorizeAll("articles:read", "articles:update"), updateArticle);
```

`getSubject` may be synchronous or asynchronous. It intentionally avoids assumptions about
`request.user`, Passport, JWTs, sessions, or an application's database.

Missing subjects receive a safe `401` JSON response. Authenticated subjects without permission
receive `403`. Default responses never reveal roles, permissions, or policy details.

## Custom denial handling

```ts
const middleware = createExpressRBAC({
  rbac,
  getSubject,
  onDenied: async ({ response, status, decision }) => {
    await auditDecision(decision);
    response.status(status).json({ error: "ACCESS_DENIED" });
  },
});
```

Errors thrown by `getSubject` or `onDenied` are passed to Express error middleware through
`next(error)`.

Authentication must run first, and all roles passed to RoleGate must come from a verified,
integrity-protected source.
