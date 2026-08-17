# @rolegate/express

Type-safe authorization middleware for Express 4 and 5, powered by `@rolegate/core`.

## Install

```sh
npm install @rolegate/express express
```

## Quick start

```ts
import { createExpressRoleGate } from "@rolegate/express";

const { rbac, authorize, authorizeAny, authorizeAll } = createExpressRoleGate({
  permissions: ["articles:read", "articles:create", "articles:update", "articles:publish"],
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
  getRoles: async (request) => {
    const user = await loadAuthenticatedUser(request);
    return user?.roles;
  },
});

app.get("/articles", authorize("articles:read"), listArticles);
app.post("/articles", authorizeAny("articles:create", "articles:publish"), createArticle);
app.patch("/articles/:id", authorizeAll("articles:read", "articles:update"), updateArticle);

rbac.can({ roles: ["editor"] }, "articles:update"); // true
```

Inline permissions and roles are inferred without `as const`. Invalid policy grants, inherited
roles, and route permissions are reported by TypeScript and are also validated during startup.

`getRoles` may be synchronous or asynchronous and is called once for each middleware invocation:

- Return `null` or `undefined` when the request is unauthenticated. RoleGate responds with `401`.
- Return an empty array for an authenticated user with no roles. RoleGate responds with `403`.
- Return declared roles to evaluate the policy. Unknown runtime roles fail closed with `403`.

RoleGate does not assume `request.user`, Passport, JWTs, sessions, or a database shape, and it
does not augment Express's global request types. The returned `rbac` uses exactly the same policy
for programmatic `can`, `canAny`, `canAll`, and `evaluate` checks.

Default denial responses never reveal role names, requested permissions, or decision details.

## Custom denial handling

```ts
const gate = createExpressRoleGate({
  permissions,
  roles,
  getRoles,
  onDenied: async ({ response, status, decision }) => {
    await auditDecision(decision);
    response.status(status).json({ error: "ACCESS_DENIED" });
  },
});
```

Errors thrown by `getRoles` or `onDenied` are passed to Express error middleware through
`next(error)`.

## Advanced: shared core engine

Install `@rolegate/core` directly when one engine must be shared across Express and other code.
The original factories remain fully supported:

```ts
import { createRBAC } from "@rolegate/core";
import { createExpressRBAC } from "@rolegate/express";

const rbac = createRBAC({ permissions, roles });
const middleware = createExpressRBAC({
  rbac,
  getSubject: (request) => {
    const roles = getTrustedRoles(request);
    return roles ? { roles } : null;
  },
});
```

RoleGate performs authorization, not authentication. Authentication middleware must run first, and
roles from JWTs, headers, sessions, or other sources must be trusted only after integrity and
identity validation. Browser-side checks are presentation logic; backend authorization remains
authoritative.
