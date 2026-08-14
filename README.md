# RoleGate

[![CI](https://github.com/Dev-Dixit/rolegate/actions/workflows/ci.yml/badge.svg)](https://github.com/Dev-Dixit/rolegate/actions/workflows/ci.yml)
[![npm core](https://img.shields.io/npm/v/%40rolegate%2Fcore.svg?label=%40rolegate%2Fcore)](https://www.npmjs.com/package/@rolegate/core)
[![npm express](https://img.shields.io/npm/v/%40rolegate%2Fexpress.svg?label=%40rolegate%2Fexpress)](https://www.npmjs.com/package/@rolegate/express)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Type-safe, deny-by-default role and permission authorization for Node.js applications.

RoleGate separates authorization from authentication. Your application verifies who the user is,
then RoleGate decides whether that trusted subject has a required permission.

## Packages

- `@rolegate/core` is the dependency-free authorization engine.
- `@rolegate/express` provides Express 4 and 5 middleware.
- `@rolegate/example-express-basic` is a private runnable example in this repository.

The packages require Node.js 22 or newer and publish both ESM and CommonJS entry points.

## Five-minute Express setup

```sh
npm install @rolegate/express express
```

```ts
import express from "express";
import { createExpressRoleGate } from "@rolegate/express";

const { rbac, authorize } = createExpressRoleGate({
  permissions: ["articles:read", "articles:create", "articles:update"],
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
  getRoles: (request) => request.user?.roles,
});

rbac.can({ roles: ["editor"] }, "articles:update"); // programmatic checks use the same policy

const app = express();
app.patch("/articles/:id", authenticate(), authorize("articles:update"), updateArticle);
```

Authentication middleware must run before authorization middleware. Never trust a role copied
directly from an unsigned token, request header, query parameter, or request body.

`getRoles` may be synchronous or asynchronous. Return `null` or `undefined` for an unauthenticated
request, and return an array for an authenticated user. Empty arrays and unknown roles fail closed
with `403`. For a shared engine or other advanced setup, use `createRBAC` from `@rolegate/core`
with `createExpressRBAC`; see the Express package README.

## Policy behavior

- Permissions use lowercase `resource:action` identifiers.
- Role grants match exact permissions.
- `*` grants every declared permission and is valid only inside a role.
- Multiple subject roles combine their grants.
- Role inheritance is transitive.
- Unknown permissions, unknown roles, missing subjects, and empty role lists fail closed.
- Invalid policies fail during startup with `RBACConfigurationError`.
- Ordinary access denial returns a decision or `false`; it does not throw.

There are deliberately no partial wildcards, explicit deny rules, resource predicates, database
lookups, policy mutation, NestJS adapters, or frontend helpers in the current release.

## Development

```sh
pnpm install
pnpm verify
```

Useful commands include `pnpm typecheck`, `pnpm test`, `pnpm test:coverage`, `pnpm build`,
and `pnpm pack:check`. User-visible changes should include a Changeset.

## Security

RoleGate is not an identity provider and does not verify tokens. Only pass roles obtained from an
authenticated, integrity-protected source. Frontend visibility checks are never a replacement for
server-side authorization.

See [SECURITY.md](./SECURITY.md) for reporting guidance.

## License

MIT
