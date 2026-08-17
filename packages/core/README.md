# @rolegate/core

Dependency-free, type-safe role and permission authorization.

## Usage

```ts
import { createRBAC } from "@rolegate/core";

const rbac = createRBAC({
  permissions: ["articles:read", "articles:update"],
  roles: {
    viewer: {
      permissions: ["articles:read"],
    },
    editor: {
      extends: ["viewer"],
      permissions: ["articles:update"],
    },
    admin: {
      permissions: ["*"],
    },
  },
});

rbac.can({ roles: ["editor"] }, "articles:read"); // true through inheritance
rbac.canAny({ roles: ["viewer"] }, ["articles:update", "articles:read"]); // true
rbac.canAll({ roles: ["viewer"] }, ["articles:read", "articles:update"]); // false

const decision = rbac.evaluate({ roles: ["viewer"] }, "articles:update");
```

Permission and role unions are inferred from the configuration. TypeScript reports undeclared
permissions and roles at the call site.

## Rules

Permissions must match lowercase `resource:action` syntax. Segments may also contain digits,
periods, underscores, and hyphens. The only wildcard is the exact `*` role grant; patterns such as
`articles:*` are rejected.

Multiple roles use union semantics, inheritance is transitive, and any unknown runtime role causes
the subject to fail closed. Policies are validated and copied when `createRBAC` runs, so later
configuration mutations cannot change active authorization.

`evaluate` returns an `AuthorizationDecision` with one of these denial reasons:

- `SUBJECT_MISSING`
- `NO_ROLES`
- `UNKNOWN_ROLE`
- `UNKNOWN_PERMISSION`
- `PERMISSION_NOT_GRANTED`

Invalid policy configuration throws `RBACConfigurationError`. Invalid API usage, such as an empty
`canAny` list, throws `RBACUsageError`.
