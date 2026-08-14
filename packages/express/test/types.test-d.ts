import { createRBAC } from "@rolegate/core";

import { createExpressRBAC, createExpressRoleGate } from "../src/index.js";

const rbac = createRBAC({
  permissions: ["articles:read", "articles:update"],
  roles: {
    viewer: {
      permissions: ["articles:read"],
    },
    editor: {
      permissions: ["articles:update"],
    },
  },
});

const middleware = createExpressRBAC({
  rbac,
  getSubject: (request) => (request.headers.authorization ? { roles: ["viewer"] } : null),
});

middleware.authorize("articles:read");
middleware.authorizeAny("articles:read", "articles:update");
middleware.authorizeAll("articles:read");

// @ts-expect-error Unknown permissions are rejected.
middleware.authorize("articles:delete");

// @ts-expect-error At least one permission is required.
middleware.authorizeAny();

// @ts-expect-error Returned subject roles must exist in the policy.
createExpressRBAC({ rbac, getSubject: () => ({ roles: ["admin"] }) });

const roleGate = createExpressRoleGate({
  permissions: ["articles:read", "articles:update"],
  roles: {
    viewer: {
      permissions: ["articles:read"],
    },
    editor: {
      extends: ["viewer"],
      permissions: ["articles:update"],
    },
  },
  getRoles: (request) => (request.headers.authorization ? ["viewer"] : null),
});

roleGate.authorize("articles:read");
roleGate.authorizeAny("articles:read", "articles:update");
roleGate.authorizeAll("articles:read");
roleGate.rbac.can({ roles: ["editor"] }, "articles:read");

// @ts-expect-error Unknown permissions are rejected by the convenience middleware.
roleGate.authorize("articles:delete");

// @ts-expect-error At least one permission is required.
roleGate.authorizeAny();

// @ts-expect-error At least one permission is required.
roleGate.authorizeAll();

// @ts-expect-error Unknown roles are rejected by the returned engine.
roleGate.rbac.can({ roles: ["admin"] }, "articles:read");

createExpressRoleGate({
  permissions: ["articles:read"],
  roles: {
    viewer: {
      permissions: ["articles:read"],
    },
  },
  // @ts-expect-error getRoles must return only roles declared by the inline policy.
  getRoles: () => ["admin"],
});

createExpressRoleGate({
  permissions: ["articles:read"],
  roles: {
    broken: {
      // @ts-expect-error Role grants must reference the inline permission catalog.
      permissions: ["articles:delete"],
    },
  },
  getRoles: () => null,
});

createExpressRoleGate({
  permissions: ["articles:read"],
  roles: {
    viewer: {
      permissions: ["articles:read"],
    },
    broken: {
      // @ts-expect-error Parent roles must exist in the inline policy.
      extends: ["missing"],
      permissions: [],
    },
  },
  getRoles: () => null,
});
