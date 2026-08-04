import { createRBAC } from "@rolegate/core";

import { createExpressRBAC } from "../src/index.js";

const rbac = createRBAC({
  permissions: ["articles:read", "articles:update"] as const,
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
