import { createRBAC, type PermissionOf, type RoleOf } from "../src/index.js";

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
  },
});

rbac.can({ roles: ["viewer"] }, "articles:read");
rbac.canAny({ roles: ["editor"] }, ["articles:read", "articles:update"]);
rbac.canAll({ roles: ["editor"] }, ["articles:read"]);

// @ts-expect-error Unknown permissions are rejected.
rbac.can({ roles: ["viewer"] }, "articles:delete");

// @ts-expect-error Unknown roles are rejected.
rbac.can({ roles: ["admin"] }, "articles:read");

// @ts-expect-error Permission lists must not be empty.
rbac.canAny({ roles: ["viewer"] }, []);

createRBAC({
  permissions: ["articles:read"],
  roles: {
    broken: {
      // @ts-expect-error Role grants must reference the permission catalog.
      permissions: ["articles:delete"],
    },
  },
});

createRBAC({
  permissions: ["articles:read"],
  roles: {
    viewer: {
      permissions: ["articles:read"],
    },
    broken: {
      // @ts-expect-error Parent roles must exist in this policy.
      extends: ["missing"],
      permissions: [],
    },
  },
});

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends <Value>() => Value extends Right ? 1 : 2
    ? true
    : false;
type Assert<Value extends true> = Value;

export type PermissionInference = Assert<
  Equal<PermissionOf<typeof rbac>, "articles:read" | "articles:update">
>;
export type RoleInference = Assert<Equal<RoleOf<typeof rbac>, "viewer" | "editor">>;
