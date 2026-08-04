import { describe, expect, it } from "vitest";

import {
  RBACConfigurationError,
  RBACUsageError,
  createRBAC,
  type RBACConfigurationErrorCode,
} from "../src/index.js";

function createEngine() {
  return createRBAC({
    permissions: [
      "articles:read",
      "articles:create",
      "articles:update",
      "articles:delete",
    ] as const,
    roles: {
      viewer: {
        permissions: ["articles:read"],
      },
      editor: {
        extends: ["viewer"],
        permissions: ["articles:create", "articles:update"],
      },
      publisher: {
        extends: ["editor"],
        permissions: ["articles:delete"],
      },
      admin: {
        permissions: ["*"],
      },
      auditor: {
        permissions: [],
      },
    },
  });
}

function expectConfigurationError(input: unknown, code: RBACConfigurationErrorCode): void {
  try {
    createRBAC(input as never);
    throw new Error("Expected createRBAC to throw.");
  } catch (error) {
    expect(error).toBeInstanceOf(RBACConfigurationError);
    expect((error as RBACConfigurationError).code).toBe(code);
  }
}

describe("createRBAC", () => {
  it("grants exact permissions and returns a detailed decision", () => {
    const rbac = createEngine();

    expect(rbac.evaluate({ roles: ["editor"] }, "articles:update")).toEqual({
      allowed: true,
      permission: "articles:update",
      matchedRole: "editor",
      matchedBy: "articles:update",
    });
    expect(rbac.can({ roles: ["viewer"] }, "articles:update")).toBe(false);
  });

  it("combines permissions from multiple roles", () => {
    const rbac = createEngine();
    const subject = { roles: ["viewer", "editor"] } as const;

    expect(rbac.can(subject, "articles:read")).toBe(true);
    expect(rbac.can(subject, "articles:create")).toBe(true);
    expect(rbac.can(subject, "articles:delete")).toBe(false);
  });

  it("compiles transitive role inheritance", () => {
    const rbac = createEngine();
    const publisher = { roles: ["publisher"] } as const;

    expect(rbac.can(publisher, "articles:read")).toBe(true);
    expect(rbac.can(publisher, "articles:update")).toBe(true);
    expect(rbac.can(publisher, "articles:delete")).toBe(true);
  });

  it("supports only the global wildcard grant", () => {
    const rbac = createEngine();

    expect(rbac.evaluate({ roles: ["admin"] }, "articles:delete")).toEqual({
      allowed: true,
      permission: "articles:delete",
      matchedRole: "admin",
      matchedBy: "*",
    });
    expect(rbac.isKnownPermission("*")).toBe(false);
    expect(rbac.isKnownPermission("articles:*")).toBe(false);
  });

  it("supports any and all checks", () => {
    const rbac = createEngine();
    const editor = { roles: ["editor"] } as const;

    expect(rbac.canAny(editor, ["articles:update", "articles:delete"])).toBe(true);
    expect(rbac.canAll(editor, ["articles:read", "articles:update"])).toBe(true);
    expect(rbac.canAll(editor, ["articles:update", "articles:delete"])).toBe(false);
  });

  it("fails closed when any requested permission is unknown at runtime", () => {
    const rbac = createEngine();
    const editor = { roles: ["editor"] } as const;
    const permissions = ["articles:update", "unknown:permission"] as never;

    expect(rbac.canAny(editor, permissions)).toBe(false);
    expect(rbac.canAll(editor, permissions)).toBe(false);
  });

  it("returns stable denial reasons", () => {
    const rbac = createEngine();

    expect(rbac.evaluate(null, "articles:read")).toMatchObject({
      allowed: false,
      reason: "SUBJECT_MISSING",
    });
    expect(rbac.evaluate(undefined, "articles:read")).toMatchObject({
      allowed: false,
      reason: "SUBJECT_MISSING",
    });
    expect(rbac.evaluate({ roles: [] }, "articles:read")).toMatchObject({
      allowed: false,
      reason: "NO_ROLES",
    });
    expect(rbac.evaluate({ roles: ["unknown"] } as never, "articles:read")).toMatchObject({
      allowed: false,
      reason: "UNKNOWN_ROLE",
    });
    expect(rbac.evaluate({ roles: [42] } as never, "articles:read")).toMatchObject({
      allowed: false,
      reason: "UNKNOWN_ROLE",
    });
    expect(rbac.evaluate({} as never, "articles:read")).toMatchObject({
      allowed: false,
      reason: "NO_ROLES",
    });
    expect(rbac.evaluate({ roles: ["viewer"] }, "unknown:permission" as never)).toMatchObject({
      allowed: false,
      reason: "UNKNOWN_PERMISSION",
    });
    expect(rbac.evaluate({ roles: ["auditor"] }, "articles:read")).toMatchObject({
      allowed: false,
      reason: "PERMISSION_NOT_GRANTED",
    });
  });

  it("rejects empty any and all permission lists", () => {
    const rbac = createEngine();

    for (const check of [
      () => rbac.canAny({ roles: ["viewer"] }, [] as never),
      () => rbac.canAll({ roles: ["viewer"] }, [] as never),
    ]) {
      expect(check).toThrowError(RBACUsageError);
      try {
        check();
      } catch (error) {
        expect((error as RBACUsageError).code).toBe("EMPTY_PERMISSION_LIST");
      }
    }
  });

  it("defensively copies its configuration", () => {
    const config = {
      permissions: ["articles:read", "articles:update"] as const,
      roles: {
        viewer: {
          permissions: ["articles:read"] as const,
        },
        editor: {
          extends: ["viewer"] as const,
          permissions: ["articles:update"] as const,
        },
      },
    } as const;
    const rbac = createRBAC(config);

    (config.permissions as unknown as string[])[0] = "changed:permission";
    (config.roles.viewer.permissions as unknown as string[])[0] = "articles:update";
    (config.roles.editor.extends as unknown as string[])[0] = "editor";

    expect(rbac.can({ roles: ["viewer"] }, "articles:read")).toBe(true);
    expect(rbac.can({ roles: ["viewer"] }, "articles:update")).toBe(false);
    expect(rbac.can({ roles: ["editor"] }, "articles:read")).toBe(true);
    expect(Object.isFrozen(rbac)).toBe(true);
  });

  it("accepts documented identifier characters", () => {
    const rbac = createRBAC({
      permissions: ["blog.posts_v2:read-all"] as const,
      roles: {
        "content-editor_v2": {
          permissions: ["blog.posts_v2:read-all"],
        },
      },
    });

    expect(rbac.can({ roles: ["content-editor_v2"] }, "blog.posts_v2:read-all")).toBe(true);
  });

  it.each([
    [null, "INVALID_CONFIG"],
    [{ permissions: {}, roles: {} }, "INVALID_CONFIG"],
    [{ permissions: [], roles: {} }, "EMPTY_PERMISSION_CATALOG"],
    [
      { permissions: ["Articles:read"], roles: { viewer: { permissions: [] } } },
      "INVALID_PERMISSION",
    ],
    [{ permissions: ["*"], roles: { viewer: { permissions: [] } } }, "INVALID_PERMISSION"],
    [
      {
        permissions: ["articles:read", "articles:read"],
        roles: { viewer: { permissions: [] } },
      },
      "DUPLICATE_PERMISSION",
    ],
    [{ permissions: ["articles:read"], roles: null }, "INVALID_CONFIG"],
    [{ permissions: ["articles:read"], roles: {} }, "EMPTY_ROLE_CATALOG"],
    [{ permissions: ["articles:read"], roles: { Admin: { permissions: [] } } }, "INVALID_ROLE"],
    [{ permissions: ["articles:read"], roles: { viewer: null } }, "INVALID_ROLE_DEFINITION"],
    [{ permissions: ["articles:read"], roles: { viewer: {} } }, "INVALID_ROLE_PERMISSIONS"],
    [
      { permissions: ["articles:read"], roles: { viewer: { permissions: [42] } } },
      "INVALID_ROLE_PERMISSIONS",
    ],
    [
      {
        permissions: ["articles:read"],
        roles: { viewer: { permissions: ["articles:read", "articles:read"] } },
      },
      "DUPLICATE_ROLE_PERMISSION",
    ],
    [
      {
        permissions: ["articles:read"],
        roles: { viewer: { permissions: ["articles:*"] } },
      },
      "UNKNOWN_ROLE_PERMISSION",
    ],
    [
      {
        permissions: ["articles:read"],
        roles: { viewer: { permissions: [], extends: "base" } },
      },
      "INVALID_ROLE_PARENTS",
    ],
    [
      {
        permissions: ["articles:read"],
        roles: { viewer: { permissions: [], extends: [42] } },
      },
      "INVALID_ROLE_PARENTS",
    ],
    [
      {
        permissions: ["articles:read"],
        roles: {
          base: { permissions: [] },
          viewer: { permissions: [], extends: ["base", "base"] },
        },
      },
      "DUPLICATE_PARENT_ROLE",
    ],
    [
      {
        permissions: ["articles:read"],
        roles: { viewer: { permissions: [], extends: ["missing"] } },
      },
      "UNKNOWN_PARENT_ROLE",
    ],
    [
      {
        permissions: ["articles:read"],
        roles: {
          first: { permissions: [], extends: ["second"] },
          second: { permissions: [], extends: ["first"] },
        },
      },
      "CYCLIC_ROLE_INHERITANCE",
    ],
  ] as const)("rejects invalid configuration with %s", (input, code) => {
    expectConfigurationError(input, code);
  });
});

describe("public error classes", () => {
  it("retain names, codes, and messages", () => {
    const configurationError = new RBACConfigurationError("INVALID_CONFIG", "bad config");
    const usageError = new RBACUsageError("INVALID_PERMISSION_ARGUMENT", "bad call");

    expect(configurationError).toMatchObject({
      name: "RBACConfigurationError",
      code: "INVALID_CONFIG",
      message: "bad config",
    });
    expect(usageError).toMatchObject({
      name: "RBACUsageError",
      code: "INVALID_PERMISSION_ARGUMENT",
      message: "bad call",
    });
  });
});
