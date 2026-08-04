import { RBACConfigurationError, RBACUsageError } from "./errors.js";
import type {
  AuthorizationDecision,
  AuthorizationDenialReason,
  NonEmptyReadonlyArray,
  RBAC,
  RBACConfig,
  RBACSubject,
  RoleShape,
} from "./types.js";

const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]*$/;
const PERMISSION_PATTERN = /^[a-z][a-z0-9._-]*:[a-z][a-z0-9._-]*$/;

type RuntimeRole = {
  readonly permissions: readonly string[];
  readonly parents: readonly string[];
};

type CompiledRole = {
  readonly permissions: ReadonlySet<string>;
  readonly wildcard: boolean;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function configurationError(
  code: ConstructorParameters<typeof RBACConfigurationError>[0],
  message: string,
): never {
  throw new RBACConfigurationError(code, message);
}

function validateConfiguration(config: unknown): {
  readonly permissions: ReadonlySet<string>;
  readonly roles: ReadonlyMap<string, RuntimeRole>;
} {
  if (!isRecord(config)) {
    return configurationError("INVALID_CONFIG", "RBAC configuration must be an object.");
  }

  const rawPermissions = config.permissions;
  if (!Array.isArray(rawPermissions)) {
    return configurationError("INVALID_CONFIG", "permissions must be an array.");
  }
  if (rawPermissions.length === 0) {
    return configurationError(
      "EMPTY_PERMISSION_CATALOG",
      "At least one permission must be declared.",
    );
  }

  const permissions = new Set<string>();
  for (const permission of rawPermissions) {
    if (typeof permission !== "string" || !PERMISSION_PATTERN.test(permission)) {
      return configurationError(
        "INVALID_PERMISSION",
        `Invalid permission identifier: ${String(permission)}.`,
      );
    }
    if (permissions.has(permission)) {
      return configurationError(
        "DUPLICATE_PERMISSION",
        `Permission ${permission} is declared more than once.`,
      );
    }
    permissions.add(permission);
  }

  const rawRoles = config.roles;
  if (!isRecord(rawRoles)) {
    return configurationError("INVALID_CONFIG", "roles must be an object.");
  }

  const roleEntries = Object.entries(rawRoles);
  if (roleEntries.length === 0) {
    return configurationError("EMPTY_ROLE_CATALOG", "At least one role must be declared.");
  }

  const roles = new Map<string, RuntimeRole>();
  for (const [role, definition] of roleEntries) {
    if (!IDENTIFIER_PATTERN.test(role)) {
      return configurationError("INVALID_ROLE", `Invalid role identifier: ${role}.`);
    }
    if (!isRecord(definition)) {
      return configurationError(
        "INVALID_ROLE_DEFINITION",
        `Role ${role} must be configured with an object.`,
      );
    }

    const rawRolePermissions = definition.permissions;
    if (!Array.isArray(rawRolePermissions)) {
      return configurationError(
        "INVALID_ROLE_PERMISSIONS",
        `Role ${role} permissions must be an array.`,
      );
    }

    const rolePermissions: string[] = [];
    const seenRolePermissions = new Set<string>();
    for (const permission of rawRolePermissions) {
      if (typeof permission !== "string") {
        return configurationError(
          "INVALID_ROLE_PERMISSIONS",
          `Role ${role} contains a non-string permission.`,
        );
      }
      if (seenRolePermissions.has(permission)) {
        return configurationError(
          "DUPLICATE_ROLE_PERMISSION",
          `Role ${role} grants ${permission} more than once.`,
        );
      }
      if (permission !== "*" && !permissions.has(permission)) {
        return configurationError(
          "UNKNOWN_ROLE_PERMISSION",
          `Role ${role} grants undeclared permission ${permission}.`,
        );
      }
      seenRolePermissions.add(permission);
      rolePermissions.push(permission);
    }

    const rawParents = definition.extends ?? [];
    if (!Array.isArray(rawParents)) {
      return configurationError("INVALID_ROLE_PARENTS", `Role ${role} extends must be an array.`);
    }

    const parents: string[] = [];
    const seenParents = new Set<string>();
    for (const parent of rawParents) {
      if (typeof parent !== "string") {
        return configurationError(
          "INVALID_ROLE_PARENTS",
          `Role ${role} contains a non-string parent role.`,
        );
      }
      if (seenParents.has(parent)) {
        return configurationError(
          "DUPLICATE_PARENT_ROLE",
          `Role ${role} extends ${parent} more than once.`,
        );
      }
      seenParents.add(parent);
      parents.push(parent);
    }

    roles.set(role, {
      permissions: Object.freeze(rolePermissions),
      parents: Object.freeze(parents),
    });
  }

  for (const [role, definition] of roles) {
    for (const parent of definition.parents) {
      if (!roles.has(parent)) {
        return configurationError(
          "UNKNOWN_PARENT_ROLE",
          `Role ${role} extends unknown role ${parent}.`,
        );
      }
    }
  }

  return { permissions, roles };
}

function compileRoles(roles: ReadonlyMap<string, RuntimeRole>): ReadonlyMap<string, CompiledRole> {
  const compiled = new Map<string, CompiledRole>();
  const visiting = new Set<string>();

  const visit = (role: string, path: readonly string[]): CompiledRole => {
    const existing = compiled.get(role);
    if (existing) {
      return existing;
    }
    if (visiting.has(role)) {
      const cycle = [...path, role].join(" -> ");
      return configurationError(
        "CYCLIC_ROLE_INHERITANCE",
        `Role inheritance contains a cycle: ${cycle}.`,
      );
    }

    visiting.add(role);
    const definition = roles.get(role)!;

    const permissions = new Set<string>();
    let wildcard = false;
    for (const parent of definition.parents) {
      const compiledParent = visit(parent, [...path, role]);
      wildcard ||= compiledParent.wildcard;
      for (const permission of compiledParent.permissions) {
        permissions.add(permission);
      }
    }
    for (const permission of definition.permissions) {
      if (permission === "*") {
        wildcard = true;
      } else {
        permissions.add(permission);
      }
    }

    visiting.delete(role);
    const result = { permissions, wildcard };
    compiled.set(role, result);
    return result;
  };

  for (const role of roles.keys()) {
    visit(role, []);
  }
  return compiled;
}

function denied<Permission extends string, Role extends string>(
  permission: Permission,
  reason: AuthorizationDenialReason,
): AuthorizationDecision<Permission, Role> {
  return { allowed: false, permission, reason };
}

class RBACEngine<Permission extends string, Role extends string> implements RBAC<Permission, Role> {
  readonly #permissions: ReadonlySet<string>;
  readonly #roles: ReadonlyMap<string, CompiledRole>;

  constructor(permissions: ReadonlySet<string>, roles: ReadonlyMap<string, CompiledRole>) {
    this.#permissions = permissions;
    this.#roles = roles;
    Object.freeze(this);
  }

  evaluate(
    subject: RBACSubject<Role> | null | undefined,
    permission: Permission,
  ): AuthorizationDecision<Permission, Role> {
    if (!this.#permissions.has(permission)) {
      return denied(permission, "UNKNOWN_PERMISSION");
    }
    if (subject === null || subject === undefined) {
      return denied(permission, "SUBJECT_MISSING");
    }

    const roles: unknown = (subject as { readonly roles?: unknown }).roles;
    if (!Array.isArray(roles) || roles.length === 0) {
      return denied(permission, "NO_ROLES");
    }
    for (const role of roles) {
      if (typeof role !== "string" || !this.#roles.has(role)) {
        return denied(permission, "UNKNOWN_ROLE");
      }
    }

    for (const role of roles as Role[]) {
      const compiledRole = this.#roles.get(role);
      if (compiledRole?.wildcard) {
        return { allowed: true, permission, matchedRole: role, matchedBy: "*" };
      }
      if (compiledRole?.permissions.has(permission)) {
        return { allowed: true, permission, matchedRole: role, matchedBy: permission };
      }
    }

    return denied(permission, "PERMISSION_NOT_GRANTED");
  }

  can(subject: RBACSubject<Role> | null | undefined, permission: Permission): boolean {
    return this.evaluate(subject, permission).allowed;
  }

  canAny(
    subject: RBACSubject<Role> | null | undefined,
    permissions: NonEmptyReadonlyArray<Permission>,
  ): boolean {
    this.#assertNonEmpty(permissions);
    if (permissions.some((permission) => !this.isKnownPermission(permission))) {
      return false;
    }
    return permissions.some((permission) => this.can(subject, permission));
  }

  canAll(
    subject: RBACSubject<Role> | null | undefined,
    permissions: NonEmptyReadonlyArray<Permission>,
  ): boolean {
    this.#assertNonEmpty(permissions);
    if (permissions.some((permission) => !this.isKnownPermission(permission))) {
      return false;
    }
    return permissions.every((permission) => this.can(subject, permission));
  }

  isKnownPermission(permission: string): permission is Permission {
    return this.#permissions.has(permission);
  }

  #assertNonEmpty(permissions: readonly Permission[]): void {
    if (permissions.length === 0) {
      throw new RBACUsageError(
        "EMPTY_PERMISSION_LIST",
        "At least one permission must be provided.",
      );
    }
  }
}

export function createRBAC<
  const Permissions extends NonEmptyReadonlyArray<string>,
  const Roles extends Record<string, RoleShape>,
>(config: RBACConfig<Permissions, Roles>): RBAC<Permissions[number], Extract<keyof Roles, string>> {
  const validated = validateConfiguration(config);
  const compiledRoles = compileRoles(validated.roles);
  return new RBACEngine(validated.permissions, compiledRoles);
}
