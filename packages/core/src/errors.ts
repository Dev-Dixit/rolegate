export const RBAC_CONFIGURATION_ERROR_CODES = [
  "INVALID_CONFIG",
  "EMPTY_PERMISSION_CATALOG",
  "INVALID_PERMISSION",
  "DUPLICATE_PERMISSION",
  "EMPTY_ROLE_CATALOG",
  "INVALID_ROLE",
  "INVALID_ROLE_DEFINITION",
  "INVALID_ROLE_PERMISSIONS",
  "INVALID_ROLE_PARENTS",
  "DUPLICATE_ROLE_PERMISSION",
  "DUPLICATE_PARENT_ROLE",
  "UNKNOWN_ROLE_PERMISSION",
  "UNKNOWN_PARENT_ROLE",
  "CYCLIC_ROLE_INHERITANCE",
] as const;

export type RBACConfigurationErrorCode = (typeof RBAC_CONFIGURATION_ERROR_CODES)[number];

export const RBAC_USAGE_ERROR_CODES = [
  "EMPTY_PERMISSION_LIST",
  "INVALID_PERMISSION_ARGUMENT",
  "UNKNOWN_PERMISSION_ARGUMENT",
] as const;

export type RBACUsageErrorCode = (typeof RBAC_USAGE_ERROR_CODES)[number];

export class RBACConfigurationError extends Error {
  override readonly name = "RBACConfigurationError";

  constructor(
    readonly code: RBACConfigurationErrorCode,
    message: string,
  ) {
    super(message);
  }
}

export class RBACUsageError extends Error {
  override readonly name = "RBACUsageError";

  constructor(
    readonly code: RBACUsageErrorCode,
    message: string,
  ) {
    super(message);
  }
}
