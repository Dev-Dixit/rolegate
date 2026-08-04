export {
  RBACConfigurationError,
  RBACUsageError,
  RBAC_CONFIGURATION_ERROR_CODES,
  RBAC_USAGE_ERROR_CODES,
} from "./errors.js";
export { createRBAC } from "./engine.js";
export { AUTHORIZATION_DENIAL_REASONS } from "./types.js";

export type {
  AuthorizationDecision,
  AuthorizationDenialReason,
  NonEmptyReadonlyArray,
  PermissionOf,
  RBAC,
  RBACConfig,
  RBACSubject,
  RoleDefinition,
  RoleOf,
} from "./types.js";
export type { RBACConfigurationErrorCode, RBACUsageErrorCode } from "./errors.js";
