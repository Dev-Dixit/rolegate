# @rolegate/core

## 0.2.0

### Minor Changes

- baf9226: Add `createExpressRoleGate` for a one-package Express setup that infers inline policies without
  `as const`, resolves trusted roles, exposes the shared engine, and preserves the existing advanced
  factories.

## 0.1.0

### Minor Changes

- Initial preview release of the dependency-free RoleGate authorization engine.
- Add type-safe roles, permissions, inheritance, wildcard grants, and detailed decisions.
- Add fail-closed runtime validation and stable configuration and usage errors.
