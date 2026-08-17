# @rolegate/express

## 0.2.0

### Minor Changes

- baf9226: Add `createExpressRoleGate` for a one-package Express setup that infers inline policies without
  `as const`, resolves trusted roles, exposes the shared engine, and preserves the existing advanced
  factories.

### Patch Changes

- Updated dependencies [baf9226]
  - @rolegate/core@0.2.0

## 0.1.0

### Minor Changes

- Initial preview release of the RoleGate middleware for Express 4 and Express 5.
- Add synchronous or asynchronous subject extraction and single, any, and all checks.
- Add safe default denial responses, custom denial handling, and Express error forwarding.
