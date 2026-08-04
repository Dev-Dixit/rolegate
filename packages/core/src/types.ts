export const AUTHORIZATION_DENIAL_REASONS = [
  "SUBJECT_MISSING",
  "NO_ROLES",
  "UNKNOWN_ROLE",
  "UNKNOWN_PERMISSION",
  "PERMISSION_NOT_GRANTED",
] as const;

export type AuthorizationDenialReason = (typeof AUTHORIZATION_DENIAL_REASONS)[number];

export type NonEmptyReadonlyArray<Value> = readonly [Value, ...Value[]];

export type RBACSubject<Role extends string> = {
  readonly roles: readonly Role[];
};

export type AuthorizationDecision<Permission extends string, Role extends string> =
  | {
      readonly allowed: true;
      readonly permission: Permission;
      readonly matchedRole: Role;
      readonly matchedBy: Permission | "*";
    }
  | {
      readonly allowed: false;
      readonly permission: Permission;
      readonly reason: AuthorizationDenialReason;
    };

export type RoleDefinition<Permission extends string, Role extends string> = {
  readonly permissions: readonly (Permission | "*")[];
  readonly extends?: readonly Role[];
};

export type RoleShape = {
  readonly permissions: readonly string[];
  readonly extends?: readonly string[];
};

export type RBACConfig<
  Permissions extends NonEmptyReadonlyArray<string>,
  Roles extends Record<string, RoleShape>,
> = {
  readonly permissions: Permissions;
  readonly roles: Roles & {
    readonly [Role in keyof Roles]: RoleDefinition<
      Permissions[number],
      Extract<keyof Roles, string>
    >;
  };
};

export interface RBAC<Permission extends string, Role extends string> {
  evaluate(
    subject: RBACSubject<Role> | null | undefined,
    permission: Permission,
  ): AuthorizationDecision<Permission, Role>;

  can(subject: RBACSubject<Role> | null | undefined, permission: Permission): boolean;

  canAny(
    subject: RBACSubject<Role> | null | undefined,
    permissions: NonEmptyReadonlyArray<Permission>,
  ): boolean;

  canAll(
    subject: RBACSubject<Role> | null | undefined,
    permissions: NonEmptyReadonlyArray<Permission>,
  ): boolean;

  isKnownPermission(permission: string): permission is Permission;
}

export type PermissionOf<Engine> =
  Engine extends RBAC<infer Permission, string> ? Permission : never;

export type RoleOf<Engine> = Engine extends RBAC<string, infer Role> ? Role : never;
