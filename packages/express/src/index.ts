import { RBACUsageError } from "@rolegate/core";
import type {
  AuthorizationDecision,
  NonEmptyReadonlyArray,
  RBAC,
  RBACSubject,
} from "@rolegate/core";
import type { NextFunction, Request, RequestHandler, Response } from "express";

type MaybePromise<Value> = Value | Promise<Value>;
type AuthorizationMode = "single" | "any" | "all";
type DeniedDecision<Permission extends string, Role extends string> = Extract<
  AuthorizationDecision<Permission, Role>,
  { readonly allowed: false }
>;

export type ExpressDeniedStatus = 401 | 403;

export type ExpressDeniedContext<Permission extends string, Role extends string> = {
  readonly request: Request;
  readonly response: Response;
  readonly next: NextFunction;
  readonly status: ExpressDeniedStatus;
  readonly decision: DeniedDecision<Permission, Role>;
};

export type ExpressRBACOptions<Permission extends string, Role extends string> = {
  readonly rbac: RBAC<Permission, Role>;
  readonly getSubject: (
    request: Request,
  ) => MaybePromise<RBACSubject<NoInfer<Role>> | null | undefined>;
  readonly onDenied?: (
    context: ExpressDeniedContext<NoInfer<Permission>, NoInfer<Role>>,
  ) => MaybePromise<void>;
};

export type ExpressRBAC<Permission extends string> = {
  authorize(permission: Permission): RequestHandler;
  authorizeAny(...permissions: NonEmptyReadonlyArray<Permission>): RequestHandler;
  authorizeAll(...permissions: NonEmptyReadonlyArray<Permission>): RequestHandler;
};

const DEFAULT_UNAUTHORIZED_BODY = {
  error: {
    code: "UNAUTHORIZED",
    message: "Authentication required",
  },
} as const;

const DEFAULT_FORBIDDEN_BODY = {
  error: {
    code: "FORBIDDEN",
    message: "Insufficient permissions",
  },
} as const;

function invalidPermission(message: string, unknown: boolean): never {
  throw new RBACUsageError(
    unknown ? "UNKNOWN_PERMISSION_ARGUMENT" : "INVALID_PERMISSION_ARGUMENT",
    message,
  );
}

export function createExpressRBAC<Permission extends string, Role extends string>(
  options: ExpressRBACOptions<Permission, Role>,
): ExpressRBAC<Permission> {
  const { rbac, getSubject, onDenied } = options;

  const validatePermissions = (permissions: readonly unknown[]): readonly Permission[] => {
    if (permissions.length === 0) {
      throw new RBACUsageError(
        "EMPTY_PERMISSION_LIST",
        "At least one permission must be provided.",
      );
    }

    for (const permission of permissions) {
      if (typeof permission !== "string") {
        return invalidPermission("Permission arguments must be strings.", false);
      }
      if (!rbac.isKnownPermission(permission)) {
        return invalidPermission(`Unknown permission argument: ${permission}.`, true);
      }
    }

    return [...permissions] as Permission[];
  };

  const evaluate = (
    subject: RBACSubject<Role> | null | undefined,
    permissions: readonly Permission[],
    mode: AuthorizationMode,
  ): AuthorizationDecision<Permission, Role> => {
    if (mode === "single") {
      return rbac.evaluate(subject, permissions[0]!);
    }

    const decisions = permissions.map((permission) => rbac.evaluate(subject, permission));
    if (mode === "any") {
      const allowed = decisions.find((decision) => decision.allowed);
      if (allowed) {
        return allowed;
      }
      return decisions[0]!;
    }

    const denied = decisions.find((decision) => !decision.allowed);
    return denied ?? decisions[0]!;
  };

  const createMiddleware = (
    mode: AuthorizationMode,
    rawPermissions: readonly unknown[],
  ): RequestHandler => {
    const permissions = validatePermissions(rawPermissions);

    return (request, response, next): void => {
      const run = async (): Promise<void> => {
        const subject = await getSubject(request);
        const decision = evaluate(subject, permissions, mode);

        if (decision.allowed) {
          next();
          return;
        }

        const status: ExpressDeniedStatus = subject === null || subject === undefined ? 401 : 403;
        if (onDenied) {
          await onDenied({ request, response, next, status, decision });
          return;
        }

        if (status === 401) {
          response.status(status).json(DEFAULT_UNAUTHORIZED_BODY);
          return;
        }
        response.status(status).json(DEFAULT_FORBIDDEN_BODY);
      };

      void run().catch(next);
    };
  };

  return Object.freeze({
    authorize(permission: Permission): RequestHandler {
      return createMiddleware("single", [permission]);
    },
    authorizeAny(...permissions: NonEmptyReadonlyArray<Permission>): RequestHandler {
      return createMiddleware("any", permissions);
    },
    authorizeAll(...permissions: NonEmptyReadonlyArray<Permission>): RequestHandler {
      return createMiddleware("all", permissions);
    },
  });
}
