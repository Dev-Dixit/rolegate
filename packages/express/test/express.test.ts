import express5 from "express";
import express4 from "express4";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import type { NextFunction, Request, Response } from "express";

import { RBACUsageError, createRBAC } from "@rolegate/core";

import { createExpressRBAC } from "../src/index.js";

const factories = [
  ["Express 4", express4],
  ["Express 5", express5],
] as const;

function createPolicy() {
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
      admin: {
        permissions: ["*"],
      },
    },
  });
}

function subjectFromHeader(requestValue: string | undefined) {
  if (requestValue === undefined) {
    return null;
  }
  if (requestValue === "viewer" || requestValue === "editor" || requestValue === "admin") {
    return { roles: [requestValue] } as const;
  }
  return { roles: [requestValue] } as never;
}

describe.each(factories)("%s integration", (_name, expressFactory) => {
  function createApp() {
    const app = expressFactory();
    const rbac = createPolicy();
    const middleware = createExpressRBAC({
      rbac,
      getSubject: async (incomingRequest) => {
        await Promise.resolve();
        const value = incomingRequest.header("x-role");
        return subjectFromHeader(value);
      },
    });

    app.get("/single", middleware.authorize("articles:read"), (_request, response) => {
      response.status(200).json({ ok: true });
    });
    app.post(
      "/any",
      middleware.authorizeAny("articles:create", "articles:delete"),
      (_request, response) => {
        response.status(200).json({ ok: true });
      },
    );
    app.patch(
      "/all",
      middleware.authorizeAll("articles:read", "articles:update"),
      (_request, response) => {
        response.status(200).json({ ok: true });
      },
    );
    app.delete("/admin", middleware.authorize("articles:delete"), (_request, response) => {
      response.status(200).json({ ok: true });
    });

    return app;
  }

  it("allows exact, inherited, any, all, and wildcard grants", async () => {
    const app = createApp();

    await request(app).get("/single").set("x-role", "viewer").expect(200, { ok: true });
    await request(app).post("/any").set("x-role", "editor").expect(200, { ok: true });
    await request(app).patch("/all").set("x-role", "editor").expect(200, { ok: true });
    await request(app).delete("/admin").set("x-role", "admin").expect(200, { ok: true });
  });

  it("returns the stable default 401 response for missing subjects", async () => {
    const response = await request(createApp()).get("/single").expect(401);

    expect(response.body).toEqual({
      error: {
        code: "UNAUTHORIZED",
        message: "Authentication required",
      },
    });
  });

  it("returns the stable default 403 response without leaking policy details", async () => {
    const response = await request(createApp())
      .delete("/admin")
      .set("x-role", "viewer")
      .expect(403);

    expect(response.body).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Insufficient permissions",
      },
    });
    expect(JSON.stringify(response.body)).not.toContain("articles:delete");
    expect(JSON.stringify(response.body)).not.toContain("viewer");
  });

  it("fails closed for unknown runtime roles", async () => {
    await request(createApp()).get("/single").set("x-role", "stale-role").expect(403);
  });

  it("denies any when every permission is missing and all when one is missing", async () => {
    const app = createApp();

    await request(app).post("/any").set("x-role", "viewer").expect(403);
    await request(app).patch("/all").set("x-role", "viewer").expect(403);
  });

  it("supports an asynchronous custom denial handler", async () => {
    const app = expressFactory();
    const rbac = createPolicy();
    const onDenied = vi.fn(async ({ response, status, decision }) => {
      await Promise.resolve();
      response.status(418).json({ originalStatus: status, reason: decision.reason });
    });
    const { authorize } = createExpressRBAC({
      rbac,
      getSubject: () => null,
      onDenied,
    });

    app.get("/", authorize("articles:read"));

    await request(app).get("/").expect(418, {
      originalStatus: 401,
      reason: "SUBJECT_MISSING",
    });
    expect(onDenied).toHaveBeenCalledTimes(1);
  });

  it("forwards subject extraction errors to Express", async () => {
    const app = expressFactory();
    const rbac = createPolicy();
    const { authorize } = createExpressRBAC({
      rbac,
      getSubject: () => {
        throw new Error("subject lookup failed");
      },
    });

    app.get("/", authorize("articles:read"));
    app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
      response.status(500).json({ message: (error as Error).message });
    });

    await request(app).get("/").expect(500, { message: "subject lookup failed" });
  });

  it("forwards custom denial handler errors to Express", async () => {
    const app = expressFactory();
    const rbac = createPolicy();
    const { authorize } = createExpressRBAC({
      rbac,
      getSubject: () => ({ roles: ["viewer"] }),
      onDenied: () => {
        throw new Error("denial handler failed");
      },
    });

    app.delete("/", authorize("articles:delete"));
    app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
      response.status(500).json({ message: (error as Error).message });
    });

    await request(app).delete("/").expect(500, { message: "denial handler failed" });
  });
});

describe("createExpressRBAC", () => {
  it("supports synchronous subject extraction and calls next exactly once", async () => {
    const rbac = createPolicy();
    const { authorize } = createExpressRBAC({
      rbac,
      getSubject: () => ({ roles: ["viewer"] }),
    });
    const middleware = authorize("articles:read");
    const next = vi.fn();
    const response = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    } as unknown as Response;

    middleware({} as Request, response, next);
    await vi.waitFor(() => {
      expect(next).toHaveBeenCalledTimes(1);
    });

    expect(response.status).not.toHaveBeenCalled();
    expect(response.json).not.toHaveBeenCalled();
  });

  it("constructs an immutable middleware collection", () => {
    const rbac = createPolicy();
    const middleware = createExpressRBAC({
      rbac,
      getSubject: () => ({ roles: ["viewer"] }),
    });

    expect(Object.isFrozen(middleware)).toBe(true);
  });

  it("rejects empty permission collections during route registration", () => {
    const rbac = createPolicy();
    const middleware = createExpressRBAC({
      rbac,
      getSubject: () => ({ roles: ["viewer"] }),
    });

    for (const register of [
      () => middleware.authorizeAny(...([] as unknown as ["articles:read"])),
      () => middleware.authorizeAll(...([] as unknown as ["articles:read"])),
    ]) {
      expect(register).toThrowError(RBACUsageError);
      try {
        register();
      } catch (error) {
        expect((error as RBACUsageError).code).toBe("EMPTY_PERMISSION_LIST");
      }
    }
  });

  it("rejects unknown and non-string permission arguments during route registration", () => {
    const rbac = createPolicy();
    const middleware = createExpressRBAC({
      rbac,
      getSubject: () => ({ roles: ["viewer"] }),
    });

    for (const [register, code] of [
      [() => middleware.authorize("unknown:permission" as never), "UNKNOWN_PERMISSION_ARGUMENT"],
      [() => middleware.authorize(undefined as never), "INVALID_PERMISSION_ARGUMENT"],
    ] as const) {
      expect(register).toThrowError(RBACUsageError);
      try {
        register();
      } catch (error) {
        expect((error as RBACUsageError).code).toBe(code);
      }
    }
  });
});
