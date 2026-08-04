import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const temporaryRoot = mkdtempSync(join(tmpdir(), "rolegate-smoke-"));
const consumerRoot = join(temporaryRoot, "consumer");
const pnpmCli = process.env.npm_execpath;

function run(command, arguments_, cwd) {
  execFileSync(command, arguments_, {
    cwd,
    stdio: "inherit",
  });
}

function runPnpm(arguments_, cwd) {
  if (!pnpmCli) {
    throw new Error("Run this smoke test through the pnpm pack:check script.");
  }
  run(process.execPath, [pnpmCli, ...arguments_], cwd);
}

try {
  runPnpm(
    ["--filter", "@rolegate/core", "pack", "--pack-destination", temporaryRoot],
    workspaceRoot,
  );
  runPnpm(
    ["--filter", "@rolegate/express", "pack", "--pack-destination", temporaryRoot],
    workspaceRoot,
  );

  const tarballs = readdirSync(temporaryRoot)
    .filter((file) => file.endsWith(".tgz"))
    .map((file) => join(temporaryRoot, file));
  const coreTarball = tarballs.find((file) => file.includes("core"));
  const expressTarball = tarballs.find((file) => file.includes("express"));

  if (!coreTarball || !expressTarball) {
    throw new Error("Expected both package tarballs to be created.");
  }

  const coreSpec = `file:../${basename(coreTarball)}`;
  const expressSpec = `file:../${basename(expressTarball)}`;

  mkdirSync(consumerRoot);
  writeFileSync(
    join(consumerRoot, "package.json"),
    JSON.stringify(
      {
        name: "rolegate-smoke",
        private: true,
        type: "module",
        dependencies: {
          "@rolegate/core": coreSpec,
          "@rolegate/express": expressSpec,
          express: "5",
        },
      },
      null,
      2,
    ),
  );
  writeFileSync(
    join(consumerRoot, "pnpm-workspace.yaml"),
    `overrides:\n  "@rolegate/core": "${coreSpec}"\n`,
  );

  runPnpm(["install", "--ignore-scripts"], consumerRoot);

  const requiredFiles = [
    "node_modules/@rolegate/core/dist/index.js",
    "node_modules/@rolegate/core/dist/index.cjs",
    "node_modules/@rolegate/core/dist/index.d.ts",
    "node_modules/@rolegate/core/dist/index.d.cts",
    "node_modules/@rolegate/express/dist/index.js",
    "node_modules/@rolegate/express/dist/index.cjs",
    "node_modules/@rolegate/express/dist/index.d.ts",
    "node_modules/@rolegate/express/dist/index.d.cts",
  ];
  for (const file of requiredFiles) {
    if (!existsSync(join(consumerRoot, file))) {
      throw new Error(`Packed package is missing ${file}.`);
    }
  }

  const esmSmoke = `import { createRBAC } from "@rolegate/core";
import { createExpressRBAC } from "@rolegate/express";

const rbac = createRBAC({
  permissions: ["articles:read"],
  roles: { viewer: { permissions: ["articles:read"] } },
});
if (!rbac.can({ roles: ["viewer"] }, "articles:read")) {
  throw new Error("ESM core authorization failed.");
}
const middleware = createExpressRBAC({
  rbac,
  getSubject: () => ({ roles: ["viewer"] }),
});
if (typeof middleware.authorize("articles:read") !== "function") {
  throw new Error("ESM Express middleware creation failed.");
}
`;

  const cjsSmoke = `const { createRBAC } = require("@rolegate/core");
const { createExpressRBAC } = require("@rolegate/express");

const rbac = createRBAC({
  permissions: ["articles:read"],
  roles: { viewer: { permissions: ["articles:read"] } },
});
if (!rbac.can({ roles: ["viewer"] }, "articles:read")) {
  throw new Error("CommonJS core authorization failed.");
}
const middleware = createExpressRBAC({
  rbac,
  getSubject: () => ({ roles: ["viewer"] }),
});
if (typeof middleware.authorize("articles:read") !== "function") {
  throw new Error("CommonJS Express middleware creation failed.");
}
`;

  writeFileSync(join(consumerRoot, "smoke.mjs"), esmSmoke);
  writeFileSync(join(consumerRoot, "smoke.cjs"), cjsSmoke);
  run(process.execPath, ["smoke.mjs"], consumerRoot);
  run(process.execPath, ["smoke.cjs"], consumerRoot);

  console.log("Packed ESM and CommonJS consumer smoke tests passed.");
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}
