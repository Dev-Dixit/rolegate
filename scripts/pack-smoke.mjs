import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const temporaryRoot = mkdtempSync(join(tmpdir(), "rolegate-smoke-"));
const convenienceRoot = join(temporaryRoot, "express-consumer");
const coreConsumerRoot = join(temporaryRoot, "core-consumer");
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

function writeJson(path, value) {
  writeFileSync(path, JSON.stringify(value, null, 2));
}

function assertFiles(root, files) {
  for (const file of files) {
    if (!existsSync(join(root, file))) {
      throw new Error("Packed package is missing " + file + ".");
    }
  }
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

  const coreSpec = "file:../" + basename(coreTarball);
  const expressSpec = "file:../" + basename(expressTarball);

  mkdirSync(convenienceRoot);
  writeJson(join(convenienceRoot, "package.json"), {
    name: "rolegate-express-smoke",
    private: true,
    type: "module",
    dependencies: {
      "@rolegate/express": expressSpec,
      express: "5",
    },
    devDependencies: {
      "@types/express": "5",
      typescript: "5.9.3",
    },
  });
  writeFileSync(
    join(convenienceRoot, "pnpm-workspace.yaml"),
    'overrides:\n  "@rolegate/core": "' + coreSpec + '"\n',
  );

  runPnpm(["install", "--ignore-scripts"], convenienceRoot);

  const convenienceManifest = JSON.parse(
    readFileSync(join(convenienceRoot, "package.json"), "utf8"),
  );
  if (convenienceManifest.dependencies["@rolegate/core"]) {
    throw new Error("The convenience consumer must not declare @rolegate/core directly.");
  }

  assertFiles(convenienceRoot, [
    "node_modules/@rolegate/express/dist/index.js",
    "node_modules/@rolegate/express/dist/index.cjs",
    "node_modules/@rolegate/express/dist/index.d.ts",
    "node_modules/@rolegate/express/dist/index.d.cts",
  ]);

  const packedExpressManifest = JSON.parse(
    readFileSync(join(convenienceRoot, "node_modules/@rolegate/express/package.json"), "utf8"),
  );
  const packedCoreRange = packedExpressManifest.dependencies?.["@rolegate/core"];
  if (typeof packedCoreRange !== "string" || !/^\^\d+\.\d+\.\d+$/.test(packedCoreRange)) {
    throw new Error("Packed @rolegate/express contains an invalid @rolegate/core dependency.");
  }
  if (packedCoreRange.startsWith("workspace:")) {
    throw new Error("Packed @rolegate/express leaked a workspace dependency.");
  }

  const esmSmoke = [
    'import { createExpressRoleGate } from "@rolegate/express";',
    "",
    "const gate = createExpressRoleGate({",
    '  permissions: ["articles:read"],',
    '  roles: { viewer: { permissions: ["articles:read"] } },',
    '  getRoles: () => ["viewer"],',
    "});",
    'if (!gate.rbac.can({ roles: ["viewer"] }, "articles:read")) {',
    '  throw new Error("ESM convenience authorization failed.");',
    "}",
    'if (typeof gate.authorize("articles:read") !== "function") {',
    '  throw new Error("ESM convenience middleware creation failed.");',
    "}",
    "",
  ].join("\n");

  const cjsSmoke = [
    'const { createExpressRoleGate } = require("@rolegate/express");',
    "",
    "const gate = createExpressRoleGate({",
    '  permissions: ["articles:read"],',
    '  roles: { viewer: { permissions: ["articles:read"] } },',
    '  getRoles: () => ["viewer"],',
    "});",
    'if (!gate.rbac.can({ roles: ["viewer"] }, "articles:read")) {',
    '  throw new Error("CommonJS convenience authorization failed.");',
    "}",
    'if (typeof gate.authorize("articles:read") !== "function") {',
    '  throw new Error("CommonJS convenience middleware creation failed.");',
    "}",
    "",
  ].join("\n");

  const typeSmoke = [
    'import { createExpressRoleGate } from "@rolegate/express";',
    "",
    "const gate = createExpressRoleGate({",
    '  permissions: ["articles:read", "articles:update"],',
    "  roles: {",
    '    viewer: { permissions: ["articles:read"] },',
    '    editor: { extends: ["viewer"], permissions: ["articles:update"] },',
    "  },",
    '  getRoles: () => ["editor"],',
    "});",
    "",
    'gate.authorize("articles:update");',
    'gate.rbac.can({ roles: ["editor"] }, "articles:read");',
    "",
  ].join("\n");

  writeFileSync(join(convenienceRoot, "smoke.mjs"), esmSmoke);
  writeFileSync(join(convenienceRoot, "smoke.cjs"), cjsSmoke);
  writeFileSync(join(convenienceRoot, "smoke.ts"), typeSmoke);
  writeJson(join(convenienceRoot, "tsconfig.json"), {
    compilerOptions: {
      module: "NodeNext",
      moduleResolution: "NodeNext",
      noEmit: true,
      strict: true,
      target: "ES2022",
    },
    include: ["smoke.ts"],
  });

  run(process.execPath, ["smoke.mjs"], convenienceRoot);
  run(process.execPath, ["smoke.cjs"], convenienceRoot);
  runPnpm(["exec", "tsc", "--project", "tsconfig.json"], convenienceRoot);

  mkdirSync(coreConsumerRoot);
  writeJson(join(coreConsumerRoot, "package.json"), {
    name: "rolegate-core-smoke",
    private: true,
    type: "module",
    dependencies: {
      "@rolegate/core": coreSpec,
    },
  });
  runPnpm(["install", "--ignore-scripts"], coreConsumerRoot);

  assertFiles(coreConsumerRoot, [
    "node_modules/@rolegate/core/dist/index.js",
    "node_modules/@rolegate/core/dist/index.cjs",
    "node_modules/@rolegate/core/dist/index.d.ts",
    "node_modules/@rolegate/core/dist/index.d.cts",
  ]);

  const coreEsmSmoke = [
    'import { createRBAC } from "@rolegate/core";',
    "const rbac = createRBAC({",
    '  permissions: ["articles:read"],',
    '  roles: { viewer: { permissions: ["articles:read"] } },',
    "});",
    'if (!rbac.can({ roles: ["viewer"] }, "articles:read")) {',
    '  throw new Error("ESM core authorization failed.");',
    "}",
    "",
  ].join("\n");

  const coreCjsSmoke = [
    'const { createRBAC } = require("@rolegate/core");',
    "const rbac = createRBAC({",
    '  permissions: ["articles:read"],',
    '  roles: { viewer: { permissions: ["articles:read"] } },',
    "});",
    'if (!rbac.can({ roles: ["viewer"] }, "articles:read")) {',
    '  throw new Error("CommonJS core authorization failed.");',
    "}",
    "",
  ].join("\n");

  writeFileSync(join(coreConsumerRoot, "smoke.mjs"), coreEsmSmoke);
  writeFileSync(join(coreConsumerRoot, "smoke.cjs"), coreCjsSmoke);
  run(process.execPath, ["smoke.mjs"], coreConsumerRoot);
  run(process.execPath, ["smoke.cjs"], coreConsumerRoot);

  console.log("Packed convenience, TypeScript, ESM, CommonJS, and core smoke tests passed.");
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}
