# Contributing

Use Node.js 22 or 24 and pnpm 11. Install dependencies with `pnpm install`, then run `pnpm verify`
before opening a pull request. User-visible changes require a Changeset created with
`pnpm changeset`.

Keep the core package framework-independent and free of runtime dependencies. Changes to access
decisions must include tests for both allowed and denied behavior.
