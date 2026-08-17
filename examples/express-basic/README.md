# Express basic example

Start the demo from the repository root:

```sh
pnpm --filter @rolegate/example-express-basic start
```

Try the authorization paths:

```sh
curl http://localhost:3000/articles
curl -H "x-demo-user: viewer" http://localhost:3000/articles
curl -X PATCH -H "x-demo-user: viewer" http://localhost:3000/articles/1
curl -X PATCH -H "x-demo-user: editor" http://localhost:3000/articles/1
curl -X DELETE -H "x-demo-user: admin" http://localhost:3000/articles/1
```

The header authentication is intentionally fake and exists only to make the example runnable. A real
application must verify its session or token before returning trusted roles from `getRoles`. The
example uses only `@rolegate/express` and creates its policy and middleware in one factory call.
