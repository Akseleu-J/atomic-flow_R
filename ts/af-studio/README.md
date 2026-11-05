# Atomic Flow Studio

Studio runs at `/studio/` through the native Rust server. Its requests stay on the server's origin. Enter the server token in the connection bar when authentication is enabled. The page retains it in memory until reconnect or reload.

The graph uses a registered root ID. Use the main dashboard to register a project and build its graph. Chat runs against the local scripted backend in this surface. The reviewed edit panel activates when the host exposes a profile. It displays the expected source and replacement SHA-256 values, opens a root-bound session on submit, and records the resulting status. Keep the session ID when the result asks for reconciliation.

Build using Node 22 or later. From the repository's `ts` directory:

```sh
cd af-client
npm ci --ignore-scripts
npm run build
cd ../af-studio
npm ci --ignore-scripts
npm run build
npm test -- --maxWorkers=1 --minWorkers=1
```

Serve the generated `dist/index.html` and `dist/assets/` through the native Studio route. Browser tests that use jsdom cover the client workflow against fixtures. Native HTTP smoke checks exercise the actual server routes.
