# Third-party notices

The generated `src/ypso_keys/agent.js` bundles these unmodified packages:

| Package | Version | License | Source |
|---|---|---|---|
| frida-java-bridge | 7.0.13 | LGPL-2.0 WITH WxWindows-exception-3.1 | https://github.com/frida/frida-java-bridge |
| buffer | 6.0.3 | MIT | https://github.com/feross/buffer |
| base64-js | 1.5.1 | MIT | https://github.com/beatgammit/base64-js |
| ieee754 | 1.2.1 | BSD-3-Clause | https://github.com/feross/ieee754 |

License texts are in `licenses/`. `package-lock.json` pins the package URLs and integrity hashes, so `npm ci && npm run build:agent` rebuilds the bundle from those packages and this repository's `agent/read-preferences.js`.

Frida's Python package is a runtime dependency that is installed separately and pinned in `uv.lock`. Its license is at https://github.com/frida/frida-python.
