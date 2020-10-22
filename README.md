# wasm-x25519
[![npm](https://img.shields.io/npm/v/wasm-x25519.svg)](https://www.npmjs.com/package/wasm-x25519)

### 🛠️ Build with `wasm-pack build`

```
wasm-pack build
```

### 🎁 Publish to NPM with `wasm-pack publish`

NOTE: you'll need to edit pkg/package.json to include `wasm_x25519_bg.js` under `files` before running this command

```
wasm-pack publish
```

### Local benchmarks

Local benchmarks can be run by first building with `wasm-pack build -t web`, then running `python3 -m http.server`. Then, visit http://localhost:8000 and check your browser console.
