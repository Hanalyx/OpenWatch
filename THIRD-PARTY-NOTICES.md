# Third-party notices for OpenWatch

This inventory covers third-party open-source and source-available components.
It is generated from the dependency inputs below, not from a developer's installed tree.

## Scope and license terms

OpenWatch's own terms are in [LICENSE](LICENSE). Each dependency keeps its own terms.
The tables are an index, not a substitute for the upstream license and notice texts.

The Go table covers modules linked for Linux amd64 and arm64 with CGO disabled.
Its labels describe reviewed module-level licenses; upstream notices may name other terms.
For example, modernc.org/libc carries notices for code from musl and other sources.
The Go runtime's license is also included in the package license bundle.

Separate packages, such as kensa-rules and PostgreSQL, are outside this inventory.

Kensa uses Business Source License 1.1 (SPDX: BUSL-1.1), a source-available license.
Its pinned license defines a Compliance Scanning Service restriction and an additional
grant for individuals or organizations with annual revenue below USD 5,000,000,
allowing use for any purpose, including commercial use. Its stated Change Date is
2029-01-01 and Change License is Apache-2.0. Read the full pinned terms, including
the effective-date clause, before redistributing or offering a hosted service.

The frontend tables cover the full lockfile, including scoped, nested and optional
packages for other platforms. Runtime candidates are not proof of bundle inclusion:
Vite can omit unused code. Build/test-only means npm marks the entry as dev-only.
The Inter and JetBrains Mono fonts are bundled assets under OFL-1.1.

RPM and DEB builds install this inventory, OpenWatch's LICENSE, and
THIRD-PARTY-LICENSES.txt under /usr/share/licenses/openwatch/.
The bundle preserves upstream license, copyright and notice files for linked Go
modules and installed frontend runtime candidates. Build/test dependencies are
inventoried separately; their license texts are not shipped in this bundle.
Optional packages absent from the build platform are listed in the inventory but
not copied into the bundle. license-manifest.json records bundled sources, hashes,
the source commit and the dependency inputs used for that build.

## Dependency inputs

Content hashes identify the inputs without a date that changes on each run.

| Input | SHA-256 |
|---|---|
| `go.mod` | `4f46953150226315d05198554d728c5bb9bf9ee96563e364dd0b3df2e3000e28` |
| `go.sum` | `9885408117f6f67ec09aab68fc80d9873a40c5929d4ba04348774a9675b60624` |
| `frontend/package.json` | `e6540953c7768c1f9d2e3095d5a0bef9512de2053cbcfc189e9b56c564e503f7` |
| `frontend/package-lock.json` | `648935775727fe7145294f9780decd8c961e3821fee3a53b8190ce58a27cea19` |
| `packaging/third-party-go-licenses.json` | `6087c830ed961258f15e7a77a763991b184fe3a204fc73b07bef06513852582f` |

## Go modules

| Module | Version | Module-level license |
|---|---|---|
| `github.com/BurntSushi/toml` | v1.6.0 | MIT |
| `github.com/Hanalyx/kensa` | v0.10.0 | BUSL-1.1 |
| `github.com/apapsch/go-jsonmerge/v2` | v2.0.0 | MIT |
| `github.com/boombuler/barcode` | v1.1.0 | MIT |
| `github.com/dustin/go-humanize` | v1.0.1 | MIT |
| `github.com/elastic/go-libaudit/v2` | v2.6.2 | Apache-2.0 |
| `github.com/go-chi/chi/v5` | v5.3.0 | MIT |
| `github.com/go-pdf/fpdf` | v0.9.0 | MIT |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | MIT |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause |
| `github.com/jackc/pgpassfile` | v1.0.0 | MIT |
| `github.com/jackc/pgservicefile` | v0.0.0-20240606120523-5a60cdf6a761 | MIT |
| `github.com/jackc/pgx/v5` | v5.9.2 | MIT |
| `github.com/jackc/puddle/v2` | v2.2.2 | MIT |
| `github.com/kballard/go-shellquote` | v0.0.0-20180428030007-95032a82bc51 | MIT |
| `github.com/mfridman/interpolate` | v0.0.2 | MIT |
| `github.com/oapi-codegen/runtime` | v1.4.1 | Apache-2.0 |
| `github.com/pquerna/otp` | v1.5.0 | Apache-2.0 |
| `github.com/pressly/goose/v3` | v3.27.1 | MIT |
| `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748-24d4a6f8daec | BSD-3-Clause |
| `github.com/sethvargo/go-retry` | v0.3.0 | Apache-2.0 |
| `github.com/swaggest/swgui` | v1.8.7 | Apache-2.0 |
| `github.com/vearutop/statigz` | v1.4.0 | MIT |
| `go.uber.org/multierr` | v1.11.0 | MIT |
| `golang.org/x/crypto` | v0.56.0 | BSD-3-Clause |
| `golang.org/x/net` | v0.57.0 | BSD-3-Clause |
| `golang.org/x/sync` | v0.22.0 | BSD-3-Clause |
| `golang.org/x/sys` | v0.47.0 | BSD-3-Clause |
| `golang.org/x/text` | v0.41.0 | BSD-3-Clause |
| `gopkg.in/yaml.v3` | v3.0.1 | MIT AND Apache-2.0 |
| `modernc.org/libc` | v1.73.4 | BSD-3-Clause |
| `modernc.org/mathutil` | v1.7.1 | BSD-3-Clause |
| `modernc.org/memory` | v1.11.0 | BSD-3-Clause |
| `modernc.org/sqlite` | v1.53.0 | BSD-3-Clause |

## Frontend runtime candidates

Paths retain nested versions and optional platform packages.

| Lockfile path | Version | Declared license | Optional |
|---|---|---|---|
| `node_modules/@babel/code-frame` | 7.29.7 | MIT | no |
| `node_modules/@babel/generator` | 7.29.7 | MIT | no |
| `node_modules/@babel/helper-globals` | 7.29.7 | MIT | no |
| `node_modules/@babel/helper-module-imports` | 7.29.7 | MIT | no |
| `node_modules/@babel/helper-string-parser` | 7.29.7 | MIT | no |
| `node_modules/@babel/helper-validator-identifier` | 7.29.7 | MIT | no |
| `node_modules/@babel/parser` | 7.29.7 | MIT | no |
| `node_modules/@babel/runtime` | 7.29.7 | MIT | no |
| `node_modules/@babel/template` | 7.29.7 | MIT | no |
| `node_modules/@babel/traverse` | 7.29.7 | MIT | no |
| `node_modules/@babel/types` | 7.29.7 | MIT | no |
| `node_modules/@dnd-kit/accessibility` | 3.1.1 | MIT | no |
| `node_modules/@dnd-kit/core` | 6.3.1 | MIT | no |
| `node_modules/@dnd-kit/utilities` | 3.2.2 | MIT | no |
| `node_modules/@emotion/babel-plugin` | 11.13.5 | MIT | no |
| `node_modules/@emotion/cache` | 11.14.0 | MIT | no |
| `node_modules/@emotion/hash` | 0.9.2 | MIT | no |
| `node_modules/@emotion/is-prop-valid` | 1.4.0 | MIT | no |
| `node_modules/@emotion/memoize` | 0.9.0 | MIT | no |
| `node_modules/@emotion/react` | 11.14.0 | MIT | no |
| `node_modules/@emotion/serialize` | 1.3.3 | MIT | no |
| `node_modules/@emotion/sheet` | 1.4.0 | MIT | no |
| `node_modules/@emotion/styled` | 11.14.1 | MIT | no |
| `node_modules/@emotion/unitless` | 0.10.0 | MIT | no |
| `node_modules/@emotion/use-insertion-effect-with-fallbacks` | 1.2.0 | MIT | no |
| `node_modules/@emotion/utils` | 1.4.2 | MIT | no |
| `node_modules/@emotion/weak-memoize` | 0.4.0 | MIT | no |
| `node_modules/@fontsource/inter` | 5.2.8 | OFL-1.1 | no |
| `node_modules/@fontsource/jetbrains-mono` | 5.2.8 | OFL-1.1 | no |
| `node_modules/@hookform/resolvers` | 5.4.0 | MIT | no |
| `node_modules/@jridgewell/gen-mapping` | 0.3.13 | MIT | no |
| `node_modules/@jridgewell/resolve-uri` | 3.1.2 | MIT | no |
| `node_modules/@jridgewell/sourcemap-codec` | 1.5.5 | MIT | no |
| `node_modules/@jridgewell/trace-mapping` | 0.3.31 | MIT | no |
| `node_modules/@mui/core-downloads-tracker` | 7.3.11 | MIT | no |
| `node_modules/@mui/material` | 7.3.11 | MIT | no |
| `node_modules/@mui/private-theming` | 7.3.11 | MIT | no |
| `node_modules/@mui/styled-engine` | 7.3.10 | MIT | no |
| `node_modules/@mui/system` | 7.3.11 | MIT | no |
| `node_modules/@mui/types` | 7.4.12 | MIT | no |
| `node_modules/@mui/utils` | 7.3.11 | MIT | no |
| `node_modules/@popperjs/core` | 2.11.8 | MIT | no |
| `node_modules/@standard-schema/utils` | 0.3.0 | MIT | no |
| `node_modules/@tanstack/history` | 1.162.0 | MIT | no |
| `node_modules/@tanstack/query-core` | 5.101.2 | MIT | no |
| `node_modules/@tanstack/react-query` | 5.101.2 | MIT | no |
| `node_modules/@tanstack/react-router` | 1.170.17 | MIT | no |
| `node_modules/@tanstack/react-store` | 0.9.3 | MIT | no |
| `node_modules/@tanstack/router-core` | 1.171.14 | MIT | no |
| `node_modules/@tanstack/store` | 0.9.3 | MIT | no |
| `node_modules/@types/parse-json` | 4.0.2 | MIT | no |
| `node_modules/@types/prop-types` | 15.7.15 | MIT | no |
| `node_modules/@types/react` | 19.2.17 | MIT | no |
| `node_modules/@types/react-transition-group` | 4.4.12 | MIT | no |
| `node_modules/attr-accept` | 2.2.5 | MIT | no |
| `node_modules/babel-plugin-macros` | 3.1.0 | MIT | no |
| `node_modules/callsites` | 3.1.0 | MIT | no |
| `node_modules/clsx` | 2.1.1 | MIT | no |
| `node_modules/convert-source-map` | 1.9.0 | MIT | no |
| `node_modules/cookie-es` | 3.1.1 | MIT | no |
| `node_modules/cosmiconfig` | 7.1.0 | MIT | no |
| `node_modules/cosmiconfig/node_modules/yaml` | 1.10.3 | ISC | no |
| `node_modules/csstype` | 3.2.3 | MIT | no |
| `node_modules/debug` | 4.4.3 | MIT | no |
| `node_modules/dom-helpers` | 5.2.1 | MIT | no |
| `node_modules/error-ex` | 1.3.4 | MIT | no |
| `node_modules/es-errors` | 1.3.0 | MIT | no |
| `node_modules/escape-string-regexp` | 4.0.0 | MIT | no |
| `node_modules/file-selector` | 2.1.2 | MIT | no |
| `node_modules/find-root` | 1.1.0 | MIT | no |
| `node_modules/function-bind` | 1.1.2 | MIT | no |
| `node_modules/hasown` | 2.0.4 | MIT | no |
| `node_modules/hoist-non-react-statics` | 3.3.2 | BSD-3-Clause | no |
| `node_modules/hoist-non-react-statics/node_modules/react-is` | 16.13.1 | MIT | no |
| `node_modules/import-fresh` | 3.3.1 | MIT | no |
| `node_modules/is-arrayish` | 0.2.1 | MIT | no |
| `node_modules/is-core-module` | 2.16.2 | MIT | no |
| `node_modules/isbot` | 5.1.40 | Unlicense | no |
| `node_modules/js-tokens` | 4.0.0 | MIT | no |
| `node_modules/jsesc` | 3.1.0 | MIT | no |
| `node_modules/json-parse-even-better-errors` | 2.3.1 | MIT | no |
| `node_modules/lines-and-columns` | 1.2.4 | MIT | no |
| `node_modules/loose-envify` | 1.4.0 | MIT | no |
| `node_modules/lucide-react` | 1.23.0 | ISC | no |
| `node_modules/ms` | 2.1.3 | MIT | no |
| `node_modules/object-assign` | 4.1.1 | MIT | no |
| `node_modules/openapi-fetch` | 0.17.0 | MIT | no |
| `node_modules/openapi-typescript-helpers` | 0.1.0 | MIT | no |
| `node_modules/parent-module` | 1.0.1 | MIT | no |
| `node_modules/parse-json` | 5.2.0 | MIT | no |
| `node_modules/path-parse` | 1.0.7 | MIT | no |
| `node_modules/path-type` | 4.0.0 | MIT | no |
| `node_modules/picocolors` | 1.1.1 | ISC | no |
| `node_modules/prop-types` | 15.8.1 | MIT | no |
| `node_modules/prop-types/node_modules/react-is` | 16.13.1 | MIT | no |
| `node_modules/qrcode.react` | 4.2.0 | ISC | no |
| `node_modules/react` | 19.2.7 | MIT | no |
| `node_modules/react-dom` | 19.2.7 | MIT | no |
| `node_modules/react-dropzone` | 15.0.0 | MIT | no |
| `node_modules/react-hook-form` | 7.81.0 | MIT | no |
| `node_modules/react-is` | 19.2.6 | MIT | no |
| `node_modules/react-transition-group` | 4.4.5 | BSD-3-Clause | no |
| `node_modules/resolve` | 1.22.12 | MIT | no |
| `node_modules/resolve-from` | 4.0.0 | MIT | no |
| `node_modules/scheduler` | 0.27.0 | MIT | no |
| `node_modules/seroval` | 1.5.4 | MIT | no |
| `node_modules/seroval-plugins` | 1.5.4 | MIT | no |
| `node_modules/source-map` | 0.5.7 | BSD-3-Clause | no |
| `node_modules/stylis` | 4.2.0 | MIT | no |
| `node_modules/supports-preserve-symlinks-flag` | 1.0.0 | MIT | no |
| `node_modules/tslib` | 2.8.1 | 0BSD | no |
| `node_modules/use-sync-external-store` | 1.6.0 | MIT | no |
| `node_modules/zod` | 4.4.3 | MIT | no |
| `node_modules/zustand` | 5.0.14 | MIT | no |

## Frontend build and test dependencies

Paths retain nested versions and optional platform packages.

| Lockfile path | Version | Declared license | Optional |
|---|---|---|---|
| `node_modules/@adobe/css-tools` | 4.5.0 | MIT | no |
| `node_modules/@asamuzakjp/css-color` | 5.1.11 | MIT | no |
| `node_modules/@asamuzakjp/dom-selector` | 7.1.1 | MIT | no |
| `node_modules/@asamuzakjp/generational-cache` | 1.0.1 | MIT | no |
| `node_modules/@asamuzakjp/nwsapi` | 2.3.9 | MIT | no |
| `node_modules/@axe-core/playwright` | 4.12.1 | MPL-2.0 | no |
| `node_modules/@bramus/specificity` | 2.4.2 | MIT | no |
| `node_modules/@csstools/color-helpers` | 6.1.0 | MIT-0 | no |
| `node_modules/@csstools/css-calc` | 3.2.1 | MIT | no |
| `node_modules/@csstools/css-color-parser` | 4.1.9 | MIT | no |
| `node_modules/@csstools/css-parser-algorithms` | 4.0.0 | MIT | no |
| `node_modules/@csstools/css-syntax-patches-for-csstree` | 1.1.5 | MIT-0 | no |
| `node_modules/@csstools/css-tokenizer` | 4.0.0 | MIT | no |
| `node_modules/@emnapi/core` | 1.11.1 | MIT | yes |
| `node_modules/@emnapi/runtime` | 1.11.1 | MIT | yes |
| `node_modules/@emnapi/wasi-threads` | 1.2.2 | MIT | yes |
| `node_modules/@eslint-community/eslint-utils` | 4.9.1 | MIT | no |
| `node_modules/@eslint-community/eslint-utils/node_modules/eslint-visitor-keys` | 3.4.3 | Apache-2.0 | no |
| `node_modules/@eslint-community/regexpp` | 4.12.2 | MIT | no |
| `node_modules/@eslint/config-array` | 0.21.2 | Apache-2.0 | no |
| `node_modules/@eslint/config-helpers` | 0.4.2 | Apache-2.0 | no |
| `node_modules/@eslint/core` | 0.17.0 | Apache-2.0 | no |
| `node_modules/@eslint/eslintrc` | 3.3.5 | MIT | no |
| `node_modules/@eslint/eslintrc/node_modules/globals` | 14.0.0 | MIT | no |
| `node_modules/@eslint/js` | 9.39.4 | MIT | no |
| `node_modules/@eslint/object-schema` | 2.1.7 | Apache-2.0 | no |
| `node_modules/@eslint/plugin-kit` | 0.4.1 | Apache-2.0 | no |
| `node_modules/@exodus/bytes` | 1.15.1 | MIT | no |
| `node_modules/@humanfs/core` | 0.19.2 | Apache-2.0 | no |
| `node_modules/@humanfs/node` | 0.16.8 | Apache-2.0 | no |
| `node_modules/@humanfs/types` | 0.15.0 | Apache-2.0 | no |
| `node_modules/@humanwhocodes/module-importer` | 1.0.1 | Apache-2.0 | no |
| `node_modules/@humanwhocodes/retry` | 0.4.3 | Apache-2.0 | no |
| `node_modules/@napi-rs/wasm-runtime` | 1.1.6 | MIT | yes |
| `node_modules/@oxc-project/types` | 0.138.0 | MIT | no |
| `node_modules/@playwright/test` | 1.61.1 | Apache-2.0 | no |
| `node_modules/@redocly/ajv` | 8.11.2 | MIT | no |
| `node_modules/@redocly/ajv/node_modules/json-schema-traverse` | 1.0.0 | MIT | no |
| `node_modules/@redocly/config` | 0.22.0 | MIT | no |
| `node_modules/@redocly/openapi-core` | 1.34.15 | MIT | no |
| `node_modules/@redocly/openapi-core/node_modules/brace-expansion` | 2.1.1 | MIT | no |
| `node_modules/@redocly/openapi-core/node_modules/minimatch` | 5.1.9 | ISC | no |
| `node_modules/@rolldown/binding-android-arm64` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-darwin-arm64` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-darwin-x64` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-freebsd-x64` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-linux-arm-gnueabihf` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-linux-arm64-gnu` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-linux-arm64-musl` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-linux-ppc64-gnu` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-linux-s390x-gnu` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-linux-x64-gnu` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-linux-x64-musl` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-openharmony-arm64` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-wasm32-wasi` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-win32-arm64-msvc` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/binding-win32-x64-msvc` | 1.1.4 | MIT | yes |
| `node_modules/@rolldown/pluginutils` | 1.0.1 | MIT | no |
| `node_modules/@standard-schema/spec` | 1.1.0 | MIT | no |
| `node_modules/@tanstack/react-router-devtools` | 1.167.0 | MIT | no |
| `node_modules/@tanstack/router-devtools` | 1.167.0 | MIT | no |
| `node_modules/@tanstack/router-devtools-core` | 1.168.0 | MIT | no |
| `node_modules/@testing-library/dom` | 10.4.1 | MIT | no |
| `node_modules/@testing-library/jest-dom` | 6.9.1 | MIT | no |
| `node_modules/@testing-library/jest-dom/node_modules/dom-accessibility-api` | 0.6.3 | MIT | no |
| `node_modules/@testing-library/react` | 16.3.2 | MIT | no |
| `node_modules/@testing-library/user-event` | 14.6.1 | MIT | no |
| `node_modules/@tybys/wasm-util` | 0.10.3 | MIT | yes |
| `node_modules/@types/aria-query` | 5.0.4 | MIT | no |
| `node_modules/@types/chai` | 5.2.3 | MIT | no |
| `node_modules/@types/deep-eql` | 4.0.2 | MIT | no |
| `node_modules/@types/estree` | 1.0.9 | MIT | no |
| `node_modules/@types/json-schema` | 7.0.15 | MIT | no |
| `node_modules/@types/node` | 26.1.0 | MIT | no |
| `node_modules/@types/react-dom` | 19.2.3 | MIT | no |
| `node_modules/@typescript-eslint/eslint-plugin` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/eslint-plugin/node_modules/ignore` | 7.0.5 | MIT | no |
| `node_modules/@typescript-eslint/parser` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/project-service` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/scope-manager` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/tsconfig-utils` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/type-utils` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/types` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/typescript-estree` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/typescript-estree/node_modules/balanced-match` | 4.0.4 | MIT | no |
| `node_modules/@typescript-eslint/typescript-estree/node_modules/brace-expansion` | 5.0.7 | MIT | no |
| `node_modules/@typescript-eslint/typescript-estree/node_modules/minimatch` | 10.2.5 | BlueOak-1.0.0 | no |
| `node_modules/@typescript-eslint/typescript-estree/node_modules/semver` | 7.8.5 | ISC | no |
| `node_modules/@typescript-eslint/utils` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/visitor-keys` | 8.62.1 | MIT | no |
| `node_modules/@typescript-eslint/visitor-keys/node_modules/eslint-visitor-keys` | 5.0.1 | Apache-2.0 | no |
| `node_modules/@vitejs/plugin-react` | 6.0.3 | MIT | no |
| `node_modules/@vitest/expect` | 4.1.9 | MIT | no |
| `node_modules/@vitest/mocker` | 4.1.9 | MIT | no |
| `node_modules/@vitest/pretty-format` | 4.1.9 | MIT | no |
| `node_modules/@vitest/runner` | 4.1.9 | MIT | no |
| `node_modules/@vitest/snapshot` | 4.1.9 | MIT | no |
| `node_modules/@vitest/spy` | 4.1.9 | MIT | no |
| `node_modules/@vitest/utils` | 4.1.9 | MIT | no |
| `node_modules/@vitest/utils/node_modules/convert-source-map` | 2.0.0 | MIT | no |
| `node_modules/acorn` | 8.16.0 | MIT | no |
| `node_modules/acorn-jsx` | 5.3.2 | MIT | no |
| `node_modules/agent-base` | 7.1.4 | MIT | no |
| `node_modules/ajv` | 6.15.0 | MIT | no |
| `node_modules/ansi-colors` | 4.1.3 | MIT | no |
| `node_modules/ansi-regex` | 5.0.1 | MIT | no |
| `node_modules/ansi-styles` | 4.3.0 | MIT | no |
| `node_modules/argparse` | 2.0.1 | Python-2.0 | no |
| `node_modules/aria-query` | 5.3.0 | Apache-2.0 | no |
| `node_modules/array-buffer-byte-length` | 1.0.2 | MIT | no |
| `node_modules/array-includes` | 3.1.9 | MIT | no |
| `node_modules/array.prototype.findlast` | 1.2.5 | MIT | no |
| `node_modules/array.prototype.flat` | 1.3.3 | MIT | no |
| `node_modules/array.prototype.flatmap` | 1.3.3 | MIT | no |
| `node_modules/array.prototype.tosorted` | 1.1.4 | MIT | no |
| `node_modules/arraybuffer.prototype.slice` | 1.0.4 | MIT | no |
| `node_modules/assertion-error` | 2.0.1 | MIT | no |
| `node_modules/async-function` | 1.0.0 | MIT | no |
| `node_modules/available-typed-arrays` | 1.0.7 | MIT | no |
| `node_modules/axe-core` | 4.12.1 | MPL-2.0 | no |
| `node_modules/balanced-match` | 1.0.2 | MIT | no |
| `node_modules/bidi-js` | 1.0.3 | MIT | no |
| `node_modules/brace-expansion` | 1.1.15 | MIT | no |
| `node_modules/call-bind` | 1.0.9 | MIT | no |
| `node_modules/call-bind-apply-helpers` | 1.0.2 | MIT | no |
| `node_modules/call-bound` | 1.0.4 | MIT | no |
| `node_modules/chai` | 6.2.2 | MIT | no |
| `node_modules/chalk` | 4.1.2 | MIT | no |
| `node_modules/change-case` | 5.4.4 | MIT | no |
| `node_modules/color-convert` | 2.0.1 | MIT | no |
| `node_modules/color-name` | 1.1.4 | MIT | no |
| `node_modules/colorette` | 1.4.0 | MIT | no |
| `node_modules/concat-map` | 0.0.1 | MIT | no |
| `node_modules/cross-spawn` | 7.0.6 | MIT | no |
| `node_modules/css-tree` | 3.2.1 | MIT | no |
| `node_modules/css.escape` | 1.5.1 | MIT | no |
| `node_modules/data-urls` | 7.0.0 | MIT | no |
| `node_modules/data-view-buffer` | 1.0.2 | MIT | no |
| `node_modules/data-view-byte-length` | 1.0.2 | MIT | no |
| `node_modules/data-view-byte-offset` | 1.0.1 | MIT | no |
| `node_modules/decimal.js` | 10.6.0 | MIT | no |
| `node_modules/deep-is` | 0.1.4 | MIT | no |
| `node_modules/define-data-property` | 1.1.4 | MIT | no |
| `node_modules/define-properties` | 1.2.1 | MIT | no |
| `node_modules/dequal` | 2.0.3 | MIT | no |
| `node_modules/detect-libc` | 2.1.2 | Apache-2.0 | no |
| `node_modules/doctrine` | 2.1.0 | Apache-2.0 | no |
| `node_modules/dom-accessibility-api` | 0.5.16 | MIT | no |
| `node_modules/dunder-proto` | 1.0.1 | MIT | no |
| `node_modules/entities` | 8.0.0 | BSD-2-Clause | no |
| `node_modules/es-abstract` | 1.24.2 | MIT | no |
| `node_modules/es-define-property` | 1.0.1 | MIT | no |
| `node_modules/es-iterator-helpers` | 1.3.2 | MIT | no |
| `node_modules/es-module-lexer` | 2.1.0 | MIT | no |
| `node_modules/es-object-atoms` | 1.1.2 | MIT | no |
| `node_modules/es-set-tostringtag` | 2.1.0 | MIT | no |
| `node_modules/es-shim-unscopables` | 1.1.0 | MIT | no |
| `node_modules/es-to-primitive` | 1.3.0 | MIT | no |
| `node_modules/eslint` | 9.39.4 | MIT | no |
| `node_modules/eslint-config-prettier` | 10.1.8 | MIT | no |
| `node_modules/eslint-plugin-react` | 7.37.5 | MIT | no |
| `node_modules/eslint-plugin-react-hooks` | 5.2.0 | MIT | no |
| `node_modules/eslint-plugin-react/node_modules/resolve` | 2.0.0-next.7 | MIT | no |
| `node_modules/eslint-scope` | 8.4.0 | BSD-2-Clause | no |
| `node_modules/eslint-visitor-keys` | 4.2.1 | Apache-2.0 | no |
| `node_modules/espree` | 10.4.0 | BSD-2-Clause | no |
| `node_modules/esquery` | 1.7.0 | BSD-3-Clause | no |
| `node_modules/esrecurse` | 4.3.0 | BSD-2-Clause | no |
| `node_modules/estraverse` | 5.3.0 | BSD-2-Clause | no |
| `node_modules/estree-walker` | 3.0.3 | MIT | no |
| `node_modules/esutils` | 2.0.3 | BSD-2-Clause | no |
| `node_modules/expect-type` | 1.3.0 | Apache-2.0 | no |
| `node_modules/fast-deep-equal` | 3.1.3 | MIT | no |
| `node_modules/fast-json-stable-stringify` | 2.1.0 | MIT | no |
| `node_modules/fast-levenshtein` | 2.0.6 | MIT | no |
| `node_modules/fdir` | 6.5.0 | MIT | no |
| `node_modules/file-entry-cache` | 8.0.0 | MIT | no |
| `node_modules/find-up` | 5.0.0 | MIT | no |
| `node_modules/flat-cache` | 4.0.1 | MIT | no |
| `node_modules/flatted` | 3.4.2 | ISC | no |
| `node_modules/for-each` | 0.3.5 | MIT | no |
| `node_modules/fsevents` | 2.3.2 | MIT | yes |
| `node_modules/function.prototype.name` | 1.1.8 | MIT | no |
| `node_modules/functions-have-names` | 1.2.3 | MIT | no |
| `node_modules/generator-function` | 2.0.1 | MIT | no |
| `node_modules/get-intrinsic` | 1.3.0 | MIT | no |
| `node_modules/get-proto` | 1.0.1 | MIT | no |
| `node_modules/get-symbol-description` | 1.1.0 | MIT | no |
| `node_modules/glob-parent` | 6.0.2 | ISC | no |
| `node_modules/globals` | 17.7.0 | MIT | no |
| `node_modules/globalthis` | 1.0.4 | MIT | no |
| `node_modules/goober` | 2.1.19 | MIT | no |
| `node_modules/gopd` | 1.2.0 | MIT | no |
| `node_modules/has-bigints` | 1.1.0 | MIT | no |
| `node_modules/has-flag` | 4.0.0 | MIT | no |
| `node_modules/has-property-descriptors` | 1.0.2 | MIT | no |
| `node_modules/has-proto` | 1.2.0 | MIT | no |
| `node_modules/has-symbols` | 1.1.0 | MIT | no |
| `node_modules/has-tostringtag` | 1.0.2 | MIT | no |
| `node_modules/html-encoding-sniffer` | 6.0.0 | MIT | no |
| `node_modules/https-proxy-agent` | 7.0.6 | MIT | no |
| `node_modules/ignore` | 5.3.2 | MIT | no |
| `node_modules/imurmurhash` | 0.1.4 | MIT | no |
| `node_modules/indent-string` | 4.0.0 | MIT | no |
| `node_modules/index-to-position` | 1.2.0 | MIT | no |
| `node_modules/internal-slot` | 1.1.0 | MIT | no |
| `node_modules/is-array-buffer` | 3.0.5 | MIT | no |
| `node_modules/is-async-function` | 2.1.1 | MIT | no |
| `node_modules/is-bigint` | 1.1.0 | MIT | no |
| `node_modules/is-boolean-object` | 1.2.2 | MIT | no |
| `node_modules/is-callable` | 1.2.7 | MIT | no |
| `node_modules/is-data-view` | 1.0.2 | MIT | no |
| `node_modules/is-date-object` | 1.1.0 | MIT | no |
| `node_modules/is-extglob` | 2.1.1 | MIT | no |
| `node_modules/is-finalizationregistry` | 1.1.1 | MIT | no |
| `node_modules/is-generator-function` | 1.1.2 | MIT | no |
| `node_modules/is-glob` | 4.0.3 | MIT | no |
| `node_modules/is-map` | 2.0.3 | MIT | no |
| `node_modules/is-negative-zero` | 2.0.3 | MIT | no |
| `node_modules/is-number-object` | 1.1.1 | MIT | no |
| `node_modules/is-potential-custom-element-name` | 1.0.1 | MIT | no |
| `node_modules/is-regex` | 1.2.1 | MIT | no |
| `node_modules/is-set` | 2.0.3 | MIT | no |
| `node_modules/is-shared-array-buffer` | 1.0.4 | MIT | no |
| `node_modules/is-string` | 1.1.1 | MIT | no |
| `node_modules/is-symbol` | 1.1.1 | MIT | no |
| `node_modules/is-typed-array` | 1.1.15 | MIT | no |
| `node_modules/is-weakmap` | 2.0.2 | MIT | no |
| `node_modules/is-weakref` | 1.1.1 | MIT | no |
| `node_modules/is-weakset` | 2.0.4 | MIT | no |
| `node_modules/isarray` | 2.0.5 | MIT | no |
| `node_modules/isexe` | 2.0.0 | ISC | no |
| `node_modules/iterator.prototype` | 1.1.5 | MIT | no |
| `node_modules/js-levenshtein` | 1.1.6 | MIT | no |
| `node_modules/js-yaml` | 4.2.0 | MIT | no |
| `node_modules/jsdom` | 29.1.1 | MIT | no |
| `node_modules/json-buffer` | 3.0.1 | MIT | no |
| `node_modules/json-schema-traverse` | 0.4.1 | MIT | no |
| `node_modules/json-stable-stringify-without-jsonify` | 1.0.1 | MIT | no |
| `node_modules/jsx-ast-utils` | 3.3.5 | MIT | no |
| `node_modules/keyv` | 4.5.4 | MIT | no |
| `node_modules/levn` | 0.4.1 | MIT | no |
| `node_modules/lightningcss` | 1.32.0 | MPL-2.0 | no |
| `node_modules/lightningcss-android-arm64` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-darwin-arm64` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-darwin-x64` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-freebsd-x64` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-linux-arm-gnueabihf` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-linux-arm64-gnu` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-linux-arm64-musl` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-linux-x64-gnu` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-linux-x64-musl` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-win32-arm64-msvc` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/lightningcss-win32-x64-msvc` | 1.32.0 | MPL-2.0 | yes |
| `node_modules/locate-path` | 6.0.0 | MIT | no |
| `node_modules/lodash.merge` | 4.6.2 | MIT | no |
| `node_modules/lru-cache` | 11.5.1 | BlueOak-1.0.0 | no |
| `node_modules/lz-string` | 1.5.0 | MIT | no |
| `node_modules/magic-string` | 0.30.21 | MIT | no |
| `node_modules/math-intrinsics` | 1.1.0 | MIT | no |
| `node_modules/mdn-data` | 2.27.1 | CC0-1.0 | no |
| `node_modules/min-indent` | 1.0.1 | MIT | no |
| `node_modules/minimatch` | 3.1.5 | ISC | no |
| `node_modules/nanoid` | 3.3.15 | MIT | no |
| `node_modules/natural-compare` | 1.4.0 | MIT | no |
| `node_modules/node-exports-info` | 1.6.0 | MIT | no |
| `node_modules/object-inspect` | 1.13.4 | MIT | no |
| `node_modules/object-keys` | 1.1.1 | MIT | no |
| `node_modules/object.assign` | 4.1.7 | MIT | no |
| `node_modules/object.entries` | 1.1.9 | MIT | no |
| `node_modules/object.fromentries` | 2.0.8 | MIT | no |
| `node_modules/object.values` | 1.2.1 | MIT | no |
| `node_modules/obug` | 2.1.3 | MIT | no |
| `node_modules/openapi-typescript` | 7.13.0 | MIT | no |
| `node_modules/openapi-typescript/node_modules/parse-json` | 8.3.0 | MIT | no |
| `node_modules/openapi-typescript/node_modules/supports-color` | 10.2.2 | MIT | no |
| `node_modules/optionator` | 0.9.4 | MIT | no |
| `node_modules/own-keys` | 1.0.1 | MIT | no |
| `node_modules/p-limit` | 3.1.0 | MIT | no |
| `node_modules/p-locate` | 5.0.0 | MIT | no |
| `node_modules/parse5` | 8.0.1 | MIT | no |
| `node_modules/path-exists` | 4.0.0 | MIT | no |
| `node_modules/path-key` | 3.1.1 | MIT | no |
| `node_modules/pathe` | 2.0.3 | MIT | no |
| `node_modules/picomatch` | 4.0.4 | MIT | no |
| `node_modules/playwright` | 1.61.1 | Apache-2.0 | no |
| `node_modules/playwright-core` | 1.61.1 | Apache-2.0 | no |
| `node_modules/pluralize` | 8.0.0 | MIT | no |
| `node_modules/possible-typed-array-names` | 1.1.0 | MIT | no |
| `node_modules/postcss` | 8.5.16 | MIT | no |
| `node_modules/prelude-ls` | 1.2.1 | MIT | no |
| `node_modules/prettier` | 3.9.4 | MIT | no |
| `node_modules/pretty-format` | 27.5.1 | MIT | no |
| `node_modules/pretty-format/node_modules/ansi-styles` | 5.2.0 | MIT | no |
| `node_modules/pretty-format/node_modules/react-is` | 17.0.2 | MIT | no |
| `node_modules/punycode` | 2.3.1 | MIT | no |
| `node_modules/redent` | 3.0.0 | MIT | no |
| `node_modules/reflect.getprototypeof` | 1.0.10 | MIT | no |
| `node_modules/regexp.prototype.flags` | 1.5.4 | MIT | no |
| `node_modules/require-from-string` | 2.0.2 | MIT | no |
| `node_modules/rolldown` | 1.1.4 | MIT | no |
| `node_modules/safe-array-concat` | 1.1.4 | MIT | no |
| `node_modules/safe-push-apply` | 1.0.0 | MIT | no |
| `node_modules/safe-regex-test` | 1.1.0 | MIT | no |
| `node_modules/saxes` | 6.0.0 | ISC | no |
| `node_modules/semver` | 6.3.1 | ISC | no |
| `node_modules/set-function-length` | 1.2.2 | MIT | no |
| `node_modules/set-function-name` | 2.0.2 | MIT | no |
| `node_modules/set-proto` | 1.0.0 | MIT | no |
| `node_modules/shebang-command` | 2.0.0 | MIT | no |
| `node_modules/shebang-regex` | 3.0.0 | MIT | no |
| `node_modules/side-channel` | 1.1.0 | MIT | no |
| `node_modules/side-channel-list` | 1.0.1 | MIT | no |
| `node_modules/side-channel-map` | 1.0.1 | MIT | no |
| `node_modules/side-channel-weakmap` | 1.0.2 | MIT | no |
| `node_modules/siginfo` | 2.0.0 | ISC | no |
| `node_modules/source-map-js` | 1.2.1 | BSD-3-Clause | no |
| `node_modules/stackback` | 0.0.2 | MIT | no |
| `node_modules/std-env` | 4.1.0 | MIT | no |
| `node_modules/stop-iteration-iterator` | 1.1.0 | MIT | no |
| `node_modules/string.prototype.matchall` | 4.0.12 | MIT | no |
| `node_modules/string.prototype.repeat` | 1.0.0 | MIT | no |
| `node_modules/string.prototype.trim` | 1.2.10 | MIT | no |
| `node_modules/string.prototype.trimend` | 1.0.9 | MIT | no |
| `node_modules/string.prototype.trimstart` | 1.0.8 | MIT | no |
| `node_modules/strip-indent` | 3.0.0 | MIT | no |
| `node_modules/strip-json-comments` | 3.1.1 | MIT | no |
| `node_modules/supports-color` | 7.2.0 | MIT | no |
| `node_modules/symbol-tree` | 3.2.4 | MIT | no |
| `node_modules/tinybench` | 2.9.0 | MIT | no |
| `node_modules/tinyexec` | 1.2.4 | MIT | no |
| `node_modules/tinyglobby` | 0.2.17 | MIT | no |
| `node_modules/tinyrainbow` | 3.1.0 | MIT | no |
| `node_modules/tldts` | 7.4.4 | MIT | no |
| `node_modules/tldts-core` | 7.4.4 | MIT | no |
| `node_modules/tough-cookie` | 6.0.1 | BSD-3-Clause | no |
| `node_modules/tr46` | 6.0.0 | MIT | no |
| `node_modules/ts-api-utils` | 2.5.0 | MIT | no |
| `node_modules/type-check` | 0.4.0 | MIT | no |
| `node_modules/type-fest` | 4.41.0 | (MIT OR CC0-1.0) | no |
| `node_modules/typed-array-buffer` | 1.0.3 | MIT | no |
| `node_modules/typed-array-byte-length` | 1.0.3 | MIT | no |
| `node_modules/typed-array-byte-offset` | 1.0.4 | MIT | no |
| `node_modules/typed-array-length` | 1.0.8 | MIT | no |
| `node_modules/typescript` | 5.9.3 | Apache-2.0 | no |
| `node_modules/typescript-eslint` | 8.62.1 | MIT | no |
| `node_modules/unbox-primitive` | 1.1.0 | MIT | no |
| `node_modules/undici` | 7.28.0 | MIT | no |
| `node_modules/undici-types` | 8.3.0 | MIT | no |
| `node_modules/uri-js` | 4.4.1 | BSD-2-Clause | no |
| `node_modules/uri-js-replace` | 1.0.1 | MIT | no |
| `node_modules/vite` | 8.1.3 | MIT | no |
| `node_modules/vite/node_modules/fsevents` | 2.3.3 | MIT | yes |
| `node_modules/vitest` | 4.1.9 | MIT | no |
| `node_modules/w3c-xmlserializer` | 5.0.0 | MIT | no |
| `node_modules/webidl-conversions` | 8.0.1 | BSD-2-Clause | no |
| `node_modules/whatwg-mimetype` | 5.0.0 | MIT | no |
| `node_modules/whatwg-url` | 16.0.1 | MIT | no |
| `node_modules/which` | 2.0.2 | ISC | no |
| `node_modules/which-boxed-primitive` | 1.1.1 | MIT | no |
| `node_modules/which-builtin-type` | 1.2.1 | MIT | no |
| `node_modules/which-collection` | 1.0.2 | MIT | no |
| `node_modules/which-typed-array` | 1.1.21 | MIT | no |
| `node_modules/why-is-node-running` | 2.3.0 | MIT | no |
| `node_modules/word-wrap` | 1.2.5 | MIT | no |
| `node_modules/xml-name-validator` | 5.0.0 | Apache-2.0 | no |
| `node_modules/xmlchars` | 2.2.0 | MIT | no |
| `node_modules/yaml-ast-parser` | 0.0.43 | Apache-2.0 | no |
| `node_modules/yargs-parser` | 21.1.1 | ISC | no |
| `node_modules/yocto-queue` | 0.1.0 | MIT | no |

## Regeneration

Run `make notices` to update this file. Run `make check-notices` to check for drift.
Both commands need the Go toolchain and cached modules, but do not read node_modules.
A Go module change requires review of its license texts and the versioned hashes in
`packaging/third-party-go-licenses.json`. Unknown modules or changed license bytes stop generation.

Run `npm ci --ignore-scripts --no-audit --no-fund` in a clean frontend directory
before `make license-bundle`. Package builds run the bundle check themselves.
The check rejects stale installed versions, missing non-optional dependencies and
missing license text. It never downloads a guessed license or substitutes a label
for the upstream text. To audit a separate clean install, use

```bash
python3 -S scripts/third-party-notices.py --check \
  --bundle dist/licenses --frontend-root /path/to/clean/frontend
```

CI checks inventory drift and builds the license bundle after npm ci.
Do not edit generated rows by hand or infer release contents from a stale install.
