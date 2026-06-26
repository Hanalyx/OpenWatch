# Third-Party Notices — OpenWatch

This file enumerates the third-party open-source components distributed with
OpenWatch and their licenses. It is generated; see "Regeneration" below.

**Generated:** 2026-06-26 (UTC)

## Scope and important notes

- **OpenWatch's own source code** is licensed under the terms in the repository
  [`LICENSE`](LICENSE) file. This notices file covers only *third-party*
  components, and is independent of OpenWatch's own license.
- **The shipped `openwatch` binary statically links `github.com/Hanalyx/kensa`,
  which is licensed under the Business Source License 1.1 (BSL-1.1), not a
  permissive license.** A distribution of the OpenWatch binary is therefore a
  combined work that includes a BSL-1.1 component. Redistributors are bound by
  the BSL-1.1 terms (notably, no competing hosted/managed service) with respect
  to the Kensa portion, regardless of the license on OpenWatch's own code.
- **No GPL, AGPL, or LGPL components** are present in either the Go binary or the
  frontend dependency set.
- The three **MPL-2.0** frontend entries (`axe-core`, `lightningcss`) are
  build/test-time tooling, not shipped in the production SPA bundle; MPL-2.0 is
  file-level copyleft and does not affect the license of the application as a
  whole.
- The frontend table below lists the full **installed** dependency set (a
  superset of what the production bundle ships, since it includes build and test
  tooling such as Vite, ESLint, and Vitest). Over-inclusion is intentional for
  completeness.
- Full license texts are distributed within each component's module/package
  directory (the Go module cache and `node_modules`, respectively).

## Go dependencies (linked into the `openwatch` binary)

| Module | Version | License |
|---|---|---|
| `github.com/woodsbury/decimal128` | v1.3.0 | 0BSD |
| `github.com/elastic/go-libaudit/v2` | v2.6.2 | Apache-2.0 |
| `github.com/go-openapi/jsonpointer` | v0.21.0 | Apache-2.0 |
| `github.com/go-openapi/swag` | v0.23.0 | Apache-2.0 |
| `github.com/oapi-codegen/runtime` | v1.4.1 | Apache-2.0 |
| `github.com/oasdiff/yaml3` | v0.0.13 | Apache-2.0 |
| `github.com/pquerna/otp` | v1.5.0 | Apache-2.0 |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.2 | Apache-2.0 |
| `github.com/sethvargo/go-retry` | v0.3.0 | Apache-2.0 |
| `github.com/swaggest/swgui` | v1.8.7 | Apache-2.0 |
| `gopkg.in/yaml.v3` | v3.0.1 | Apache-2.0 |
| `github.com/google/uuid` | v1.6.0 | BSD |
| `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748-24d4a6f8daec | BSD |
| `golang.org/x/crypto` | v0.52.0 | BSD |
| `golang.org/x/net` | v0.55.0 | BSD |
| `golang.org/x/sync` | v0.20.0 | BSD |
| `golang.org/x/sys` | v0.46.0 | BSD |
| `golang.org/x/text` | v0.37.0 | BSD |
| `modernc.org/libc` | v1.72.3 | BSD |
| `modernc.org/mathutil` | v1.7.1 | BSD |
| `modernc.org/memory` | v1.11.0 | BSD |
| `modernc.org/sqlite` | v1.52.0 | BSD |
| `github.com/Hanalyx/kensa` | v0.6.0 | BSL-1.1 |
| `github.com/apapsch/go-jsonmerge/v2` | v2.0.0 | MIT |
| `github.com/boombuler/barcode` | v1.1.0 | MIT |
| `github.com/BurntSushi/toml` | v1.6.0 | MIT |
| `github.com/dustin/go-humanize` | v1.0.1 | MIT |
| `github.com/getkin/kin-openapi` | v0.139.0 | MIT |
| `github.com/go-chi/chi/v5` | v5.3.0 | MIT |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | MIT |
| `github.com/go-pdf/fpdf` | v0.9.0 | MIT |
| `github.com/jackc/pgpassfile` | v1.0.0 | MIT |
| `github.com/jackc/pgservicefile` | v0.0.0-20240606120523-5a60cdf6a761 | MIT |
| `github.com/jackc/pgx/v5` | v5.9.2 | MIT |
| `github.com/jackc/puddle/v2` | v2.2.2 | MIT |
| `github.com/josharian/intern` | v1.0.0 | MIT |
| `github.com/kballard/go-shellquote` | v0.0.0-20180428030007-95032a82bc51 | MIT |
| `github.com/mailru/easyjson` | v0.7.7 | MIT |
| `github.com/mfridman/interpolate` | v0.0.2 | MIT |
| `github.com/mohae/deepcopy` | v0.0.0-20170929034955-c48cc78d4826 | MIT |
| `github.com/oasdiff/yaml` | v0.1.0 | MIT |
| `github.com/perimeterx/marshmallow` | v1.1.5 | MIT |
| `github.com/pressly/goose/v3` | v3.27.1 | MIT |
| `github.com/vearutop/statigz` | v1.4.0 | MIT |
| `go.uber.org/multierr` | v1.11.0 | MIT |

## Frontend dependencies (npm — full installed set)

License tally: MIT 276 · ISC 11 · Apache-2.0 10 · BSD-2-Clause 8 · BSD-3-Clause 6 · MPL-2.0 3 · 0BSD 1 · Unlicense 1 · Python-2.0 1 · (MIT OR CC0-1.0) 1

| Package | Version | License |
|---|---|---|
| `acorn` | 8.16.0 | MIT |
| `acorn-jsx` | 5.3.2 | MIT |
| `agent-base` | 7.1.4 | MIT |
| `ajv` | 6.15.0 | MIT |
| `ansi-colors` | 4.1.3 | MIT |
| `ansi-regex` | 5.0.1 | MIT |
| `ansi-styles` | 4.3.0 | MIT |
| `argparse` | 2.0.1 | Python-2.0 |
| `aria-query` | 5.3.0 | Apache-2.0 |
| `array-buffer-byte-length` | 1.0.2 | MIT |
| `arraybuffer.prototype.slice` | 1.0.4 | MIT |
| `array-includes` | 3.1.9 | MIT |
| `array.prototype.findlast` | 1.2.5 | MIT |
| `array.prototype.flat` | 1.3.3 | MIT |
| `array.prototype.flatmap` | 1.3.3 | MIT |
| `array.prototype.tosorted` | 1.1.4 | MIT |
| `assertion-error` | 2.0.1 | MIT |
| `async-function` | 1.0.0 | MIT |
| `asynckit` | 0.4.0 | MIT |
| `attr-accept` | 2.2.5 | MIT |
| `available-typed-arrays` | 1.0.7 | MIT |
| `axe-core` | 4.12.1 | MPL-2.0 |
| `babel-plugin-macros` | 3.1.0 | MIT |
| `balanced-match` | 1.0.2 | MIT |
| `brace-expansion` | 1.1.15 | MIT |
| `call-bind` | 1.0.9 | MIT |
| `call-bind-apply-helpers` | 1.0.2 | MIT |
| `call-bound` | 1.0.4 | MIT |
| `callsites` | 3.1.0 | MIT |
| `chai` | 6.2.2 | MIT |
| `chalk` | 4.1.2 | MIT |
| `change-case` | 5.4.4 | MIT |
| `clsx` | 2.1.1 | MIT |
| `color-convert` | 2.0.1 | MIT |
| `colorette` | 1.4.0 | MIT |
| `color-name` | 1.1.4 | MIT |
| `combined-stream` | 1.0.8 | MIT |
| `concat-map` | 0.0.1 | MIT |
| `convert-source-map` | 1.9.0 | MIT |
| `cookie-es` | 3.1.1 | MIT |
| `cosmiconfig` | 7.1.0 | MIT |
| `cross-spawn` | 7.0.6 | MIT |
| `css.escape` | 1.5.1 | MIT |
| `cssstyle` | 4.6.0 | MIT |
| `csstype` | 3.2.3 | MIT |
| `data-urls` | 5.0.0 | MIT |
| `data-view-buffer` | 1.0.2 | MIT |
| `data-view-byte-length` | 1.0.2 | MIT |
| `data-view-byte-offset` | 1.0.1 | MIT |
| `debug` | 4.4.3 | MIT |
| `decimal.js` | 10.6.0 | MIT |
| `deep-is` | 0.1.4 | MIT |
| `define-data-property` | 1.1.4 | MIT |
| `define-properties` | 1.2.1 | MIT |
| `delayed-stream` | 1.0.0 | MIT |
| `dequal` | 2.0.3 | MIT |
| `detect-libc` | 2.1.2 | Apache-2.0 |
| `doctrine` | 2.1.0 | Apache-2.0 |
| `dom-accessibility-api` | 0.5.16 | MIT |
| `dom-helpers` | 5.2.1 | MIT |
| `dunder-proto` | 1.0.1 | MIT |
| `entities` | 6.0.1 | BSD-2-Clause |
| `error-ex` | 1.3.4 | MIT |
| `es-abstract` | 1.24.2 | MIT |
| `escape-string-regexp` | 4.0.0 | MIT |
| `es-define-property` | 1.0.1 | MIT |
| `es-errors` | 1.3.0 | MIT |
| `es-iterator-helpers` | 1.3.2 | MIT |
| `eslint` | 9.39.4 | MIT |
| `eslint-config-prettier` | 10.1.8 | MIT |
| `eslint-plugin-react` | 7.37.5 | MIT |
| `eslint-plugin-react-hooks` | 5.2.0 | MIT |
| `eslint-scope` | 8.4.0 | BSD-2-Clause |
| `eslint-visitor-keys` | 4.2.1 | Apache-2.0 |
| `es-module-lexer` | 2.1.0 | MIT |
| `es-object-atoms` | 1.1.2 | MIT |
| `espree` | 10.4.0 | BSD-2-Clause |
| `esquery` | 1.7.0 | BSD-3-Clause |
| `esrecurse` | 4.3.0 | BSD-2-Clause |
| `es-set-tostringtag` | 2.1.0 | MIT |
| `es-shim-unscopables` | 1.1.0 | MIT |
| `es-to-primitive` | 1.3.0 | MIT |
| `estraverse` | 5.3.0 | BSD-2-Clause |
| `estree-walker` | 3.0.3 | MIT |
| `esutils` | 2.0.3 | BSD-2-Clause |
| `expect-type` | 1.3.0 | Apache-2.0 |
| `fast-deep-equal` | 3.1.3 | MIT |
| `fast-json-stable-stringify` | 2.1.0 | MIT |
| `fast-levenshtein` | 2.0.6 | MIT |
| `fdir` | 6.5.0 | MIT |
| `file-entry-cache` | 8.0.0 | MIT |
| `file-selector` | 2.1.2 | MIT |
| `find-root` | 1.1.0 | MIT |
| `find-up` | 5.0.0 | MIT |
| `flat-cache` | 4.0.1 | MIT |
| `flatted` | 3.4.2 | ISC |
| `for-each` | 0.3.5 | MIT |
| `form-data` | 4.0.6 | MIT |
| `function-bind` | 1.1.2 | MIT |
| `function.prototype.name` | 1.1.8 | MIT |
| `functions-have-names` | 1.2.3 | MIT |
| `generator-function` | 2.0.1 | MIT |
| `get-intrinsic` | 1.3.0 | MIT |
| `get-proto` | 1.0.1 | MIT |
| `get-symbol-description` | 1.1.0 | MIT |
| `globals` | 17.6.0 | MIT |
| `globalthis` | 1.0.4 | MIT |
| `glob-parent` | 6.0.2 | ISC |
| `goober` | 2.1.19 | MIT |
| `gopd` | 1.2.0 | MIT |
| `has-bigints` | 1.1.0 | MIT |
| `has-flag` | 4.0.0 | MIT |
| `hasown` | 2.0.4 | MIT |
| `has-property-descriptors` | 1.0.2 | MIT |
| `has-proto` | 1.2.0 | MIT |
| `has-symbols` | 1.1.0 | MIT |
| `has-tostringtag` | 1.0.2 | MIT |
| `hoist-non-react-statics` | 3.3.2 | BSD-3-Clause |
| `html-encoding-sniffer` | 4.0.0 | MIT |
| `http-proxy-agent` | 7.0.2 | MIT |
| `https-proxy-agent` | 7.0.6 | MIT |
| `iconv-lite` | 0.6.3 | MIT |
| `ignore` | 5.3.2 | MIT |
| `import-fresh` | 3.3.1 | MIT |
| `imurmurhash` | 0.1.4 | MIT |
| `indent-string` | 4.0.0 | MIT |
| `index-to-position` | 1.2.0 | MIT |
| `internal-slot` | 1.1.0 | MIT |
| `isarray` | 2.0.5 | MIT |
| `is-array-buffer` | 3.0.5 | MIT |
| `is-arrayish` | 0.2.1 | MIT |
| `is-async-function` | 2.1.1 | MIT |
| `is-bigint` | 1.1.0 | MIT |
| `is-boolean-object` | 1.2.2 | MIT |
| `isbot` | 5.1.40 | Unlicense |
| `is-callable` | 1.2.7 | MIT |
| `is-core-module` | 2.16.2 | MIT |
| `is-data-view` | 1.0.2 | MIT |
| `is-date-object` | 1.1.0 | MIT |
| `isexe` | 2.0.0 | ISC |
| `is-extglob` | 2.1.1 | MIT |
| `is-finalizationregistry` | 1.1.1 | MIT |
| `is-generator-function` | 1.1.2 | MIT |
| `is-glob` | 4.0.3 | MIT |
| `is-map` | 2.0.3 | MIT |
| `is-negative-zero` | 2.0.3 | MIT |
| `is-number-object` | 1.1.1 | MIT |
| `is-potential-custom-element-name` | 1.0.1 | MIT |
| `is-regex` | 1.2.1 | MIT |
| `is-set` | 2.0.3 | MIT |
| `is-shared-array-buffer` | 1.0.4 | MIT |
| `is-string` | 1.1.1 | MIT |
| `is-symbol` | 1.1.1 | MIT |
| `is-typed-array` | 1.1.15 | MIT |
| `is-weakmap` | 2.0.2 | MIT |
| `is-weakref` | 1.1.1 | MIT |
| `is-weakset` | 2.0.4 | MIT |
| `iterator.prototype` | 1.1.5 | MIT |
| `jsdom` | 25.0.1 | MIT |
| `jsesc` | 3.1.0 | MIT |
| `js-levenshtein` | 1.1.6 | MIT |
| `json-buffer` | 3.0.1 | MIT |
| `json-parse-even-better-errors` | 2.3.1 | MIT |
| `json-schema-traverse` | 0.4.1 | MIT |
| `json-stable-stringify-without-jsonify` | 1.0.1 | MIT |
| `js-tokens` | 4.0.0 | MIT |
| `jsx-ast-utils` | 3.3.5 | MIT |
| `js-yaml` | 4.1.1 | MIT |
| `keyv` | 4.5.4 | MIT |
| `levn` | 0.4.1 | MIT |
| `lightningcss` | 1.32.0 | MPL-2.0 |
| `lightningcss-linux-x64-gnu` | 1.32.0 | MPL-2.0 |
| `lines-and-columns` | 1.2.4 | MIT |
| `locate-path` | 6.0.0 | MIT |
| `lodash.merge` | 4.6.2 | MIT |
| `loose-envify` | 1.4.0 | MIT |
| `lucide-react` | 1.20.0 | ISC |
| `lz-string` | 1.5.0 | MIT |
| `magic-string` | 0.30.21 | MIT |
| `math-intrinsics` | 1.1.0 | MIT |
| `mime-db` | 1.52.0 | MIT |
| `mime-types` | 2.1.35 | MIT |
| `minimatch` | 3.1.5 | ISC |
| `min-indent` | 1.0.1 | MIT |
| `ms` | 2.1.3 | MIT |
| `nanoid` | 3.3.12 | MIT |
| `natural-compare` | 1.4.0 | MIT |
| `node-exports-info` | 1.6.0 | MIT |
| `nwsapi` | 2.2.23 | MIT |
| `object-assign` | 4.1.1 | MIT |
| `object.assign` | 4.1.7 | MIT |
| `object.entries` | 1.1.9 | MIT |
| `object.fromentries` | 2.0.8 | MIT |
| `object-inspect` | 1.13.4 | MIT |
| `object-keys` | 1.1.1 | MIT |
| `object.values` | 1.2.1 | MIT |
| `obug` | 2.1.3 | MIT |
| `openapi-fetch` | 0.17.0 | MIT |
| `openapi-typescript` | 7.13.0 | MIT |
| `openapi-typescript-helpers` | 0.1.0 | MIT |
| `optionator` | 0.9.4 | MIT |
| `own-keys` | 1.0.1 | MIT |
| `parent-module` | 1.0.1 | MIT |
| `parse5` | 7.3.0 | MIT |
| `parse-json` | 5.2.0 | MIT |
| `pathe` | 2.0.3 | MIT |
| `path-exists` | 4.0.0 | MIT |
| `path-key` | 3.1.1 | MIT |
| `path-parse` | 1.0.7 | MIT |
| `path-type` | 4.0.0 | MIT |
| `picocolors` | 1.1.1 | ISC |
| `picomatch` | 4.0.4 | MIT |
| `playwright` | 1.60.0 | Apache-2.0 |
| `playwright-core` | 1.60.0 | Apache-2.0 |
| `p-limit` | 3.1.0 | MIT |
| `p-locate` | 5.0.0 | MIT |
| `pluralize` | 8.0.0 | MIT |
| `possible-typed-array-names` | 1.1.0 | MIT |
| `postcss` | 8.5.15 | MIT |
| `prelude-ls` | 1.2.1 | MIT |
| `prettier` | 3.8.4 | MIT |
| `pretty-format` | 27.5.1 | MIT |
| `prop-types` | 15.8.1 | MIT |
| `punycode` | 2.3.1 | MIT |
| `react` | 19.2.7 | MIT |
| `react-dom` | 19.2.7 | MIT |
| `react-dropzone` | 15.0.0 | MIT |
| `react-hook-form` | 7.79.0 | MIT |
| `react-is` | 19.2.6 | MIT |
| `react-transition-group` | 4.4.5 | BSD-3-Clause |
| `redent` | 3.0.0 | MIT |
| `reflect.getprototypeof` | 1.0.10 | MIT |
| `regexp.prototype.flags` | 1.5.4 | MIT |
| `require-from-string` | 2.0.2 | MIT |
| `resolve` | 1.22.12 | MIT |
| `resolve-from` | 4.0.0 | MIT |
| `rolldown` | 1.0.3 | MIT |
| `rrweb-cssom` | 0.7.1 | MIT |
| `safe-array-concat` | 1.1.4 | MIT |
| `safe-push-apply` | 1.0.0 | MIT |
| `safer-buffer` | 2.1.2 | MIT |
| `safe-regex-test` | 1.1.0 | MIT |
| `saxes` | 6.0.0 | ISC |
| `scheduler` | 0.27.0 | MIT |
| `semver` | 6.3.1 | ISC |
| `seroval` | 1.5.4 | MIT |
| `seroval-plugins` | 1.5.4 | MIT |
| `set-function-length` | 1.2.2 | MIT |
| `set-function-name` | 2.0.2 | MIT |
| `set-proto` | 1.0.0 | MIT |
| `shebang-command` | 2.0.0 | MIT |
| `shebang-regex` | 3.0.0 | MIT |
| `side-channel` | 1.1.0 | MIT |
| `side-channel-list` | 1.0.1 | MIT |
| `side-channel-map` | 1.0.1 | MIT |
| `side-channel-weakmap` | 1.0.2 | MIT |
| `siginfo` | 2.0.0 | ISC |
| `source-map` | 0.5.7 | BSD-3-Clause |
| `source-map-js` | 1.2.1 | BSD-3-Clause |
| `stackback` | 0.0.2 | MIT |
| `std-env` | 4.1.0 | MIT |
| `stop-iteration-iterator` | 1.1.0 | MIT |
| `string.prototype.matchall` | 4.0.12 | MIT |
| `string.prototype.repeat` | 1.0.0 | MIT |
| `string.prototype.trim` | 1.2.10 | MIT |
| `string.prototype.trimend` | 1.0.9 | MIT |
| `string.prototype.trimstart` | 1.0.8 | MIT |
| `strip-indent` | 3.0.0 | MIT |
| `strip-json-comments` | 3.1.1 | MIT |
| `stylis` | 4.2.0 | MIT |
| `supports-color` | 7.2.0 | MIT |
| `supports-preserve-symlinks-flag` | 1.0.0 | MIT |
| `symbol-tree` | 3.2.4 | MIT |
| `tinybench` | 2.9.0 | MIT |
| `tinyexec` | 1.2.4 | MIT |
| `tinyglobby` | 0.2.17 | MIT |
| `tinyrainbow` | 3.1.0 | MIT |
| `tldts` | 6.1.86 | MIT |
| `tldts-core` | 6.1.86 | MIT |
| `tough-cookie` | 5.1.2 | BSD-3-Clause |
| `tr46` | 5.1.1 | MIT |
| `ts-api-utils` | 2.5.0 | MIT |
| `tslib` | 2.8.1 | 0BSD |
| `type-check` | 0.4.0 | MIT |
| `typed-array-buffer` | 1.0.3 | MIT |
| `typed-array-byte-length` | 1.0.3 | MIT |
| `typed-array-byte-offset` | 1.0.4 | MIT |
| `typed-array-length` | 1.0.8 | MIT |
| `type-fest` | 4.41.0 | (MIT OR CC0-1.0) |
| `typescript` | 5.9.3 | Apache-2.0 |
| `typescript-eslint` | 8.61.0 | MIT |
| `unbox-primitive` | 1.1.0 | MIT |
| `undici-types` | 6.21.0 | MIT |
| `uri-js` | 4.4.1 | BSD-2-Clause |
| `uri-js-replace` | 1.0.1 | MIT |
| `use-sync-external-store` | 1.6.0 | MIT |
| `vite` | 8.0.16 | MIT |
| `vitest` | 4.1.9 | MIT |
| `w3c-xmlserializer` | 5.0.0 | MIT |
| `webidl-conversions` | 7.0.0 | BSD-2-Clause |
| `whatwg-encoding` | 3.1.1 | MIT |
| `whatwg-mimetype` | 4.0.0 | MIT |
| `whatwg-url` | 14.2.0 | MIT |
| `which` | 2.0.2 | ISC |
| `which-boxed-primitive` | 1.1.1 | MIT |
| `which-builtin-type` | 1.2.1 | MIT |
| `which-collection` | 1.0.2 | MIT |
| `which-typed-array` | 1.1.21 | MIT |
| `why-is-node-running` | 2.3.0 | MIT |
| `word-wrap` | 1.2.5 | MIT |
| `ws` | 8.21.0 | MIT |
| `xmlchars` | 2.2.0 | MIT |
| `xml-name-validator` | 5.0.0 | Apache-2.0 |
| `yaml-ast-parser` | 0.0.43 | Apache-2.0 |
| `yargs-parser` | 21.1.1 | ISC |
| `yocto-queue` | 0.1.0 | MIT |
| `zod` | 4.4.3 | MIT |
| `zustand` | 5.0.14 | MIT |

## Regeneration

This file is produced by scanning the linked Go module set
(`go list -deps ./cmd/openwatch`) against the module cache, and the installed
`frontend/node_modules` `package.json` `license` fields. The Go classifier
checks for BSL-1.1 *before* Apache-2.0, because the BSL-1.1 template names
Apache-2.0 as its Change License and would otherwise be misclassified.

Note: `go-licenses` v1.x is currently incompatible with the go1.26 toolchain
module layout (it fails to resolve stdlib module info), so the cache-based scan
above is the working audit method until that is resolved.
