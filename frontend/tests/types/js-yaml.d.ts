// Minimal declaration for js-yaml, which ships no bundled types and which the
// repo installs without @types. Only the one function the tests use is
// declared, so this cannot drift into pretending to describe the whole library.
declare module 'js-yaml' {
  export function load(input: string): unknown;
}
