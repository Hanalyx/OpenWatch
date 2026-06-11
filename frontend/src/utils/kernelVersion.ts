// stripKernelDistroSuffix — keep only the upstream kernel version,
// drop distro markers and arch.
//
// Examples:
//   5.14.0-611.42.1.el9_7.x86_64  -> 5.14.0-611.42.1
//   5.14.0-503.el9.aarch64        -> 5.14.0-503
//   6.8.0-45-generic              -> 6.8.0-45-generic   (Ubuntu — no suffix to strip)
//   6.1.0-25-amd64                -> 6.1.0-25-amd64     (Debian — no suffix to strip)
//   6.1.110-0-lts                 -> 6.1.110-0-lts      (Alpine)
//
// Strategy:
//   1. Drop a trailing .<arch> if arch is a known token.
//   2. Drop a trailing .<rhel-marker> matching .el<digits>(_<digits>)?
//      or .fc<digits> (Fedora).
//   3. Leave anything else alone so Ubuntu/Debian/Alpine/SUSE strings
//      pass through unchanged.

const ARCH_RE = /\.(x86_64|i686|aarch64|arm64|armv7l|armv7hl|ppc64le|ppc64|s390x|riscv64)$/;
const DISTRO_MARKER_RE = /\.(el\d+(?:_\d+)?|fc\d+)$/;

export function stripKernelDistroSuffix(release: string | null | undefined): string {
  if (!release) return '';
  let out = release;
  // Order matters: arch is innermost, distro marker outermost.
  out = out.replace(ARCH_RE, '');
  out = out.replace(DISTRO_MARKER_RE, '');
  return out;
}
