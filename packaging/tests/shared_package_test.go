package packaging_test

// One native package build per format, shared by the tests that only read it.
//
// rpmPath and debPath run `make rpm` / `make deb` on every call. Most of their
// callers only query metadata or list the payload, and each call cost a full
// rebuild: about 12.5 s for the RPM and 16 s for the DEB on the hosted runner,
// 23 builds per run, plus 7 of the kensa-rules corpus package. Those
// read-only callers now use sharedRPMPath, sharedDEBPath and the kensa-rules
// helpers, which build each format once per test binary.
//
// The shared artifact must never be stale or shared mutable state:
//
//   - It is identified by the name the build script reports writing, not by
//     the newest file matching a glob in dist/, so a leftover from an earlier
//     run or another version cannot be picked up.
//   - It is copied out of dist/ into a private directory under the system
//     temp dir, outside the checkout (release-ci-gates C-13), and made
//     read-only. Later builds into dist/ by other tests cannot change it.
//   - It is bound to a fingerprint of the source tree and the build settings
//     taken just before the build. Every hand-out recomputes the fingerprint
//     and the artifact's sha256 and fails the test if either moved, so a
//     changed tree or a modified artifact is reported, never consumed.
//
// Tests that prove the build itself (AC-01, AC-02, AC-13), change its inputs
// (engine pairing fixtures, FIPS) or work on a copy of the tree keep their own
// builds, through freshArtifact or their own helpers.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"
)

// buildSettingEnv names the environment that changes what `make rpm` or
// `make deb` produces. A value that differs between the build and a hand-out
// makes the shared artifact stale.
var buildSettingEnv = []string{
	"VERSION", "ARCH", "RPM_RELEASE", "GOOS", "GOARCH", "GOFLAGS",
	"GOFIPS140", "GOEXPERIMENT", "CGO_ENABLED",
}

// wroteLine matches the line each build script prints for its final artifact:
// ">> wrote <name> to <dir>/".
var wroteLine = regexp.MustCompile(`(?m)^>> wrote (\S+) to `)

// sharedPackage is one package format built at most once per test binary.
type sharedPackage struct {
	target string         // make target
	tool   string         // required packaging tool
	name   *regexp.Regexp // the openwatch artifact the build must report

	// build and fingerprint are fields so the mechanism can be tested without
	// a native build. Production values are set in newSharedPackage.
	build       func(appDir string) (stdout string, err error)
	fingerprint func(appDir string) (string, error)

	once  sync.Once
	path  string // private read-only copy
	sum   string // sha256 of the copy
	print string // fingerprint taken before the build
	err   error
}

func newSharedPackage(target, tool, name string) *sharedPackage {
	return &sharedPackage{
		target:      target,
		tool:        tool,
		name:        regexp.MustCompile(name),
		build:       func(dir string) (string, error) { return makeTarget(dir, target) },
		fingerprint: sourceFingerprint,
	}
}

var (
	sharedRPM = newSharedPackage("rpm", "rpmbuild", `^openwatch-[^/]+\.rpm$`)
	sharedDEB = newSharedPackage("deb", "dpkg-deb", `^openwatch_[^/]+\.deb$`)

	// `make kensa-rules` writes both formats; each shared instance keeps the
	// one its name matches. Every kensa-rules caller only reads the package.
	sharedKensaRPM = newSharedPackage("kensa-rules", "rpmbuild", `^kensa-rules-[^/]+\.rpm$`)
	sharedKensaDEB = newSharedPackage("kensa-rules", "dpkg-deb", `^kensa-rules_[^/]+\.deb$`)

	sharedRoot     string
	sharedRootOnce sync.Once
	sharedRootErr  error
)

// sharedRPMPath returns the shared, read-only openwatch RPM. Callers must
// only read it.
func sharedRPMPath(t *testing.T) string {
	t.Helper()
	requirePackagingBuild(t)
	haveTool(t, sharedRPM.tool)
	return sharedRPM.get(t, appDir(t))
}

// sharedDEBPath returns the shared, read-only openwatch DEB. Callers must
// only read it.
func sharedDEBPath(t *testing.T) string {
	t.Helper()
	requirePackagingBuild(t)
	haveTool(t, sharedDEB.tool)
	return sharedDEB.get(t, appDir(t))
}

func (p *sharedPackage) get(t *testing.T, appDir string) string {
	t.Helper()
	path, err := p.handout(appDir)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// handout builds on first use, then checks the artifact is still current
// before every return.
func (p *sharedPackage) handout(appDir string) (string, error) {
	p.once.Do(func() { p.path, p.sum, p.print, p.err = p.produce(appDir) })
	if p.err != nil {
		return "", fmt.Errorf("shared %s build: %w", p.target, p.err)
	}
	if err := p.verify(appDir); err != nil {
		return "", fmt.Errorf("shared %s artifact is stale: %w", p.target, err)
	}
	return p.path, nil
}

// produce builds once and copies the reported artifact into a private
// directory. It returns the copy, its digest and the pre-build fingerprint.
func (p *sharedPackage) produce(appDir string) (string, string, string, error) {
	print, err := p.fingerprint(appDir)
	if err != nil {
		return "", "", "", fmt.Errorf("fingerprint before build: %w", err)
	}
	src, err := buildReported(appDir, p.target, p.name, p.build)
	if err != nil {
		return "", "", "", err
	}
	after, err := p.fingerprint(appDir)
	if err != nil {
		return "", "", "", fmt.Errorf("fingerprint after build: %w", err)
	}
	if after != print {
		return "", "", "", fmt.Errorf("the source tree or build settings changed during make %s", p.target)
	}

	root, err := sharedPackageRoot()
	if err != nil {
		return "", "", "", err
	}
	dir, err := os.MkdirTemp(root, p.target+"-")
	if err != nil {
		return "", "", "", err
	}
	dst := filepath.Join(dir, filepath.Base(src))
	sum, err := copyAndHash(src, dst)
	if err != nil {
		return "", "", "", err
	}
	if err := os.Chmod(dst, 0o444); err != nil {
		return "", "", "", err
	}
	return dst, sum, print, nil
}

// buildReported runs build for target and returns the one artifact matching
// name that the build reports writing (">> wrote <name> to dist/"). It
// refuses a report of zero or several matching artifacts, and a reported
// file older than the build, so a leftover in dist/ is never mistaken for
// this build's output.
func buildReported(appDir, target string, name *regexp.Regexp, build func(string) (string, error)) (string, error) {
	started := time.Now()
	stdout, err := build(appDir)
	if err != nil {
		return "", fmt.Errorf("make %s: %w\nstdout: %s", target, err, stdout)
	}
	var reported []string
	for _, m := range wroteLine.FindAllStringSubmatch(stdout, -1) {
		if name.MatchString(m[1]) {
			reported = append(reported, m[1])
		}
	}
	if len(reported) != 1 {
		return "", fmt.Errorf("make %s reported %d artifacts matching %s %q, want exactly 1\nstdout: %s",
			target, len(reported), name, reported, stdout)
	}
	src := filepath.Join(appDir, "dist", reported[0])
	info, err := os.Stat(src)
	if err != nil {
		return "", fmt.Errorf("reported artifact: %w", err)
	}
	// A file older than this build was not written by it.
	if info.ModTime().Before(started.Add(-2 * time.Second)) {
		return "", fmt.Errorf("%s predates the build (mtime %s, build started %s)",
			src, info.ModTime().Format(time.RFC3339Nano), started.Format(time.RFC3339Nano))
	}
	return src, nil
}

// freshArtifact builds target and returns the artifact the build reported,
// under dist/. For the tests that prove the build itself and so need their
// own build.
func freshArtifact(t *testing.T, appDir, target, name string) string {
	t.Helper()
	requirePackagingBuild(t)
	path, err := buildReported(appDir, target, regexp.MustCompile(name),
		func(dir string) (string, error) { return makeTarget(dir, target) })
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// verify refuses a hand-out when the tree, the build settings or the
// artifact changed since the build.
func (p *sharedPackage) verify(appDir string) error {
	now, err := p.fingerprint(appDir)
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}
	if now != p.print {
		return fmt.Errorf("the source tree or build settings changed since %s was built; it no longer describes this checkout", p.path)
	}
	sum, err := fileSHA256(p.path)
	if err != nil {
		return err
	}
	if sum != p.sum {
		return fmt.Errorf("%s was modified after the build (sha256 %s, built %s); callers must only read it", p.path, sum, p.sum)
	}
	return nil
}

// sourceFingerprint hashes the repository state the package is built from,
// and the build settings (CP bugs/OW-115 defines the contract):
//
//  1. the HEAD commit;
//  2. every uncommitted change to tracked paths, which includes a tracked
//     symlink's target text;
//  3. every untracked entry that is not ignored, as its path plus
//     untrackedEntry's description of it: a regular file by its permission
//     bits and content, a symlink by its stored target text;
//  4. the build-setting environment.
//
// A symlink is link metadata: retargeting it moves the fingerprint, but the
// link is never followed. Content reached through a link is covered only when
// the target is itself a repository path listed above. A target outside the
// repository or under an ignored path is an external build input, like the
// module cache, node_modules, the toolchains and ignored generated files. The
// fingerprint does not cover external inputs, and a change to one during a
// test run is not detected.
func sourceFingerprint(appDir string) (string, error) {
	h := sha256.New()
	git := func(args ...string) ([]byte, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = appDir
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git %v: %w: %s", args, err, stderr.String())
		}
		return out, nil
	}
	for _, args := range [][]string{
		{"rev-parse", "HEAD"},
		{"diff", "HEAD", "--binary", "--no-ext-diff"},
	} {
		out, err := git(args...)
		if err != nil {
			return "", err
		}
		h.Write(out)
		h.Write([]byte{0})
	}
	untracked, err := git("ls-files", "-z", "--others", "--exclude-standard")
	if err != nil {
		return "", err
	}
	for _, name := range bytes.Split(bytes.TrimRight(untracked, "\x00"), []byte{0}) {
		if len(name) == 0 {
			continue
		}
		entry, err := untrackedEntry(filepath.Join(appDir, string(name)))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%s\x00", name, entry)
	}
	for _, k := range buildSettingEnv {
		v, ok := os.LookupEnv(k)
		fmt.Fprintf(h, "%s\x00%t\x00%s\x00", k, ok, v)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// untrackedEntry describes one untracked path without following a symlink:
// "symlink:<target text>" for a link, whatever it points at and whether or
// not the target exists, and "file:<perm>:<sha256>" for a regular file.
// Anything else fails, so an entry the contract does not describe cannot
// pass unhashed.
func untrackedEntry(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	switch mode := info.Mode(); {
	case mode&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		return "symlink:" + target, nil
	case mode.IsRegular():
		sum, err := fileSHA256(path)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("file:%o:%s", mode.Perm(), sum), nil
	default:
		return "", fmt.Errorf("untracked %s is a %v, which the source fingerprint does not describe", path, mode.Type())
	}
}

// makeTarget runs one make target and returns its stdout.
func makeTarget(appDir, target string) (string, error) {
	cmd := exec.Command("make", target)
	cmd.Dir = appDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%w\nstderr: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

func sharedPackageRoot() (string, error) {
	sharedRootOnce.Do(func() {
		sharedRoot, sharedRootErr = os.MkdirTemp("", "ow-shared-packages-")
	})
	return sharedRoot, sharedRootErr
}

func copyAndHash(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// TestMain removes the shared copies after the run. They live outside the
// checkout, so nothing here touches the repository.
func TestMain(m *testing.M) {
	code := m.Run()
	if sharedRoot != "" {
		// The copies are read-only files in writable directories, so
		// RemoveAll can delete them.
		os.RemoveAll(sharedRoot)
	}
	os.Exit(code)
}
