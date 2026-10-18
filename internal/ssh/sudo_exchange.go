package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/Hanalyx/openwatch/internal/credprotect"
)

// sudoCapture drains the whole stream, even when the retained output is full.
// A limit hit means incomplete evidence and forbids recovery and fallback.
type sudoCapture struct {
	data      []byte
	limit     int
	truncated bool
}

func (c *sudoCapture) Write(p []byte) (int, error) {
	n := len(p)
	keep := min(n, c.limit-len(c.data))
	c.data = append(c.data, p[:keep]...)
	if keep < n {
		c.truncated = true
	}
	return n, nil
}

// sudoPrompt scans the full nonce across writes. A lecture's colon is not a
// prompt. The only password write is here, after the fence, and it occurs once.
type sudoPrompt struct {
	capture   sudoCapture
	token     string
	tail      string
	count     int
	submitted bool
	stdin     io.WriteCloser
	secret    func() (string, error)
	abort     func()
	err       error
}

func (p *sudoPrompt) Write(b []byte) (int, error) {
	n, _ := p.capture.Write(b)
	if p.token == "" {
		return n, nil
	}
	text := p.tail + string(b)
	for {
		i := strings.Index(text, p.token)
		if i < 0 {
			break
		}
		p.count++
		text = text[i+len(p.token):]
		if p.count > 1 {
			p.err = ErrUnsupportedExchange
			p.abort()
			return n, p.err
		}
		if p.capture.truncated {
			p.err = errors.New("ssh: sudo prompt capture limit reached")
		} else {
			var pw string
			pw, p.err = p.secret()
			if p.err == nil {
				// A partial write is still a submission; it must never be retried.
				p.submitted = true
				var wrote int
				wrote, p.err = io.WriteString(p.stdin, pw+"\n")
				if p.err == nil && wrote != len(pw)+1 {
					p.err = io.ErrShortWrite
				}
			}
		}
		if p.err != nil {
			p.abort()
			return n, p.err
		}
		if p.err = p.stdin.Close(); p.err != nil {
			p.abort()
			return n, p.err
		}
	}
	p.tail = text[max(0, len(text)-len(p.token)+1):]
	return n, nil
}

type sudoExchange struct {
	out          sudoCapture
	prompt       sudoPrompt
	marker       string
	exit         int
	complete     bool
	invoked      bool
	verifiedOnly bool
}

func (x *sudoExchange) started() bool {
	return x.marker != "" && bytes.Contains(x.prompt.capture.data, []byte(x.marker))
}
func (x *sudoExchange) result() SudoResult {
	return SudoResult{Stdout: x.out.data, Stderr: x.prompt.capture.data, ExitCode: x.exit,
		Complete: x.complete, CommandStarted: x.started(), PromptSeen: x.prompt.count > 0, Submitted: x.prompt.submitted}
}
func (x *sudoExchange) fallback() bool { return x.complete && x.exit != 0 && !x.started() }
func (x *sudoExchange) outcome() credprotect.Outcome {
	if !x.invoked {
		return credprotect.OutcomeNotSubmitted
	}
	// A repeated nonce prompt proves a profile violation even when aborting
	// the exchange leaves its transport or output incomplete.
	if x.prompt.count > 1 {
		return credprotect.OutcomeUnsupportedProfile
	}
	// Starting PAM can count an attempt even if a fence refusal or cancellation
	// prevents the password write. An uncertain launched invocation must block.
	if !x.complete {
		return credprotect.OutcomeUnknown
	}
	if !x.prompt.submitted {
		if x.exit == 0 || x.started() {
			return credprotect.OutcomeNotSubmitted
		}
		return credprotect.OutcomeUnknown
	}
	if (x.verifiedOnly && x.exit == 0) || (!x.verifiedOnly && x.started()) {
		return credprotect.OutcomeVerified
	}
	return credprotect.OutcomeUnsuccessful
}

func sudoExec(ctx context.Context, client *cryptossh.Client, command string, password, verify bool,
	limit int, secret func() (string, error)) (*sudoExchange, error) {
	x := &sudoExchange{out: sudoCapture{limit: limit}, exit: -1, verifiedOnly: verify}
	nonce, err := sudoNonce()
	if err != nil {
		return x, err
	}
	x.marker = "OWEXEC-" + nonce + "\n"
	x.prompt.capture.limit = limit
	args := []string{"sudo", "-n"}
	if password {
		x.prompt.token = "OWPROMPT-" + nonce + ":"
		args = []string{"sudo", "-k", "-S", "-p", x.prompt.token}
	}
	if verify {
		args = append(args, "-v")
	} else {
		args = append(args, "--", "/bin/sh", "-c", sudoMarkerScript, "ow-exec", nonce, command)
	}
	// Closing the connection also unblocks NewSession, Start and pipe writes.
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	if err := ctx.Err(); err != nil {
		return x, err
	}
	session, err := client.NewSession()
	if err != nil {
		return x, err
	}
	defer func() { _ = session.Close() }()
	stdin, err := session.StdinPipe()
	if err != nil {
		return x, err
	}
	defer func() { _ = stdin.Close() }()
	x.prompt.stdin = stdin
	x.prompt.secret = secret // pragma: allowlist secret (callback, not material)
	x.prompt.abort = func() { _ = client.Close() }
	stdout, err := session.StdoutPipe()
	if err != nil {
		return x, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return x, err
	}
	x.invoked = true
	if err = session.Start(sudoArgv(args...)); err != nil {
		return x, err
	}
	if !password {
		_ = stdin.Close()
	}
	// Session.Wait gives an ExitError precedence over copy errors. Collect
	// both streams ourselves so a nonzero exit cannot hide a read failure.
	reads := make(chan error, 2)
	go func() { _, e := io.Copy(&x.out, stdout); reads <- e }()
	go func() { _, e := io.Copy(&x.prompt, stderr); reads <- e }()
	err = session.Wait()
	readErr := errors.Join(<-reads, <-reads)
	var status *cryptossh.ExitError
	switch {
	case err == nil:
		x.exit = 0
		x.complete = true
	case errors.As(err, &status):
		x.exit = status.ExitStatus()
		x.complete = status.Signal() == ""
	}
	if x.out.truncated || x.prompt.capture.truncated || x.prompt.err != nil || readErr != nil || ctx.Err() != nil {
		x.complete = false
	}
	// Channel EOF also occurs on connection loss. Require a reply on the
	// same transport after draining: a false keepalive reply is fine, but a
	// lost connection cannot turn a partial transcript into safe fallback.
	if x.complete {
		if _, _, probeErr := client.SendRequest("keepalive@openssh.com", true, nil); probeErr != nil {
			x.complete = false
			return x, fmt.Errorf("ssh: confirm sudo transport: %w", probeErr)
		}
	}
	if x.prompt.err != nil {
		return x, x.prompt.err
	}
	if readErr != nil {
		return x, fmt.Errorf("ssh: read sudo output: %w", readErr)
	}
	if ctx.Err() != nil {
		return x, ctx.Err()
	}
	if !x.complete && err == nil {
		err = errors.New("ssh: sudo output is incomplete")
	}
	if err != nil {
		return x, fmt.Errorf("ssh: sudo command: %w", err)
	}
	return x, nil
}
