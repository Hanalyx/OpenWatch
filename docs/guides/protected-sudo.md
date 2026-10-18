# Protected sudo contract amendment

This change implements OW-122 slice 5 on main `b646a9f3`. It is a proposal
for review. Consumer wiring and operator controls belong to slices 6 and 7.
No production consumer calls this adapter yet.

## Two separate bounds

One OpenWatch password write does not imply one PAM failure. In the reported
Rocky 9 measurements, sudo 1.9.17p2 with its default retry policy recorded
two failures after one wrong password line followed by EOF. With
`passwd_tries=1`, the same sequence recorded one failure. These measurements
apply to that sudo/PAM profile, not to every host.

The adapter enforces one secret submission per reservation. A separate,
validated host profile is required for a one-failure PAM bound. It covers
sudoers, PAM, the invoking account, and the exact command (or verification).
The established SSH connection must belong to that account.
Unknown profiles refuse password mode before a session starts. OpenWatch
does not change sudoers, disable lockout, or test guesses to learn the policy.

The profile names its evidence, host, username, command and expiry. It must
assert one password try, at most one PAM failure, and authentication of the
invoking user. It cannot cover rootpw, targetpw, another host or another
command. This is trusted configuration, not proof manufactured by the
adapter. A changed policy invalidates it even before expiry. Slice 6 must
resolve it from trusted evidence; slice 7 must restrict and audit its setup.
There is no API in this slice that accepts such assertions from a user.

This is a deliberate compatibility limit: password-based sudo remains
supported on validated profiles. It is refused on unknown profiles. A login,
a version string, cached privilege or NOPASSWD success is not validation of
sudoers or PAM. The profile does not guarantee that an account with earlier
failures cannot lock on its next attempt.

## Invocation and recovery

Every password invocation reserves the shared password state before opening
its SSH session. Its stage is sudo. The fence runs immediately before the
write and uses its own transaction to read the credential. The reservation
lasts for the command, with a timeout margin. The caller must not share this
SSH connection during the invocation: cancellation closes the connection.

Fresh verification uses `sudo -k -S -p OWPROMPT-<nonce>: -v`. It sends one
line only after the complete nonce prompt, then closes stdin. A lecture's
colon is not a prompt. Embedded line breaks and NUL in a password are refused.
A second prompt never receives another answer. This is a profile violation,
not proof that the password was rejected.

An ordinary password command runs under a constant marker script. A complete
prompt, one submission, and the marker prove that sudo admitted the command.
Its exit status may still be nonzero: a failed command is not a failed login.
Only a dedicated verification can recover a blocked secret. No command is
allowed to acquire a verification reservation.

The outcomes are:

| Evidence | Outcome |
|---|---|
| No remote invocation started | not_submitted |
| Complete success without a prompt, or a command marker without a submission | not_submitted |
| Fresh verification: prompt, submission, complete exit 0 | verified |
| Ordinary command: prompt, submission, complete marker | verified, as evidence only |
| Complete nonzero result after submission, without a marker | unsuccessful |
| Lost channel, canceled invocation, failed fence after sudo started, or incomplete output | unknown |

A launched invocation may start PAM even when no password is ultimately
written. For this reason, a refusal or cancellation after launch is unknown,
not a claim that the host counted nothing. It blocks automatic password
retries. A second prompt also blocks. No error-message text is interpreted as
proof of password rejection. Submission and prompt flags remain separate
from the outcome.

Settlement runs with a bounded context independent of the caller's canceled
context. Failed settlement closes the connection and returns ErrNotRecorded.
The reservation then remains for expiry handling. The adapter never releases
or resets protection by itself.

## Command execution

Modes are chosen before execution:

- Cached-only: sudo -n, no password, no fallback.
- Password-only: one reserved invocation, no fallback.
- Read-only fallback: sudo -n first; one password invocation is possible only
  after a complete nonzero result with no execution marker.
- Verify: a fresh password check with no command.

Remediation and rollback must choose cached-only or password-only. Slice 6
must enforce that mapping; passing a state-changing command as read-only is
not a supported caller contract.

The marker script is constant. All arguments, including the command, are
quoted separately. Fallback requires a normal exit status, complete output
and absence of the fresh marker across the whole stderr stream. Truncation,
a lost channel, a signal exit, cancellation or a command that already began
forbids it. The runner collects stream errors separately from the exit
status. It also requires a keepalive response on the same connection after
draining output: SSH channel EOF alone can mean a lost transport. This adds
one SSH round trip per completed invocation.
The runner drains output while bounding retained bytes. It neither replays
a command because of its error text nor uses that text to infer credentials.

## Acceptance evidence

AC-35 covers admission; AC-36 covers prompt and fence behavior; AC-37 covers
execution and fallback; AC-38 covers outcomes and cancellation. AC-39 measures
the PAM bound with the real protection store. AC-40 checks NOPASSWD, cached
privilege, quoting, command replay and unknown-policy refusal in containers.
The container criteria run under the existing mandatory CI opt-in.

The container policy is installed only in disposable test images. It is not
an installer change or an instruction to modify fleet hosts. The production
read callback and profile resolver still need integration tests in slice 6.
