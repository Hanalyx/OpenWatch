# A disposable sshd whose PAM stack counts failed authentications with
# pam_faillock, for the protected-dial container tests (spec C-15). The
# account and its passwords are synthetic; the tests set them.
FROM rockylinux/rockylinux:9
RUN dnf -y -q install openssh-server authselect passwd && dnf clean all \
 && authselect select minimal with-faillock --force \
 && printf 'deny = 3\nunlock_time = 0\n' > /etc/security/faillock.conf \
 && ssh-keygen -A \
 && useradd -m ops
COPY sshd_config /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
