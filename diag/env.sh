#!/bin/bash
echo "== uname"; uname -a; id
echo "== lsm"; cat /sys/kernel/security/lsm 2>&1
echo "== sysctls"; for f in kernel/apparmor_restrict_unprivileged_userns kernel/unprivileged_userns_clone kernel/yama/ptrace_scope user/max_user_namespaces net/ipv6/conf/all/disable_ipv6 kernel/unprivileged_bpf_disabled; do echo -n "$f="; cat /proc/sys/$f 2>&1; done
echo "== unshare -Urn"; unshare -Urn true 2>&1 && echo "userns+netns OK" ; unshare -n true 2>&1 && echo "netns as is OK"
echo "== which"; which bwrap unshare curl python3 sudo 2>&1
echo "== seccomp of this shell"; grep -i seccomp /proc/self/status
echo "== ipv6 loopback"; python3 -c "
import socket
s=socket.socket(socket.AF_INET6); s.bind(('::1',0)); print('::1 bind ok')" 2>&1
