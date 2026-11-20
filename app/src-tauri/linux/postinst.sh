#!/bin/sh
# Let the recovery server open UDP ports 67 (DHCP) and 69 (TFTP) without running as root.
setcap cap_net_bind_service=+ep /usr/bin/miwifi-recovery 2>/dev/null || true
exit 0
