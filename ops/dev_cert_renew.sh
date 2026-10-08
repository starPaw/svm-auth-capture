#!/usr/bin/env bash
# Certbot deploy hook for the dev certificate only. No application restarts.
set -euo pipefail
case " ${RENEWED_DOMAINS:-} " in
  *" dev.capture402.xyz "*) /usr/sbin/nginx -t; /usr/bin/systemctl reload nginx ;;
esac
