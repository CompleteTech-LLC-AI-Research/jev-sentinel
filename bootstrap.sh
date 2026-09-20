#!/bin/sh
# No downloads. Forward all arguments to the bundled, plan-first installer.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -I "$HERE/install.py" "$@"
