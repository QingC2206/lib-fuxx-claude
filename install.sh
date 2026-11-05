#!/bin/sh
set -eu
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_command=${CCGUARD_PYTHON:-python3}
if ! command -v "$python_command" >/dev/null 2>&1; then
    echo '需要 Python 3.9 或以上版本。也可以用 CCGUARD_PYTHON 指定 Python 路径。' >&2
    exit 1
fi
exec "$python_command" -B "$package_dir/install.py" "$@"
