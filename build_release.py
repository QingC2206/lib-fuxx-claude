#!/usr/bin/env python3
"""Build a source ZIP from an explicit allowlist; never run installed commands."""
from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
import zipfile
from pathlib import Path


FILES = ("README.md", "LICENSE", "VERSION", "install.sh", "uninstall.sh", "install.py", "background-access.sh",
         "ccguard.py", "net_check.py", "build_release.py", "tests/test_ccguard.py",
         "tests/test_net_check.py", "tests/test_installer.py", "tests/test_background_access.py")


def build(source: Path, output: Path) -> Path:
    contents = {}
    for name in FILES:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"缺少分发文件或文件是符号链接: {path}")
        contents[name] = path.read_bytes()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / "ccguard-macos.zip"
    descriptor, temporary = tempfile.mkstemp(prefix=".ccguard-release-", suffix=".zip", dir=str(output))
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in contents.items():
                # 固定时间戳和模式，使相同源码构建出的 ZIP 相同。
                entry = zipfile.ZipInfo("ccguard/" + name, date_time=(2026, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = (0o100755 if name.endswith(".sh") else 0o100644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, data)
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise OSError("分发包校验失败")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    checksum = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(".zip.sha256").write_text(checksum + "  " + destination.name + "\n")
    return destination


def main() -> None:
    source = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="构建 CCGuard macOS 源码分发包")
    parser.add_argument("--output", type=Path, default=source / "dist")
    args = parser.parse_args()
    print(build(source, args.output.expanduser().resolve()))


if __name__ == "__main__":
    main()
