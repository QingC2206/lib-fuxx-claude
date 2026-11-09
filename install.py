#!/usr/bin/env python3
"""Install files and PATH entries only; never execute Claude or net_check."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple


APP_ID = "personal-ccguard"
MARKER = "# Managed by personal-ccguard."
PATH_BEGIN = "# >>> personal-ccguard PATH >>>"
PATH_END = "# <<< personal-ccguard PATH <<<"
COMMANDS = {"ccguard-check": "check", "ccguard-cli": "cli",
            "ccguard-desktop": "desktop", "ccguard-kill": "kill"}
PAYLOAD = ("ccguard.py", "net_check.py", "install.py", "VERSION", "background-access.sh")
LEGACY_APP_ID = "personal-claude-tools"
LEGACY_COMMANDS = {"fuck-claude-check": "check", "fuck-claude-cli": "cli",
                   "fuck-claude-desktop": "desktop", "kill-claude": "kill"}
LEGACY_PAYLOAD = ("claude_commands.py", "net_check.py", "install.py", "VERSION")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".ccguard-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            os.fchmod(handle.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def wrapper(python: Path, controller: Path, kind: str) -> bytes:
    return (f"#!/bin/sh\n{MARKER}\nexec {shlex.quote(str(python))} -B "
            f"{shlex.quote(str(controller))} {kind} \"$@\"\n").encode()


def path_block(bin_dir: Path) -> str:
    return (f"{PATH_BEGIN}\n_ccguard_bin={shlex.quote(str(bin_dir))}\n"
            'case ":$PATH:" in\n'
            '    *":$_ccguard_bin:"*) ;;\n'
            '    *) export PATH="$_ccguard_bin:$PATH" ;;\n'
            'esac\nunset _ccguard_bin\n' + PATH_END + "\n")


def read_manifest(path: Path, app_id: str = APP_ID) -> Optional[dict]:
    if path.is_symlink():
        raise ValueError(f"安装记录是符号链接，已停止: {path}")
    if not path.exists():
        return None
    manifest = json.loads(path.read_text())
    if not isinstance(manifest, dict) or manifest.get("app_id") != app_id:
        raise ValueError(f"无法确认现有目录属于本工具: {path.parent}")
    if not isinstance(manifest.get("files"), dict):
        raise ValueError("安装记录缺少有效文件清单")
    return manifest


def safe_existing(path: Path, hashes: Dict[str, str], relative: str, desired: bytes) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"保留已有链接或非普通文件，未覆盖: {path}")
    current = path.read_bytes()
    if current == desired or digest(current) == hashes.get(relative):
        return
    raise ValueError(f"已有同名文件或本地修改，已保留且停止安装: {path}")


def legacy_installation(prefix: Path) -> Optional[dict]:
    """仅迁移带有效清单且内容未修改的旧分发包；不按命令名字直接删除。"""
    app_dir = prefix / "lib/claude-tools"
    if app_dir.is_symlink():
        raise ValueError(f"旧程序目录是符号链接，已保留: {app_dir}")
    manifest = read_manifest(app_dir / "manifest.json", LEGACY_APP_ID)
    if manifest is None:
        if any((prefix / "bin" / name).exists() or (prefix / "bin" / name).is_symlink()
               for name in LEGACY_COMMANDS):
            raise ValueError("旧命令缺少安装清单，无法核验归属，已保留且停止迁移")
        return None
    allowed = {"lib/claude-tools/" + name for name in LEGACY_PAYLOAD} | {
        "bin/" + name for name in LEGACY_COMMANDS}
    required = allowed - {"bin/fuck-claude-check"}  # 兼容尚未添加 check 的三命令分发包。
    if (manifest.get("prefix") != str(prefix) or not required <= set(manifest["files"])
            or set(manifest["files"]) - allowed):
        raise ValueError("旧安装清单的前缀或文件范围无效，已停止迁移")
    for relative, expected in manifest["files"].items():
        path = prefix / relative
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != expected:
            raise ValueError(f"旧安装文件缺失或有本地修改，已保留且停止迁移: {path}")
    for name in LEGACY_COMMANDS:
        path = prefix / "bin" / name
        if "bin/" + name not in manifest["files"] and (path.exists() or path.is_symlink()):
            raise ValueError(f"发现未登记的旧命令，已保留: {path}")
    return manifest


def backup_migration(prefix: Path, paths: List[Path]) -> Path:
    parent = prefix / "state/ccguard/backups"
    parent.mkdir(parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix="from-claude-tools-", dir=str(parent)))
    records = []
    for path in dict.fromkeys(paths):
        if not path.exists():
            continue
        destination = backup / str(len(records))
        shutil.copy2(path, destination)
        checksum = digest(path.read_bytes())
        if digest(destination.read_bytes()) != checksum:
            raise OSError(f"迁移备份校验失败: {path}")
        records.append({"original": str(path), "backup": destination.name, "sha256": checksum,
                        "mode": stat.S_IMODE(path.stat().st_mode)})
    (backup / "backup.json").write_text(json.dumps({"files": records}, ensure_ascii=False, indent=2) + "\n")
    return backup


def install(package: Path, prefix: Path, python: Path, profile: Optional[Path]) -> List[str]:
    app_dir = prefix / "lib/ccguard"
    if app_dir.is_symlink():
        raise ValueError(f"目标程序目录是符号链接，未覆盖: {app_dir}")
    manifest_path = app_dir / "manifest.json"
    previous = read_manifest(manifest_path)
    if not previous and app_dir.exists() and any(app_dir.iterdir()):
        raise ValueError(f"目标目录已有未识别内容，未覆盖: {app_dir}")
    legacy = legacy_installation(prefix)
    if previous and legacy:
        raise ValueError("检测到新旧两套安装同时存在，已保留并停止，请先检查冲突")
    hashes = previous.get("files", {}) if previous else {}
    writes: List[Tuple[Path, bytes, int]] = []
    new_hashes = {}
    for name in PAYLOAD:
        data = (package / name).read_bytes()
        relative = "lib/ccguard/" + name
        destination = prefix / relative
        safe_existing(destination, hashes, relative, data)
        writes.append((destination, data, 0o644))
        new_hashes[relative] = digest(data)
    for name, kind in COMMANDS.items():
        data = wrapper(python, app_dir / "ccguard.py", kind)
        relative = "bin/" + name
        destination = prefix / relative
        safe_existing(destination, hashes, relative, data)
        writes.append((destination, data, 0o755))
        new_hashes[relative] = digest(data)

    # 重复安装沿用首次加入的准确区块，卸载只删除这段，不改其他 Shell 配置。
    profile_record = previous.get("profile") if previous else None
    legacy_profile = legacy.get("profile") if legacy else None
    if legacy_profile:
        if (profile is None or legacy_profile.get("path") != str(profile)
                or not isinstance(legacy_profile.get("block"), str)
                or not legacy_profile["block"]
                or type(legacy_profile.get("created")) is not bool):
            raise ValueError("迁移需使用旧安装登记的 Shell 配置；有 PATH 区块时不可使用 --no-path")
        expected_block = path_block(prefix / "bin").replace("personal-ccguard", LEGACY_APP_ID).replace(
            "_ccguard_bin", "_claude_tools_bin")
        if legacy_profile["block"] not in (expected_block, "\n" + expected_block):
            raise ValueError("旧安装 PATH 区块格式无效，已保留且停止迁移")
    if profile_record and profile is not None and profile_record["path"] != str(profile):
        raise ValueError("现有安装使用不同的 Shell 配置文件，请先卸载后再更改")
    if profile is not None:
        if profile.is_symlink():
            raise ValueError(f"Shell 配置是符号链接；可用 --no-path 安装后手动配置 PATH: {profile}")
        existed = profile.exists()
        old_text = profile.read_text() if existed else ""
        block = path_block(prefix / "bin")
        if legacy_profile:
            old_block = legacy_profile["block"]
            if old_text.count(old_block) != 1 or PATH_BEGIN in old_text or PATH_END in old_text:
                raise ValueError("旧 PATH 区块被修改或新旧区块冲突，已保留且停止迁移")
            addition = ("\n" if old_block.startswith("\n") else "") + block
            writes.append((profile, old_text.replace(old_block, addition, 1).encode(),
                           stat.S_IMODE(profile.stat().st_mode)))
            profile_record = {"path": str(profile), "block": addition, "created": legacy_profile["created"]}
        elif profile_record:
            if profile_record["block"] not in old_text:
                raise ValueError("本工具的 PATH 区块已被手动修改，已保留且停止安装")
        else:
            if PATH_BEGIN in old_text or PATH_END in old_text:
                raise ValueError("发现未登记的 PATH 区块，请检查 Shell 配置")
            addition = ("\n" if old_text and not old_text.endswith("\n") else "") + block
            mode = stat.S_IMODE(profile.stat().st_mode) if existed else 0o644
            writes.append((profile, (old_text + addition).encode(), mode))
            profile_record = {"path": str(profile), "block": addition, "created": not existed}
    manifest = {
        "app_id": APP_ID, "version": (package / "VERSION").read_text().strip(),
        "prefix": str(prefix), "python": str(python), "files": new_hashes, "profile": profile_record,
    }
    removals = ([prefix / relative for relative in legacy["files"]]
                + [prefix / "lib/claude-tools/manifest.json"]) if legacy else []
    if legacy:
        backup = backup_migration(prefix, removals + [path for path, _, _ in writes])
        manifest["migration_backup"] = str(backup)
    elif previous and previous.get("migration_backup"):
        manifest["migration_backup"] = previous["migration_backup"]
    writes.append((manifest_path, (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode(), 0o644))
    originals = {path: (path.read_bytes() if path.exists() else None,
                       stat.S_IMODE(path.stat().st_mode) if path.exists() else None)
                 for path in [item[0] for item in writes] + removals}
    completed = []
    try:
        for path, data, mode in writes:
            atomic_write(path, data, mode)
            completed.append(path)
        # 新文件已全部落盘后，才删除经清单校验的旧命令和旧程序。
        for path in removals:
            relative = str(path.relative_to(prefix))
            expected = legacy["files"].get(relative, digest(originals[path][0]))
            if path.is_symlink() or digest(path.read_bytes()) != expected:
                raise ValueError(f"迁移过程中旧文件发生变化，已停止: {path}")
            path.unlink()
            completed.append(path)
    except BaseException:
        for path in reversed(completed):
            data, mode = originals[path]
            if data is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, data, mode)
        raise
    if legacy:
        try:
            (prefix / "lib/claude-tools").rmdir()
        except OSError:
            pass  # 只移除登记的文件，用户额外文件保留。
    return [str(prefix / "bin" / name) for name in COMMANDS]


def background_rule_path() -> Path:
    return Path(f"/private/etc/sudoers.d/ccguard-btm-{os.getuid()}")


def uninstall(prefix: Path) -> List[str]:
    app_dir = prefix / "lib/ccguard"
    if app_dir.is_symlink():
        raise ValueError(f"程序目录是符号链接，停止卸载: {app_dir}")
    manifest_path = app_dir / "manifest.json"
    manifest = read_manifest(manifest_path)
    if manifest is None:
        return []
    rule = background_rule_path()
    if rule.exists() or rule.is_symlink():
        command = "bash " + shlex.quote(str(app_dir / "background-access.sh")) + " disable"
        raise ValueError(f"请先撤销本用户的后台只读授权，再卸载: {command}")
    preserved = []
    # 固定白名单，安装记录中的路径不能导致删除安装目录外的文件。
    allowed = {"lib/ccguard/" + name for name in PAYLOAD} | {"bin/" + name for name in COMMANDS}
    if set(manifest["files"]) - allowed:
        raise ValueError("安装记录含未知路径，停止卸载")
    for relative, expected in manifest["files"].items():
        path = prefix / relative
        if path.is_symlink() or (path.exists() and (not path.is_file() or digest(path.read_bytes()) != expected)):
            preserved.append(str(path))
        elif path.exists():
            path.unlink()
    profile_record = manifest.get("profile")
    if profile_record:
        path = Path(profile_record["path"])
        if path.is_symlink():
            preserved.append(str(path))
        elif path.exists():
            text = path.read_text()
            block = profile_record["block"]
            if block not in text:
                preserved.append(str(path))
            else:
                remaining = text.replace(block, "", 1)
                if not remaining and profile_record["created"]:
                    path.unlink()
                else:
                    atomic_write(path, remaining.encode(), stat.S_IMODE(path.stat().st_mode))
    if not preserved:
        manifest_path.unlink()
        try:
            app_dir.rmdir()
        except OSError:
            pass  # 用户额外文件留在原处。
    return preserved


def main(arguments=None) -> int:
    parser = argparse.ArgumentParser(description="安装/迁移/卸载 CCGuard；不会运行网络检查或操作 Claude")
    parser.add_argument("--uninstall", action="store_true", help="卸载本工具")
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".local", help="安装前缀，默认 ~/.local")
    parser.add_argument("--no-path", action="store_true", help="不修改 Shell 配置，手动把 PREFIX/bin 加入 PATH")
    args = parser.parse_args(arguments)
    if sys.platform != "darwin" or sys.version_info < (3, 9):
        print("此分发包需要 macOS 和 Python 3.9 或以上版本。", file=sys.stderr)
        return 1
    prefix = args.prefix.expanduser().resolve()
    try:
        if args.uninstall:
            preserved = uninstall(prefix)
            if preserved:
                print("已移除未修改的工具文件；以下本地修改已保留:\n" + "\n".join(preserved))
                return 1
            print("已卸载 CCGuard；Claude 应用、登录信息和对话数据未改动。")
            return 0
        profile = None
        if not args.no_path:
            shell = Path(os.environ.get("SHELL", "/bin/zsh")).name
            if shell not in ("zsh", "bash", "sh"):
                raise ValueError("此 Shell 请使用 --no-path 安装，然后手动把 PREFIX/bin 加入 PATH")
            profile = Path.home() / (".zshrc" if shell == "zsh" else ".bash_profile")
        installed = install(Path(__file__).resolve().parent, prefix, Path(sys.executable).resolve(), profile)
        print("已安装（仅复制文件和设置 PATH，未运行网络检查或 Claude）:\n" + "\n".join(installed))
        manifest = read_manifest(prefix / "lib/ccguard/manifest.json")
        if manifest.get("migration_backup"):
            print("旧版迁移备份: " + manifest["migration_backup"])
        print("新开一个终端窗口后可用；当前窗口也可执行:\nexport PATH=" + shlex.quote(str(prefix / "bin")) + ':"$PATH"')
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"操作未完成: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
