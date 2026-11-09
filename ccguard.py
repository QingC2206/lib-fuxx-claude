#!/usr/bin/env python3
"""CCGuard: macOS Claude check, launch and quit commands. Standard library only.

Launch: run the adjacent net_check.py, then require y (default n).
Check: run net_check.py only, forwarding its arguments and exit status.
Quit: request app quit / CLI SIGTERM, wait, then SIGKILL remaining Claude trees.
"""
from __future__ import annotations

import ctypes
import functools
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


NET_CHECK = Path(__file__).resolve().with_name("net_check.py")
DESKTOP_APP = Path("/Applications/Claude.app")
DESKTOP_ID = "com.anthropic.claudefordesktop"
DESKTOP_TEAM_ID = "Q6L2SF6YDW"
DESKTOP_REQUIREMENT = (
    f'=identifier "{DESKTOP_ID}" and anchor apple generic '
    'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
    'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
    f'and certificate leaf[subject.OU] = "{DESKTOP_TEAM_ID}"'
)
GRACE_SECONDS = 5.0
KILL_WAIT_SECONDS = 8.0
QUIET_SECONDS = 3.0
POLL_SECONDS = 0.2
QUIT_SCRIPT = '''on run argv
    set appPath to item 1 of argv
    with timeout of 3 seconds
        tell application appPath
            if it is running then quit
        end tell
    end timeout
end run
'''


def confirm_launch(label: str) -> bool:
    while True:
        try:
            answer = input(f"是否启动 {label}？[y/N] ").strip().lower()
        except EOFError:
            return False
        if answer in ("", "n"):
            return False
        if answer == "y":
            return True
        print("请输入 y 或 n；直接回车为 n。", flush=True)


@functools.lru_cache(maxsize=128)
def desktop_bundle(path: Path) -> bool:
    try:
        with (path / "Contents/Info.plist").open("rb") as handle:
            metadata = plistlib.load(handle)
            return isinstance(metadata, dict) and metadata.get("CFBundleIdentifier") == DESKTOP_ID
    except (OSError, ValueError, plistlib.InvalidFileException):
        return False


def find_desktop() -> Optional[Path]:
    """只允许已安装的固定路径；每次启动前重新读身份并核验 Anthropic 签名。"""
    app = DESKTOP_APP
    if app.is_symlink():
        raise RuntimeError(f"桌面启动路径不能是符号链接: {app}")
    if not app.exists():
        return None
    info = app / "Contents/Info.plist"
    executable = app / "Contents/MacOS/Claude"
    if not app.is_dir():
        raise RuntimeError(f"桌面启动路径不是应用目录: {app}")
    if not info.is_file() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError(f"桌面应用缺少有效的元数据或主程序: {app}")
    for path in (app, info, executable):
        if path.resolve(strict=True) != path:
            raise RuntimeError(f"桌面应用路径被重定向，已取消启动: {path}")
    try:
        with info.open("rb") as handle:
            metadata = plistlib.load(handle)
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        raise RuntimeError(f"无法读取桌面应用身份，已取消启动: {app}") from exc
    if (not isinstance(metadata, dict) or metadata.get("CFBundleIdentifier") != DESKTOP_ID
            or metadata.get("CFBundleExecutable") != "Claude"
            or metadata.get("CFBundlePackageType") != "APPL"
            or metadata.get("LSBackgroundOnly") or metadata.get("LSUIElement")):
        raise RuntimeError(f"固定路径中的应用不是预期的 Claude Desktop，已取消启动: {app}")
    # Bundle ID 可以被仿写；同时验证完整签名、开发者身份和签名标识。
    # 不缓存启动校验，避免正常更新或路径内容变化后复用旧结果。
    try:
        result = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict",
             "--test-requirement", DESKTOP_REQUIREMENT, str(app)],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Claude Desktop 签名核验超时，已取消启动。") from exc
    except OSError as exc:
        raise RuntimeError("无法执行 Claude Desktop 签名核验，已取消启动。") from exc
    if result.returncode:
        raise RuntimeError("Claude Desktop 签名或开发者身份核验失败，已取消启动。")
    return app


def check_network(arguments: List[str]) -> int:
    """只运行网络检查，保持输出与参数；不询问或操作 Claude。"""
    if not NET_CHECK.is_file():
        print(f"找不到网络检查脚本: {NET_CHECK}", file=sys.stderr)
        return 1
    result = subprocess.run([sys.executable, "-B", str(NET_CHECK), *arguments], check=False)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


def launch(kind: str, arguments: List[str]) -> int:
    if not NET_CHECK.is_file():
        print(f"找不到网络检查脚本: {NET_CHECK}", file=sys.stderr)
        return 1
    # 不改变 cwd，Claude CLI 仍从用户当前项目目录启动。
    result = subprocess.run([sys.executable, "-B", str(NET_CHECK)], check=False)
    if result.returncode not in (0, 1, 2):
        print("网络检查被中断或未正常完成，已取消启动。", file=sys.stderr)
        return 1
    label = "Claude CLI" if kind == "cli" else "Claude Desktop"
    if kind == "desktop":
        print(f"桌面启动目标（固定）: {DESKTOP_APP}", flush=True)
    # PASS / FAIL / WARN 均由用户看完结果后决定，不隐式放行或替用户拒绝。
    if not confirm_launch(label):
        print("已取消启动。", flush=True)
        return 0
    if kind == "cli":
        command = shutil.which("claude")
        if not command:
            print("未找到 claude，请先安装 Claude CLI。", file=sys.stderr)
            return 127
        os.execv(command, [command, *arguments])
        return 0
    app = find_desktop()
    if app is None:
        print(f"未找到固定路径的 Claude Desktop: {DESKTOP_APP}；请安装到此位置后重试。",
              file=sys.stderr)
        return 127
    command = ["/usr/bin/open", "-a", str(app)]
    if arguments:
        command.extend(["--args", *arguments])
    return subprocess.run(command, check=False).returncode


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    uid: int
    started: str
    executable: str
    responsible_pid: Optional[int] = None

    @property
    def identity(self) -> Tuple[int, int, str, str]:
        # 每次发信号前重新核验 PID、归属、出生时间和可执行文件，避免 PID 复用误杀。
        return self.pid, self.uid, self.started, self.executable


@functools.lru_cache(maxsize=1)
def libproc():
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    return library


def executable_path(pid: int) -> str:
    buffer = ctypes.create_string_buffer(4096)
    if libproc().proc_pidpath(pid, buffer, len(buffer)) <= 0:
        return ""
    return os.fsdecode(buffer.value)


@functools.lru_cache(maxsize=1)
def responsibility_function():
    """macOS SPI：可用于识别 launchd 代为启动的进程；不可用时明确降低核验范围。"""
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        function = library.responsibility_get_pid_responsible_for_pid
        function.argtypes, function.restype = [ctypes.c_int], ctypes.c_int
        return function
    except (OSError, AttributeError):
        return None


def responsible_process_id(pid: int) -> Optional[int]:
    function = responsibility_function()
    if function is None:
        return None
    value = function(pid)
    return value if value > 0 else None


def snapshot_processes() -> Dict[int, Process]:
    # comm 不含用户 prompt/参数；libproc 取得实际程序路径，避免进程改名影响识别。
    result = subprocess.run(
        ["/bin/ps", "-ww", "-axo", "pid=,ppid=,uid=,lstart=,stat=,comm="],
        capture_output=True, text=True, check=True, timeout=5,
        env={**os.environ, "LC_ALL": "C"},
    )
    processes = {}
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 9)
        if len(fields) != 10:
            raise RuntimeError("无法解析进程列表，停止清理")
        pid, ppid, uid = map(int, fields[:3])
        if fields[8].startswith("Z"):
            continue
        path = executable_path(pid) or fields[9]
        responsible = responsible_process_id(pid) if uid == os.getuid() else None
        processes[pid] = Process(pid, ppid, uid, " ".join(fields[3:8]), path, responsible)
    return processes


def claude_app_for_executable(executable: str) -> Optional[Path]:
    path = Path(executable)
    # 由外向内检查应用包，主程序、Helper、Crashpad 都归到同一桌面应用。
    for parent in reversed(path.parents):
        if parent.suffix == ".app" and desktop_bundle(parent):
            return parent
    return None


def cli_executables() -> Set[Path]:
    candidates = [Path.home() / ".local/bin/claude"]
    found = shutil.which("claude")
    if found:
        candidates.append(Path(found))
    return {path.resolve() for path in candidates if path.is_file()}


def root_kind(process: Process, cli_paths: Set[Path]) -> str:
    path = Path(process.executable)
    if claude_app_for_executable(process.executable) is not None:
        return "desktop"
    versions = Path.home() / ".local/share/claude/versions"
    # 同时识别更新前仍在运行的 native CLI 版本；不按裸进程名/参数关键词杀进程。
    if path in cli_paths or (path.is_absolute() and path.parent == versions):
        return "cli"
    return ""


def protected_pids(processes: Dict[int, Process]) -> Set[int]:
    protected = {0, 1}
    pid = os.getpid()
    while pid not in protected:
        protected.add(pid)
        process = processes.get(pid)
        if process is None:
            break
        pid = process.ppid
    return protected


def refresh_targets(processes: Dict[int, Process], tracked: Dict[int, Process],
                    cli_paths: Set[Path], protected: Set[int]) -> Dict[int, Process]:
    eligible = {pid: process for pid, process in processes.items()
                if process.uid == os.getuid() and pid not in protected}
    targets = {pid: process for pid, process in eligible.items()
               if root_kind(process, cli_paths)
               or (pid in tracked and process.identity == tracked[pid].identity)}
    # 责任进程可以已退出，但若 PID 已复用为其他进程，则不再使用旧关联。
    departed = {pid for pid in tracked if pid not in processes and pid not in protected}
    # 在正常关闭前记下子进程，PPID 变成 1 或 launchd 代启动也保留已验证的归属。
    while True:
        children = {pid: process for pid, process in eligible.items()
                    if pid not in targets and (process.ppid in targets
                       or process.responsible_pid in targets or process.responsible_pid in departed)}
        if not children:
            return targets
        targets.update(children)


def signal_if_current(process: Process, sig: int) -> None:
    if process.uid != os.getuid() or process.pid in (0, 1, os.getpid()):
        return
    current = snapshot_processes().get(process.pid)
    if current is None or current.identity != process.identity:
        return
    try:
        os.kill(process.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        print(f"无法向 PID {process.pid} 发信号；最终检查会报告是否仍有残留。", file=sys.stderr)


def request_desktop_quit(app: Path) -> None:
    # 参数单独传入，应用路径不会被当作 AppleScript 源码。
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", QUIT_SCRIPT, str(app)],
            capture_output=True, text=True, check=False, timeout=4,
        )
        if result.returncode:
            print("桌面版正常退出请求未完成，继续检查残留。", flush=True)
    except subprocess.TimeoutExpired:
        print("桌面版正常退出请求超时，继续检查残留。", flush=True)


@dataclass
class BackgroundState:
    jobs: Dict[int, List[str]] = field(default_factory=dict)
    registered_jobs: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def is_claude_service(label: str) -> bool:
    return (label == DESKTOP_ID or label.startswith(DESKTOP_ID + ".")
            or label.startswith("application." + DESKTOP_ID + ".")
            or label == "com.anthropic.claude-code" or label.startswith("com.anthropic.claude-code."))


def read_background_state() -> BackgroundState:
    # dumpbtm 即便只读也会请求 system.privilege.admin，可能弹出密码窗口。
    # 不查询 BTM、不提权、不使用缓存冒充当前权限；只读取当前用户的服务状态。
    state = BackgroundState()
    try:
        result = subprocess.run(["/bin/launchctl", "list"], capture_output=True, text=True,
                                check=True, timeout=5, stdin=subprocess.DEVNULL)
        lines = result.stdout.splitlines()
        if not lines or lines[0].split() != ["PID", "Status", "Label"]:
            raise ValueError("无法识别 launchd 服务列表")
        for line in lines[1:]:
            parts = line.split(None, 2)
            if len(parts) != 3:
                raise ValueError("launchd 服务条目格式异常")
            pid, _, label = parts
            if not is_claude_service(label):
                continue
            state.registered_jobs.append(label)
            if pid != "-":
                if not pid.isdecimal() or int(pid) <= 0:
                    raise ValueError("launchd 服务 PID 无效")
                state.jobs.setdefault(int(pid), []).append(label)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        state.errors.append(f"后台服务未核验: {type(exc).__name__}")
    if responsibility_function() is None:
        state.errors.append("进程归属接口不可用，无法完整核验脱离父进程的助手")
    return state


def report_background(state: BackgroundState) -> None:
    print("[INFO] 后台权限: 未读取（免密码模式）；可在「系统设置 → 通用 → 登录项与扩展 → App 后台活动」中查看或关闭 Claude。",
          flush=True)
    for pid, labels_for_pid in sorted(state.jobs.items()):
        print(f"后台服务仍报告 PID {pid}: {', '.join(labels_for_pid)}", file=sys.stderr)
    for error in state.errors:
        print(error, file=sys.stderr)


def wait_for_exit(tracked: Dict[int, Process], cli_paths: Set[Path],
                  protected: Set[int], seconds: float, force: bool = False) -> Dict[int, Process]:
    deadline = time.monotonic() + seconds
    # 调用方保留历史，跨正常退出、强制清理和最终复检追踪已脱离父进程的助手。
    history = tracked
    quiet_since = None
    signalled = set()
    while True:
        processes = snapshot_processes()
        for pid in list(history):
            if pid in processes and processes[pid].identity != history[pid].identity:
                del history[pid]
        tracked = refresh_targets(processes, history, cli_paths, protected)
        history.update(tracked)
        now = time.monotonic()
        if tracked:
            quiet_since = None
            if force:
                for process in tracked.values():
                    if process.identity not in signalled:
                        signal_if_current(process, signal.SIGKILL)
                        signalled.add(process.identity)
            if now >= deadline:
                return tracked
        else:
            if quiet_since is None:
                quiet_since = now
            if now - quiet_since >= QUIET_SECONDS:
                return {}
            # 到达期限时若刚好为空，仍补足连续观察；一旦再次出现进程即结束或清理。
        time.sleep(POLL_SECONDS)


def kill_claude(dry_run: bool = False) -> int:
    processes = snapshot_processes()
    protected = protected_pids(processes)
    cli_paths = cli_executables()
    tracked = refresh_targets(processes, {}, cli_paths, protected)
    if dry_run:
        for process in sorted(tracked.values(), key=lambda item: item.pid):
            print(f"PID {process.pid}: {process.executable}")
        background = read_background_state()
        report_background(background)
        print("仅预览，未发送退出请求、信号或修改后台权限。")
        return 2 if background.errors else 0

    if tracked:
        print(f"请求正常退出 Claude（含关联进程共 {len(tracked)} 个），最多等待 {GRACE_SECONDS:g} 秒…",
              flush=True)
    else:
        print(f"暂未发现 Claude 进程，继续观察 {QUIET_SECONDS:g} 秒并核验后台状态…", flush=True)
    apps = {app for process in tracked.values()
            for app in [claude_app_for_executable(process.executable)] if app is not None}
    for app in sorted(apps):
        request_desktop_quit(app)
    for process in tracked.values():
        if root_kind(process, cli_paths) == "cli":
            signal_if_current(process, signal.SIGTERM)

    remaining = wait_for_exit(tracked, cli_paths, protected, GRACE_SECONDS)
    if remaining:
        print(f"发现 {len(remaining)} 个残留进程，强制清理并观察重新出现的进程…", flush=True)
        for process in remaining.values():
            signal_if_current(process, signal.SIGKILL)
        remaining = wait_for_exit(tracked, cli_paths, protected, KILL_WAIT_SECONDS, force=True)
    quiet_verified = not remaining
    background = read_background_state()
    if not quiet_verified:
        background.errors.append(f"观察期限内未确认连续 {QUIET_SECONDS:g} 秒无相关进程")
    # 后台查询本身可能耗时；查询完再拍一次快照，防止这段时间出现的新进程漏报。
    final = snapshot_processes()
    remaining = refresh_targets(final, {**tracked, **remaining}, cli_paths, protected)
    report_background(background)
    if remaining:
        print("仍有残留 PID: " + ", ".join(map(str, sorted(remaining))), file=sys.stderr)
        return 1
    excluded = [process for process in final.values() if root_kind(process, cli_paths)
                and (process.uid != os.getuid() or process.pid in protected)]
    unresolved = [process for process in final.values()
                  if not Path(process.executable).is_absolute()
                  and re.match(r"(?i)^claude(?:$| helper\b)", process.executable)]
    for process in excluded + unresolved:
        print(f"关联进程未处理或归属无法核验: PID {process.pid}, UID {process.uid}, {process.executable}",
              file=sys.stderr)
    if excluded or unresolved or background.jobs or background.errors:
        print("当前可识别进程已复核，但后台或其他进程仍有未确认项。", file=sys.stderr)
        return 2
    print(f"当前用户可识别的 Claude 进程连续 {QUIET_SECONDS:g} 秒未检出；后台服务未报告运行 PID。",
          flush=True)
    return 0


def main(arguments: Optional[List[str]] = None) -> int:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if not arguments or arguments[0] not in ("check", "cli", "desktop", "kill"):
        print("请使用 ccguard-check、ccguard-cli、ccguard-desktop 或 ccguard-kill。", file=sys.stderr)
        return 2
    kind, forwarded = arguments[0], arguments[1:]
    if kind != "check" and forwarded in (["-h"], ["--help"]):
        print("ccguard-kill [--dry-run]：正常退出、清理残留，连续观察后核验后台服务；不读取或更改后台权限，无需管理员密码。"
              "返回码 0=范围内未检出，1=有残留/失败，2=后台或归属未确认。" if kind == "kill" else
              f"ccguard-{kind} [参数…]：先运行 net_check.py，再询问 [y/N]；参数原样传给 Claude。")
        return 0
    if forwarded[:1] == ["--"]:
        forwarded = forwarded[1:]
    try:
        if sys.platform != "darwin":
            raise RuntimeError("这些命令仅用于 macOS")
        if kind == "check":
            return check_network(forwarded)
        if kind == "kill":
            if forwarded not in ([], ["--dry-run"]):
                print("用法: ccguard-kill [--dry-run]", file=sys.stderr)
                return 2
            return kill_claude(dry_run=bool(forwarded))
        return launch(kind, forwarded)
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"操作未完成: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
