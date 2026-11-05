"""Offline only: never run net_check, Claude, osascript, open or real kill signals."""
import contextlib
import io
import os
import plistlib
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

import ccguard as commands


UID = 501
CLI = Path("/fixture/claude-native")
APP = Path("/Applications/Claude.app")


def process(pid, ppid=1, executable=str(CLI), started="Wed Nov 4 10:00:00 2026", uid=UID, responsible=None):
    return commands.Process(pid, ppid, uid, started, executable, responsible)


class OfflineCase(unittest.TestCase):
    def setUp(self):
        # Every side-effect boundary is blocked, including process inspection and waits.
        for owner, name in ((commands.subprocess, "run"), (commands.os, "execv"),
                            (commands.os, "kill"), (commands, "executable_path"),
                            (commands.time, "sleep")):
            blocker = patch.object(owner, name, side_effect=AssertionError("real operation forbidden"))
            blocker.start()
            self.addCleanup(blocker.stop)
        for owner, name, value in ((commands.os, "getuid", UID), (commands.os, "getpid", 9000),
                                   (commands, "responsible_process_id", None)):
            blocker = patch.object(owner, name, return_value=value)
            blocker.start()
            self.addCleanup(blocker.stop)
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        for redirect in (contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr)):
            redirect.__enter__()
            self.addCleanup(redirect.__exit__, None, None, None)
        commands.desktop_bundle.cache_clear()


class CheckTests(OfflineCase):
    def test_check_preserves_three_statuses_without_confirmation_or_claude(self):
        for code in (0, 1, 2):
            with self.subTest(code=code), \
                 patch.object(commands.subprocess, "run", return_value=Mock(returncode=code)) as run, \
                 patch("builtins.input", side_effect=AssertionError("check must not prompt")), \
                 patch.object(commands, "launch", side_effect=AssertionError("check must not launch")), \
                 patch.object(commands, "kill_claude", side_effect=AssertionError("check must not quit")):
                self.assertEqual(commands.main(["check"]), code)
                run.assert_called_once_with([commands.sys.executable, "-B", str(commands.NET_CHECK)], check=False)

    def test_check_forwards_network_options_as_arguments(self):
        arguments = ["--json", "--timeout", "6", "--dns-samples", "3", "--candidate", "sample with spaces"]
        with patch.object(commands.subprocess, "run", return_value=Mock(returncode=2)) as run:
            self.assertEqual(commands.main(["check", *arguments]), 2)
        run.assert_called_once_with([commands.sys.executable, "-B", str(commands.NET_CHECK), *arguments], check=False)

    def test_check_help_is_network_check_help(self):
        for arguments in (["--help"], ["-h"], ["--", "--help"]):
            with self.subTest(arguments=arguments), \
                 patch.object(commands.subprocess, "run", return_value=Mock(returncode=0)) as run:
                self.assertEqual(commands.main(["check", *arguments]), 0)
                self.assertEqual(run.call_args.args[0][-1], arguments[-1])

    def test_check_missing_script_does_not_prompt_or_start_process(self):
        with patch.object(commands, "NET_CHECK", Path("/nonexistent-net-check-fixture.py")), \
             patch("builtins.input", side_effect=AssertionError("check must not prompt")):
            self.assertEqual(commands.main(["check"]), 1)

    def test_check_interruption_has_shell_exit_status(self):
        for returncode, expected in ((-2, 130), (-15, 143), (127, 127)):
            with self.subTest(returncode=returncode), \
                 patch.object(commands.subprocess, "run", return_value=Mock(returncode=returncode)):
                self.assertEqual(commands.main(["check"]), expected)
        with patch.object(commands.subprocess, "run", side_effect=KeyboardInterrupt):
            self.assertEqual(commands.main(["check"]), 130)


class LaunchTests(OfflineCase):
    def test_blank_n_eof_never_launch(self):
        for answer in ("", "n", "N", EOFError()):
            with self.subTest(answer=answer), patch("builtins.input", side_effect=[answer]), \
                 patch.object(commands.subprocess, "run", return_value=Mock(returncode=0)) as run:
                self.assertEqual(commands.launch("cli", []), 0)
                run.assert_called_once_with([commands.sys.executable, "-B", str(commands.NET_CHECK)], check=False)

    def test_check_then_confirmation_then_cli_exec_for_all_three_statuses(self):
        for code in (0, 1, 2):
            events = []
            def check(*args, **kwargs):
                events.append("check")
                self.assertNotIn("cwd", kwargs)
                return Mock(returncode=code)
            def confirm(prompt):
                events.append("confirm")
                self.assertIn("[y/N]", prompt)
                return "Y"
            def start(*args):
                events.append("launch")
            with self.subTest(code=code), patch.object(commands.subprocess, "run", side_effect=check), \
                 patch("builtins.input", side_effect=confirm), \
                 patch.object(commands.shutil, "which", return_value=str(CLI)), \
                 patch.object(commands.os, "execv", side_effect=start) as execute:
                self.assertEqual(commands.launch("cli", ["--resume", "a b; $(ignored)"]), 0)
                self.assertEqual(events, ["check", "confirm", "launch"])
                execute.assert_called_once_with(str(CLI), [str(CLI), "--resume", "a b; $(ignored)"])

    def test_invalid_confirmation_does_not_count_as_yes(self):
        with patch("builtins.input", side_effect=["yes", "maybe", ""]):
            self.assertFalse(commands.confirm_launch("Claude CLI"))

    def test_desktop_opens_only_after_confirmation_and_forwards_arguments_as_values(self):
        with patch.object(commands.subprocess, "run", side_effect=[Mock(returncode=0), Mock(returncode=0)]) as run, \
             patch("builtins.input", return_value="y"), \
             patch.object(commands, "find_desktop", return_value=APP):
            self.assertEqual(commands.launch("desktop", ["a b", "$(ignored)"]), 0)
        self.assertEqual(run.call_args_list[-1], call(
            ["/usr/bin/open", "-a", str(APP), "--args", "a b", "$(ignored)"], check=False))

    def test_desktop_cancel_does_not_resolve_or_open_application(self):
        with patch.object(commands.subprocess, "run", return_value=Mock(returncode=2)) as run, \
             patch("builtins.input", return_value=""), patch.object(commands, "find_desktop") as find:
            self.assertEqual(commands.launch("desktop", []), 0)
        run.assert_called_once()
        find.assert_not_called()

    def test_missing_desktop_reports_installation_needed_without_open(self):
        with patch.object(commands.subprocess, "run", return_value=Mock(returncode=0)) as run, \
             patch("builtins.input", return_value="y"), patch.object(commands, "find_desktop", return_value=None):
            self.assertEqual(commands.launch("desktop", []), 127)
        run.assert_called_once()
        self.assertIn("未找到固定路径的 Claude Desktop: /Applications/Claude.app", self.stderr.getvalue())

    def test_missing_cli_reports_failure_without_exec(self):
        with patch.object(commands.subprocess, "run", return_value=Mock(returncode=0)), \
             patch("builtins.input", return_value="y"), patch.object(commands.shutil, "which", return_value=None):
            self.assertEqual(commands.launch("cli", []), 127)

    def test_missing_check_file_stops_before_confirmation(self):
        with patch.object(commands, "NET_CHECK", Path("/nonexistent-net-check-fixture.py")), \
             patch("builtins.input") as read:
            self.assertEqual(commands.launch("cli", []), 1)
        read.assert_not_called()

    def test_interrupted_check_does_not_prompt_or_launch(self):
        for code in (-2, 130, 127):
            with self.subTest(code=code), \
                 patch.object(commands.subprocess, "run", return_value=Mock(returncode=code)), \
                 patch("builtins.input") as read:
                self.assertEqual(commands.launch("cli", []), 1)
                read.assert_not_called()

    def test_control_c_cancels_launch(self):
        with patch.object(commands.subprocess, "run", side_effect=KeyboardInterrupt):
            self.assertEqual(commands.main(["cli"]), 130)

    def test_help_and_bad_kill_options_have_no_side_effects(self):
        self.assertEqual(commands.main(["cli", "--help"]), 0)
        self.assertEqual(commands.main(["kill", "--help"]), 0)
        self.assertEqual(commands.main(["kill", "unexpected"]), 2)

    def test_separator_preserves_cli_help_argument(self):
        with patch.object(commands, "launch", return_value=0) as launch:
            self.assertEqual(commands.main(["cli", "--", "--help"]), 0)
        launch.assert_called_once_with("cli", ["--help"])


class DiscoveryTests(OfflineCase):
    def test_app_bundle_id_is_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, identifier in (("Claude.app", commands.DESKTOP_ID),
                                     ("Other.app", "unrelated.application")):
                path = root / name / "Contents"
                path.mkdir(parents=True)
                (path / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": identifier}))
            self.assertTrue(commands.desktop_bundle(root / "Claude.app"))
            self.assertFalse(commands.desktop_bundle(root / "Other.app"))
            helper = root / "Claude.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper"
            self.assertEqual(commands.claude_app_for_executable(str(helper)), root / "Claude.app")

    def test_default_desktop_path_is_fixed(self):
        self.assertEqual(commands.DESKTOP_APP, Path("/Applications/Claude.app"))


class DesktopIdentityTests(OfflineCase):
    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory(prefix="ccguard-desktop-identity-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.app = self.root / "Claude.app"
        self.info = self.app / "Contents/Info.plist"
        self.executable = self.app / "Contents/MacOS/Claude"
        self.executable.parent.mkdir(parents=True)
        self.executable.write_text("fixture only; must never be executed\n")
        self.executable.chmod(0o755)
        self.write_metadata()
        patcher = patch.object(commands, "DESKTOP_APP", self.app)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_metadata(self, **changes):
        metadata = {"CFBundleIdentifier": commands.DESKTOP_ID, "CFBundleExecutable": "Claude",
                    "CFBundlePackageType": "APPL"}
        metadata.update(changes)
        self.info.write_bytes(plistlib.dumps(metadata))

    def test_valid_locked_bundle_requires_verified_vendor_signature(self):
        with patch.object(commands.subprocess, "run", return_value=Mock(returncode=0)) as run:
            self.assertEqual(commands.find_desktop(), self.app)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:5], ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--test-requirement"])
        self.assertEqual(argv[-1], str(self.app))
        self.assertIn('identifier "com.anthropic.claudefordesktop"', argv[-2])
        self.assertIn('anchor apple generic', argv[-2])
        self.assertIn('certificate leaf[subject.OU] = "Q6L2SF6YDW"', argv[-2])
        self.assertIn('certificate leaf[field.1.2.840.113635.100.6.1.13] exists', argv[-2])

    def test_old_override_cannot_redirect_to_handler_chrome_or_other_copy(self):
        for override in ("/Custom/Claude.app", "/Users/test/Applications/Claude Code URL Handler.app",
                         "/Users/test/Applications/Chrome Apps.localized/Claude.app", "/Volumes/Claude/Claude.app"):
            with self.subTest(override=override), patch.dict(os.environ, {"CLAUDE_DESKTOP_APP": override}), \
                 patch.object(commands.subprocess, "run", return_value=Mock(returncode=0)) as run:
                self.assertEqual(commands.find_desktop(), self.app)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][-1], str(self.app))

    def test_missing_locked_path_does_not_search_or_use_override(self):
        with patch.object(commands, "DESKTOP_APP", self.root/"missing.app"), \
             patch.dict(os.environ, {"CLAUDE_DESKTOP_APP": str(self.app)}):
            self.assertIsNone(commands.find_desktop())

    def test_root_symlink_cannot_redirect_to_another_copy(self):
        alias = self.root / "alias.app"
        alias.symlink_to(self.app, target_is_directory=True)
        with patch.object(commands, "DESKTOP_APP", alias), self.assertRaisesRegex(RuntimeError, "符号链接"):
            commands.find_desktop()

    def test_executable_symlink_cannot_redirect_to_cli(self):
        cli = self.root / "claude-cli"
        self.executable.rename(cli)
        self.executable.symlink_to(cli)
        with self.assertRaisesRegex(RuntimeError, "重定向"):
            commands.find_desktop()

    def test_metadata_symlink_is_rejected(self):
        metadata = self.root / "other.plist"
        self.info.rename(metadata)
        self.info.symlink_to(metadata)
        with self.assertRaisesRegex(RuntimeError, "重定向"):
            commands.find_desktop()

    def test_url_handler_chrome_and_helpers_are_rejected_before_signature_check(self):
        for identifier in ("com.anthropic.claude-code-url-handler",
                           "com.google.Chrome.app.fmpnliohjhemenmnlpbfagaolkdacoja",
                           "com.anthropic.claudefordesktop.helper"):
            with self.subTest(identifier=identifier):
                self.write_metadata(CFBundleIdentifier=identifier)
                with self.assertRaisesRegex(RuntimeError, "不是预期的 Claude Desktop"):
                    commands.find_desktop()

    def test_wrong_program_or_background_bundle_is_rejected_even_with_matching_id(self):
        for changes in ({"CFBundleExecutable": "claude"}, {"CFBundleExecutable": "app_mode_loader"},
                        {"CFBundlePackageType": "BNDL"}, {"LSBackgroundOnly": True}, {"LSUIElement": True}):
            with self.subTest(changes=changes):
                self.write_metadata(**changes)
                with self.assertRaisesRegex(RuntimeError, "不是预期的 Claude Desktop"):
                    commands.find_desktop()

    def test_missing_or_nonexecutable_main_program_is_rejected(self):
        self.executable.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "缺少有效"):
            commands.find_desktop()
        self.executable.unlink()
        with self.assertRaisesRegex(RuntimeError, "缺少有效"):
            commands.find_desktop()

    def test_malformed_metadata_is_rejected(self):
        for data in (b'not a plist', plistlib.dumps([commands.DESKTOP_ID])):
            with self.subTest(data=data):
                self.info.write_bytes(data)
                with self.assertRaises(RuntimeError):
                    commands.find_desktop()

    def test_matching_metadata_does_not_override_invalid_signature(self):
        with patch.object(commands.subprocess, "run", return_value=Mock(returncode=1)), \
             self.assertRaisesRegex(RuntimeError, "签名或开发者身份核验失败"):
            commands.find_desktop()

    def test_signature_timeout_and_missing_verifier_stop_launch(self):
        for error in (subprocess.TimeoutExpired("codesign", 20), FileNotFoundError("codesign")):
            with self.subTest(error=error), patch.object(commands.subprocess, "run", side_effect=error), \
                 self.assertRaisesRegex(RuntimeError, "已取消启动"):
                commands.find_desktop()

    def test_launch_identity_is_not_reused_from_process_discovery_cache(self):
        self.assertTrue(commands.desktop_bundle(self.app))
        self.write_metadata(CFBundleIdentifier="com.anthropic.claude-code-url-handler")
        with self.assertRaisesRegex(RuntimeError, "不是预期的 Claude Desktop"):
            commands.find_desktop()

    def test_signature_is_verified_on_every_launch_attempt(self):
        with patch.object(commands.subprocess, "run", side_effect=[Mock(returncode=0), Mock(returncode=1)]) as run:
            self.assertEqual(commands.find_desktop(), self.app)
            with self.assertRaisesRegex(RuntimeError, "签名或开发者身份核验失败"):
                commands.find_desktop()
        self.assertEqual(run.call_count, 2)

    def test_target_is_visible_before_confirmation_and_verification_precedes_open(self):
        events = []
        def external(argv, **kwargs):
            events.append(Path(argv[0]).name if argv[0] != commands.sys.executable else "net_check")
            return Mock(returncode=0)
        def confirm(prompt):
            self.assertIn(str(self.app), self.stdout.getvalue())
            events.append("confirm")
            return "y"
        with patch.object(commands.subprocess, "run", side_effect=external) as run, \
             patch("builtins.input", side_effect=confirm):
            self.assertEqual(commands.launch("desktop", ["argument with spaces"]), 0)
        self.assertEqual(events, ["net_check", "confirm", "codesign", "open"])
        self.assertEqual(run.call_args.args[0], ["/usr/bin/open", "-a", str(self.app), "--args", "argument with spaces"])

    def test_failed_identity_never_reaches_open(self):
        with patch.object(commands.subprocess, "run", side_effect=[Mock(returncode=0), Mock(returncode=1)]) as run, \
             patch("builtins.input", return_value="y"):
            self.assertEqual(commands.main(["desktop"]), 1)
        self.assertEqual([Path(item.args[0][0]).name for item in run.call_args_list],
                         [Path(commands.sys.executable).name, "codesign"])
        self.assertIn("已取消启动", self.stderr.getvalue())


class ProcessTests(OfflineCase):
    def setUp(self):
        super().setUp()
        patcher = patch.object(commands, "claude_app_for_executable", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_exact_cli_paths_match_but_other_names_do_not(self):
        old = Path.home() / ".local/share/claude/versions/old-version"
        self.assertEqual(commands.root_kind(process(10), {CLI}), "cli")
        self.assertEqual(commands.root_kind(process(11, executable=str(old)), {CLI}), "cli")
        for path in ("/usr/bin/node", "/other/claude", "claude", "/usr/bin/python3"):
            self.assertEqual(commands.root_kind(process(12, executable=path), {CLI}), "")

    def test_descendants_tracked_but_unrelated_users_and_ancestors_excluded(self):
        processes = {
            10: process(10), 11: process(11, 10, "/usr/bin/node"),
            12: process(12, 11, "/bin/sh"), 13: process(13, 1, "/bin/zsh"),
            14: process(14, 10, uid=999), 9000: process(9000, 10, "/usr/bin/python3"),
        }
        targets = commands.refresh_targets(processes, {}, {CLI}, {9000})
        self.assertEqual(set(targets), {10, 11, 12})

    def test_orphaned_children_remain_tracked_after_parent_exits(self):
        child = process(11, 10, "/usr/bin/node")
        orphan = process(11, 1, "/usr/bin/node")
        targets = commands.refresh_targets({11: orphan}, {11: child}, {CLI}, set())
        self.assertEqual(set(targets), {11})

    def test_reused_pid_is_not_inherited_from_old_tree(self):
        old = process(11, 10, "/usr/bin/node")
        replacement = process(11, 1, "/usr/bin/node", started="new start time")
        self.assertEqual(commands.refresh_targets({11: replacement}, {11: old}, {CLI}, set()), {})

    def test_responsibility_finds_launchd_started_helper_outside_app(self):
        helper = process(11, 1, "/usr/bin/node", responsible=10)
        targets = commands.refresh_targets({10: process(10), 11: helper}, {}, {CLI}, set())
        self.assertEqual(set(targets), {10, 11})

    def test_responsibility_to_departed_known_process_is_retained(self):
        helper = process(11, 1, "/usr/bin/node", responsible=10)
        self.assertEqual(set(commands.refresh_targets({11: helper}, {10: process(10)}, {CLI}, set())), {11})

    def test_responsibility_does_not_follow_reused_parent_pid(self):
        unrelated = process(10, 1, "/usr/bin/other", started="new start time")
        helper = process(11, 1, "/usr/bin/node", responsible=10)
        self.assertEqual(commands.refresh_targets({10: unrelated, 11: helper}, {10: process(10)}, {CLI}, set()), {})

    def test_responsibility_does_not_override_user_or_self_protection(self):
        targets = commands.refresh_targets({10: process(10),
            11: process(11, 1, "/usr/bin/node", uid=0, responsible=10),
            9000: process(9000, 1, "/usr/bin/python3", responsible=10)}, {}, {CLI}, {9000})
        self.assertEqual(set(targets), {10})

    def test_self_and_ancestor_chain_are_protected(self):
        processes = {9000: process(9000, 42), 42: process(42, 1, "/bin/zsh")}
        self.assertEqual(commands.protected_pids(processes), {0, 1, 42, 9000})

    def test_signal_revalidates_process_identity(self):
        original = process(10)
        for current in ({}, {10: process(10, started="new start time")},
                        {10: process(10, executable="/usr/bin/other")}, {10: process(10, uid=999)}):
            with self.subTest(current=current), patch.object(commands, "snapshot_processes", return_value=current):
                commands.signal_if_current(original, signal.SIGKILL)
        with patch.object(commands, "snapshot_processes", return_value={10: original}), \
             patch.object(commands.os, "kill") as kill:
            commands.signal_if_current(original, signal.SIGTERM)
        kill.assert_called_once_with(10, signal.SIGTERM)

    def test_process_exiting_between_validation_and_signal_is_ok(self):
        original = process(10)
        with patch.object(commands, "snapshot_processes", return_value={10: original}), \
             patch.object(commands.os, "kill", side_effect=ProcessLookupError):
            commands.signal_if_current(original, signal.SIGKILL)

    def test_process_snapshot_keeps_other_users_for_reporting_but_excludes_zombies(self):
        output = ("10 1 501 Wed Nov 4 10:00:00 2026 S /fixture/claude-native\n"
                  "11 1 999 Wed Nov 4 10:00:00 2026 S /fixture/claude-native\n"
                  "12 1 501 Wed Nov 4 10:00:00 2026 Z /fixture/claude-native\n")
        with patch.object(commands.subprocess, "run", return_value=Mock(stdout=output)), \
             patch.object(commands, "executable_path", return_value=str(CLI)):
            self.assertEqual(set(commands.snapshot_processes()), {10, 11})

    def test_other_user_process_is_never_signalled(self):
        commands.signal_if_current(process(10, uid=0), signal.SIGKILL)

    def test_unrecognized_process_output_is_not_assumed_clean(self):
        with patch.object(commands.subprocess, "run", return_value=Mock(stdout="invalid line")), \
             self.assertRaises(RuntimeError):
            commands.snapshot_processes()


class BackgroundTests(OfflineCase):
    RECORD = """ #12:
                 Name: Claude - background tasks
                 Type: background tasks (0x2000)
          Disposition: [enabled, disallowed, notified] (0x9)
           Identifier: 8192.com.anthropic.claudefordesktop
                  URL: (null)
    Parent Identifier: 2.com.anthropic.claudefordesktop
"""
    HEADER = " Records for UID 501 : 00000000-0000-0000-0000-000000000000\n"

    def setUp(self):
        super().setUp()
        patcher = patch.object(commands, "responsibility_function", return_value=Mock())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_actual_macos_format_enabled_disallowed_is_permission_denied(self):
        self.assertEqual(commands.parse_background_permission(self.HEADER + self.RECORD, UID), "disallowed")

    def test_allowed_permission_is_recognized(self):
        self.assertEqual(commands.parse_background_permission(
            self.HEADER + self.RECORD.replace("disallowed", "allowed"), UID), "allowed")

    def test_records_are_scoped_to_current_user(self):
        output = (self.HEADER.replace("501", "0") + self.RECORD.replace("disallowed", "allowed")
                  + self.HEADER + self.RECORD
                  + self.HEADER.replace("501", "502") + self.RECORD.replace("disallowed", "allowed"))
        self.assertEqual(commands.parse_background_permission(output, UID), "disallowed")

    def test_app_record_is_not_mistaken_for_background_task_permission(self):
        app = " #11:\n Type: app (0x2)\n Disposition: [enabled, allowed]\n Identifier: 2." + commands.DESKTOP_ID + "\n"
        self.assertEqual(commands.parse_background_permission(self.HEADER + app + self.RECORD, UID), "disallowed")
        self.assertEqual(commands.parse_background_permission(self.HEADER + app, UID), "not_registered")

    def test_unknown_or_conflicting_permission_is_not_assumed_clean(self):
        for output in ("unrecognized output", self.HEADER + self.RECORD.replace("disallowed", "unknown"),
                       self.HEADER + self.RECORD.replace("disallowed", "allowed, disallowed"),
                       self.HEADER + self.RECORD + self.RECORD.replace("#12", "#13").replace("disallowed", "allowed")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                commands.parse_background_permission(output, UID)

    def test_inactive_registered_service_is_not_a_running_pid(self):
        output = "PID\tStatus\tLabel\n-\t0\t" + commands.DESKTOP_ID + "\n"
        with patch.object(commands.subprocess, "run", side_effect=[
                Mock(stdout=self.HEADER + self.RECORD), Mock(stdout=output)]) as run:
            state = commands.read_background_state()
        self.assertEqual(state.permission, "disallowed")
        self.assertEqual(state.jobs, {})
        self.assertEqual(state.registered_jobs, [commands.DESKTOP_ID])
        self.assertEqual(state.errors, [])
        self.assertEqual([item.args[0] for item in run.call_args_list], [
            ["/usr/bin/sfltool", "dumpbtm"], ["/bin/launchctl", "list"]])

    def test_active_service_is_reported_without_trusting_lookalike_labels(self):
        label = "application." + commands.DESKTOP_ID + ".123.456"
        output = ("PID Status Label\n77 0 " + label + "\n"
                  "78 0 " + commands.DESKTOP_ID + "unrelated\n"
                  "79 0 example.com.anthropic.claudefordesktop\n")
        with patch.object(commands.subprocess, "run", side_effect=[
                Mock(stdout=self.HEADER + self.RECORD), Mock(stdout=output)]):
            state = commands.read_background_state()
        self.assertEqual(state.jobs, {77: [label]})
        self.assertEqual(state.errors, [])

    def test_timeout_and_invalid_btm_format_preserve_uncertainty(self):
        for result in (subprocess.TimeoutExpired("sfltool", 5), Mock(stdout="unknown format")):
            with self.subTest(result=result), patch.object(commands.subprocess, "run", side_effect=[
                    result, Mock(stdout="PID Status Label\n")]):
                state = commands.read_background_state()
            self.assertEqual(state.permission, "unknown")
            self.assertEqual(len(state.errors), 1)
            self.assertIn("后台权限未核验", state.errors[0])

    def test_service_read_failure_does_not_overwrite_known_permission(self):
        for result in (subprocess.CalledProcessError(1, "launchctl"), Mock(stdout="unknown format"),
                       Mock(stdout="PID Status Label\nbad line\n"),
                       Mock(stdout="PID Status Label\n0 0 " + commands.DESKTOP_ID + "\n")):
            with self.subTest(result=result), patch.object(commands.subprocess, "run", side_effect=[
                    Mock(stdout=self.HEADER + self.RECORD), result]):
                state = commands.read_background_state()
            self.assertEqual(state.permission, "disallowed")
            self.assertEqual(len(state.errors), 1)
            self.assertIn("后台服务未核验", state.errors[0])

    def test_unavailable_responsibility_interface_is_reported(self):
        with patch.object(commands.subprocess, "run", side_effect=[
                Mock(stdout=self.HEADER + self.RECORD), Mock(stdout="PID Status Label\n")]), \
             patch.object(commands, "responsibility_function", return_value=None):
            state = commands.read_background_state()
        self.assertEqual(len(state.errors), 1)
        self.assertIn("进程归属接口不可用", state.errors[0])


class QuitTests(OfflineCase):
    def setUp(self):
        super().setUp()
        for name, value in (("cli_executables", {CLI}), ("protected_pids", {0, 1, 9000}),
                            ("claude_app_for_executable", None)):
            patcher = patch.object(commands, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(commands, "read_background_state",
                               side_effect=lambda: commands.BackgroundState(permission="disallowed"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_processes_does_not_send_quit_or_signals(self):
        with patch.object(commands, "snapshot_processes", return_value={}), \
             patch.object(commands.time, "monotonic", side_effect=[0, 0, 3]), \
             patch.object(commands.time, "sleep"):
            self.assertEqual(commands.kill_claude(), 0)
        self.assertIn("[OK] 后台任务权限: 已关闭", self.stdout.getvalue())

    def test_dry_run_has_no_quit_or_signal_side_effects(self):
        with patch.object(commands, "snapshot_processes", return_value={10: process(10)}):
            self.assertEqual(commands.kill_claude(dry_run=True), 0)
        self.assertIn("PID 10", self.stdout.getvalue())

    def test_cli_normal_exit_needs_no_kill(self):
        root = process(10)
        with patch.object(commands, "snapshot_processes", side_effect=[{10: root}, {}]), \
             patch.object(commands, "signal_if_current") as send, \
             patch.object(commands, "wait_for_exit", return_value={}):
            self.assertEqual(commands.kill_claude(), 0)
        send.assert_called_once_with(root, signal.SIGTERM)

    def test_cli_orphan_is_force_killed_after_normal_exit(self):
        root, child = process(10), process(11, 10, "/usr/bin/node")
        events = []
        def wait(tracked, paths, protected, seconds, force=False):
            events.append("wait")
            return {11: child} if seconds == commands.GRACE_SECONDS else {}
        with patch.object(commands, "snapshot_processes", side_effect=[{10: root, 11: child}, {}]), \
             patch.object(commands, "signal_if_current", side_effect=lambda p, sig: events.append((p.pid, sig))), \
             patch.object(commands, "wait_for_exit", side_effect=wait):
            self.assertEqual(commands.kill_claude(), 0)
        self.assertEqual(events, [(10, signal.SIGTERM), "wait", (11, signal.SIGKILL), "wait"])

    def test_desktop_quit_precedes_residual_kill(self):
        root = process(10, executable=str(APP / "Contents/MacOS/Claude"))
        events = []
        with patch.object(commands, "snapshot_processes", side_effect=[{10: root}, {}]), \
             patch.object(commands, "claude_app_for_executable", return_value=APP), \
             patch.object(commands, "request_desktop_quit", side_effect=lambda app: events.append("quit")), \
             patch.object(commands, "signal_if_current", side_effect=lambda p, sig: events.append(sig)), \
             patch.object(commands, "wait_for_exit", side_effect=[{10: root}, {}]):
            self.assertEqual(commands.kill_claude(), 0)
        self.assertEqual(events, ["quit", signal.SIGKILL])

    def test_remaining_process_is_reported_as_failure(self):
        root = process(10)
        with patch.object(commands, "snapshot_processes", return_value={10: root}), \
             patch.object(commands, "signal_if_current"), \
             patch.object(commands, "wait_for_exit", return_value={10: root}):
            self.assertEqual(commands.kill_claude(), 1)
        self.assertIn("残留 PID: 10", self.stderr.getvalue())

    def test_wait_discovers_child_created_during_shutdown(self):
        root, child = process(10), process(11, 10, "/usr/bin/node")
        with patch.object(commands, "snapshot_processes", side_effect=[{10: root, 11: child}, {11: child}]), \
             patch.object(commands.time, "monotonic", side_effect=[0, 0, 5]), \
             patch.object(commands.time, "sleep"):
            self.assertEqual(set(commands.wait_for_exit({10: root}, {CLI}, {9000}, 5)), {11})

    def test_one_empty_snapshot_is_not_a_success(self):
        with patch.object(commands, "snapshot_processes", return_value={}) as snapshot, \
             patch.object(commands.time, "monotonic", side_effect=[0, 0, 1, 2, 3]), \
             patch.object(commands.time, "sleep"):
            self.assertEqual(commands.wait_for_exit({}, {CLI}, {9000}, 5), {})
        self.assertEqual(snapshot.call_count, 4)

    def test_respawn_restarts_quiet_window(self):
        with patch.object(commands, "snapshot_processes", side_effect=[{}, {11: process(11)}, {}, {}, {}]) as snapshot, \
             patch.object(commands.time, "monotonic", side_effect=[0, 0, 1, 2, 4.9, 5]), \
             patch.object(commands.time, "sleep"):
            self.assertEqual(commands.wait_for_exit({10: process(10)}, {CLI}, {9000}, 5), {})
        self.assertEqual(snapshot.call_count, 5)

    def test_quiet_window_is_completed_even_at_deadline(self):
        with patch.object(commands, "snapshot_processes", side_effect=[{10: process(10)}, {}, {}]), \
             patch.object(commands.time, "monotonic", side_effect=[0, 4.9, 5, 8]), \
             patch.object(commands.time, "sleep"):
            self.assertEqual(commands.wait_for_exit({10: process(10)}, {CLI}, {9000}, 5), {})

    def test_orphan_appearing_after_empty_snapshot_is_still_found(self):
        helper = process(11, 1, "/usr/bin/node", responsible=10)
        with patch.object(commands, "snapshot_processes", side_effect=[{}, {11: helper}]), \
             patch.object(commands.time, "monotonic", side_effect=[0, 0, 5]), \
             patch.object(commands.time, "sleep"):
            self.assertEqual(commands.wait_for_exit({10: process(10)}, {CLI}, {9000}, 5), {11: helper})

    def test_newly_discovered_helper_identity_survives_for_final_verification(self):
        root, child = process(10), process(11, 10, "/usr/bin/node")
        history = {10: root}
        with patch.object(commands, "snapshot_processes", side_effect=[{10: root, 11: child}, {}, {}]), \
             patch.object(commands.time, "monotonic", side_effect=[0, 0, 1, 4]), \
             patch.object(commands.time, "sleep"):
            self.assertEqual(commands.wait_for_exit(history, {CLI}, {9000}, 5), {})
        orphan = process(11, 1, "/usr/bin/node")
        self.assertEqual(commands.refresh_targets({11: orphan}, history, {CLI}, {9000}), {11: orphan})

    def test_observed_pid_reuse_invalidates_old_responsibility_after_replacement_exits(self):
        history = {10: process(10)}
        replacement = process(10, executable="/usr/bin/other", started="new start time")
        unrelated = process(11, executable="/usr/bin/node", responsible=10)
        with patch.object(commands, "snapshot_processes", side_effect=[{10: replacement}, {11: unrelated}]), \
             patch.object(commands.time, "monotonic", side_effect=[0, 0, 3]), \
             patch.object(commands.time, "sleep"):
            self.assertEqual(commands.wait_for_exit(history, {CLI}, {9000}, 5), {})
        self.assertEqual(history, {})

    def test_force_phase_cleans_restarted_processes_then_verifies_quiet(self):
        first, second = process(11), process(12)
        with patch.object(commands, "snapshot_processes", side_effect=[{11: first}, {}, {12: second}, {}, {}]), \
             patch.object(commands.time, "monotonic", side_effect=[0, 0, .5, 1, 2, 5]), \
             patch.object(commands.time, "sleep"), patch.object(commands, "signal_if_current") as send:
            self.assertEqual(commands.wait_for_exit({}, {CLI}, {9000}, 8, force=True), {})
        self.assertEqual(send.call_args_list, [call(first, signal.SIGKILL), call(second, signal.SIGKILL)])

    def test_repeated_respawn_is_bounded_and_reported(self):
        with patch.object(commands, "snapshot_processes", side_effect=[{11: process(11)}, {12: process(12)}, {13: process(13)}]), \
             patch.object(commands.time, "monotonic", side_effect=[0, 0, 4, 8]), \
             patch.object(commands.time, "sleep"), patch.object(commands, "signal_if_current"):
            self.assertEqual(set(commands.wait_for_exit({}, {CLI}, {9000}, 8, force=True)), {13})

    def test_late_respawn_during_background_query_prevents_success(self):
        with patch.object(commands, "snapshot_processes", side_effect=[{}, {10: process(10)}]), \
             patch.object(commands, "wait_for_exit", return_value={}):
            self.assertEqual(commands.kill_claude(), 1)

    def test_no_quiet_window_cannot_be_overridden_by_one_final_empty_snapshot(self):
        with patch.object(commands, "snapshot_processes", side_effect=[{10: process(10)}, {}]), \
             patch.object(commands, "signal_if_current"), \
             patch.object(commands, "wait_for_exit", return_value={10: process(10)}):
            self.assertEqual(commands.kill_claude(), 2)

    def test_background_read_error_is_warning_not_all_clear(self):
        with patch.object(commands, "snapshot_processes", return_value={}), \
             patch.object(commands, "wait_for_exit", return_value={}), \
             patch.object(commands, "read_background_state", return_value=commands.BackgroundState(errors=["unreadable"])):
            self.assertEqual(commands.kill_claude(), 2)
        self.assertNotIn("连续 3 秒未检出", self.stdout.getvalue())
        self.assertIn("[WARN] 后台任务权限: 未确认", self.stdout.getvalue())

    def test_active_background_service_without_verified_process_is_not_ignored(self):
        state = commands.BackgroundState(permission="allowed", jobs={77: [commands.DESKTOP_ID + ".helper"]})
        with patch.object(commands, "snapshot_processes", return_value={}), \
             patch.object(commands, "wait_for_exit", return_value={}), \
             patch.object(commands, "read_background_state", return_value=state):
            self.assertEqual(commands.kill_claude(), 2)
        self.assertIn("PID 77", self.stderr.getvalue())

    def test_allowed_permission_alone_is_not_claimed_to_be_a_running_process(self):
        state = commands.BackgroundState(permission="allowed", registered_jobs=[commands.DESKTOP_ID])
        with patch.object(commands, "snapshot_processes", return_value={}), \
             patch.object(commands, "wait_for_exit", return_value={}), \
             patch.object(commands, "read_background_state", return_value=state), \
             patch("builtins.input", side_effect=AssertionError("background warning must not prompt")):
            self.assertEqual(commands.kill_claude(), 0)
        self.assertIn("⚠️⚠️⚠️ Claude 的后台权限处于开启状态", self.stdout.getvalue())
        self.assertIn("系统设置 → 通用 → 登录项与扩展 → App 后台活动", self.stdout.getvalue())

    def test_other_user_claude_process_is_reported_without_killing(self):
        with patch.object(commands, "snapshot_processes", return_value={10: process(10, uid=0)}), \
             patch.object(commands, "wait_for_exit", return_value={}):
            self.assertEqual(commands.kill_claude(), 2)
        self.assertIn("UID 0", self.stderr.getvalue())

    def test_quit_script_is_guarded_and_app_path_is_not_interpolated(self):
        path = Path('/Custom/Claude "quoted".app')
        with patch.object(commands.subprocess, "run", return_value=Mock(returncode=0)) as run:
            commands.request_desktop_quit(path)
        argv = run.call_args.args[0]
        self.assertIn("if it is running then quit", argv[2])
        self.assertEqual(argv[-1], str(path))
        self.assertNotIn(str(path), argv[2])

    def test_quit_timeout_allows_remaining_process_check(self):
        with patch.object(commands.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", 4)):
            commands.request_desktop_quit(APP)
        self.assertIn("超时", self.stdout.getvalue())

    def test_snapshot_failure_does_not_claim_success(self):
        with patch.object(commands, "snapshot_processes", side_effect=RuntimeError("cannot inspect")):
            self.assertEqual(commands.main(["kill"]), 1)
        self.assertIn("cannot inspect", self.stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
