"""Installer verification in temporary directories; never execute installed commands."""
import contextlib
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import install as installer


PACKAGE = Path(installer.__file__).resolve().parent


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ccguard-install-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "user space ' quote"
        self.prefix = self.root / ".local"
        self.profile = self.root / ".zshrc"
        self.python = Path(sys.executable).resolve()
        # Installing files must never run a subprocess, exec or kill any process.
        for name in ("run", "Popen"):
            blocker = patch.object(subprocess, name, side_effect=AssertionError("external execution forbidden"))
            blocker.start()
            self.addCleanup(blocker.stop)
        for name in ("execv", "kill"):
            blocker = patch.object(os, name, side_effect=AssertionError("process operation forbidden"))
            blocker.start()
            self.addCleanup(blocker.stop)

    def install(self, profile=True):
        return installer.install(PACKAGE, self.prefix, self.python, self.profile if profile else None)

    def test_first_install_is_self_contained_and_executable(self):
        paths = self.install()
        self.assertEqual({Path(path).name for path in paths}, {
            'ccguard-check', 'ccguard-cli', 'ccguard-desktop', 'ccguard-kill'})
        app_dir = self.prefix / "lib/ccguard"
        for name in installer.PAYLOAD:
            self.assertEqual((app_dir/name).read_bytes(), (PACKAGE/name).read_bytes())
        for name, kind in installer.COMMANDS.items():
            path = self.prefix / "bin" / name
            tokens = shlex.split(path.read_text().splitlines()[-1])
            self.assertEqual(tokens, ["exec", str(self.python), "-B", str(app_dir/'ccguard.py'), kind, "$@"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        self.assertIn(str(self.prefix/'bin'), self.profile.read_text().replace("'\"'\"'", "'"))

    def test_reinstall_is_idempotent(self):
        self.install()
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        self.install()
        self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()})
        self.assertEqual(self.profile.read_text().count(installer.PATH_BEGIN), 1)

    def test_existing_shell_config_is_exactly_restored(self):
        for original in (b'export EXISTING=value\n', b'export EXISTING=value'):
            with self.subTest(original=original):
                self.profile.parent.mkdir(parents=True, exist_ok=True)
                self.profile.write_bytes(original)
                self.profile.chmod(0o600)
                self.install()
                self.assertEqual(self.profile.stat().st_mode & 0o777, 0o600)
                self.assertEqual(installer.uninstall(self.prefix), [])
                self.assertEqual(self.profile.read_bytes(), original)
                self.assertEqual(self.profile.stat().st_mode & 0o777, 0o600)

    def test_uninstall_removes_only_managed_files(self):
        self.install()
        unrelated = self.prefix/'bin/unrelated'
        unrelated.write_text('keep me')
        self.assertEqual(installer.uninstall(self.prefix), [])
        self.assertEqual(unrelated.read_text(), 'keep me')
        self.assertFalse(self.profile.exists())
        for name in installer.COMMANDS:
            self.assertFalse((self.prefix/'bin'/name).exists())
        self.assertFalse((self.prefix/'lib/ccguard').exists())

    def test_conflicting_command_stops_before_any_install_writes(self):
        conflict = self.prefix/'bin/ccguard-kill'
        conflict.parent.mkdir(parents=True)
        conflict.write_text('my existing command\n')
        with self.assertRaisesRegex(ValueError, '同名文件'):
            self.install()
        self.assertEqual(conflict.read_text(), 'my existing command\n')
        self.assertFalse((self.prefix/'lib/ccguard').exists())
        self.assertFalse(self.profile.exists())

    def test_command_symlink_is_not_followed_or_overwritten(self):
        unrelated = self.root/'original'
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text('keep')
        link = self.prefix/'bin/ccguard-kill'
        link.parent.mkdir(parents=True)
        link.symlink_to(unrelated)
        with self.assertRaises(ValueError):
            self.install()
        self.assertTrue(link.is_symlink())
        self.assertEqual(unrelated.read_text(), 'keep')

    def test_unknown_nonempty_app_directory_is_preserved(self):
        path = self.prefix/'lib/ccguard/unrelated'
        path.parent.mkdir(parents=True)
        path.write_text('keep')
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(path.read_text(), 'keep')

    def test_local_policy_edits_are_not_overwritten_on_update(self):
        self.install()
        path = self.prefix/'lib/ccguard/net_check.py'
        path.write_text('# personal edits\n' + path.read_text())
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, '本地修改'):
            self.install()
        self.assertEqual(path.read_bytes(), before)

    def test_uninstall_preserves_modified_core_file(self):
        self.install()
        path = self.prefix/'lib/ccguard/net_check.py'
        path.write_text('# personal edits\n')
        self.assertIn(str(path), installer.uninstall(self.prefix))
        self.assertEqual(path.read_text(), '# personal edits\n')

    def test_uninstall_preserves_user_added_app_directory_content(self):
        self.install()
        path = self.prefix/'lib/ccguard/user-notes.txt'
        path.write_text('keep')
        self.assertEqual(installer.uninstall(self.prefix), [])
        self.assertEqual(path.read_text(), 'keep')

    def test_no_path_option_does_not_touch_profile(self):
        self.install(profile=False)
        self.assertFalse(self.profile.exists())
        self.assertIsNone(json.loads((self.prefix/'lib/ccguard/manifest.json').read_text())['profile'])

    def test_modified_path_block_is_preserved(self):
        self.install()
        changed = self.profile.read_text().replace('export PATH=', 'export CUSTOM_PATH=')
        self.profile.write_text(changed)
        with self.assertRaisesRegex(ValueError, 'PATH 区块'):
            self.install()
        self.assertIn(str(self.profile), installer.uninstall(self.prefix))
        self.assertEqual(self.profile.read_text(), changed)

    def test_profile_symlink_requires_no_path_mode(self):
        self.root.mkdir(parents=True)
        original = self.root/'profile-original'
        original.write_text('original')
        self.profile.symlink_to(original)
        with self.assertRaisesRegex(ValueError, '--no-path'):
            self.install()
        self.install(profile=False)
        self.assertEqual(original.read_text(), 'original')

    def test_failed_install_rolls_back_files_and_profile(self):
        original_write = installer.atomic_write
        def write(path, data, mode=0o644):
            if path.name == 'manifest.json':
                raise OSError('simulated disk failure')
            original_write(path, data, mode)
        with patch.object(installer, 'atomic_write', side_effect=write), self.assertRaises(OSError):
            self.install()
        self.assertEqual([path for path in self.root.rglob('*') if path.is_file()], [])

    def test_failed_upgrade_keeps_previous_install_complete(self):
        self.install()
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        original_write = installer.atomic_write
        def write(path, data, mode=0o644):
            if path.name == 'manifest.json':
                raise OSError('simulated manifest write failure')
            original_write(path, data, mode)
        with patch.object(installer, 'atomic_write', side_effect=write), self.assertRaises(OSError):
            self.install()
        self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()})

    def test_symlinked_application_directory_is_not_installed_or_uninstalled(self):
        outside = self.root/'outside'
        outside.mkdir(parents=True)
        app_dir = self.prefix/'lib/ccguard'
        app_dir.parent.mkdir(parents=True)
        app_dir.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.install()
        with self.assertRaises(ValueError):
            installer.uninstall(self.prefix)
        self.assertEqual(list(outside.iterdir()), [])

    def test_upgrading_owned_payload_works(self):
        self.install()
        updated = self.root/'new-package'
        updated.mkdir()
        for name in installer.PAYLOAD:
            (updated/name).write_bytes((PACKAGE/name).read_bytes())
        (updated/'VERSION').write_text('test-next-version\n')
        (updated/'ccguard.py').write_text('# updated fixture\n')
        installer.install(updated, self.prefix, self.python, self.profile)
        self.assertEqual((self.prefix/'lib/ccguard/ccguard.py').read_text(), '# updated fixture\n')
        self.assertEqual(self.profile.read_text().count(installer.PATH_BEGIN), 1)

    def test_three_command_install_upgrades_to_four_and_uninstalls_cleanly(self):
        old_commands = {name: kind for name, kind in installer.COMMANDS.items() if kind != 'check'}
        with patch.object(installer, 'COMMANDS', old_commands):
            self.install()
        check = self.prefix/'bin/ccguard-check'
        self.assertFalse(check.exists())
        self.install()
        self.assertTrue(check.is_file())
        self.assertEqual(shlex.split(check.read_text().splitlines()[-1])[-2:], ['check', '$@'])
        self.assertEqual(self.profile.read_text().count(installer.PATH_BEGIN), 1)
        self.assertEqual(installer.uninstall(self.prefix), [])
        for name in installer.COMMANDS:
            self.assertFalse((self.prefix/'bin'/name).exists())

    def test_unmanaged_new_command_is_preserved_even_if_it_looks_like_old_wrapper(self):
        legacy = self.root/'old-workspace/ccguard.py'
        legacy.parent.mkdir(parents=True)
        legacy.write_text('"""Personal macOS Claude launch/quit commands."""\n')
        old = self.prefix/'bin/ccguard-cli'
        old.parent.mkdir(parents=True)
        old.write_text('#!/bin/sh\nexec /usr/bin/python3 -B ' + shlex.quote(str(legacy)) + ' cli "$@"\n')
        before = old.read_bytes()
        with self.assertRaisesRegex(ValueError, '同名文件'):
            self.install()
        self.assertEqual(old.read_bytes(), before)
        self.assertTrue(legacy.exists())

    def create_legacy(self, original_profile=b'export EXISTING=value\n', with_check=True, with_profile=True):
        old_app = self.prefix / 'lib/claude-tools'
        old_app.mkdir(parents=True)
        files = {}
        for name in installer.LEGACY_PAYLOAD:
            path = old_app / name
            path.write_text('legacy fixture: ' + name + '\n')
            files['lib/claude-tools/' + name] = installer.digest(path.read_bytes())
        for name, kind in installer.LEGACY_COMMANDS.items():
            if not with_check and kind == 'check':
                continue
            path = self.prefix / 'bin' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#!/bin/sh\n# Managed by personal-claude-tools.\nexec '
                + shlex.quote(str(self.python)) + ' -B ' + shlex.quote(str(old_app/'claude_commands.py'))
                + ' ' + kind + ' "$@"\n')
            path.chmod(0o755)
            files['bin/' + name] = installer.digest(path.read_bytes())
        profile_record = None
        if with_profile:
            block = installer.path_block(self.prefix / 'bin').replace(
                'personal-ccguard', 'personal-claude-tools').replace('_ccguard_bin', '_claude_tools_bin')
            addition = ('\n' if original_profile and not original_profile.endswith(b'\n') else '') + block
            self.profile.write_bytes(original_profile + addition.encode())
            self.profile.chmod(0o600)
            profile_record = {'path': str(self.profile), 'block': addition, 'created': not original_profile}
        manifest = {'app_id': installer.LEGACY_APP_ID, 'version': '2026.11.04.4',
                    'prefix': str(self.prefix), 'python': str(self.python), 'files': files, 'profile': profile_record}
        (old_app / 'manifest.json').write_text(json.dumps(manifest))
        return old_app

    def installed_files(self):
        # Backups deliberately survive a rollback; compare active files separately.
        return {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob('*')
                if path.is_file() and 'state/ccguard/backups/' not in str(path)}

    def test_managed_legacy_migration_backups_renames_and_preserves_unrelated_content(self):
        old_app = self.create_legacy()
        extra = old_app / 'personal-note.txt'
        extra.write_text('keep me')
        before = self.installed_files()
        self.install()
        self.assertEqual(extra.read_text(), 'keep me')
        self.assertFalse((old_app/'manifest.json').exists())
        for name in installer.LEGACY_COMMANDS:
            self.assertFalse((self.prefix/'bin'/name).exists())
        for name in installer.COMMANDS:
            self.assertTrue((self.prefix/'bin'/name).is_file())
        manifest = json.loads((self.prefix/'lib/ccguard/manifest.json').read_text())
        backup = Path(manifest['migration_backup'])
        records = json.loads((backup/'backup.json').read_text())['files']
        self.assertEqual(len(records), 10)  # 8 owned files + old manifest + profile
        for record in records:
            data = (backup/record['backup']).read_bytes()
            self.assertEqual(installer.digest(data), record['sha256'])
            self.assertEqual(data, before[str(Path(record['original']).relative_to(self.root))])
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.profile.read_text().count(installer.PATH_BEGIN), 1)
        self.assertNotIn('personal-claude-tools', self.profile.read_text())
        self.assertEqual(self.profile.stat().st_mode & 0o777, 0o600)
        after = {str(path): path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        self.install()
        self.assertEqual(after, {str(path): path.read_bytes() for path in self.root.rglob('*') if path.is_file()})
        self.assertEqual(installer.uninstall(self.prefix), [])
        self.assertEqual(self.profile.read_bytes(), b'export EXISTING=value\n')
        self.assertTrue((backup/'backup.json').is_file())

    def test_three_command_legacy_package_migrates(self):
        old_app = self.create_legacy(with_check=False)
        self.install()
        self.assertFalse(old_app.exists())
        self.assertTrue((self.prefix/'bin/ccguard-check').is_file())

    def test_migration_preserves_profile_without_original_trailing_newline(self):
        self.create_legacy(original_profile=b'export EXISTING=value')
        self.install()
        self.assertEqual(installer.uninstall(self.prefix), [])
        self.assertEqual(self.profile.read_bytes(), b'export EXISTING=value')

    def test_migration_preserves_originally_created_profile_semantics(self):
        self.create_legacy(original_profile=b'')
        self.install()
        self.assertEqual(installer.uninstall(self.prefix), [])
        self.assertFalse(self.profile.exists())

    def test_modified_legacy_file_is_preserved_without_any_migration(self):
        old_app = self.create_legacy()
        (old_app/'net_check.py').write_text('personal policy')
        before = self.installed_files()
        with self.assertRaisesRegex(ValueError, '本地修改'):
            self.install()
        self.assertEqual(before, self.installed_files())
        self.assertFalse((self.prefix/'state/ccguard/backups').exists())

    def test_modified_legacy_profile_is_preserved_without_any_migration(self):
        self.create_legacy()
        self.profile.write_text(self.profile.read_text().replace('export PATH=', 'export MY_PATH='))
        before = self.installed_files()
        with self.assertRaisesRegex(ValueError, 'PATH 区块'):
            self.install()
        self.assertEqual(before, self.installed_files())

    def test_new_name_conflict_leaves_legacy_installation_usable(self):
        self.create_legacy()
        conflict = self.prefix/'bin/ccguard-kill'
        conflict.write_text('my own command')
        before = self.installed_files()
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(before, self.installed_files())

    def test_unmanaged_old_name_is_not_deleted(self):
        path = self.prefix/'bin/kill-claude'
        path.parent.mkdir(parents=True)
        path.write_text('unmanaged')
        with self.assertRaisesRegex(ValueError, '无法核验归属'):
            self.install()
        self.assertEqual(path.read_text(), 'unmanaged')
        self.assertFalse((self.prefix/'lib/ccguard').exists())

    def test_legacy_manifest_cannot_expand_removal_scope(self):
        old_app = self.create_legacy()
        manifest_path = old_app/'manifest.json'
        data = json.loads(manifest_path.read_text())
        data['files']['../outside'] = installer.digest(b'keep')
        manifest_path.write_text(json.dumps(data))
        before = self.installed_files()
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(before, self.installed_files())

    def test_migration_write_failure_restores_legacy_installation(self):
        self.create_legacy()
        before = self.installed_files()
        original_write = installer.atomic_write
        def fail(path, data, mode=0o644):
            if path == self.prefix/'lib/ccguard/manifest.json':
                raise OSError('simulated new manifest failure')
            original_write(path, data, mode)
        with patch.object(installer, 'atomic_write', side_effect=fail), self.assertRaises(OSError):
            self.install()
        self.assertEqual(before, self.installed_files())

    def test_migration_delete_failure_restores_new_and_already_removed_old_files(self):
        old_app = self.create_legacy()
        before = self.installed_files()
        original_unlink = Path.unlink
        def fail(path, *args, **kwargs):
            if path == old_app/'net_check.py':
                raise OSError('simulated old file removal failure')
            return original_unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', new=fail), self.assertRaises(OSError):
            self.install()
        self.assertEqual(before, self.installed_files())

    def test_migration_no_path_rejects_existing_managed_profile(self):
        self.create_legacy()
        before = self.installed_files()
        with self.assertRaisesRegex(ValueError, '--no-path'):
            self.install(profile=False)
        self.assertEqual(before, self.installed_files())

    def test_migration_no_path_works_when_old_install_has_no_profile(self):
        self.create_legacy(with_profile=False)
        self.install(profile=False)
        self.assertFalse(self.profile.exists())
        self.assertTrue((self.prefix/'bin/ccguard-kill').is_file())

    def test_legacy_symlink_is_not_followed_or_removed(self):
        old_app = self.create_legacy()
        path = old_app/'net_check.py'
        path.unlink()
        outside = self.root/'outside'
        outside.write_text('keep')
        path.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.install()
        self.assertTrue(path.is_symlink())
        self.assertEqual(outside.read_text(), 'keep')

    def test_unsupported_platform_rejected_without_writes(self):
        with patch.object(installer.sys, 'platform', 'win32'), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(installer.main(['--prefix', str(self.prefix), '--no-path']), 1)
        self.assertFalse(self.prefix.exists())

    def test_uninstall_without_install_is_noop(self):
        self.assertEqual(installer.uninstall(self.prefix), [])

    def test_manifest_cannot_delete_outside_install_prefix(self):
        self.install()
        outside = self.root/'do-not-delete'
        outside.write_text('keep')
        path = self.prefix/'lib/ccguard/manifest.json'
        manifest = json.loads(path.read_text())
        manifest['files']['../do-not-delete'] = installer.digest(b'keep')
        path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            installer.uninstall(self.prefix)
        self.assertEqual(outside.read_text(), 'keep')
        for name in installer.COMMANDS:
            self.assertTrue((self.prefix/'bin'/name).exists())


if __name__ == '__main__':
    unittest.main()
