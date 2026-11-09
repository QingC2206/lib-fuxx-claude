"""Exercise setup transactions in a temporary sandbox; never run sudo or real setup."""
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

import install as installer


SOURCE = (Path(installer.__file__).parent / "background-access.sh").read_text()
ROOT_SCRIPT = SOURCE.split("<<'CCGUARD_ROOT'\n", 1)[1].rsplit("\nCCGUARD_ROOT", 1)[0]


class BackgroundAccessSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ccguard-sudoers-fixture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.rules = self.root / "sudoers.d"
        self.rules.mkdir()
        self.master = self.root / "sudoers"
        self.master.write_text("#includedir /private/etc/sudoers.d\n")
        self.target = self.rules / "ccguard-btm-501"
        self.expected = ("# Managed by ccguard-background-access-v1\n"
                         "# Read-only BTM query for UID 501\n"
                         "#501 ALL=(root) NOPASSWD: NOSETENV: /usr/bin/sfltool dumpbtm\n")
        self.stat = self.make_stub("stat", '''
if [ "$3" = "$CCGUARD_FIXTURE/sudoers.d" ]; then
    printf '%s\\n' "${CCGUARD_DIR_META:-0:0:755}"
else
    printf '%s\\n' "${CCGUARD_FILE_META:-0:0:440}"
fi
''')
        self.chown = self.make_stub("chown", 'exit 0\n')
        self.visudo = self.make_stub("visudo", '''
counter=$CCGUARD_FIXTURE/visudo-count
count=0
if [ -f "$counter" ]; then count=$(/bin/cat "$counter"); fi
count=$((count + 1))
printf '%s\\n' "$count" > "$counter"
[ "$count" != "${CCGUARD_FAIL_AT:-0}" ]
''')
        self.script = ROOT_SCRIPT.replace("rules=/private/etc/sudoers.d", "rules=" + shlex.quote(str(self.rules)))
        self.script = self.script.replace("master=/private/etc/sudoers", "master=" + shlex.quote(str(self.master)))
        self.script = self.script.replace("/usr/bin/id -u", "printf 0")
        for original, replacement in (("/usr/bin/stat", self.stat), ("/usr/sbin/chown", self.chown),
                                      ("/usr/sbin/visudo", self.visudo)):
            self.script = self.script.replace(original, shlex.quote(str(replacement)))
        # The only remaining system path is the literal include pattern, never an operation.
        self.assertNotIn("=/private/etc/", self.script)
        self.assertNotIn("/usr/bin/sudo", self.script)
        self.assertNotIn("/usr/sbin/visudo", self.script)

    def make_stub(self, name, body):
        path = self.root / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o700)
        return path

    def run_setup(self, action="enable", uid="501", **environment):
        (self.root / "visudo-count").unlink(missing_ok=True)
        result = subprocess.run(["/bin/sh", "-s", "--", action, uid], input=self.script,
                                text=True, capture_output=True, timeout=5,
                                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SUDO_UID": "501",
                                     "CCGUARD_FIXTURE": str(self.root), **environment})
        self.assertEqual(list(self.rules.glob('.ccguard-btm-*')), [])
        return result

    def test_enable_has_exact_scope_and_is_idempotent(self):
        self.assertEqual(self.run_setup().returncode, 0)
        self.assertEqual(self.target.read_text(), self.expected)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o440)
        before = self.target.stat().st_mtime_ns
        self.assertEqual(self.run_setup().returncode, 0)
        self.assertEqual(self.target.stat().st_mtime_ns, before)
        # Validate the generated isolated rule using the actual system parser, without sudo.
        result = subprocess.run(["/usr/sbin/visudo", "-c", "-f", str(self.target)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_disable_removes_only_exact_owned_rule(self):
        self.assertEqual(self.run_setup().returncode, 0)
        other = self.rules / 'unrelated'
        other.write_text('unrelated rule')
        self.assertEqual(self.run_setup('disable').returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertEqual(other.read_text(), 'unrelated rule')
        self.assertEqual(self.run_setup('disable').returncode, 0)

    def test_conflicting_content_is_preserved_for_both_actions(self):
        self.target.write_text('# unrelated rule\n')
        for action in ('enable', 'disable'):
            result = self.run_setup(action)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.target.read_text(), '# unrelated rule\n')

    def test_symlink_is_rejected_without_touching_destination(self):
        destination = self.root / 'untouched'
        destination.write_text(self.expected)
        self.target.symlink_to(destination)
        for action in ('enable', 'disable'):
            self.assertNotEqual(self.run_setup(action).returncode, 0)
            self.assertTrue(self.target.is_symlink())
            self.assertEqual(destination.read_text(), self.expected)

    def test_invalid_user_and_action_do_not_create_rule(self):
        for action, uid in (('reset', '501'), ('enable', '0'), ('enable', '502'),
                            ('enable', '501 ALL=(root) NOPASSWD: ALL'), ('enable', '../501')):
            with self.subTest(action=action, uid=uid):
                self.assertNotEqual(self.run_setup(action, uid).returncode, 0)
                self.assertFalse(self.target.exists())

    def test_insecure_directory_or_file_metadata_prevents_changes(self):
        for metadata in ('501:20:755', '0:0:777'):
            self.assertNotEqual(self.run_setup(CCGUARD_DIR_META=metadata).returncode, 0)
            self.assertFalse(self.target.exists())
        self.target.write_text(self.expected)
        self.assertNotEqual(self.run_setup('disable', CCGUARD_FILE_META='501:20:440').returncode, 0)
        self.assertEqual(self.target.read_text(), self.expected)

    def test_missing_include_does_not_edit_global_sudoers(self):
        self.master.write_text('root ALL=(ALL) ALL\n')
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.master.read_text(), 'root ALL=(ALL) ALL\n')
        self.assertFalse(self.target.exists())

    def test_precheck_and_candidate_validation_fail_before_install(self):
        for call in ('1', '2'):
            self.assertNotEqual(self.run_setup(CCGUARD_FAIL_AT=call).returncode, 0)
            self.assertFalse(self.target.exists())

    def test_failed_full_validation_rolls_back_new_rule(self):
        self.assertNotEqual(self.run_setup(CCGUARD_FAIL_AT='3').returncode, 0)
        self.assertFalse(self.target.exists())

    def test_failed_full_validation_restores_revoked_rule(self):
        self.assertEqual(self.run_setup().returncode, 0)
        self.assertNotEqual(self.run_setup('disable', CCGUARD_FAIL_AT='3').returncode, 0)
        self.assertEqual(self.target.read_text(), self.expected)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o440)


if __name__ == "__main__":
    unittest.main()
