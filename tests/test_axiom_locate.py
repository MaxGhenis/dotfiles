import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
LOCATOR = REPO_ROOT / "bin" / "axiom-locate"
SUBPROCESS_TIMEOUT = 15


class AxiomLocateTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temp_path = Path(self.temporary_directory.name).resolve()
        self.mirror = self.temp_path / "mirror"
        self.home = self.temp_path / "home"
        self.mirror.mkdir()
        self.home.mkdir()
        self.environment = os.environ.copy()
        self.environment["AXIOM_MIRROR_ROOT"] = str(self.mirror)
        self.environment["HOME"] = str(self.home)
        self.environment.pop("VIRTUAL_ENV", None)

    def run_locator(self, *arguments, environment=None):
        return subprocess.run(
            [str(LOCATOR), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            env=environment or self.environment,
        )

    def make_file(self, relative_path, mtime_ns=1_000_000_000):
        path = self.mirror / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
        os.utime(path, ns=(mtime_ns, mtime_ns))
        return path

    def make_directory(self, relative_path, mtime_ns=1_000_000_000):
        path = self.mirror / relative_path
        path.mkdir(parents=True, exist_ok=True)
        os.utime(path, ns=(mtime_ns, mtime_ns))
        return path

    def test_engine_returns_newest_direct_or_container_match(self):
        older = self.make_file(
            "repo-a/target/release/axiom-rules-engine", 1_000_000_000
        )
        newer = self.make_file(
            "_worktrees/repo-b/target/release/axiom-rules-engine", 2_000_000_000
        )

        completed = self.run_locator("engine")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), str(newer))
        self.assertNotEqual(completed.stdout.strip(), str(older))

    def test_engine_absent_returns_one_and_stderr_message(self):
        completed = self.run_locator("engine")

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn("no results for engine", completed.stderr)

    def test_release_returns_direct_and_container_matches_newest_first(self):
        older = self.make_directory("repo-a/releases/release-demo", 1_000_000_000)
        newer = self.make_directory(
            "_container/repo-b/releases/release-demo", 2_000_000_000
        )

        completed = self.run_locator("release", "release-demo")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.splitlines(), [str(newer), str(older)])

    def test_release_name_is_literal_and_must_be_one_component(self):
        literal = self.make_directory("repo-a/releases/release-[x]")

        completed = self.run_locator("release", "release-[x]")
        invalid = self.run_locator("release", "../release-[x]")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), str(literal))
        self.assertEqual(invalid.returncode, 2)

    def test_pypkg_uses_requested_interpreter(self):
        import json as json_module

        environment = self.environment.copy()
        environment["VIRTUAL_ENV"] = str(self.temp_path / "missing-venv")

        completed = self.run_locator(
            "pypkg", "json", "--python", sys.executable, environment=environment
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            Path(completed.stdout.strip()).resolve(),
            Path(json_module.__file__).resolve(),
        )

    def test_pypkg_rejects_non_identifier_and_keyword(self):
        injected = self.run_locator("pypkg", "json;print('bad')")
        keyword_name = self.run_locator("pypkg", "class")

        self.assertEqual(injected.returncode, 2)
        self.assertEqual(keyword_name.returncode, 2)

    def test_corpus_file_uses_git_tracked_files(self):
        git = shutil.which("git")
        if git is None:
            self.skipTest("git is not installed")
        corpus = self.mirror / "axiom-corpus-fixture"
        corpus.mkdir()
        subprocess.run(
            [git, "init", "-q", str(corpus)],
            check=True,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        tracked = corpus / "rules" / "364" / "350" / "block-1.yaml"
        tracked.parent.mkdir(parents=True)
        tracked.write_text("tracked\n", encoding="utf-8")
        untracked = corpus / "rules" / "364" / "350" / "untracked.yaml"
        untracked.write_text("untracked\n", encoding="utf-8")
        subprocess.run(
            [git, "-C", str(corpus), "add", "--", str(tracked.relative_to(corpus))],
            check=True,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
        )

        substring = self.run_locator("corpus-file", "364/350/block-1")
        wildcard = self.run_locator("corpus-file", "*/350/block-1.yaml")
        untracked_result = self.run_locator("corpus-file", "untracked.yaml")

        self.assertEqual(substring.returncode, 0, substring.stderr)
        self.assertEqual(substring.stdout.strip(), str(tracked))
        self.assertEqual(wildcard.returncode, 0, wildcard.stderr)
        self.assertEqual(wildcard.stdout.strip(), str(tracked))
        self.assertEqual(untracked_result.returncode, 1)

    def test_cache_hit_refresh_and_deleted_path_invalidation(self):
        initially_newest = self.make_file(
            "repo-a/target/release/axiom-rules-engine", 1_000_000_000
        )
        primed = self.run_locator("engine")
        cache_file = self.home / ".axiom" / "locate-cache.json"

        self.assertEqual(primed.returncode, 0, primed.stderr)
        self.assertTrue(cache_file.is_file())
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
        cached_records = next(iter(cache["entries"].values()))["results"]
        self.assertEqual(cached_records[0]["path"], str(initially_newest))
        self.assertIn("mtime", cached_records[0])

        new_candidate = self.make_file(
            "repo-b/target/release/axiom-rules-engine", 2_000_000_000
        )
        cached = self.run_locator("engine")
        refreshed = self.run_locator("engine", "--refresh")

        self.assertEqual(cached.stdout.strip(), str(initially_newest))
        self.assertEqual(refreshed.stdout.strip(), str(new_candidate))

        new_candidate.unlink()
        after_deletion = self.run_locator("engine")

        self.assertEqual(after_deletion.returncode, 0, after_deletion.stderr)
        self.assertEqual(after_deletion.stdout.strip(), str(initially_newest))

    def test_engine_cache_invalidates_when_mtime_changes(self):
        cached_path = self.make_file(
            "repo-a/target/release/axiom-rules-engine", 2_000_000_000
        )
        other_path = self.make_file(
            "repo-b/target/release/axiom-rules-engine", 1_000_000_000
        )
        self.assertEqual(self.run_locator("engine").stdout.strip(), str(cached_path))

        os.utime(cached_path, ns=(500_000_000, 500_000_000))
        completed = self.run_locator("engine")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), str(other_path))

    def test_refresh_flag_before_subcommand_and_json_shape(self):
        engine = self.make_file("repo-a/target/release/axiom-rules-engine")

        completed = self.run_locator("--refresh", "--json", "engine")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            json.loads(completed.stdout),
            {"query": "engine", "results": [str(engine)]},
        )

    def test_json_not_found_keeps_exit_one_and_empty_results(self):
        completed = self.run_locator("engine", "--json")

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(
            json.loads(completed.stdout), {"query": "engine", "results": []}
        )
        self.assertIn("no results", completed.stderr)

    def test_cache_keys_are_isolated_by_mirror_root(self):
        first = self.make_file("repo-a/target/release/axiom-rules-engine")
        self.assertEqual(self.run_locator("engine").stdout.strip(), str(first))

        second_mirror = self.temp_path / "second-mirror"
        second = second_mirror / "repo-b" / "target" / "release" / "axiom-rules-engine"
        second.parent.mkdir(parents=True)
        second.write_bytes(b"")
        second_environment = self.environment.copy()
        second_environment["AXIOM_MIRROR_ROOT"] = str(second_mirror)

        completed = self.run_locator("engine", environment=second_environment)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), str(second))

    def test_corrupt_cache_is_ignored_and_replaced(self):
        engine = self.make_file("repo-a/target/release/axiom-rules-engine")
        cache_file = self.home / ".axiom" / "locate-cache.json"
        cache_file.parent.mkdir()
        cache_file.write_text("not json", encoding="utf-8")

        completed = self.run_locator("engine")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), str(engine))
        self.assertEqual(json.loads(cache_file.read_text())["version"], 1)


if __name__ == "__main__":
    unittest.main()
