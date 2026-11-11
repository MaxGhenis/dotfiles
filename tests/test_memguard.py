import importlib.machinery
import importlib.util
import itertools
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
MEMGUARD_PATH = REPO_ROOT / "bin" / "memguard"
SUBPROCESS_TIMEOUT = 60


def load_memguard():
    loader = importlib.machinery.SourceFileLoader("memguard", str(MEMGUARD_PATH))
    spec = importlib.util.spec_from_loader("memguard", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


memguard = load_memguard()
GB = memguard.GB
FLOOR = memguard.MIN_TARGET_FOOTPRINT
UID = memguard.UID
MiB = 1 << 20


def row(pid, footprint, rss, argv, uid=UID, exe=""):
    return {
        "pid": pid,
        "uid": uid,
        "footprint": int(footprint),
        "rss": int(rss),
        "exe": exe or (argv[0] if argv else ""),
        "argv": argv,
        "cmd": " ".join(argv),
    }


# 2026-10-01 11:33-11:43 EDT, from ~/reviews/compute-contention-2026-10-01
# (data/adhoc-measurements.json "rss_vs_footprint": top MEM and ps RSS taken
# in the same sampler row). The 25 GiB bun stands in for the non-python
# giants of that hour.
OCTOBER_FIRST = [
    row(62275, 114 * GB, 7613 * MiB,
        ["/Users/maxghenis/PolicyEngine/_worktrees/pe-us-cow-bench/.venv/bin/python",
         "us_bench.py", "ecps"]),
    row(41790, 87 * GB, 621 * MiB,
        ["/Users/maxghenis/PolicyEngine/.worktrees/fix-in-place-cache-writes/.venv/bin/python",
         "impact.py"]),
    row(62807, 25 * GB, 800 * MiB, ["/Users/maxghenis/.bun/bin/bun", "run", "dev"]),
]


class PickTargetTests(unittest.TestCase):
    def test_october_first_python_is_targeted_by_footprint_not_rss(self):
        target, giants = memguard.pick_target(OCTOBER_FIRST)

        self.assertIsNotNone(target)
        self.assertEqual(target["pid"], 62275)
        self.assertEqual(target["footprint"], 114 * GB)
        # The RSS floor saw none of these: each is far below 20 GiB.
        self.assertTrue(all(r["rss"] < FLOOR for r in OCTOBER_FIRST))
        self.assertEqual([g["pid"] for g in giants], [62807])

    def test_non_python_over_the_floor_is_never_the_target(self):
        for argv in (
            ["/Users/maxghenis/.bun/bin/bun", "run"],
            ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
            ["node", "server.js"],
        ):
            with self.subTest(argv=argv[0]):
                giant = row(500, 40 * GB, 1 * GB, argv)
                target, giants = memguard.pick_target([giant])
                self.assertIsNone(target)
                self.assertEqual([g["pid"] for g in giants], [500])

    def test_owner_deny_list_floor_and_reserved_pids_are_respected(self):
        python = ["/usr/bin/python3.13", "sim.py"]
        rows = [
            row(10, 90 * GB, 1 * GB, python, uid=0),
            row(11, 80 * GB, 1 * GB, ["/Applications/Claude.app/Contents/MacOS/Claude"]),
            row(12, 70 * GB, 1 * GB, ["claude-python-helper"]),
            row(1, 60 * GB, 1 * GB, python),
            row(os.getpid(), 50 * GB, 1 * GB, python),
            row(13, FLOOR - 1, 30 * GB, python),
            row(14, FLOOR, 1 * GB, python),
        ]

        target, giants = memguard.pick_target(rows)

        self.assertEqual(target["pid"], 14)
        self.assertEqual(giants, [])

    def test_clean_rss_without_footprint_does_not_reach_the_floor(self):
        # 30 GiB resident but 5 GiB footprint: clean file-backed pages the
        # kernel can reclaim on its own. Killing it would not free 20 GiB.
        mapped = row(20, 5 * GB, 30 * GB, ["/usr/bin/python3", "read_h5.py"])

        target, giants = memguard.pick_target([mapped])

        self.assertIsNone(target)
        self.assertEqual(giants, [])

    def test_giants_are_reported_largest_first(self):
        rows = [
            row(30, 21 * GB, 0, ["bun"]),
            row(31, 60 * GB, 0, ["node"]),
            row(32, 35 * GB, 0, ["ruby"]),
        ]

        _, giants = memguard.pick_target(rows)

        self.assertEqual([g["pid"] for g in giants], [31, 32, 30])

    def test_python_detection_uses_basenames_of_argv0_and_executable(self):
        framework = ("/opt/homebrew/Cellar/python@3.14/3.14.7/Frameworks/Python.framework/"
                     "Versions/3.14/Resources/Python.app/Contents/MacOS/Python")
        cases = {
            ".venv/bin/python": True,
            "python3.13": True,
            "/usr/local/bin/ipython": True,
            "/Users/maxghenis/python-tools/bin/node": False,
            "bun": False,
        }
        for argv0, expected in cases.items():
            with self.subTest(argv0=argv0):
                self.assertEqual(memguard.is_python(row(1, 0, 0, [argv0])), expected)
        retitled = row(1, 0, 0, ["pytest-xdist worker gw3"], exe=framework)
        self.assertTrue(memguard.is_python(retitled))


class PickTargetInvariantTests(unittest.TestCase):
    """Exhaustive over every ordered list of up to three archetype rows.

    Each property is checked against an independent restatement of the
    policy, so a change to pick_target that breaks it shows up as a
    counterexample with the exact rows.
    """

    ARGVS = {
        "python": ["/usr/bin/python3", "job.py"],
        "framework": ["renamed-worker"],
        "bun": ["/Users/maxghenis/.bun/bin/bun"],
        "claude": ["/Applications/Claude.app/Contents/MacOS/Claude"],
    }
    FRAMEWORK_EXE = "/Library/Frameworks/Python.framework/Resources/Python.app/Contents/MacOS/Python"

    @classmethod
    def archetypes(cls):
        sizes = (FLOOR - 1, FLOOR, FLOOR + 1, 3 * FLOOR)
        pids = (100, 1, os.getpid())
        out = []
        for kind, uid, size, pid in itertools.product(cls.ARGVS, (UID, 0), sizes, pids):
            if pid != 100 and (uid != UID or size != 3 * FLOOR):
                continue  # reserved pids only need the otherwise-eligible case
            exe = cls.FRAMEWORK_EXE if kind == "framework" else ""
            out.append(row(pid, size, 1 * GB, cls.ARGVS[kind], uid=uid, exe=exe))
        return out

    @staticmethod
    def eligible(r):
        names = [os.path.basename(n).lower() for n in (r["argv"][0], r["exe"]) if n]
        return (
            r["uid"] == UID
            and r["footprint"] >= FLOOR
            and r["pid"] not in (1, os.getpid())
            and not any(n.startswith(p) for n in names for p in memguard.DENY_PREFIXES)
        )

    @staticmethod
    def python(r):
        names = [os.path.basename(n).lower() for n in (r["argv"][0], r["exe"]) if n]
        return any("python" in n for n in names)

    def test_properties_hold_for_every_small_process_table(self):
        archetypes = self.archetypes()
        cases = 0
        for size in range(0, 4):
            for rows in itertools.product(archetypes, repeat=size):
                rows = [dict(r, pid=r["pid"] if r["pid"] != 100 else 100 + i)
                        for i, r in enumerate(rows)]
                target, giants = memguard.pick_target(rows)
                eligible = [r for r in rows if self.eligible(r)]
                pythons = [r for r in eligible if self.python(r)]
                others = [r for r in eligible if not self.python(r)]
                context = {"rows": rows, "target": target, "giants": giants}

                # 1. The target is eligible, python, and the largest such.
                if pythons:
                    self.assertIsNotNone(target, context)
                    self.assertIn(target, pythons, context)
                    self.assertEqual(target["footprint"],
                                     max(r["footprint"] for r in pythons), context)
                else:
                    self.assertIsNone(target, context)
                # 2. Giants are exactly the eligible non-python rows,
                #    largest first, and never include the target.
                self.assertCountEqual([g["pid"] for g in giants],
                                      [r["pid"] for r in others], context)
                self.assertEqual([g["footprint"] for g in giants],
                                 sorted((g["footprint"] for g in giants), reverse=True),
                                 context)
                self.assertNotIn(target, giants, context)
                # 3. Row order never changes how big the target is.
                reversed_target, _ = memguard.pick_target(list(reversed(rows)))
                self.assertEqual(target and target["footprint"],
                                 reversed_target and reversed_target["footprint"],
                                 context)
                # 4. Adding a non-python giant never changes the target.
                extra = row(99999, 10 * FLOOR, 0, ["bun"])
                with_extra, _ = memguard.pick_target(rows + [extra])
                self.assertIs(with_extra, target, context)
                cases += 1
        self.assertGreater(cases, 10000)


class BigProcessesTests(unittest.TestCase):
    def test_reads_uid_only_over_the_floor_and_argv_only_for_our_uid(self):
        sizes = {
            101: (25 * GB, 1 * GB),
            102: (5 * GB, 5 * GB),
            103: (40 * GB, 1 * GB),
            104: None,
            105: (30 * GB, 1 * GB),
            106: (50 * GB, 1 * GB),
        }
        owners = {101: UID, 103: 0, 105: UID, 106: None}
        lookups = []

        def uid_of(pid):
            lookups.append(("uid", pid))
            return owners.get(pid)

        def argv_of(pid):
            lookups.append(("argv", pid))
            return None if pid == 105 else ("/usr/bin/python3", ["python3", "x.py"])

        rows = memguard.big_processes(
            pids=[101, 102, 103, 104, 105, 106], usage=sizes.get, uid_of=uid_of, argv_of=argv_of)

        self.assertEqual([r["pid"] for r in rows], [101, 103, 105])
        self.assertEqual(
            lookups,
            [("uid", 101), ("argv", 101), ("uid", 103), ("uid", 105), ("argv", 105),
             ("uid", 106)],
        )
        by_pid = {r["pid"]: r for r in rows}
        self.assertEqual(by_pid[101]["cmd"], "python3 x.py")
        self.assertEqual(by_pid[103]["argv"], [])  # never read another user's argv
        # An unreadable argv leaves the row unrecognised, so never a target.
        self.assertEqual(by_pid[105]["cmd"], "(argv unreadable)")
        target, giants = memguard.pick_target(rows)
        self.assertEqual(target["pid"], 101)
        self.assertEqual([g["pid"] for g in giants], [105])


class ProcArgsTests(unittest.TestCase):
    @staticmethod
    def buffer(argc, exe, argv, env=(b"HOME=/x",)):
        return (argc.to_bytes(4, sys.byteorder) + exe + b"\0" * 4
                + b"".join(a + b"\0" for a in list(argv) + list(env)))

    def test_parses_exec_path_and_argv_but_not_the_environment(self):
        raw = self.buffer(3, b"/usr/bin/python3", [b"python3", b"-m", b"pytest"])

        self.assertEqual(memguard.parse_procargs2(raw),
                         ("/usr/bin/python3", ["python3", "-m", "pytest"]))

    def test_short_or_undecodable_buffers_do_not_raise(self):
        self.assertIsNone(memguard.parse_procargs2(b"\x01\x00"))
        exe, argv = memguard.parse_procargs2(self.buffer(1, b"/bin/x\xff", [b"\xfe"]))
        self.assertEqual(exe, "/bin/x�")
        self.assertEqual(argv, ["�"])


@unittest.skipUnless(sys.platform == "darwin" and memguard.LIBC is not None, "libproc is macOS-only")
class LiveReaderTests(unittest.TestCase):
    """Reads real processes. Nothing here sends a signal: the child exits
    when its stdin closes."""

    def setUp(self):
        self.child = subprocess.Popen(
            [sys.executable, "-c",
             "import sys\nb = bytearray(256 << 20)\n"
             "for i in range(0, len(b), 4096): b[i] = 1\n"
             "print('ready', flush=True)\nsys.stdin.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(self.child.wait, SUBPROCESS_TIMEOUT)
        self.addCleanup(self.child.stdin.close)
        self.assertEqual(self.child.stdout.readline().strip(), "ready")

    def test_child_footprint_uid_and_argv(self):
        rows = memguard.big_processes(min_footprint=200 * MiB, pids=[self.child.pid])

        self.assertEqual(len(rows), 1)
        found = rows[0]
        self.assertGreaterEqual(found["footprint"], 256 * MiB)
        self.assertLessEqual(found["footprint"], 320 * MiB)
        self.assertEqual(found["uid"], os.getuid())
        self.assertIn("-c", found["argv"])
        self.assertTrue(memguard.is_python(found))

    def test_footprint_agrees_with_the_footprint_tool(self):
        tool = shutil.which("footprint") or "/usr/bin/footprint"
        if not os.path.exists(tool):
            self.skipTest("no footprint(1)")
        result = subprocess.run([tool, "-p", str(self.child.pid)], capture_output=True,
                                text=True, timeout=SUBPROCESS_TIMEOUT, check=False)
        match = re.search(r"phys_footprint:\s+([\d.]+)\s+MB", result.stdout)
        if result.returncode != 0 or not match:
            self.skipTest("footprint(1) unavailable here: " + result.stderr[:200])
        ours = memguard.proc_usage(self.child.pid)[0] / MiB

        self.assertAlmostEqual(ours, float(match.group(1)), delta=4)

    def test_pid_list_and_uid_agree_with_ps(self):
        result = subprocess.run(["/bin/ps", "-axo", "pid=,uid="], capture_output=True,
                                text=True, timeout=SUBPROCESS_TIMEOUT, check=True)
        ps_uids = {}
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) == 2:
                ps_uids[int(fields[0])] = int(fields[1])
        pids = memguard.list_pids()

        self.assertIn(os.getpid(), pids)
        self.assertIn(self.child.pid, pids)
        self.assertGreater(len(set(pids) & set(ps_uids)), 0.9 * len(ps_uids))
        mismatches = []
        for pid in set(pids) & set(ps_uids):
            uid = memguard.proc_uid(pid)
            if uid is not None and uid != ps_uids[pid]:
                mismatches.append((pid, uid, ps_uids[pid]))
        self.assertEqual(mismatches, [])


@unittest.skipUnless(sys.platform == "darwin", "memguard samples macOS tools")
class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.home = Path(self.temporary_directory.name).resolve()
        self.environment = os.environ.copy()
        self.environment["HOME"] = str(self.home)

    def run_memguard(self, *arguments):
        return subprocess.run(
            [sys.executable, str(MEMGUARD_PATH), *arguments],
            check=False, capture_output=True, text=True,
            timeout=SUBPROCESS_TIMEOUT, env=self.environment)

    def test_self_test_without_the_live_signal_passes(self):
        result = self.run_memguard("test", "--dry-run")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SKIP live SIGTERM path", result.stdout)
        self.assertNotIn("FAIL", result.stdout)
        self.assertEqual(list(self.home.rglob("*")), [])

    def test_dry_tick_prints_one_csv_line_and_writes_nothing(self):
        result = self.run_memguard("tick", "--dry-run")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("DRY "), result.stdout)
        self.assertEqual(result.stdout.strip().count(","), 9)
        self.assertEqual(list(self.home.rglob("*")), [])

    def test_status_reports_what_it_would_target(self):
        result = self.run_memguard("status")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("would target:", result.stdout)


if __name__ == "__main__":
    unittest.main()
