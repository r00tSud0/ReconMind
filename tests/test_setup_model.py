"""Model install tests. Offline: downloads, child processes and torch are faked."""
import io
import json
import os
import tarfile
import tempfile
import unittest
from unittest import mock

from reconmind.ai import attack_mapper
from reconmind.setup import install, manifest, model


def make_archive(path, entries):
    """entries: [(name, bytes or None for a folder, type)]."""
    with tarfile.open(path, "w:gz") as t:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                t.addfile(info)
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                t.addfile(info)
            else:
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))


def good_entries(folder="attack_mapper_run3"):
    out = [(folder, None, "dir")]
    out += [(folder + "/" + n, b"x", "file") for n in attack_mapper.REQUIRED_FILES]
    return out


class Response:
    def __init__(self, body, status=200):
        self.body, self.status, self.pos = body, status, 0

    def read(self, n):
        chunk = self.body[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Proc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.archive = os.path.join(self.tmp.name, "m.tar.gz")

    def tearDown(self):
        self.tmp.cleanup()

    def test_good_archive(self):
        make_archive(self.archive, good_entries())
        holder, extracted = model.safe_extract(self.archive, self.tmp.name, "attack_mapper_run3")
        self.assertEqual(sorted(os.listdir(extracted)), sorted(attack_mapper.REQUIRED_FILES))
        self.assertTrue(holder.startswith(self.tmp.name))

    def test_bad_entries_rejected_and_nothing_left(self):
        bad = {
            "dot dot": good_entries() + [("attack_mapper_run3/../evil", b"x", "file")],
            "absolute": good_entries() + [("/tmp/evil", b"x", "file")],
            "symlink": good_entries() + [("attack_mapper_run3/link", None, "sym")],
            "other folder": good_entries() + [("other/x", b"x", "file")],
            "missing file": good_entries()[:-1],
        }
        for label, entries in bad.items():
            with self.subTest(label=label):
                make_archive(self.archive, entries)
                with self.assertRaises(model.ModelError):
                    model.safe_extract(self.archive, self.tmp.name, "attack_mapper_run3")
                self.assertEqual([n for n in os.listdir(self.tmp.name)
                                  if n.startswith(".model-")], [])

    def test_not_an_archive(self):
        with open(self.archive, "wb") as f:
            f.write(b"not gzip")
        with self.assertRaises(model.ModelError):
            model.safe_extract(self.archive, self.tmp.name, "attack_mapper_run3")


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = os.path.join(self.tmp.name, "f")

    def tearDown(self):
        self.tmp.cleanup()

    def test_resume_appends_after_partial(self):
        with open(self.dest, "wb") as f:
            f.write(b"abc")
        seen = []

        def opener(request, timeout):
            seen.append(request.get_header("Range"))
            return Response(b"defgh", status=206)
        model.download_resume("https://x/f", self.dest, 8, opener=opener, sleep=lambda s: None)
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), b"abcdefgh")
        self.assertEqual(seen, ["bytes=3-"])

    def test_server_ignoring_range_restarts(self):
        with open(self.dest, "wb") as f:
            f.write(b"zz")
        model.download_resume("https://x/f", self.dest, 4,
                              opener=lambda r, timeout: Response(b"abcd", status=200),
                              sleep=lambda s: None)
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), b"abcd")

    def test_oversize_stops(self):
        with self.assertRaises(model.ModelError):
            model.download_resume("https://x/f", self.dest, 2,
                                  opener=lambda r, timeout: Response(b"abcd"),
                                  sleep=lambda s: None)

    def test_gives_up_after_retries(self):
        def opener(request, timeout):
            raise OSError("reset")
        with self.assertRaises(model.ModelError) as err:
            model.download_resume("https://x/f", self.dest, 4, attempts=2, opener=opener,
                                  sleep=lambda s: None)
        self.assertIn("2 tries", str(err.exception))


class VerifyTests(unittest.TestCase):
    def run_with(self, report=None, stderr=""):
        out = json.dumps(report) if report is not None else "garbage"
        return model.verify("/m", 394, run=lambda *a, **k: Proc(out + "\n", stderr))

    def test_ok(self):
        self.assertEqual(self.run_with({"status": "ok", "labels": 394, "predicted": True})["labels"], 394)

    def test_failures(self):
        cases = [
            ({"status": "label-mismatch", "labels": 394, "error": "order"}, "did not load"),
            ({"status": "ok", "labels": 12, "predicted": True}, "12 labels"),
            ({"status": "ok", "labels": 394}, "prediction"),
            (None, "crashed"),
        ]
        for report, words in cases:
            with self.subTest(words=words):
                with self.assertRaises(model.ModelError) as err:
                    self.run_with(report, stderr="Traceback\nboom")
                self.assertIn(words, str(err.exception))

    def test_child_uses_the_folder_and_a_time_limit(self):
        calls = []

        def run(cmd, **kw):
            calls.append((cmd, kw))
            return Proc(json.dumps({"status": "ok", "labels": 394, "predicted": True}))
        model.verify("/models/x", 394, python="/py", run=run)
        cmd, kw = calls[0]
        self.assertEqual(cmd[0], "/py")
        self.assertEqual(cmd[-1], "/models/x")
        self.assertEqual(kw["timeout"], model.VERIFY_TIMEOUT)


class SwapTests(unittest.TestCase):
    def test_old_folder_restored_when_move_fails(self):
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "attack_mapper_run3")
            os.mkdir(dest)
            open(os.path.join(dest, "old"), "w").close()
            real = os.replace
            calls = []

            def flaky(src, dst):
                calls.append((src, dst))
                if len(calls) == 2:
                    raise OSError("disk full")
                return real(src, dst)
            with mock.patch.object(model.os, "replace", side_effect=flaky):
                with self.assertRaises(OSError):
                    model.swap_in(os.path.join(d, "new"), dest)
            self.assertTrue(os.path.isfile(os.path.join(dest, "old")))


class StepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.worker = install.Installer("ubuntu", "amd64", data_dir=self.tmp.name, root=True,
                                        log=lambda *a: None)
        self.dest = os.path.join(self.tmp.name, "models", "attack_mapper_run3")

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_source_set_is_a_clear_failure(self):
        with mock.patch.dict(manifest.MODEL, {"url": None, "sha256": None, "size": None}):
            with self.assertRaises(install.StepError) as err:
                self.worker.step_model(verify=lambda d: None, model_dir=self.dest)
        self.assertIn("not set yet", str(err.exception))

    def test_working_model_is_left_alone(self):
        os.makedirs(self.dest)
        for n in attack_mapper.REQUIRED_FILES:
            open(os.path.join(self.dest, n), "w").close()
        with mock.patch.dict(manifest.MODEL, {"url": None}):
            status, _ = self.worker.step_model(verify=lambda d: None, model_dir=self.dest)
        self.assertEqual(status, install.SKIPPED)

    def test_model_step_stops_early_without_torch(self):
        self.worker._run = lambda *a, **k: Proc(returncode=1)
        with mock.patch.object(model, "download_resume",
                               side_effect=AssertionError("must not download")):
            with self.assertRaises(install.StepError) as err:
                self.worker.step_model(model_dir=self.dest)
        self.assertIn("mapper packages", str(err.exception))

    def test_pip_noise_becomes_one_sentence(self):
        answers = iter([Proc(returncode=1), Proc(stdout="True\n"),
                        Proc(returncode=1, stderr="WARNING: Retrying ... ERROR: No matching")])
        self.worker._run = lambda *a, **k: next(answers)
        with self.assertRaises(install.StepError) as err:
            self.worker.step_mapper_packages()
        self.assertNotIn("WARNING", str(err.exception))
        self.assertIn("setup.log", str(err.exception))

    def test_pip_failures_name_the_cause(self):
        self.assertIn("memory", install.pip_failure("python failed (exit -9). Killed"))
        self.assertIn("disk is full", install.pip_failure("OSError: No space left on device"))
        self.assertIn("Python version", install.pip_failure("ERROR: No matching distribution"))
        self.assertIn("internet", install.pip_failure("Read timed out"))

    def test_torch_install_skips_the_pip_cache(self):
        calls = []
        answers = iter([Proc(returncode=1), Proc(stdout="True\n"), Proc(), Proc(), Proc()])
        def fake(cmd, **k):
            calls.append(cmd)
            return next(answers)
        self.worker._run = fake
        self.worker.step_mapper_packages()
        self.assertIn("--no-cache-dir", calls[2])
        self.assertIn("--no-cache-dir", calls[3])
        self.assertIn('transformers==5.20.2; python_version < "3.11"', calls[3])
        self.assertIn('transformers==5.22.1; python_version >= "3.11"', calls[3])

    def test_mapper_packages_refuse_system_python(self):
        answers = iter([Proc(returncode=1), Proc(stdout="False\n")])
        self.worker._run = lambda *a, **k: next(answers)
        with self.assertRaises(install.StepError) as err:
            self.worker.step_mapper_packages()
        self.assertIn("own Python environment", str(err.exception))


if __name__ == "__main__":
    unittest.main()
