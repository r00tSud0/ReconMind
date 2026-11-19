"""
Download, check and install the SciBERT Run 3 ATT&CK mapper.

1. Download the release archive, resuming a partial download.
2. Check its exact byte size and SHA-256 against the manifest.
3. Extract into a temporary folder next to the model folder. Only regular
   files and folders under attack_mapper_run3/ are allowed: absolute paths,
   "..", links and device files make the whole archive rejected.
4. Load the extracted model in a separate process with a time limit, check it
   has the expected number of labels and run one small prediction.
5. Swap it into place. The previous folder is kept until the swap worked and
   is put back if anything fails.
"""

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

from reconmind.ai import attack_mapper
from reconmind.setup import manifest

VERIFY_TIMEOUT = 600
VERIFY_CODE = r"""
import json, sys
from reconmind.ai import attack_mapper
m = attack_mapper.load(sys.argv[1])
out = {"status": m.status, "labels": len(m.labels), "error": m.error}
if m.status == "ok":
    m.predict(["SMB signing is not required on the file server"])
    out["predicted"] = True
print(json.dumps(out))
"""


class ModelError(Exception):
    pass


def download_resume(url, dest, size, attempts=4, timeout=60,
                    opener=urllib.request.urlopen, sleep=time.sleep, progress=None):
    """Download url to dest, continuing a partial file with an HTTP Range
    request. Stops at size bytes; a server that ignores Range restarts it."""
    last = None
    for attempt in range(attempts):
        have = os.path.getsize(dest) if os.path.exists(dest) else 0
        if size and have > size:
            os.unlink(dest)
            have = 0
        if size and have == size:
            return
        request = urllib.request.Request(url)
        if have:
            request.add_header("Range", "bytes={h}-".format(h=have))
        try:
            with opener(request, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                mode = "ab" if have and status == 206 else "wb"
                total = have if mode == "ab" else 0
                with open(dest, mode) as out:
                    while True:
                        block = response.read(1 << 20)
                        if not block:
                            break
                        total += len(block)
                        if size and total > size:
                            raise ModelError("The download is larger than the published size.")
                        out.write(block)
                        if progress:
                            progress(total)
            if not size or os.path.getsize(dest) == size:
                return
            last = "the connection closed early"
        except ModelError:
            raise
        except urllib.error.HTTPError as exc:
            if exc.code == 416:  # range past the end: start over
                os.unlink(dest)
            last = exc
        except Exception as exc:
            last = exc
        if attempt + 1 < attempts:
            sleep(3 * (attempt + 1))
    raise ModelError("The model download did not finish after {n} tries: {e}".format(
        n=attempts, e=last))


def safe_extract(archive, dest_parent, folder):
    """Extract a .tar.gz that must hold only folder/... into a new temporary
    folder inside dest_parent. Returns the path of the extracted folder."""
    tmp = tempfile.mkdtemp(prefix=".model-", dir=dest_parent)
    try:
        with tarfile.open(archive, "r:gz") as t:
            members = t.getmembers()
            for m in members:
                name = m.name[2:] if m.name.startswith("./") else m.name
                parts = name.split("/")
                if (name.startswith("/") or ".." in parts or parts[0] != folder
                        or not (m.isfile() or m.isdir())):
                    raise ModelError("The model archive holds an unexpected entry: " + m.name)
            for m in members:
                name = m.name[2:] if m.name.startswith("./") else m.name
                target = os.path.join(tmp, *name.split("/"))
                if m.isdir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with t.extractfile(m) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                os.chmod(target, 0o644)
        extracted = os.path.join(tmp, folder)
        missing = [n for n in attack_mapper.REQUIRED_FILES
                   if not os.path.isfile(os.path.join(extracted, n))]
        if missing:
            raise ModelError("The model archive is missing: " + ", ".join(missing))
        return tmp, extracted
    except (tarfile.TarError, OSError, EOFError) as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ModelError("The model archive could not be read: {e}".format(e=exc)) from None
    except ModelError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def verify(directory, labels, python=None, run=subprocess.run, timeout=VERIFY_TIMEOUT):
    """Load the model in a child process and run one prediction. Returns the
    child's report; raises ModelError unless status is ok with labels labels."""
    import json
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        proc = run([python or sys.executable, "-c", VERIFY_CODE, directory], cwd=repo,
                   capture_output=True, text=True, timeout=timeout, check=False,
                   stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise ModelError("Loading the model took longer than {s} seconds.".format(
            s=timeout)) from None
    line = (proc.stdout or "").strip().splitlines()[-1:] or [""]
    try:
        report = json.loads(line[0])
    except ValueError:
        tail = (proc.stderr or "").strip().splitlines()[-2:]
        raise ModelError("The model check crashed. " + " ".join(tail)) from None
    if report.get("status") != "ok":
        raise ModelError("The model did not load: {s}. {e}".format(
            s=report.get("status"), e=report.get("error", "")).strip())
    if report.get("labels") != labels:
        raise ModelError("The model has {n} labels, expected {e}.".format(
            n=report.get("labels"), e=labels))
    if not report.get("predicted"):
        raise ModelError("The model loaded but could not make a prediction.")
    return report


def swap_in(new_dir, dest):
    """Move new_dir to dest. An existing dest is set aside first and put back
    if the move fails, then removed."""
    old = None
    if os.path.exists(dest):
        old = dest + ".old-" + time.strftime("%Y%m%d%H%M%S")
        os.replace(dest, old)
    try:
        os.replace(new_dir, dest)
    except OSError:
        if old:
            os.replace(old, dest)
        raise
    if old:
        shutil.rmtree(old, ignore_errors=True)
