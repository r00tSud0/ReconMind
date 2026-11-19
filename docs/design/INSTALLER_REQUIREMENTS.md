# ReconMind installer and repair wizard
Status: tools installer implemented as a command (`python3 -m reconmind.setup`).
Model download included. Setup screen and desktop packaging are not built yet.
For Claude Code handoff. Source of truth for the installer-first distribution.

## Product contract
A normal user should install ReconMind through a guided wizard, not manually
install scanners one-by-one on System or New Scan. Tool installation/repair
must be performed **only after user consent**, before first use, and never
triggered merely by opening an application screen.

Supported operating systems and packaging format must be selected from real
targets and tested. The current known development environment is Ubuntu/WSL;
do not claim Windows or macOS support without testing.

## Wizard sequence
1. Welcome and terms: explain that scans only work on systems the operator
   owns or is authorized to assess. Present disk/network/privilege requirements.
2. Preflight: OS, CPU architecture, network access, disk space, correct
   permissions, existing dependencies, executable PATH, and Python runtime.
3. Install packaged dependencies: use verified, pinned versions; install
   required scanners in a controlled order and record which ones were
   installed/updated. Distinguish ProjectDiscovery httpx from Python httpx.
   Respect system package manager locks and confirm before privileged actions.
4. Model retrieval: use a verified user-provided GitHub Releases asset or
   Git LFS object location for the SciBERT Run 3 model. Do not invent a URL.
   Download to temporary storage; validate artifact SHA-256, size and expected
   files; atomically install to models/attack_mapper_run3. Never execute files
   from an unverified archive. Avoid leaking URLs with tokens in logs.
5. Dependency setup: install the compatible Python interpreter and pinned
   model requirements in an isolated application environment. Run the model
   load test and one bounded local inference, verifying 394 technique labels.
6. Optional configuration: AI provider, model and API key. A third-party AI
   key should not be silently required for tools-only operation. Keep existing
   secret-handling rules and do not print/return key values.
7. Final verification: use the same discovery routines as the engine for
   nmap, searchsploit, ProjectDiscovery httpx, ffuf, nuclei, testssl.sh,
   enum4linux-ng, Semgrep, Bandit, and the required Python/model pieces.
   Confirm required tools actually execute; report version and check outcome.
   No scanning of any targets in the installer.
8. Success: offer Launch ReconMind only when all mandatory components are
   ready; otherwise show Install failed / Retry / Repair with an actionable
   error that does not fabricate successful coverage.

## Experience after installation
- New Scan remains focused on selecting plans and obtaining authorization.
  Do not reintroduce frequent missing-tool installation instructions.
- System summary reports detected tools without advising per-tool manual installation.
- System is a read-only health/status dashboard with Check again; failed tool
  checks point users to Repair Setup **once a real repair action exists**.
  Do not add buttons that do nothing.
- An interrupted or partial setup is never marked Complete.
- Existing authorization gates and safety limits are never bypassed, and
  the installer cannot modify allowed/blocked scan networks.

## GitHub model source and trust
- The uploaded model's filesystem name is `scibert_attack_mapper_run3`;
  ReconMind expects `models/attack_mapper_run3`.
- The right Run 3 asset exists in the user's supplied archives. Its intended
  hosted location was described as GitHub large-file storage, but the exact
  Releases/Git LFS repository path and release tag are NOT verified in
  the uploaded source or conversation.
- Define a versioned manifest with source URL/reference, SHA-256 digest,
  byte size, extracted paths, model revision and compatible requirements.
- For LFS, the installer must fetch actual content, not the small Git LFS
  pointer file. For Releases, use the versioned asset URL and verify its hash.
- Support partial-download retry and safe rollback of model files if validation
  or inference fails.

## Testing and review
- Test preflight, missing packages, cancellation, retries, privilege denied,
  wrong downloaded payload, checksum failure, interruptions, wrong architecture,
  offline mode and existing-install upgrades using fakes/mocks.
- Test a real install in a clean isolated Ubuntu/WSL environment separately.
- Confirm no API secrets or privileged information leak into logs.
- Record the full command/version manifest and how to uninstall/repair.
- Do not merge/push installer code before user and Claude review.

## Implemented: tools installer (milestone M1 plus M3, command line)
- `python3 -m reconmind.setup --check` runs preflight (OS, CPU, Python,
  disk, network, apt, sudo), shows the 9 tools as the engine sees them and the
  install plan. It changes nothing.
- `python3 -m reconmind.setup --install` asks once, then installs or repairs.
  Running it again skips what is already in place, so it is also the repair.
- Supported: Ubuntu, Debian and Kali (WSL included), 64 bit Intel/AMD and ARM.
  Anything else stops at preflight with "not supported yet".
- System packages, one sudo step: nmap, testssl.sh, dirb (wordlist),
  smbclient, samba-common-bin, git, python3-venv; on Kali also exploitdb,
  ffuf, nuclei, httpx-toolkit and enum4linux-ng.
- Ubuntu and Debian, no sudo: ffuf 2.3.0, nuclei 3.11.1 and ProjectDiscovery
  httpx 1.12.0 release binaries checked against pinned SHA-256 digests from
  each project's checksums file; Exploit-DB from GitLab (newest commit,
  logged); enum4linux-ng v1.3.10 at a pinned commit in its own venv.
- Everywhere: Semgrep 1.185.0 and Bandit 1.9.4 each in their own venv, Semgrep
  rules at the pinned commit, nuclei templates (official updater, else the
  pinned v10.5.2 release).
- Everything lives in `~/.local/share/reconmind/`. `reconmind/toolpath.py`
  puts its `bin/` first on PATH when the package is imported, so the CLI, the
  web app and scan child processes all find the tools.
- Never scans and never reads or writes the allow or deny lists
  (enforced by `tests/test_setup.py`).
- Verified for real on a clean Ubuntu 24.04 machine: 9 of 9 tools ready, a
  second run skipped every step, a local code scan ran Semgrep and Bandit.

## Implemented: model download (milestone M2)
- Source: GitHub Release `model-run3-v1` on r00tSud0/ReconMind, asset
  `attack_mapper_run3.tar.gz`, 409970311 bytes, SHA-256
  `6ce8ca961388546f8779a382e454b3775a3d5cddf4b6a812d5d1fdb4ad128a23`.
- Resumes an interrupted download, checks exact size and SHA-256, extracts only
  regular files under `attack_mapper_run3/` (no absolute paths, `..`, links),
  loads it in a child process with a 10 minute limit, requires 394 labels and
  one test prediction, then swaps it into `models/attack_mapper_run3` keeping
  the old folder until the swap worked.
- Installs torch (CPU), transformers 5.22.1 (5.20.2 on Python 3.10) and safetensors into ReconMind's own
  Python environment first when missing; refuses the system Python.
- A working installed model is checked and left alone, so rerunning is safe.
