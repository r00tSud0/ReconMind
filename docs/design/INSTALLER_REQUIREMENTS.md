# ReconMind installer and repair wizard
Status: approved product direction; **NOT implemented** in this preview.
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
