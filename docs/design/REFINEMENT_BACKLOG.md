# ReconMind refinement backlog (separate preview copy)

This list is for Claude Code review. It has not been merged, committed or
pushed to the user's GitHub repository.

## Implemented and tested
- [x] Saved AI/NVD keys show clear Saved / Not saved state without revealing values.
- [x] Saving refreshes the relevant System statuses without a manual Check again.
- [x] Test connection clearly distinguishes a successful test from saving.
- [x] Preserved the existing scanner readiness checks in System.
- [x] Reverted extra scanner-install explanations and New Scan unavailable-tool
      notices from the recent experimental tool-guidance patch.
- [x] Removed manual per-tool install commands from the System UI. The System
      panel is diagnostic, not an installer.
- [x] Preserved authorization, scan plan, and core tool execution behavior.

## Product requirement: installer-first distribution
- [ ] Build a guided installation and repair wizard that provisions all required
      scanning executables and compatible Python dependencies before normal use.
- [ ] Retrieve the fine-tuned SciBERT Run 3 model weights and metadata from the
      user's configured GitHub large-file location (Releases or Git LFS).
      The exact repository/asset URL and artifact checksum must be verified.
- [ ] Verify tools using the same binary-resolution rules as the engine.
- [ ] Perform bounded local SciBERT inference verification during setup.
- [ ] Present installation errors with retry/repair, rather than presenting
      ongoing manual installation instructions inside New Scan.
- [ ] Provide an offline/mock integration test of installer progress, failure,
      retry and idempotent reruns.
- [ ] Only report setup Complete after mandatory checks pass.

## Still pending
- [ ] Verify System and New Scan in the user's live browser.
- [ ] Complete Step 4 problem states and model readiness workflow.
- [ ] Off / AI analysis / AI agent modes and MORVAIN-X0 human-approved agent.
- [ ] Authorized-lab end-to-end scan testing, when safe and explicitly requested.

See docs/design/INSTALLER_REQUIREMENTS.md for the detailed installer contract.
