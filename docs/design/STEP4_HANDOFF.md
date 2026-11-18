# ReconMind Step 4 handoff for Claude Code review

## Project origin and isolation
Base: `ReconMind_frontend_Step4_progress.zip`, which was a separate copy of the
user's `frontend` branch plus the first Step 4 implementation. The local
GitHub repository was not accessed or changed. No git commands, commits,
pushes, scans, or live provider connection tests were executed.

## Implemented in the first Step 4 copy (retained)
- Code report: expandable saved findings, flagged snippet lines, tool version
  chips, report-wide AI explanation, and correct distinction between a
  finding-specific explanation and a report-wide summary.
- System check: installed tool names/versions, provider and model, key-state,
  ATT&CK model state, NVD key-state, scope, disk free. Check again refreshes.
- Clean missing-report and missing-scan states, existing problem-state UX.

## Implemented in this continuation
- `reconmind/web/settings.py`: validated AI provider/model and new key input;
  atomic local `.env` save with mode 0600 and symlink refusal. Preserves
  unrelated lines and other providers' keys. Empty key fields retain saved
  credentials; removal must be explicitly selected.
- On save, updates running process environment. The next scan child process
  inherits updated settings (consistent with agent `_load_dotenv` setdefault).
- `POST /api/system/save`: local guarded JSON route. Returns `{"saved":true}`
  or a safe error, never key values.
- `POST /api/system/test`: one small provider request with an 8-second timeout,
  no redirect forwarding of credentials, sanitized status, no scan. Custom
  RECONMIND_BASE_URL must be tested in CLI, never through the web page.
  DO NOT assume real external provider reachability was tested.
- System UI includes provider/model fields, secret input boxes, explicit
  remove-key controls, save/test buttons, status feedback, and keyboard labels.
  Never uses innerHTML or untrusted HTML. AI options cache invalidates on save.
- Code scans now capture up to 3 nearby source lines on either side of each
  finding *at scan time* as separate `display_context` fields. They are
  displayed locally with the flagged line(s) highlighted. The original
  `snippet` is unchanged and remains the only code fragment passed to the
  LLM in `reconmind/code/explain.py`; no source files are read on report view.
  Old reports continue using the existing snippet fallback. Input containment
  is checked with `resolve_reported` and `read_snippet`.

## Files changed relative to the first Step 4 copy
- `reconmind/web/settings.py` (new)
- `reconmind/web/server.py`
- `reconmind/web/system.py`
- `reconmind/web/static/js/api.js`
- `reconmind/web/static/js/app.js`
- `reconmind/web/static/js/views/system.js`
- `reconmind/web/static/js/views/report.js`
- `reconmind/web/static/css/app.css`
- `reconmind/code/code_scan.py`
- `reconmind/web/runs.py`
- `tests/test_system_settings.py` (new)
- `tests/test_code_context.py` (new)

## Verification
- `python3 -m unittest discover -s tests`: 1080 tests, OK
- `node --check`: all nine frontend JavaScript files, OK
- No real scan, no external provider call, no .env with user credentials.
- Live browser rendering and real provider connection were not verified.
  A headless browser attempt failed at environment startup, so it is NOT
  reported as a passed browser test.
- A spreadsheet-related warmup warning from the execution environment
  appeared before unittest; the unittest suite itself completed successfully.
- Read `docs/design/step4-logs/STEP4_TEST_LOG.txt` for exact test output.

## Suggested review tomorrow
1. Verify the `/api/system/save` route against the original intended UX,
   especially existing environment variable overrides and .env ownership.
2. Check model-specific connection probe compatibility for all providers.
3. Run System UI locally and verify responsive layout and Check again.
4. Confirm code contexts do not leak into LLM payloads (they are not in
   `reconmind/code/explain.py:finding_payload`).
5. Run scans only against the project's authorized lab networks, if needed
   for manual integration verification.
6. Preserve the three-mode AI plan (Off / AI analysis / AI agent), and the
   next MORVAIN-X0 human-approved agent phase, as separately planned.
7. Keep the user's final MORVAIN-X0 visual asset unchanged when integrating
   it into the working UI later.

## Known remaining work
- Full pixel-level review against `08_System.html` and `09_States.html` in a
  real browser with user screenshots.
- Real provider credentials/connection validation (explicit user action only).
- MORVAIN-X0 autonomous chat and agent choice/approval workflow is separate
  and not implemented in this Step 4 patch.

## System settings UX refinements (this follow-up, separate copy)
- `reconmind/web/static/js/views/system.js`: saved AI and NVD credentials
  now have clear Saved / Not saved labels and replacement-only input hints.
  The key itself is never displayed; changing providers never assumes another
  provider's key is saved. Ollama correctly shows No key required.
- Connection test feedback explicitly says nothing was saved. It does not
  modify settings or mark the model/key as configured.
- After a successful Save, the System page calls the existing GET /api/system,
  refreshes only the AI and NVD status sections, and preserves the settings
  form, current focus, and success message. The New Scan options cache is
  still invalidated. On refresh failure, Save reports that settings were saved
  but the status panel needs Check again; it does not pretend Save failed.
- `reconmind/web/static/css/app.css`: minor field-label/status layout styling.
- `tests/test_system_ui_refinements.mjs`: dependency-free fake DOM/API tests
  for tested-not-saved, save-and-refresh, secret handling, provider switching,
  and rejected Save, without live requests or browser dependencies.
- No changes to `reconmind/web/settings.py`, scan engine, model, authorization,
  or network scope. No Git commands or live scan execution were performed.

### Follow-up review checklist
- Test the System settings page visually in a real browser on the user's WSL
  preview, including keyboard focus, zoom, small screens, and status refresh.
- Run a real provider test only on user action, with a user's own key.
- Confirm System reports only file/dependency presence for Run 3; actual model
  inference was separately verified by the user with `load()` (status ok,
  394 labels, error None) in stable Python 3.11.
- Security tool provisioning belongs to the planned installer wizard, not
  the System/New Scan views. No setup wizard exists in this preview yet.
- MORVAIN-X0 human-approved autonomous agent is future work.

## Installer-first correction (after user review)
- Reverted the experimental scanner-availability patch: no selected-scanner
  warning on New Scan; no added per-tool missing-reason copy on System.
- Removed manual per-tool installation command strings from the System view.
  Tool Ready/Missing statuses remain diagnostics and core authorization and
  scan execution paths are unchanged.
- Preserved the saved-key and status-refresh refinements from the earlier patch.
- Added INSTALLER_REQUIREMENTS.md and updated the backlog so future development
  builds setup/repair instead of extending manual tool-install hints.
- This ZIP is an isolated preview, not a finished distributable. It has NO
  installation wizard yet. The exact GitHub large-file location for SciBERT
  must be confirmed before wiring automated download.
