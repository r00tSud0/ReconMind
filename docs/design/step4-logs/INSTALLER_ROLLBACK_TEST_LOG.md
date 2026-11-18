# Installer-first rollback verification

Scope: isolated ReconMind `frontend` preview, not user GitHub.

Changes:
- Removed the experimental selected-scanner warning from New Scan.
- Removed extra missing-reason descriptions and per-tool manual install
  commands from System; Ready/Missing health indicators remain.
- Preserved saved-key form language, connection feedback, and refresh on save.
- Added the approved installation-wizard requirements document; installer
  implementation remains future work.

Offline verification:
- `python -m unittest discover -s tests -q`: 1080 tests, OK.
- `node --test tests/test_system_ui_refinements.mjs tests/test_installer_first_ui.mjs`:
  2 tests, 2 passed.
- `node --check reconmind/web/static/js/views/system.js`: passed.
- `node --check reconmind/web/static/js/views/newscan.js`: passed.
- `python -m py_compile reconmind/web/system.py`: passed.
- Patch dry-run against the previous guidance ZIP: passed.

Not tested:
- A real-browser layout/interaction review after applying the patch.
- Any installation wizard, package installation, GitHub artifact download,
  API connection, model inference or live target scanning.

No Git commit or push. No code changes in user's local machine were performed.
