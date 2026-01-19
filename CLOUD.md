# CLOUD.md — Enterprise Release Candidate 2026 Runbook

## A) Quickstart (local static run)
1. Start a local static server in repo root:
   - `python3 -m http.server 8080`
2. Open:
   - `http://localhost:8080/`
3. Optional: open the smoke harness:
   - `http://localhost:8080/tests/smoke.test.html`

## B) Security model summary (light threat model)
**Assets**
- BYOK API keys (sensitive).
- Local cases/logs (business data).
- UI integrity (single-file app).

**Entry points**
- User input (objection, store policy).
- Import JSON (settings/cases/logs).
- Remote library sync (`library.json`).
- Network calls to AI providers.

**Threats**
- XSS via imported content.
- Supply chain tampering of library data.
- CSP bypass via unsafe-inline.
- Key exposure via DOM/logs.
- Proxy abuse / exfiltration.

**Mitigations**
- `escapeHTML` for dynamic inserts.
- Schema validation + sanitization on import.
- SHA-256 integrity check for library sync.
- CSP Level 1 (local) & Level 2 (hash-based).
- Same-origin proxy restriction + no key logs.
- BYOK passphrase lock via AES-GCM.

## C) Testing steps (manual + regression)
### Manual Smoke Tests (UI)
1. Theme toggle (header): auto → light → dark; verify label updates.
2. Density toggle (header): compact ↔ comfort; verify spacing changes.
3. Settings modal opens/closes via button + Esc.
4. Focus returns to trigger after modal close.
5. Expanders open/close via click + keyboard.
6. Offline banner shows on offline event.
7. Sync status updates (idle → syncing → ok/error).
8. Export/Import flow: confirm sheet appears, import invalid JSON fails with toast.
9. Diagnostics panel (Ctrl+Shift+I): shows theme/density/online/dbReady/CSP.

### Automated Smoke Harness
Open `tests/smoke.test.html` and run:
- In-browser tests with PASS/FAIL UI.
- No external dependencies.

## D) Device matrix
**iOS**
- Safari 17+ (iPhone / iPad)

**Android**
- Chrome latest
- Samsung Internet latest

**Desktop**
- Chrome latest
- Edge latest
- Firefox latest
- Safari macOS latest

## E) Accessibility checklist (WCAG 2.2 AA)
- Keyboard-only navigation for all controls.
- Visible focus ring on all focusable elements.
- Tap targets ≥ 44px.
- Modal focus trap + focus restore.
- `aria-expanded` and `aria-controls` on expanders.
- `aria-live` for status/toast.
- `prefers-reduced-motion` respected.

## F) Performance checklist (Core Web Vitals)
- LCP < 2.5s on mid-tier mobile.
- INP < 200ms on main interactions.
- CLS < 0.1 (stable layout).
- Avoid heavy blur/shadows on low-end devices.
- Passive listeners for viewport handling.

## G) Release Gates (Go/No-Go)
**Go if:**
- CSP Level 2 hashes validated in deployed build.
- Smoke harness shows PASS for all critical tests.
- Manual checks across device matrix pass.
- No console errors on load.
- Import/export rejects invalid JSON.
- Offline banner and sync states behave correctly.

**No-Go if:**
- Any CSP violations block core functionality.
- Focus trap fails or keyboard navigation breaks.
- Integrity hash mismatch on library sync.
- Unhandled errors on open/submit/import.

## H) Incident fallback plan
1. If CSP blocks scripts/styles:
   - Temporarily revert to CSP Level 1 (with `'unsafe-inline'`) for hotfix.
   - Recompute hashes and redeploy with Level 2.
2. If library integrity check fails:
   - Pause sync (offline mode).
   - Restore last known-good `library.json`.
3. If API calls fail:
   - Ensure proxy URL is same-origin.
   - Validate provider and model settings.
   - Use local seed responses temporarily.

## I) CSP Level 1 vs Level 2 (hash-based)
### Level 1 (Local Copy/Paste)
Use inline scripts and styles with `'unsafe-inline'`:
```
Content-Security-Policy: default-src 'none'; base-uri 'self'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://api.openai.com https://api.groq.com; frame-ancestors 'none'; object-src 'none';
```

### Level 2 (Enterprise Deployed)
Remove `'unsafe-inline'` and add hashes for inline CSS/JS:
```
Content-Security-Policy: default-src 'none'; base-uri 'self'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'sha256-<STYLE_HASH>'; script-src 'self' 'sha256-<SCRIPT_HASH>'; connect-src 'self' https://api.openai.com https://api.groq.com; frame-ancestors 'none'; object-src 'none';
```

**Hash generation steps (from `index.html`):**
1. Run this in repo root:
   - `python3 - <<'PY'`
   - `import base64,hashlib,re`
   - `text=open('index.html','r',encoding='utf-8').read()`
   - `style=re.search(r'<style>\\n([\\s\\S]*?)\\n\\s*</style>',text).group(1)`
   - `script=re.search(r'<script>\\n([\\s\\S]*?)\\n\\s*</script>',text).group(1)`
   - `print('STYLE', base64.b64encode(hashlib.sha256(style.encode()).digest()).decode())`
   - `print('SCRIPT', base64.b64encode(hashlib.sha256(script.encode()).digest()).decode())`
   - `PY`
2. Replace `<STYLE_HASH>` and `<SCRIPT_HASH>` in CSP.

**Alternative packaging (optional):**
- Move inline CSS/JS to external files and set:
  - `style-src 'self'`
  - `script-src 'self'`
