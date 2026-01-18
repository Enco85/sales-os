BLOCK 1: Executive Summary + Findings

1. Executive Summary (max 10 bullets)
- Critical Blocker: CSP fehlte komplett (default allow). Jetzt Level 1/2 CSP mit Hash-Plan und Default-Deny umgesetzt.
- Größtes Security Risiko: Ungepinnter Remote-Sync ohne Integrität. Jetzt Same-Origin + SHA-256 Integrity Lock.
- Größtes Data Integrity Risiko: BYOK Key ungeschützt + Import ohne Schema. Jetzt Passphrase-Lock + Sanitizing.
- Größtes A11y Risiko: Expanders/Modal ohne ARIA und Fokus-Management. Jetzt Buttons, ARIA, Fokusfalle.
- Größter Performance Bottleneck: Animations/Shadow ohne Reduced-Motion. Jetzt reduziertes Motion-System.
- Größter UX Trust Gap: Offline/Sync und Destruction unsichtbar. Jetzt Banner, Sync-Status, Confirm Sheet.
- Design Modernization Blocker: Keine Tokens + List-Layout + externe Fonts. Jetzt Token-first Bento + System-Fonts.
- Platform Risk iOS: Keyboard-Overlay + 100vh-Drop. Jetzt dvh + VisualViewport + Safe-Area.
- Platform Risk Android: Back-Button schließt Modal nicht, History-Spam. Jetzt Modal-Stack + Popstate.
- Platform Risk Desktop: Keine Density + inkonsistente Hover/Fokus. Jetzt Density Toggle + Focus Ring.

2. Findings Register Tabelle
| ID | Kategorie | Severity | Typ | Stelle | Kurzbeschreibung |
| --- | --- | --- | --- | --- | --- |
| F-01 | Security | Critical | CSP | `index.html` `<head>` | CSP fehlte, inline Ausführung erlaubt. |
| F-02 | Security | High | Supply Chain | `syncLibrary()` | Ungepinnter Remote-Sync ohne Integrität. |
| F-03 | Data Integrity | High | Storage | Settings/Import/Export | BYOK Key ungeschützt, Import/Export ohne Schema. |
| F-04 | Accessibility | High | ARIA/Keyboard | Expanders/Modals | Keine ARIA/Focus Trap, nicht keyboard-safe. |
| F-05 | UX Trust | High | State/Confirm | Header/Modals | Offline/Sync unsichtbar, destructive Actions ohne Sheet. |
| F-06 | Performance | Medium | Motion | CSS/Animations | Keine Reduced-Motion Strategie, schwere Shadows. |
| F-07 | iOS | Medium | Viewport | Control Bar/Layout | Keyboard-Overlay + 100vh Bugs. |
| F-08 | Android | Medium | Navigation | Modal History | Back-Button ignoriert, Risiko für History-Spam. |
| F-09 | Design System | Medium | Tokens/Layout | Global | Keine Tokens, kein Bento, keine Density/Theme Toggle. |

3. Deep Dive je Finding

F-01 – CSP fehlt (Critical)
Root Cause: Kein CSP gesetzt, inline Styles/Scripts unkontrolliert.
Impact: XSS/Injection kann direkt laufen, Supply-Chain Schutz fehlt.
Repro Steps: App laden → Developer Tools → Inline Script/Style möglich.
Fix: CSP Level 1 (local) + Level 2 Hashes dokumentiert. Default-Deny.
Patch Snippet (copy paste ready):
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'self'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://api.openai.com https://api.groq.com; frame-ancestors 'none'; object-src 'none';">
<!-- CSP Level 2 (Enterprise, hash-based, no unsafe-inline):
     Content-Security-Policy: default-src 'none'; base-uri 'self'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'sha256-DfpShdlp4EVLA30rFHv1hJT4U1scXYSZsGgjcQh540U='; script-src 'self' 'sha256-sx0jgiuSguIPgxrujv4zWxp4Siu19SQLZwyb3jkKxeE='; connect-src 'self' https://api.openai.com https://api.groq.com; frame-ancestors 'none'; object-src 'none';
     Hash calculation details: see REPORT.md
-->
Regression Risk: Niedrig (nur CSP-Tuning).
Test Cases: CSP kopieren, Seite neu laden, API Calls ok.
Device Matrix Coverage: iOS Safari 17+, Android Chrome/Samsung, Desktop Chrome/Edge/Firefox/Safari.

F-02 – Supply Chain ohne Integrität (High)
Root Cause: Raw GitHub Sync ohne Pin/Hash.
Impact: Manipulierte JSONs können Verhalten ändern.
Repro Steps: Offline/Online wechseln → Sync pullt unverified data.
Fix: Same-Origin `library.json` + SHA-256 Integrity Lock.
Patch Snippet (copy paste ready):
const LIBRARY_URL = "./library.json";
const LIBRARY_SHA256 = "pM/qq9A97C8i/Bgtyx2UG/8gtFdRzlangPRZbIYFbUQ=";
async function verifyLibraryHash(buffer) {
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashBase64 = btoa(String.fromCharCode(...hashArray));
    return hashBase64 === LIBRARY_SHA256;
}
Regression Risk: Mittel (Sync-Quelle geändert).
Test Cases: Sync bei Online, Integrity Fail simulieren.
Device Matrix Coverage: iOS Safari 17+, Android Chrome/Samsung, Desktop.

F-03 – BYOK Key + Import ohne Schutz (High)
Root Cause: Klartext-Key und ungeprüfter Import.
Impact: Key-Leak, Datenkorruption.
Repro Steps: Settings öffnen, Key speichern; Import einer invalid JSON.
Fix: Passphrase Lock (AES-GCM), Schema/Sanitize Import.
Patch Snippet (copy paste ready):
async function encryptSecret(secret, passphrase) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const keyMaterial = await window.crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    const key = await window.crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const cipher = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(secret));
    return { cipher: btoa(String.fromCharCode(...new Uint8Array(cipher))), iv: btoa(String.fromCharCode(...iv)), salt: btoa(String.fromCharCode(...salt)) };
}
Regression Risk: Mittel (Crypto API abhängig).
Test Cases: Lock aktivieren, Unlock mit falscher Passphrase, Import valid/invalid.
Device Matrix Coverage: iOS Safari 17+, Android Chrome/Samsung, Desktop.

F-04 – A11y Expanders/Modals (High)
Root Cause: Div-Trigger ohne ARIA, Modal ohne Fokusfalle.
Impact: Screen Reader/Keyboard unbedienbar.
Repro Steps: Tab-Navigation → Expanders nicht erreichbar.
Fix: Button-Trigger + aria-expanded + Focus Trap.
Patch Snippet (copy paste ready):
<button class="expand-trigger" type="button" aria-expanded="false" aria-controls="smart-123" data-target="smart-123">Smart Script</button>
<div class="expand-content" id="smart-123" hidden>...</div>
function trapFocus(modal) {
    const focusable = modal.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    modal._focusHandler = (event) => { if (event.key === "Tab" && event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); } };
    modal.addEventListener("keydown", modal._focusHandler);
}
Regression Risk: Niedrig.
Test Cases: Tab/Shift+Tab, ESC closes, SR announces expanders.
Device Matrix Coverage: iOS Safari 17+, Android Chrome/Samsung, Desktop.

F-05 – Offline/Sync und Destruction (High)
Root Cause: Keine sichtbaren Sync-States, native confirm-only.
Impact: Trust-Loss, Datenverlust-Risiko.
Repro Steps: Offline gehen, Sync starten, Clear drücken.
Fix: Offline-Banner + Sync-Indikator + Confirm Sheet.
Patch Snippet (copy paste ready):
<div class="offline-banner" id="offlineBanner" role="status" aria-live="polite">Offline – Lokale Daten aktiv. Sync pausiert.</div>
async function confirmAction({ title, message, confirmLabel }) { /* modal confirm */ }
Regression Risk: Niedrig.
Test Cases: Offline switch, Sync, Clear mit confirm.
Device Matrix Coverage: iOS Safari 17+, Android Chrome/Samsung, Desktop.

F-06 – Motion/Performance (Medium)
Root Cause: Animationen ohne Reduced Motion.
Impact: Motion-Sickness, Perf-Drop.
Repro Steps: Reduce Motion aktivieren → Animationen bleiben.
Fix: Reduced-Motion CSS.
Patch Snippet (copy paste ready):
@media (prefers-reduced-motion: reduce) {
    * { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; scroll-behavior: auto !important; }
}
Regression Risk: Niedrig.
Test Cases: OS Reduce Motion toggeln.
Device Matrix Coverage: iOS Safari 17+, Android Chrome/Samsung, Desktop.

F-07 – iOS Keyboard/Viewport (Medium)
Root Cause: Kein VisualViewport Handling.
Impact: Input verdeckt, Scroll-Jank.
Repro Steps: iOS Safari → Keyboard öffnen.
Fix: VisualViewport Offset + dvh.
Patch Snippet (copy paste ready):
function setupViewportHandling() {
    const update = () => {
        const offset = Math.max(0, window.innerHeight - window.visualViewport.height - window.visualViewport.offsetTop);
        document.documentElement.style.setProperty("--keyboard-offset", `${Math.round(offset)}px`);
    };
    window.visualViewport.addEventListener("resize", update, { passive: true });
    window.visualViewport.addEventListener("scroll", update, { passive: true });
}
Regression Risk: Niedrig.
Test Cases: Keyboard open/close on iOS Safari.
Device Matrix Coverage: iOS Safari 17+.

F-08 – Android Back/History (Medium)
Root Cause: Kein popstate Handling.
Impact: Back button exit statt Modal close.
Repro Steps: Android Back bei offenem Modal.
Fix: Modal Stack + Popstate.
Patch Snippet (copy paste ready):
const modalStack = [];
window.addEventListener("popstate", () => {
    const activeModalId = modalStack[modalStack.length - 1];
    if (activeModalId) closeModal(document.getElementById(activeModalId), true);
});
Regression Risk: Niedrig.
Test Cases: Back Button bei Modal offen.
Device Matrix Coverage: Android Chrome/Samsung.

F-09 – Design Tokens/Bento/Density (Medium)
Root Cause: Hardcoded Styles + List Layout.
Impact: Kein 2026 Enterprise Look & Feel.
Repro Steps: UI öffnen → kein Bento, keine Density/Theme toggle.
Fix: Token-first Bento + Header toggles.
Patch Snippet (copy paste ready):
:root { --color-bg: #F3F4F6; --color-accent: #E3000F; --shadow-2: 0 8px 24px rgba(0,0,0,0.08); }
<div class="bento-grid">...</div>
<button class="toggle-btn" id="densityToggleBtn" type="button">Dichte: Kompakt</button>
Regression Risk: Niedrig.
Test Cases: Theme/Density toggles, Bento layout responsive.
Device Matrix Coverage: iOS/Android/Desktop.

4. 2026 DESIGN UPGRADE SPEC
A) Token System vollständige Liste
- Typography: `--font-sans`, `--font-mono`, `--font-size-base`
- Spacing: `--space-1`..`--space-8`
- Radius: `--radius-1`, `--radius-2`, `--radius-3`, `--radius-pill`
- Shadows: `--shadow-1`, `--shadow-2`, `--shadow-3`
- Backgrounds/Surfaces: `--color-bg`, `--color-surface`, `--color-elevated`
- Borders/Dividers: `--color-border`, `--color-divider`
- Text: `--color-text-primary`, `--color-text-secondary`, `--color-text-muted`
- Accent/States: `--color-accent`, `--color-danger`, `--color-warning`, `--color-success`
- Glass: `--color-glass`, `--color-glass-border`
- Focus Ring: `--color-focus`, `--outline-offset`
- Interaction: `--color-hover`, `--color-pressed`, `--color-selection`
- Toast: `--color-toast`, `--color-toast-text`
- Skeleton: `--color-skeleton-base`, `--color-skeleton-shine`
- Scrollbar: `--color-scrollbar-thumb`, `--color-scrollbar-track`
- Backdrop: `--color-backdrop`
- Density: `--tile-padding`, `--control-bar-padding`, `--input-height`
- Tap Target: `--tap-min`
- Motion: `--easing-standard`, `--duration-fast`, `--duration-medium`, `--duration-slow`
- Safe Area: `--safe-top`, `--safe-bottom`, `--safe-left`, `--safe-right`
- Keyboard Offset: `--keyboard-offset`
- Control Bar Height: `--control-bar-height`

B) Theme Toggle Spec Auto/Light/Dark + Persistenz
- Modes: Auto (prefers-color-scheme), Light, Dark.
- Header Quick Toggle cycles Auto → Light → Dark.
- Settings Segmented Control mirrors and persists.
- Auto listens to OS theme changes.

C) Density Toggle Spec Compact/Comfortable
- Default: Mobile Comfort, Desktop Kompakt.
- Header Quick Toggle, Settings Segmented Control.
- Persisted with `densityUserSet` to avoid jitter.

D) Component Craft Upgrade
- Header: Glass HUD bar, status pill, sync icon, theme/density toggles.
- Bento Grid: 1/2/3/4 columns, tile spans, density-aware spacing.
- Cards: Tokenized status accent, expandable sections, coach blocks.
- Chips: `aria-pressed`, 44px min tap, active accent styling.
- Modal: focus trap, alertdialog confirm sheet, overlay click close.
- Toast: queued, no overlap, `role="status"`.
- Input + Mic: keyboard submit, mic safe state, busy lock.
- Loading skeleton: stable shimmer, reduce motion aware.
- Empty state: clear action prompt, consistent typography.
- Error state: fallback to Joker card + toast.
- Sync/Offline indicator: banner + tile + header pill.

E) Motion and Interaction Spec
- Single easing curve `--easing-standard`.
- Reduced motion fully respected.
- Hover/Pressed tokens, no excessive blur.

F) iOS Spec
- Safe area via `env()` tokens.
- dvh layout, VisualViewport keyboard handling.
- Overscroll containment.

G) Android Spec
- dvh for dynamic toolbar.
- Back button closes modal via popstate.
- Vibration optional and safe.

H) Desktop Spec
- Hover states enabled.
- Density default compact.
- Keyboard shortcuts documented.
- Scrollbar styling subtle.

I) A11y Spec
- Focus ring visible on all controls.
- Tap targets >= 44px.
- ARIA expanded/controls on expanders.
- Modal focus trap + restore focus on close.
- Keyboard navigation on chips, buttons, modals.
- `prefers-reduced-motion` enforced.

5. FINAL PATCHSET Pflicht
PATCH HTML, CSS, JS vollständig in BLOCK 2–4.

6. Testing
How to run:
- Local server: `python3 -m http.server 8080`
- App: `http://localhost:8080/`
- Smoke harness: `http://localhost:8080/tests/smoke.test.html`
Manual checks:
- Theme/Density toggles + persistence
- Modal open/close + focus return
- Offline banner + Sync states
- Import invalid JSON -> toast error

7. Release Recommendation
GO if:
- CSP Level 2 (hashes) activated in production.
- Smoke harness passes without FAIL.
- Manual checks pass on device matrix.
NO-GO if:
- CSP blocks core runtime.
- Focus/keyboard regressions exist.
- Sync integrity fails for `library.json`.

8. Known limitations
- Offline test mock may warn if `navigator.onLine` is non-configurable in the test browser.
- Web Speech API support varies by device/browser.
- CSP Level 2 hashes must be regenerated after any inline change.

9. Quellen
Siehe BLOCK 5.

10. Trust Score
Trust Score: 4/5 (automated smoke harness exists, manual QA pending).

BLOCK 2: PATCH HTML komplett
```html
<!DOCTYPE html>
<html lang="de" data-theme="light" data-density="comfortable" data-debug="false">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="color-scheme" content="light dark">
    <meta name="theme-color" content="#F3F4F6" id="themeColorMeta">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'self'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://api.openai.com https://api.groq.com; frame-ancestors 'none'; object-src 'none';">
    <!-- CSP Level 2 (Enterprise, hash-based, no unsafe-inline):
         Content-Security-Policy: default-src 'none'; base-uri 'self'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'sha256-DfpShdlp4EVLA30rFHv1hJT4U1scXYSZsGgjcQh540U='; script-src 'self' 'sha256-sx0jgiuSguIPgxrujv4zWxp4Siu19SQLZwyb3jkKxeE='; connect-src 'self' https://api.openai.com https://api.groq.com; frame-ancestors 'none'; object-src 'none';
         Hash calculation details: see REPORT.md
    -->
    <title>MEHIC SALES OS — Enterprise RC 2026</title>
    <style>
        *,
        *::before,
        *::after {
            box-sizing: border-box;
        }

        html {
            height: 100%;
            text-size-adjust: 100%;
        }

        :root {
            --font-sans: system-ui, -apple-system, "SF Pro Text", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
            --font-mono: ui-monospace, "SF Mono", Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;

            --color-bg: #F3F4F6;
            --color-surface: #FFFFFF;
            --color-elevated: #FFFFFF;
            --color-border: rgba(0, 0, 0, 0.06);
            --color-divider: rgba(0, 0, 0, 0.08);
            --color-text-primary: #111827;
            --color-text-secondary: #6B7280;
            --color-text-muted: #9CA3AF;
            --color-accent: #E3000F;
            --color-danger: #DC2626;
            --color-warning: #F59E0B;
            --color-success: #10B981;
            --color-glass: rgba(255, 255, 255, 0.72);
            --color-glass-border: rgba(255, 255, 255, 0.35);
            --color-focus: rgba(227, 0, 15, 0.35);
            --color-selection: rgba(227, 0, 15, 0.18);
            --color-hover: rgba(17, 24, 39, 0.04);
            --color-pressed: rgba(17, 24, 39, 0.08);
            --color-toast: #111827;
            --color-toast-text: #FFFFFF;
            --color-skeleton-base: #E5E7EB;
            --color-skeleton-shine: #F3F4F6;
            --color-scrollbar-thumb: rgba(17, 24, 39, 0.25);
            --color-scrollbar-track: rgba(17, 24, 39, 0.08);
            --color-backdrop: rgba(0, 0, 0, 0.6);

            --shadow-1: 0 1px 2px rgba(0, 0, 0, 0.06);
            --shadow-2: 0 8px 24px rgba(0, 0, 0, 0.08);
            --shadow-3: 0 20px 48px rgba(0, 0, 0, 0.12);

            --radius-1: 10px;
            --radius-2: 14px;
            --radius-3: 18px;
            --radius-pill: 999px;

            --space-1: 4px;
            --space-2: 8px;
            --space-3: 12px;
            --space-4: 16px;
            --space-5: 20px;
            --space-6: 24px;
            --space-7: 32px;
            --space-8: 40px;

            --tap-min: 44px;
            --font-size-base: 16px;
            --tile-padding: 24px;
            --control-bar-padding: 20px;
            --input-height: 54px;

            --easing-standard: cubic-bezier(0.2, 0.8, 0.2, 1);
            --duration-fast: 120ms;
            --duration-medium: 240ms;
            --duration-slow: 360ms;
            --outline-offset: 2px;

            --safe-top: env(safe-area-inset-top);
            --safe-bottom: env(safe-area-inset-bottom);
            --safe-left: env(safe-area-inset-left);
            --safe-right: env(safe-area-inset-right);

            --keyboard-offset: 0px;
            --control-bar-height: 140px;
        }

        html[data-theme="dark"] {
            --color-bg: #09090B;
            --color-surface: #18181B;
            --color-elevated: #1F1F23;
            --color-border: #27272A;
            --color-divider: rgba(255, 255, 255, 0.08);
            --color-text-primary: #FAFAFA;
            --color-text-secondary: #A1A1AA;
            --color-text-muted: #71717A;
            --color-accent: #E3000F;
            --color-danger: #F43F5E;
            --color-warning: #FBBF24;
            --color-success: #34D399;
            --color-glass: rgba(24, 24, 27, 0.7);
            --color-glass-border: rgba(255, 255, 255, 0.08);
            --color-focus: rgba(227, 0, 15, 0.45);
            --color-selection: rgba(227, 0, 15, 0.28);
            --color-hover: rgba(250, 250, 250, 0.06);
            --color-pressed: rgba(250, 250, 250, 0.12);
            --color-toast: #F8FAFC;
            --color-toast-text: #0B0B0D;
            --color-skeleton-base: #27272A;
            --color-skeleton-shine: #1F1F23;
            --color-scrollbar-thumb: rgba(250, 250, 250, 0.25);
            --color-scrollbar-track: rgba(250, 250, 250, 0.08);

            --shadow-1: 0 1px 2px rgba(0, 0, 0, 0.4);
            --shadow-2: 0 10px 30px rgba(0, 0, 0, 0.5);
            --shadow-3: 0 24px 60px rgba(0, 0, 0, 0.6);
        }

        html[data-density="compact"] {
            --tile-padding: 18px;
            --control-bar-padding: 16px;
            --font-size-base: 14px;
            --input-height: 46px;
        }

        html[data-density="comfortable"] {
            --tile-padding: 24px;
            --control-bar-padding: 20px;
            --font-size-base: 16px;
            --input-height: 54px;
        }

        body {
            margin: 0;
            font-family: var(--font-sans);
            font-size: var(--font-size-base);
            line-height: 1.6;
            font-variant-numeric: tabular-nums;
            background: var(--color-bg);
            color: var(--color-text-primary);
            -webkit-font-smoothing: antialiased;
            text-rendering: optimizeLegibility;
            overflow-x: hidden;
            min-height: 100dvh;
            display: flex;
            flex-direction: column;
        }

        ::selection {
            background: var(--color-selection);
        }

        a {
            color: inherit;
        }

        button,
        input,
        select,
        textarea {
            font: inherit;
            color: inherit;
        }

        button {
            background: none;
            border: none;
            padding: 0;
            cursor: pointer;
            touch-action: manipulation;
        }

        button:disabled,
        input:disabled,
        select:disabled,
        textarea:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        button:focus-visible,
        input:focus-visible,
        select:focus-visible,
        textarea:focus-visible,
        a:focus-visible,
        [tabindex="0"]:focus-visible {
            outline: 2px solid transparent;
            box-shadow: 0 0 0 3px var(--color-focus);
            outline-offset: var(--outline-offset);
        }

        .skip-link {
            position: absolute;
            left: -999px;
            top: 0;
            background: var(--color-accent);
            color: #FFFFFF;
            padding: var(--space-2) var(--space-4);
            border-radius: var(--radius-2);
            z-index: 5000;
        }

        .skip-link:focus {
            left: var(--space-4);
            top: calc(var(--space-4) + var(--safe-top));
        }

        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            border: 0;
        }

        .header {
            position: sticky;
            top: 0;
            z-index: 200;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: var(--space-4);
            padding: calc(var(--space-4) + var(--safe-top)) calc(var(--space-6) + var(--safe-right)) var(--space-4) calc(var(--space-6) + var(--safe-left));
            background: var(--color-glass);
            border-bottom: 1px solid var(--color-divider);
            box-shadow: var(--shadow-1);
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
        }

        .logo-container {
            display: flex;
            align-items: center;
            gap: var(--space-3);
        }

        .logo-svg {
            width: 44px;
            height: 44px;
        }

        .logo-text {
            font-size: 18px;
            font-weight: 800;
            letter-spacing: -0.3px;
            color: var(--color-text-primary);
        }

        .logo-text span {
            font-weight: 300;
            color: var(--color-text-secondary);
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: var(--space-2);
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            padding: 6px 12px;
            border-radius: var(--radius-pill);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            min-height: var(--tap-min);
        }

        .status-pill[data-status="online"] .status-dot {
            background: var(--color-success);
        }

        .status-pill[data-status="offline"] .status-dot {
            background: var(--color-danger);
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }

        .dept-badge {
            padding: 6px 12px;
            border-radius: var(--radius-pill);
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            background: var(--color-accent);
            color: #FFFFFF;
            min-height: var(--tap-min);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--shadow-1);
        }

        .toggle-btn {
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            padding: 8px 12px;
            border-radius: var(--radius-pill);
            border: 1px solid var(--color-border);
            background: var(--color-surface);
            min-height: var(--tap-min);
            transition: background var(--duration-fast) var(--easing-standard), border var(--duration-fast) var(--easing-standard);
        }

        .toggle-btn:hover {
            background: var(--color-hover);
        }

        .toggle-btn:active {
            background: var(--color-pressed);
        }

        .toggle-btn svg {
            width: 18px;
            height: 18px;
            stroke: var(--color-text-primary);
            fill: none;
            stroke-width: 2;
        }

        .toggle-label {
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            color: var(--color-text-secondary);
            white-space: nowrap;
        }

        .icon-btn {
            width: var(--tap-min);
            height: var(--tap-min);
            border-radius: var(--radius-2);
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: transform var(--duration-fast) var(--easing-standard), background var(--duration-fast) var(--easing-standard);
        }

        .icon-btn:hover {
            background: var(--color-hover);
        }

        .icon-btn:active {
            transform: scale(0.98);
            background: var(--color-pressed);
        }

        .icon-btn svg {
            width: 18px;
            height: 18px;
            stroke: var(--color-text-primary);
            fill: none;
            stroke-width: 2.2;
            stroke-linecap: round;
            stroke-linejoin: round;
        }

        .offline-banner {
            display: none;
            align-items: center;
            justify-content: center;
            gap: var(--space-2);
            padding: var(--space-2) var(--space-4);
            background: rgba(220, 38, 38, 0.12);
            color: var(--color-danger);
            font-weight: 700;
            font-size: 13px;
            letter-spacing: 0.3px;
            border-bottom: 1px solid var(--color-divider);
        }

        .offline-banner.show {
            display: flex;
        }

        .stage {
            flex: 1;
            overflow-y: auto;
            padding: var(--space-6);
            padding-bottom: calc(var(--control-bar-height) + var(--keyboard-offset) + var(--space-6) + var(--safe-bottom));
            overscroll-behavior: contain;
        }

        .bento-grid {
            display: grid;
            gap: var(--space-5);
            grid-template-columns: 1fr;
        }

        .tile {
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-3);
            padding: var(--tile-padding);
            box-shadow: var(--shadow-1);
            position: relative;
        }

        .tile.glass {
            background: var(--color-glass);
            border: 1px solid var(--color-glass-border);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
        }

        .tile-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: var(--space-3);
            margin-bottom: var(--space-4);
        }

        .tile-title {
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-secondary);
        }

        .tile-subtitle {
            font-size: 20px;
            font-weight: 800;
            color: var(--color-text-primary);
            margin-top: var(--space-2);
        }

        .tile-desc {
            font-size: 14px;
            color: var(--color-text-secondary);
        }

        .stat-grid {
            display: grid;
            gap: var(--space-4);
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
        }

        .stat {
            display: flex;
            flex-direction: column;
            gap: var(--space-1);
        }

        .stat-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-muted);
            font-weight: 700;
        }

        .stat-value {
            font-size: 20px;
            font-weight: 800;
            color: var(--color-text-primary);
        }

        .pill-row {
            display: flex;
            flex-wrap: wrap;
            gap: var(--space-2);
            margin-top: var(--space-4);
        }

        .pill {
            padding: 6px 10px;
            border-radius: var(--radius-pill);
            border: 1px solid var(--color-border);
            font-size: 12px;
            font-weight: 600;
            color: var(--color-text-secondary);
            background: var(--color-elevated);
        }

        .sync-indicator {
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            padding: 6px 12px;
            border-radius: var(--radius-pill);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            border: 1px solid var(--color-border);
            background: var(--color-elevated);
            white-space: nowrap;
        }

        .sync-indicator[data-status="syncing"] {
            color: var(--color-warning);
            border-color: rgba(245, 158, 11, 0.4);
        }

        .sync-indicator[data-status="ok"] {
            color: var(--color-success);
            border-color: rgba(16, 185, 129, 0.4);
        }

        .sync-indicator[data-status="error"],
        .sync-indicator[data-status="offline"] {
            color: var(--color-danger);
            border-color: rgba(220, 38, 38, 0.4);
        }

        .shortcut-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: var(--space-3);
            padding: var(--space-2) 0;
            border-bottom: 1px solid var(--color-divider);
        }

        .shortcut-row:last-child {
            border-bottom: none;
        }

        .shortcut-key {
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: 700;
            padding: 4px 8px;
            border-radius: var(--radius-1);
            background: var(--color-elevated);
            border: 1px solid var(--color-border);
        }

        .bento-cards {
            display: contents;
        }

        .card {
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: "";
            position: absolute;
            left: 0;
            top: 0;
            width: 4px;
            height: 100%;
            background: var(--color-accent);
        }

        .card.success::before {
            background: var(--color-success);
        }

        .card.warning::before {
            background: var(--color-warning);
        }

        .card.error::before {
            background: var(--color-danger);
        }

        .card-header {
            display: flex;
            align-items: center;
            gap: var(--space-3);
            margin-bottom: var(--space-4);
        }

        .card-icon {
            width: 28px;
            height: 28px;
            stroke: var(--color-accent);
            fill: none;
            stroke-width: 2.2;
        }

        .card-title {
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-secondary);
        }

        .card-badge {
            margin-left: auto;
            padding: 4px 8px;
            border-radius: var(--radius-1);
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            background: var(--color-elevated);
            border: 1px solid var(--color-border);
            color: var(--color-text-secondary);
        }

        .quick-cues {
            display: grid;
            gap: var(--space-4);
        }

        .cue-label {
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            color: var(--color-text-muted);
            margin-bottom: var(--space-2);
        }

        .cue-text {
            font-size: 14px;
            color: var(--color-text-primary);
        }

        .cue-text.spacing {
            margin-bottom: var(--space-3);
        }

        .expandable {
            margin-top: var(--space-4);
            padding-top: var(--space-4);
            border-top: 1px solid var(--color-divider);
        }

        .expand-trigger {
            display: flex;
            align-items: center;
            justify-content: space-between;
            width: 100%;
            padding: var(--space-2) 0;
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-primary);
        }

        .expand-trigger:hover {
            color: var(--color-text-secondary);
        }

        .expand-icon {
            width: 18px;
            height: 18px;
            stroke: currentColor;
            fill: none;
            stroke-width: 2.2;
            transition: transform var(--duration-medium) var(--easing-standard);
        }

        .expand-icon.open {
            transform: rotate(180deg);
        }

        .expand-content {
            overflow: hidden;
            max-height: 0;
            opacity: 0;
            transition: max-height var(--duration-slow) var(--easing-standard), opacity var(--duration-medium) var(--easing-standard);
        }

        .expand-content.open {
            max-height: 2000px;
            opacity: 1;
            padding-top: var(--space-3);
        }

        .coach-block {
            margin-bottom: var(--space-4);
        }

        .coach-label {
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-accent);
            margin-bottom: var(--space-2);
        }

        .coach-text {
            font-size: 13px;
            color: var(--color-text-primary);
        }

        .drill-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .drill-list li {
            padding-left: 18px;
            position: relative;
            font-size: 13px;
            color: var(--color-text-secondary);
            margin-bottom: var(--space-2);
        }

        .drill-list li::before {
            content: "→";
            position: absolute;
            left: 0;
            color: var(--color-accent);
            font-weight: 900;
        }

        .card-actions {
            margin-top: var(--space-4);
            padding-top: var(--space-4);
            border-top: 1px solid var(--color-divider);
            display: grid;
            gap: var(--space-3);
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
        }

        .feedback-btn {
            padding: 10px;
            border-radius: var(--radius-2);
            border: 1px solid var(--color-border);
            background: var(--color-elevated);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: var(--space-2);
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }

        .feedback-btn.success {
            color: var(--color-success);
            border-color: rgba(16, 185, 129, 0.4);
        }

        .feedback-btn.error {
            color: var(--color-danger);
            border-color: rgba(220, 38, 38, 0.4);
        }

        .feedback-btn svg {
            width: 16px;
            height: 16px;
            stroke: currentColor;
            fill: none;
            stroke-width: 2.2;
        }

        .empty-state,
        .loading-state {
            text-align: center;
            padding: var(--space-7) var(--space-4);
        }

        .empty-title {
            font-size: 20px;
            font-weight: 800;
            color: var(--color-text-primary);
            margin-bottom: var(--space-2);
        }

        .empty-subtitle {
            font-size: 14px;
            color: var(--color-text-secondary);
        }

        .skeleton-line {
            height: 14px;
            border-radius: var(--radius-pill);
            background: linear-gradient(90deg, var(--color-skeleton-base), var(--color-skeleton-shine), var(--color-skeleton-base));
            background-size: 200% 100%;
            animation: shimmer 1.4s infinite;
            margin-bottom: var(--space-2);
        }

        .skeleton-line.wide {
            height: 18px;
        }

        @keyframes shimmer {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        .control-bar {
            position: fixed;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: 300;
            padding: var(--control-bar-padding);
            padding-bottom: calc(var(--control-bar-padding) + var(--safe-bottom));
            background: var(--color-glass);
            border-top: 1px solid var(--color-divider);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            box-shadow: var(--shadow-2);
            transform: translateY(calc(-1 * var(--keyboard-offset)));
        }

        .context-chips {
            display: flex;
            gap: var(--space-2);
            overflow-x: auto;
            padding-bottom: var(--space-2);
            margin-bottom: var(--space-3);
            scrollbar-width: none;
        }

        .context-chips::-webkit-scrollbar {
            display: none;
        }

        .chip {
            min-height: var(--tap-min);
            padding: 8px 14px;
            border-radius: var(--radius-pill);
            border: 1px solid var(--color-border);
            background: var(--color-surface);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.2px;
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            white-space: nowrap;
            transition: transform var(--duration-fast) var(--easing-standard), background var(--duration-fast) var(--easing-standard);
        }

        .chip[aria-pressed="true"] {
            background: var(--color-accent);
            color: #FFFFFF;
            border-color: var(--color-accent);
        }

        .chip svg {
            width: 16px;
            height: 16px;
            stroke: currentColor;
            fill: none;
            stroke-width: 2.2;
        }

        .input-area {
            display: grid;
            gap: var(--space-3);
            grid-template-columns: 1fr auto auto;
            align-items: center;
        }

        .input-wrapper {
            position: relative;
        }

        .input-field {
            width: 100%;
            min-height: var(--input-height);
            padding: 12px 16px;
            border-radius: var(--radius-2);
            border: 1px solid var(--color-border);
            background: var(--color-surface);
            font-size: 15px;
        }

        .input-field:focus-visible {
            border-color: var(--color-accent);
        }

        .send-btn {
            width: var(--tap-min);
            height: var(--tap-min);
        }

        .mic-fab {
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: var(--color-accent);
            border: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--shadow-2);
            transition: transform var(--duration-fast) var(--easing-standard);
        }

        .mic-fab.recording {
            animation: micPulseRecording 1.4s infinite;
        }

        .mic-fab.processing {
            background: var(--color-warning);
        }

        .mic-fab svg {
            width: 22px;
            height: 22px;
            stroke: #FFFFFF;
            fill: none;
            stroke-width: 2.2;
        }

        @keyframes micPulseRecording {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.04); }
        }

        .modal {
            display: none;
            position: fixed;
            inset: 0;
            background: var(--color-backdrop);
            backdrop-filter: blur(8px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            padding: var(--space-6);
        }

        .modal.open {
            display: flex;
        }

        .modal-content {
            background: var(--color-surface);
            border-radius: var(--radius-3);
            padding: var(--space-6);
            max-width: 560px;
            width: 100%;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: var(--shadow-3);
            border: 1px solid var(--color-border);
        }

        .modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: var(--space-5);
        }

        .modal-title {
            font-size: 22px;
            font-weight: 800;
            color: var(--color-text-primary);
        }

        .close-btn {
            width: var(--tap-min);
            height: var(--tap-min);
            border-radius: var(--radius-2);
            background: var(--color-elevated);
            border: 1px solid var(--color-border);
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .form-group {
            margin-bottom: var(--space-5);
        }

        .form-label {
            display: block;
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-secondary);
            margin-bottom: var(--space-2);
        }

        .form-input,
        .form-select,
        .form-textarea {
            width: 100%;
            padding: 12px 14px;
            border-radius: var(--radius-2);
            border: 1px solid var(--color-border);
            background: var(--color-elevated);
            font-size: 14px;
        }

        .form-textarea {
            min-height: 90px;
            resize: vertical;
        }

        .helper-text {
            font-size: 12px;
            color: var(--color-text-muted);
            margin-top: var(--space-2);
        }

        .warning-box {
            display: flex;
            gap: var(--space-2);
            padding: var(--space-3);
            border-radius: var(--radius-2);
            background: rgba(245, 158, 11, 0.12);
            border: 1px solid rgba(245, 158, 11, 0.3);
            margin-top: var(--space-3);
        }

        .warning-box svg {
            width: 18px;
            height: 18px;
            stroke: var(--color-warning);
            stroke-width: 2.2;
        }

        .warning-text {
            font-size: 12px;
            color: var(--color-text-secondary);
        }

        .segmented {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: var(--space-2);
        }

        .segmented-option {
            position: relative;
            display: block;
        }

        .segmented-option input {
            position: absolute;
            opacity: 0;
            inset: 0;
        }

        .segmented-option span {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 10px 12px;
            border-radius: var(--radius-2);
            border: 1px solid var(--color-border);
            background: var(--color-elevated);
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            min-height: var(--tap-min);
        }

        .segmented-option input:checked + span {
            border-color: var(--color-accent);
            color: var(--color-accent);
            background: rgba(227, 0, 15, 0.08);
        }

        .btn-group {
            display: grid;
            gap: var(--space-3);
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            margin-top: var(--space-3);
        }

        .btn {
            padding: 12px 16px;
            border-radius: var(--radius-2);
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            border: 1px solid transparent;
            min-height: var(--tap-min);
        }

        .btn-primary {
            background: var(--color-accent);
            color: #FFFFFF;
        }

        .btn-secondary {
            background: var(--color-elevated);
            color: var(--color-text-primary);
            border-color: var(--color-border);
        }

        .btn-danger {
            background: var(--color-danger);
            color: #FFFFFF;
        }

        .toast {
            position: fixed;
            bottom: calc(var(--control-bar-height) + var(--space-4));
            left: 50%;
            transform: translateX(-50%) translateY(20px);
            opacity: 0;
            pointer-events: none;
            padding: 14px 20px;
            border-radius: var(--radius-2);
            background: var(--color-toast);
            color: var(--color-toast-text);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.3px;
            transition: opacity var(--duration-medium) var(--easing-standard), transform var(--duration-medium) var(--easing-standard);
            z-index: 4000;
        }

        .toast.show {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }

        .footer {
            text-align: center;
            padding: var(--space-3);
            font-size: 11px;
            color: var(--color-text-muted);
            border-top: 1px solid var(--color-divider);
            background: var(--color-surface);
        }

        .build-info {
            margin-top: var(--space-1);
            font-size: 10px;
            font-family: var(--font-mono);
            color: var(--color-text-muted);
        }

        .stealth-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.92);
            backdrop-filter: blur(24px);
            display: none;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            gap: var(--space-4);
            z-index: 5000;
            text-align: center;
            color: #FFFFFF;
        }

        .stealth-overlay.active {
            display: flex;
        }

        .stealth-icon {
            width: 72px;
            height: 72px;
            stroke: #FFFFFF;
            stroke-width: 1.6;
            opacity: 0.5;
        }

        .stealth-text {
            font-size: 16px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            color: rgba(255, 255, 255, 0.8);
        }

        .stealth-hint {
            font-size: 12px;
            color: rgba(255, 255, 255, 0.6);
        }

        @media (min-width: 720px) {
            .bento-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .tile--wide {
                grid-column: span 2;
            }
        }

        @media (min-width: 1024px) {
            .bento-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }

            .tile--hero {
                grid-column: span 2;
            }

            .tile--tall {
                grid-row: span 2;
            }
        }

        @media (min-width: 1280px) {
            .bento-grid {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }

            .tile--hero {
                grid-column: span 2;
            }
        }

        @media (max-width: 680px) {
            .header {
                padding: calc(var(--space-3) + var(--safe-top)) var(--space-4) var(--space-3) var(--space-4);
            }

            .input-area {
                grid-template-columns: 1fr auto;
            }

            .send-btn {
                display: none;
            }

            .toggle-label {
                display: none;
            }
        }

        @media (hover: hover) and (pointer: fine) {
            .stage::-webkit-scrollbar {
                width: 10px;
            }

            .stage::-webkit-scrollbar-thumb {
                background: var(--color-scrollbar-thumb);
                border-radius: var(--radius-pill);
            }

            .stage::-webkit-scrollbar-track {
                background: var(--color-scrollbar-track);
            }
        }

        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        }
    </style>
</head>
<body>
    <a class="skip-link" href="#stage">Zum Inhalt springen</a>

    <div class="stealth-overlay" id="stealthOverlay" aria-hidden="true" tabindex="-1">
        <svg class="stealth-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <rect x="2" y="2" width="20" height="20" rx="2"/>
            <line x1="7" y1="12" x2="17" y2="12"/>
        </svg>
        <div class="stealth-text">Stealth aktiv</div>
        <div class="stealth-hint">Zweimal tippen oder ESC zum Beenden</div>
    </div>

    <header class="header" id="header">
        <div class="logo-container" aria-label="MEHIC SALES OS">
            <svg class="logo-svg" viewBox="0 0 100 100" fill="none" aria-hidden="true">
                <defs>
                    <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#E3000F" />
                        <stop offset="100%" stop-color="#C70010" />
                    </linearGradient>
                </defs>
                <path d="M20 80 L20 20 L50 50 L80 20 L80 80" stroke="url(#logoGrad)" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" fill="none" opacity="0.9"/>
                <circle cx="50" cy="50" r="8" fill="url(#logoGrad)" opacity="0.8"/>
            </svg>
            <div class="logo-text">MEHIC SALES <span>OS</span></div>
        </div>
        <div class="header-actions">
            <div class="status-pill" id="onlineStatus" data-status="online" role="status" aria-live="polite">
                <span class="status-dot" aria-hidden="true"></span>
                <span id="onlineStatusLabel">Online</span>
            </div>
            <div class="dept-badge" id="deptBadge">TV</div>
            <button class="toggle-btn" id="themeToggleBtn" type="button" aria-live="polite">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>
                </svg>
                <span class="toggle-label" id="themeToggleLabel">Theme: Auto</span>
            </button>
            <button class="toggle-btn" id="densityToggleBtn" type="button">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <rect x="4" y="5" width="16" height="4" rx="2"/>
                    <rect x="4" y="11" width="16" height="4" rx="2"/>
                    <rect x="4" y="17" width="16" height="2" rx="1"/>
                </svg>
                <span class="toggle-label" id="densityToggleLabel">Dichte: Kompakt</span>
            </button>
            <button class="icon-btn" id="syncBtn" type="button" title="Sync starten" aria-label="Sync starten">
                <svg viewBox="0 0 24 24">
                    <path d="M3 12a9 9 0 0 1 15.54-5.54"/>
                    <polyline points="21 3 21 8 16 8"/>
                    <path d="M21 12a9 9 0 0 1-15.54 5.54"/>
                    <polyline points="3 21 3 16 8 16"/>
                </svg>
            </button>
            <button class="icon-btn" id="stealthBtn" type="button" title="Stealth aktivieren" aria-label="Stealth aktivieren">
                <svg viewBox="0 0 24 24">
                    <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/>
                    <circle cx="12" cy="12" r="3"/>
                </svg>
            </button>
            <button class="icon-btn" id="resetBtn" type="button" title="Ansicht zurücksetzen" aria-label="Ansicht zurücksetzen">
                <svg viewBox="0 0 24 24">
                    <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/>
                    <path d="M21 3v5h-5"/>
                </svg>
            </button>
            <button class="icon-btn" id="settingsBtn" type="button" title="Einstellungen öffnen" aria-label="Einstellungen öffnen">
                <svg viewBox="0 0 24 24">
                    <circle cx="12" cy="12" r="3"/>
                    <path d="M12 1v6m0 6v6"/>
                </svg>
            </button>
        </div>
    </header>

    <div class="offline-banner" id="offlineBanner" role="status" aria-live="polite">
        Offline – Lokale Daten aktiv. Sync pausiert.
    </div>

    <main class="stage" id="stage">
        <div class="bento-grid" id="bentoGrid">
            <section class="tile tile--hero glass" id="statusTile">
                <div class="tile-header">
                    <div>
                        <div class="tile-title">Command HUD</div>
                        <div class="tile-subtitle" id="hudSubtitle">Bereit</div>
                    </div>
                    <div class="sync-indicator" id="syncIndicator" data-status="idle">Sync Idle</div>
                </div>
                <div class="stat-grid">
                    <div class="stat">
                        <div class="stat-label">Library</div>
                        <div class="stat-value" id="statCases">0</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Logs</div>
                        <div class="stat-value" id="statLogs">0</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Modus</div>
                        <div class="stat-value" id="statMode">Auto</div>
                    </div>
                </div>
                <div class="pill-row">
                    <span class="pill" id="statTheme">Theme: Auto</span>
                    <span class="pill" id="statDensity">Dichte: Comfort</span>
                    <span class="pill" id="statContext">Kontext: Neutral</span>
                </div>
            </section>

            <section class="tile" id="policyTile">
                <div class="tile-title">Store Policy</div>
                <div class="tile-subtitle" id="policyTitle">Keine Aktion aktiv</div>
                <div class="tile-desc" id="policyText">Trage im Settings-Panel aktuelle Aktionen ein, um Scarcity sicher zu nutzen.</div>
            </section>

            <section class="tile" id="trustTile">
                <div class="tile-title">Trust & Safety</div>
                <div class="tile-desc">BYOK bleibt lokal. Keine Keys im DOM. Keine Calls ohne Freigabe.</div>
                <div class="pill-row">
                    <span class="pill" id="trustKeyStatus">Key: Nicht gesetzt</span>
                    <span class="pill" id="trustProxyStatus">Proxy: Aus</span>
                    <span class="pill" id="trustMotionStatus">Motion: Standard</span>
                </div>
            </section>

            <section class="tile tile--wide" id="shortcutsTile">
                <div class="tile-title">Shortcuts</div>
                <div class="shortcut-row">
                    <div>Focus Input</div>
                    <div class="shortcut-key">Ctrl / ⌘ + K</div>
                </div>
                <div class="shortcut-row">
                    <div>Theme Cycle</div>
                    <div class="shortcut-key">Ctrl + Shift + T</div>
                </div>
                <div class="shortcut-row">
                    <div>Dichte Toggle</div>
                    <div class="shortcut-key">Ctrl + Shift + D</div>
                </div>
                <div class="shortcut-row">
                    <div>Einstellungen</div>
                    <div class="shortcut-key">Ctrl + S</div>
                </div>
            </section>

            <section class="tile" id="syncTile">
                <div class="tile-title">Sync Status</div>
                <div class="tile-subtitle" id="syncTitle">Bereit</div>
                <div class="tile-desc" id="syncDesc">Letzter Sync: <span id="syncTime">–</span></div>
            </section>

            <div id="cardsContainer" class="bento-cards"></div>
        </div>
    </main>

    <div class="control-bar" id="controlBar" role="region" aria-label="Eingabe Steuerung">
        <div class="context-chips" id="contextChips" role="group" aria-label="Kontext Filter">
            <button class="chip" type="button" data-context="hurry" aria-pressed="false">
                <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
                Eilig
            </button>
            <button class="chip" type="button" data-context="duo" aria-pressed="false">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/></svg>
                Paar
            </button>
            <button class="chip" type="button" data-context="easy" aria-pressed="false">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2v20M2 12h20"/></svg>
                Einfach
            </button>
            <button class="chip" type="button" data-context="techie" aria-pressed="false">
                <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
                Techie
            </button>
        </div>

        <div class="input-area">
            <label class="sr-only" for="objectionInput">Kundeneinwand</label>
            <div class="input-wrapper">
                <input type="text" class="input-field" id="objectionInput" placeholder="Kundeneinwand eingeben..." autocomplete="off" />
            </div>
            <button class="icon-btn send-btn" id="submitBtn" type="button" title="Antwort erstellen" aria-label="Antwort erstellen">
                <svg viewBox="0 0 24 24">
                    <path d="M22 2L11 13"/>
                    <path d="M22 2L15 22L11 13L2 9L22 2Z"/>
                </svg>
            </button>
            <button class="mic-fab" id="micBtn" type="button" aria-label="Spracheingabe" aria-pressed="false">
                <svg viewBox="0 0 24 24">
                    <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
                    <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
                    <line x1="12" y1="19" x2="12" y2="23"/>
                    <line x1="8" y1="23" x2="16" y2="23"/>
                </svg>
            </button>
        </div>
    </div>

    <div class="modal" id="settingsModal" role="dialog" aria-modal="true" aria-labelledby="settingsTitle" aria-hidden="true">
        <div class="modal-content" role="document">
            <div class="modal-header">
                <div class="modal-title" id="settingsTitle">Einstellungen</div>
                <button class="close-btn" id="closeSettingsBtn" type="button" aria-label="Einstellungen schließen">
                    <svg viewBox="0 0 24 24">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            </div>

            <div class="form-group">
                <div class="form-label">Theme</div>
                <div class="segmented" role="radiogroup" aria-label="Theme Auswahl">
                    <label class="segmented-option">
                        <input type="radio" name="themeMode" value="auto" id="themeAuto">
                        <span>Auto</span>
                    </label>
                    <label class="segmented-option">
                        <input type="radio" name="themeMode" value="light" id="themeLight">
                        <span>Light</span>
                    </label>
                    <label class="segmented-option">
                        <input type="radio" name="themeMode" value="dark" id="themeDark">
                        <span>Dark</span>
                    </label>
                </div>
            </div>

            <div class="form-group">
                <div class="form-label">Density</div>
                <div class="segmented" role="radiogroup" aria-label="Density Auswahl">
                    <label class="segmented-option">
                        <input type="radio" name="densityMode" value="compact" id="densityCompact">
                        <span>Kompakt</span>
                    </label>
                    <label class="segmented-option">
                        <input type="radio" name="densityMode" value="comfortable" id="densityComfortable">
                        <span>Comfort</span>
                    </label>
                </div>
                <div class="helper-text">Default: Mobile Comfort, Desktop Kompakt. Manuelle Wahl wird gespeichert.</div>
            </div>

            <div class="form-group">
                <label class="form-label" for="apiProvider">API Provider</label>
                <select class="form-select" id="apiProvider">
                    <option value="openai">OpenAI</option>
                    <option value="groq">Groq</option>
                </select>
            </div>

            <div class="form-group">
                <label class="form-label" for="apiKey">API Key (BYOK)</label>
                <input type="password" class="form-input" id="apiKey" placeholder="sk-..." autocomplete="off" />
                <div class="warning-box">
                    <svg viewBox="0 0 24 24">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    <div class="warning-text">Schlüssel wird lokal gespeichert. Passphrase-Lock empfohlen. Niemals auf öffentlichen Geräten verwenden.</div>
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="passphraseInput">Passphrase (optional)</label>
                <input type="password" class="form-input" id="passphraseInput" placeholder="Nur lokal verwendet" autocomplete="off" />
                <div class="helper-text" id="lockStatus">Lock deaktiviert</div>
                <div class="btn-group">
                    <button class="btn btn-secondary" id="lockToggleBtn" type="button">Passphrase-Lock aktivieren</button>
                    <button class="btn btn-secondary" id="unlockBtn" type="button">Unlock</button>
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="modelName">AI Model Name</label>
                <input type="text" class="form-input" id="modelName" placeholder="gpt-4o-mini" />
            </div>

            <div class="form-group">
                <label class="form-label" for="proxyUrl">API Proxy URL (optional)</label>
                <input type="text" class="form-input" id="proxyUrl" placeholder="https://your-proxy.example" />
                <div class="helper-text">Nur Same-Origin Proxies erlaubt (CSP-konform).</div>
            </div>

            <div class="form-group">
                <label class="form-label" for="department">Abteilung</label>
                <select class="form-select" id="department">
                    <option value="TV">TV & Audio</option>
                    <option value="Mobile">Mobile</option>
                    <option value="IT">IT</option>
                    <option value="Weiß">Weiße Ware</option>
                </select>
            </div>

            <div class="form-group">
                <label class="form-label" for="storePolicy">Store Policy</label>
                <textarea class="form-textarea" id="storePolicy" placeholder="z.B. 'Winteraktion bis 31.01.2026'"></textarea>
            </div>

            <div class="form-group">
                <label class="form-label">Datenmanagement</label>
                <div class="btn-group">
                    <button class="btn btn-secondary" id="exportBtn" type="button">Export</button>
                    <button class="btn btn-secondary" id="importBtn" type="button">Import</button>
                </div>
                <input type="file" id="importFile" accept=".json" class="sr-only" />
                <div class="btn-group">
                    <button class="btn btn-danger" id="clearBtn" type="button">Löschen</button>
                </div>
            </div>

            <div class="btn-group">
                <button class="btn btn-primary" id="saveSettingsBtn" type="button">Speichern</button>
            </div>
        </div>
    </div>

    <div class="modal confirm-modal" id="confirmModal" role="alertdialog" aria-modal="true" aria-labelledby="confirmTitle" aria-describedby="confirmMessage" aria-hidden="true">
        <div class="modal-content" role="document">
            <div class="modal-header">
                <div class="modal-title" id="confirmTitle">Bestätigen</div>
                <button class="close-btn" id="confirmCloseBtn" type="button" aria-label="Dialog schließen">
                    <svg viewBox="0 0 24 24">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            </div>
            <div class="tile-desc" id="confirmMessage">Bitte bestätigen.</div>
            <div class="btn-group">
                <button class="btn btn-secondary" id="confirmCancelBtn" type="button">Abbrechen</button>
                <button class="btn btn-danger" id="confirmConfirmBtn" type="button">Bestätigen</button>
            </div>
        </div>
    </div>

    <div class="toast" id="toast" role="status" aria-live="polite"></div>

    <footer class="footer">
        © 2026 Enes Mehic. All rights reserved.
        <div class="build-info" id="buildInfo"></div>
    </footer>

    <script>
        const APP_VERSION = "2026.1.0-rc1";
        const BUILD_DATE = "2026-01-18";
        const BUILD_SIGNATURE = `MEHIC_SALES_OS_RC_${APP_VERSION}__${BUILD_DATE}`;

        const DB_NAME = "MehicSalesOS_DB";
        const DB_VERSION = 2;
        const LIBRARY_URL = "./library.json";
        const LIBRARY_SHA256 = "pM/qq9A97C8i/Bgtyx2UG/8gtFdRzlangPRZbIYFbUQ=";

        const MODEL_DEFAULTS = {
            openai: "gpt-4o-mini",
            groq: "llama-3.3-70b-versatile"
        };

        const appState = {
            objection: "",
            contexts: [],
            cards: [],
            loading: false,
            stealthMode: false,
            lastFocused: null,
            settings: {
                apiProvider: "openai",
                apiKey: "",
                apiKeyEncrypted: "",
                apiKeyIv: "",
                apiKeySalt: "",
                apiKeyLocked: false,
                modelName: "gpt-4o-mini",
                proxyUrl: "",
                department: "TV",
                storePolicy: "",
                themeMode: "auto",
                densityMode: "",
                densityUserSet: false
            },
            ui: {
                online: navigator.onLine,
                syncStatus: "idle",
                lastSync: null
            },
            stats: {
                cases: 0,
                logs: 0
            }
        };

        const storage = {
            mode: "indexeddb",
            db: null,
            ready: false
        };

        const toastQueue = [];
        let toastActive = false;
        let recognition = null;
        let modalHistoryActive = false;
        let ignoreNextPop = false;
        let reduceMotionMedia = window.matchMedia("(prefers-reduced-motion: reduce)");
        let themeMedia = window.matchMedia("(prefers-color-scheme: dark)");
        let controlBarObserver = null;
        let densityResizeRaf = null;
        const modalStack = [];

        const elements = {};

        const SEED_DATA = [
            {
                id: "seed_1",
                objection: "zu teuer",
                keywords: ["teuer", "preis", "kostet", "viel", "hoch", "expensive"],
                meta: { status: "success", pattern: "price", safety: "clean" },
                ui: { color: "success", icon: "tag" },
                content: {
                    quick: {
                        entry: "Ich verstehe, dass der Preis im ersten Moment hoch erscheint.",
                        anchor: "Viele Kundinnen und Kunden haben anfangs dieselbe Reaktion und sind dann sehr zufrieden mit ihrer Entscheidung.",
                        question: "Darf ich Ihnen kurz zeigen, was dieses Gerät von günstigeren Modellen unterscheidet?",
                        bridge: "Langfristig gesehen investieren Sie hier in Qualität, die sich rechnet.",
                        close: "Wenn wir gemeinsam schauen, welche Features Sie wirklich brauchen, finden wir das beste Preis-Leistungs-Verhältnis für Sie."
                    },
                    smart: {
                        text: "Verstehe ich absolut. Preis ist wichtig. Lassen Sie uns kurz vergleichen: Das günstigere Modell hat X, unser Modell bietet zusätzlich Y und Z. Das bedeutet für Sie konkret [Vorteile]. Viele Kundinnen und Kunden entscheiden sich letztlich für die höhere Investition, weil sie langfristig profitieren.",
                        closing: "Möchten Sie beide Modelle nebeneinander sehen, damit Sie selbst entscheiden können?"
                    },
                    coach: {
                        diagnosis: "Preiseinwand ist oft ein Kontrolleinwand. Kunde sucht Rechtfertigung für Investition.",
                        strategy: "Nicht verteidigen, sondern Wert aufbauen. Von Preis auf Wert shiften.",
                        behavioral_fix: "Anchor-Technik: 'Viele Kundinnen und Kunden...' schafft Social Proof. Frage am Ende gibt Kontrolle zurück.",
                        drill: [
                            "Üben: 'Verstehe ich. Darf ich fragen, was Ihnen an diesem Modell gefällt?' (Commitment verstärken)",
                            "Üben: Preisvergleich immer mit konkretem Mehrwert verknüpfen, nie nur Zahlen nennen"
                        ]
                    }
                }
            },
            {
                id: "seed_2",
                objection: "keine versicherung",
                keywords: ["versicherung", "garantie", "schutz", "abo", "absicherung"],
                meta: { status: "success", pattern: "subscription_aversion", safety: "transparency_required" },
                ui: { color: "warning", icon: "shield" },
                content: {
                    quick: {
                        entry: "Verstehe ich vollkommen, Versicherungen sind nicht jedermanns Sache.",
                        anchor: "Viele Kundinnen und Kunden denken anfangs ähnlich, bis sie die erste Reparatur brauchen.",
                        question: "Darf ich Ihnen transparent zeigen, was genau abgedeckt wäre und wie sich das rechnet?",
                        bridge: "Wichtig: Sie entscheiden natürlich selbst. Mir geht es nur darum, dass Sie alle Infos haben.",
                        close: "Wenn wir einmal durchrechnen, können Sie in Ruhe entscheiden, ob es sich für Sie lohnt."
                    },
                    smart: {
                        text: "Alles klar, kein Problem. Viele verzichten darauf und kommen dann doch zurück. Die Versicherung deckt [konkrete Leistungen] ab. Das bedeutet: [Beispiel Schadensfall]. Hinweis: Alle Konditionen stehen transparent im Vertrag, keine versteckten Kosten.",
                        closing: "Möchten Sie die Unterlagen mitnehmen und in Ruhe entscheiden?"
                    },
                    coach: {
                        diagnosis: "Versicherungs-Aversion ist häufig. Oft fehlt Vertrauen oder Transparenz.",
                        strategy: "Transparenz vor Verkauf. Konkrete Beispiele statt Angstmache.",
                        behavioral_fix: "Niemals Druck aufbauen. 'Sie entscheiden' gibt Kontrolle zurück und baut Vertrauen auf.",
                        drill: [
                            "Üben: Schadensfall-Beispiel parat haben (konkret, realistisch, keine Übertreibung)",
                            "Üben: Kosten transparent darstellen (monatlich UND jährlich nennen)"
                        ]
                    }
                }
            },
            {
                id: "seed_3",
                objection: "muss überlegen",
                keywords: ["überlegen", "bedenkzeit", "später", "nachdenken", "warten"],
                meta: { status: "success", pattern: "uncertainty", safety: "clean" },
                ui: { color: "success", icon: "clock" },
                content: {
                    quick: {
                        entry: "Natürlich, das ist eine wichtige Entscheidung. Nehmen Sie sich ruhig Zeit.",
                        anchor: "Viele Kundinnen und Kunden gehen das genauso an und überlegen in Ruhe.",
                        question: "Darf ich fragen, worüber Sie noch nachdenken möchten? Vielleicht kann ich noch etwas klären?",
                        bridge: "Mir ist wichtig, dass Sie sich sicher fühlen mit Ihrer Entscheidung.",
                        close: "Wenn Sie mögen, reserviere ich das Gerät für Sie, damit Sie in Ruhe überlegen können, ohne dass es weg ist."
                    },
                    smart: {
                        text: "Absolut verständlich. Ist eine Investition und die sollte gut überlegt sein. Viele vergleichen erst noch online oder besprechen es zu Hause. Gibt es noch einen speziellen Punkt, den ich klären kann?",
                        closing: "Möchten Sie, dass ich das Gerät für 24 Stunden reserviere?"
                    },
                    coach: {
                        diagnosis: "Bedenkzeit ist legitim, aber oft versteckt sich ein ungelöster Einwand dahinter.",
                        strategy: "Respektieren, aber nachfragen. Offene Frage stellen, um echten Grund zu finden.",
                        behavioral_fix: "Reservierungs-Offer gibt Kontrolle und schafft sanften Commitment-Anker ohne Druck.",
                        drill: [
                            "Üben: 'Worüber möchten Sie noch nachdenken?' (offene Frage, kein Druck)",
                            "Üben: Reservierungsangebot als Service-Geste positionieren, nicht als Druck"
                        ]
                    }
                }
            }
        ];

        const JOKER_CARD = {
            id: "joker",
            meta: { status: "success", pattern: "trust", safety: "clean" },
            ui: { color: "success", icon: "info" },
            content: {
                quick: {
                    entry: "Ich verstehe Ihre Bedenken vollkommen.",
                    anchor: "Viele Kundinnen und Kunden stellen diese Frage, und das ist auch richtig so.",
                    question: "Darf ich Ihnen erklären, wie wir das bei uns handhaben?",
                    bridge: "Mir ist wichtig, dass Sie sich gut informiert fühlen.",
                    close: "Lassen Sie uns gemeinsam schauen, was für Sie die beste Lösung ist."
                },
                smart: {
                    text: "Das ist eine berechtigte Frage. In meiner Erfahrung hilft es, wenn wir das ganz konkret durchgehen. Viele Kundinnen und Kunden sind dann beruhigt.",
                    closing: "Welche Informationen brauchen Sie noch, um sich sicher zu fühlen?"
                },
                coach: {
                    diagnosis: "Unbekannter Einwand. Empathie und Nachfragen ist der Schlüssel.",
                    strategy: "Aktives Zuhören, offene Fragen stellen, Vertrauen aufbauen.",
                    behavioral_fix: "Niemals defensive Position. Kunde hat immer einen guten Grund für seinen Einwand.",
                    drill: [
                        "Üben: Pausentechnik - 2 Sekunden warten nach Kundenaussage, dann erst antworten",
                        "Üben: 'Verstehe ich richtig, dass...' (Reformulierung zum Validieren)"
                    ]
                }
            }
        };

        function cacheElements() {
            elements.header = document.getElementById("header");
            elements.stage = document.getElementById("stage");
            elements.themeColorMeta = document.getElementById("themeColorMeta");
            elements.onlineStatus = document.getElementById("onlineStatus");
            elements.onlineStatusLabel = document.getElementById("onlineStatusLabel");
            elements.deptBadge = document.getElementById("deptBadge");
            elements.themeToggleBtn = document.getElementById("themeToggleBtn");
            elements.themeToggleLabel = document.getElementById("themeToggleLabel");
            elements.densityToggleBtn = document.getElementById("densityToggleBtn");
            elements.densityToggleLabel = document.getElementById("densityToggleLabel");
            elements.syncBtn = document.getElementById("syncBtn");
            elements.stealthBtn = document.getElementById("stealthBtn");
            elements.resetBtn = document.getElementById("resetBtn");
            elements.settingsBtn = document.getElementById("settingsBtn");
            elements.offlineBanner = document.getElementById("offlineBanner");
            elements.cardsContainer = document.getElementById("cardsContainer");
            elements.objectionInput = document.getElementById("objectionInput");
            elements.submitBtn = document.getElementById("submitBtn");
            elements.micBtn = document.getElementById("micBtn");
            elements.contextChips = document.getElementById("contextChips");
            elements.controlBar = document.getElementById("controlBar");
            elements.buildInfo = document.getElementById("buildInfo");
            elements.toast = document.getElementById("toast");
            elements.settingsModal = document.getElementById("settingsModal");
            elements.closeSettingsBtn = document.getElementById("closeSettingsBtn");
            elements.saveSettingsBtn = document.getElementById("saveSettingsBtn");
            elements.apiProvider = document.getElementById("apiProvider");
            elements.apiKey = document.getElementById("apiKey");
            elements.passphraseInput = document.getElementById("passphraseInput");
            elements.lockToggleBtn = document.getElementById("lockToggleBtn");
            elements.unlockBtn = document.getElementById("unlockBtn");
            elements.lockStatus = document.getElementById("lockStatus");
            elements.modelName = document.getElementById("modelName");
            elements.proxyUrl = document.getElementById("proxyUrl");
            elements.department = document.getElementById("department");
            elements.storePolicy = document.getElementById("storePolicy");
            elements.exportBtn = document.getElementById("exportBtn");
            elements.importBtn = document.getElementById("importBtn");
            elements.importFile = document.getElementById("importFile");
            elements.clearBtn = document.getElementById("clearBtn");
            elements.confirmModal = document.getElementById("confirmModal");
            elements.confirmTitle = document.getElementById("confirmTitle");
            elements.confirmMessage = document.getElementById("confirmMessage");
            elements.confirmConfirmBtn = document.getElementById("confirmConfirmBtn");
            elements.confirmCancelBtn = document.getElementById("confirmCancelBtn");
            elements.confirmCloseBtn = document.getElementById("confirmCloseBtn");
            elements.stealthOverlay = document.getElementById("stealthOverlay");
            elements.themeAuto = document.getElementById("themeAuto");
            elements.themeLight = document.getElementById("themeLight");
            elements.themeDark = document.getElementById("themeDark");
            elements.densityCompact = document.getElementById("densityCompact");
            elements.densityComfortable = document.getElementById("densityComfortable");
            elements.hudSubtitle = document.getElementById("hudSubtitle");
            elements.statCases = document.getElementById("statCases");
            elements.statLogs = document.getElementById("statLogs");
            elements.statMode = document.getElementById("statMode");
            elements.statTheme = document.getElementById("statTheme");
            elements.statDensity = document.getElementById("statDensity");
            elements.statContext = document.getElementById("statContext");
            elements.policyTitle = document.getElementById("policyTitle");
            elements.policyText = document.getElementById("policyText");
            elements.trustKeyStatus = document.getElementById("trustKeyStatus");
            elements.trustProxyStatus = document.getElementById("trustProxyStatus");
            elements.trustMotionStatus = document.getElementById("trustMotionStatus");
            elements.syncIndicator = document.getElementById("syncIndicator");
            elements.syncTitle = document.getElementById("syncTitle");
            elements.syncDesc = document.getElementById("syncDesc");
            elements.syncTime = document.getElementById("syncTime");
        }

        function escapeHTML(value) {
            return String(value)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        }

        function sanitizeString(value, maxLength = 200) {
            if (typeof value !== "string") return "";
            return value.trim().slice(0, maxLength);
        }

        function sanitizeEnum(value, allowed, fallback) {
            if (allowed.includes(value)) return value;
            return fallback;
        }

        function sanitizeArray(values, maxLength = 50) {
            if (!Array.isArray(values)) return [];
            return values.map(item => sanitizeString(item, maxLength)).filter(Boolean);
        }

        function safeParseJSON(raw, fallback) {
            if (!raw) return fallback;
            try {
                return JSON.parse(raw);
            } catch (error) {
                return fallback;
            }
        }

        function showToast(message, options = {}) {
            const entry = {
                message: sanitizeString(message, 160),
                duration: options.duration || 3000
            };
            toastQueue.push(entry);
            if (!toastActive) {
                displayNextToast();
            }
        }

        function displayNextToast() {
            if (toastQueue.length === 0) {
                toastActive = false;
                return;
            }
            toastActive = true;
            const { message, duration } = toastQueue.shift();
            elements.toast.textContent = message;
            elements.toast.classList.add("show");
            setTimeout(() => {
                elements.toast.classList.remove("show");
                setTimeout(displayNextToast, 250);
            }, duration);
        }

        function haptic(pattern = [40]) {
            if ("vibrate" in navigator) {
                navigator.vibrate(pattern);
            }
        }

        function updateThemeColorMeta() {
            const color = getComputedStyle(document.documentElement).getPropertyValue("--color-bg").trim();
            elements.themeColorMeta.setAttribute("content", color || "#000000");
        }

        function resolveTheme(mode) {
            if (mode === "auto") {
                return themeMedia.matches ? "dark" : "light";
            }
            return mode;
        }

        function applyTheme(mode, persist = true) {
            appState.settings.themeMode = mode;
            const resolved = resolveTheme(mode);
            document.documentElement.setAttribute("data-theme", resolved);
            elements.themeToggleLabel.textContent = `Theme: ${mode === "auto" ? "Auto" : resolved.charAt(0).toUpperCase() + resolved.slice(1)}`;
            elements.statTheme.textContent = `Theme: ${mode === "auto" ? "Auto" : resolved.charAt(0).toUpperCase() + resolved.slice(1)}`;
            updateThemeColorMeta();
            if (persist) {
                saveSettings(buildPersistedSettings());
            }
        }

        function computeDensity(width) {
            return width >= 900 ? "compact" : "comfortable";
        }

        function applyDensity(mode, userSet = false, persist = true) {
            appState.settings.densityMode = mode;
            if (userSet) {
                appState.settings.densityUserSet = true;
            }
            document.documentElement.setAttribute("data-density", mode);
            const label = mode === "compact" ? "Kompakt" : "Comfort";
            elements.densityToggleLabel.textContent = `Dichte: ${label}`;
            elements.statDensity.textContent = `Dichte: ${label}`;
            if (persist) {
                saveSettings(buildPersistedSettings());
            }
        }

        function updateContextStatus() {
            const label = appState.contexts.length ? appState.contexts.join(", ") : "Neutral";
            elements.statContext.textContent = `Kontext: ${label}`;
        }

        function updateTrustStatus() {
            const keyStatus = appState.settings.apiKeyLocked ? "Key: Locked" : appState.settings.apiKey ? "Key: Aktiv" : "Key: Nicht gesetzt";
            elements.trustKeyStatus.textContent = keyStatus;
            const proxyValid = validateProxyUrl(appState.settings.proxyUrl);
            const proxyStatus = proxyValid.ok ? "Proxy: Aktiv" : "Proxy: Aus";
            elements.trustProxyStatus.textContent = proxyStatus;
            elements.trustMotionStatus.textContent = reduceMotionMedia.matches ? "Motion: Reduced" : "Motion: Standard";
        }

        function updatePolicyTile() {
            const policy = appState.settings.storePolicy.trim();
            if (policy) {
                elements.policyTitle.textContent = "Aktive Policy";
                elements.policyText.textContent = policy;
            } else {
                elements.policyTitle.textContent = "Keine Aktion aktiv";
                elements.policyText.textContent = "Trage im Settings-Panel aktuelle Aktionen ein, um Scarcity sicher zu nutzen.";
            }
        }

        function updateOnlineStatus() {
            appState.ui.online = navigator.onLine;
            elements.onlineStatus.dataset.status = appState.ui.online ? "online" : "offline";
            elements.onlineStatusLabel.textContent = appState.ui.online ? "Online" : "Offline";
            elements.statMode.textContent = appState.ui.online ? "Online" : "Offline";
            elements.offlineBanner.classList.toggle("show", !appState.ui.online);
            if (!appState.ui.online) {
                setSyncStatus("offline", "Offline");
            }
        }

        function setSyncStatus(status, label) {
            appState.ui.syncStatus = status;
            elements.syncIndicator.dataset.status = status;
            elements.syncIndicator.textContent = label || status;
            elements.syncTitle.textContent = label || status;
        }

        function updateSyncTime() {
            if (!appState.ui.lastSync) {
                elements.syncTime.textContent = "–";
                return;
            }
            const date = new Date(appState.ui.lastSync);
            elements.syncTime.textContent = date.toLocaleString("de-AT", { hour: "2-digit", minute: "2-digit" });
        }

        function buildPersistedSettings() {
            const settings = { ...appState.settings };
            if (settings.apiKeyLocked) {
                settings.apiKey = "";
            }
            return settings;
        }

        function setAppInert(isInert) {
            const targets = [elements.header, elements.stage, elements.controlBar, document.querySelector("footer")];
            targets.forEach(target => {
                if (!target) return;
                if (isInert) {
                    target.setAttribute("aria-hidden", "true");
                } else {
                    target.removeAttribute("aria-hidden");
                }
            });
        }

        function openModal(modal) {
            appState.lastFocused = document.activeElement;
            modal.classList.add("open");
            modal.setAttribute("aria-hidden", "false");
            setAppInert(true);
            trapFocus(modal);
            if (!modalStack.includes(modal.id)) {
                modalStack.push(modal.id);
            }
            if (modalStack.length === 1 && !modalHistoryActive) {
                history.pushState({ modal: modal.id }, "");
                modalHistoryActive = true;
            }
        }

        function closeModal(modal, fromPopstate = false) {
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            releaseFocusTrap(modal);
            const index = modalStack.indexOf(modal.id);
            if (index > -1) {
                modalStack.splice(index, 1);
            }
            setAppInert(modalStack.length > 0);
            if (appState.lastFocused) {
                appState.lastFocused.focus();
            }
            if (modalHistoryActive && !fromPopstate && modalStack.length === 0) {
                ignoreNextPop = true;
                history.back();
            }
            if (modalStack.length === 0) {
                modalHistoryActive = false;
            }
        }

        function trapFocus(modal) {
            const focusable = modal.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
            if (!focusable.length) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            modal._focusHandler = (event) => {
                if (event.key !== "Tab") return;
                if (event.shiftKey && document.activeElement === first) {
                    event.preventDefault();
                    last.focus();
                } else if (!event.shiftKey && document.activeElement === last) {
                    event.preventDefault();
                    first.focus();
                }
            };
            modal.addEventListener("keydown", modal._focusHandler);
            first.focus();
        }

        function releaseFocusTrap(modal) {
            if (modal._focusHandler) {
                modal.removeEventListener("keydown", modal._focusHandler);
                modal._focusHandler = null;
            }
        }

        function confirmAction({ title, message, confirmLabel }) {
            return new Promise(resolve => {
                elements.confirmTitle.textContent = title;
                elements.confirmMessage.textContent = message;
                elements.confirmConfirmBtn.textContent = confirmLabel || "Bestätigen";

                const handleConfirm = () => {
                    cleanup();
                    resolve(true);
                };

                const handleCancel = () => {
                    cleanup();
                    resolve(false);
                };

                const cleanup = () => {
                    elements.confirmConfirmBtn.removeEventListener("click", handleConfirm);
                    elements.confirmCancelBtn.removeEventListener("click", handleCancel);
                    elements.confirmCloseBtn.removeEventListener("click", handleCancel);
                    closeModal(elements.confirmModal);
                };

                elements.confirmConfirmBtn.addEventListener("click", handleConfirm);
                elements.confirmCancelBtn.addEventListener("click", handleCancel);
                elements.confirmCloseBtn.addEventListener("click", handleCancel);
                openModal(elements.confirmModal);
            });
        }

        function setStealthMode(enabled) {
            appState.stealthMode = enabled;
            elements.stealthOverlay.classList.toggle("active", enabled);
            elements.stealthOverlay.setAttribute("aria-hidden", String(!enabled));
            if (enabled) {
                elements.stealthOverlay.focus();
            }
        }

        function setupStealthOverlay() {
            let lastTap = 0;
            elements.stealthOverlay.addEventListener("click", () => {
                const now = Date.now();
                if (now - lastTap < 350) {
                    setStealthMode(false);
                }
                lastTap = now;
            });
        }

        function sanitizeImportSettings(settings) {
            if (!settings || typeof settings !== "object") return null;
            return {
                apiProvider: sanitizeEnum(settings.apiProvider, ["openai", "groq"], "openai"),
                apiKey: sanitizeString(settings.apiKey, 200),
                apiKeyEncrypted: sanitizeString(settings.apiKeyEncrypted, 2000),
                apiKeyIv: sanitizeString(settings.apiKeyIv, 200),
                apiKeySalt: sanitizeString(settings.apiKeySalt, 200),
                apiKeyLocked: Boolean(settings.apiKeyLocked),
                modelName: sanitizeString(settings.modelName, 80) || MODEL_DEFAULTS.openai,
                proxyUrl: sanitizeString(settings.proxyUrl, 200),
                department: sanitizeString(settings.department, 40) || "TV",
                storePolicy: sanitizeString(settings.storePolicy, 400),
                themeMode: sanitizeEnum(settings.themeMode, ["auto", "light", "dark"], "auto"),
                densityMode: sanitizeEnum(settings.densityMode, ["compact", "comfortable"], ""),
                densityUserSet: Boolean(settings.densityUserSet)
            };
        }

        function sanitizeCaseItem(item) {
            if (!item || typeof item !== "object") return null;
            const safeId = sanitizeString(item.id || `import_${Date.now()}`, 80);
            const quick = item.content && item.content.quick ? item.content.quick : {};
            const smart = item.content && item.content.smart ? item.content.smart : {};
            const coach = item.content && item.content.coach ? item.content.coach : {};
            return {
                id: safeId,
                objection: sanitizeString(item.objection, 200),
                keywords: sanitizeArray(item.keywords, 40),
                timestamp: sanitizeString(item.timestamp, 60) || new Date().toISOString(),
                meta: {
                    status: sanitizeEnum(item.meta && item.meta.status, ["success", "error", "check_datasheet", "transparency_missing_details"], "success"),
                    pattern: sanitizeString(item.meta && item.meta.pattern, 40) || "trust",
                    safety: sanitizeEnum(item.meta && item.meta.safety, ["clean", "transparency_required", "fact_check_needed"], "clean")
                },
                ui: {
                    color: sanitizeEnum(item.ui && item.ui.color, ["success", "warning", "error"], "success"),
                    icon: sanitizeEnum(item.ui && item.ui.icon, ["shield", "clock", "tag", "info", "users"], "info")
                },
                content: {
                    quick: {
                        entry: sanitizeString(quick.entry, 400),
                        anchor: sanitizeString(quick.anchor, 400),
                        question: sanitizeString(quick.question, 400),
                        bridge: sanitizeString(quick.bridge, 400),
                        close: sanitizeString(quick.close, 400)
                    },
                    smart: {
                        text: sanitizeString(smart.text, 600),
                        closing: sanitizeString(smart.closing, 400)
                    },
                    coach: {
                        diagnosis: sanitizeString(coach.diagnosis, 400),
                        strategy: sanitizeString(coach.strategy, 400),
                        behavioral_fix: sanitizeString(coach.behavioral_fix, 400),
                        drill: sanitizeArray(coach.drill, 200)
                    }
                },
                isMaster: Boolean(item.isMaster)
            };
        }

        function sanitizeLogItem(log) {
            if (!log || typeof log !== "object") return null;
            return {
                id: sanitizeString(log.id, 80) || undefined,
                timestamp: sanitizeString(log.timestamp, 60) || new Date().toISOString(),
                type: sanitizeString(log.type, 40) || "event",
                objection: sanitizeString(log.objection, 200),
                contexts: sanitizeArray(log.contexts, 40),
                data: log.data && typeof log.data === "object" ? log.data : {}
            };
        }

        function initDB() {
            return new Promise(resolve => {
                if (!("indexedDB" in window)) {
                    storage.mode = "local";
                    storage.ready = true;
                    resolve();
                    return;
                }
                const request = indexedDB.open(DB_NAME, DB_VERSION);
                request.onerror = () => {
                    storage.mode = "local";
                    storage.ready = true;
                    resolve();
                };
                request.onsuccess = () => {
                    storage.db = request.result;
                    storage.ready = true;
                    resolve();
                };
                request.onupgradeneeded = (event) => {
                    const db = event.target.result;
                    if (!db.objectStoreNames.contains("settings")) {
                        db.createObjectStore("settings", { keyPath: "id" });
                    }
                    if (!db.objectStoreNames.contains("cases")) {
                        db.createObjectStore("cases", { keyPath: "id" });
                    }
                    if (!db.objectStoreNames.contains("logs")) {
                        db.createObjectStore("logs", { keyPath: "id", autoIncrement: true });
                    }
                };
            });
        }

        function waitForDB() {
            return new Promise(resolve => {
                if (storage.ready) {
                    resolve();
                    return;
                }
                const interval = setInterval(() => {
                    if (storage.ready) {
                        clearInterval(interval);
                        resolve();
                    }
                }, 50);
            });
        }

        async function saveSettings(settings) {
            await waitForDB();
            if (storage.mode === "local") {
                localStorage.setItem("msos_settings", JSON.stringify(settings));
                return;
            }
            const tx = storage.db.transaction("settings", "readwrite");
            tx.objectStore("settings").put({ id: "main", ...settings });
            return new Promise(resolve => {
                tx.oncomplete = () => resolve();
            });
        }

        async function loadSettings() {
            await waitForDB();
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_settings");
                return safeParseJSON(raw, null);
            }
            return new Promise(resolve => {
                const tx = storage.db.transaction("settings", "readonly");
                const req = tx.objectStore("settings").get("main");
                req.onsuccess = () => resolve(req.result || null);
                req.onerror = () => resolve(null);
            });
        }

        async function saveCaseToLibrary(caseData) {
            await waitForDB();
            const baseKeywords = appState.objection.toLowerCase().split(" ").filter(word => word.length > 3);
            const synonymMap = {
                teuer: ["preis", "kostet", "hoch", "viel", "expensive"],
                versicherung: ["garantie", "schutz", "absicherung", "abo"],
                überlegen: ["bedenkzeit", "später", "nachdenken", "warten"],
                rabatt: ["nachlass", "discount", "günstiger", "reduzierung"],
                vergleichen: ["andere", "konkurrenz", "woanders"],
                qualität: ["hochwertig", "premium", "gut"],
                lieferung: ["versand", "transport", "zustellung"],
                garantie: ["gewährleistung", "rückgabe", "umtausch"]
            };

            const enhancedKeywords = [...new Set([
                ...baseKeywords,
                ...baseKeywords.flatMap(keyword => synonymMap[keyword] || [])
            ])];

            const item = {
                id: "case_" + Date.now() + "_" + Math.random().toString(36).slice(2, 9),
                objection: appState.objection,
                keywords: enhancedKeywords,
                timestamp: new Date().toISOString(),
                ...caseData
            };

            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_cases");
                const data = safeParseJSON(raw, []);
                data.push(item);
                localStorage.setItem("msos_cases", JSON.stringify(data));
                return;
            }

            const tx = storage.db.transaction("cases", "readwrite");
            tx.objectStore("cases").put(item);
            return new Promise(resolve => {
                tx.oncomplete = () => resolve();
            });
        }

        async function searchLocalCases(query) {
            await waitForDB();
            const queryLower = query.toLowerCase();
            const queryWords = queryLower.split(" ").filter(word => word.length > 3);
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_cases");
                const results = safeParseJSON(raw, []);
                return findBestMatch(results, queryWords);
            }
            return new Promise((resolve, reject) => {
                const tx = storage.db.transaction("cases", "readonly");
                const store = tx.objectStore("cases");
                const request = store.getAll();
                request.onsuccess = () => {
                    resolve(findBestMatch(request.result, queryWords));
                };
                request.onerror = () => reject(request.error);
            });
        }

        function findBestMatch(results, queryWords) {
            return results.find(item => {
                const keywords = Array.isArray(item.keywords) ? item.keywords : [];
                return keywords.some(keyword => {
                    return queryWords.some(qw => {
                        if (qw.includes(keyword.toLowerCase()) || keyword.toLowerCase().includes(qw)) {
                            return true;
                        }
                        const distance = levenshteinDistance(qw, keyword.toLowerCase());
                        return distance <= 2;
                    });
                });
            }) || null;
        }

        async function logEvent(type, data) {
            await waitForDB();
            const log = {
                timestamp: new Date().toISOString(),
                type,
                objection: appState.objection,
                contexts: [...appState.contexts],
                data: data || {}
            };
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_logs");
                const logs = safeParseJSON(raw, []);
                logs.push(log);
                localStorage.setItem("msos_logs", JSON.stringify(logs));
                return;
            }
            const tx = storage.db.transaction("logs", "readwrite");
            tx.objectStore("logs").add(log);
            return new Promise(resolve => {
                tx.oncomplete = () => resolve();
            });
        }

        async function getAllCases() {
            await waitForDB();
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_cases");
                return safeParseJSON(raw, []);
            }
            return new Promise(resolve => {
                const tx = storage.db.transaction("cases", "readonly");
                const req = tx.objectStore("cases").getAll();
                req.onsuccess = () => resolve(req.result || []);
                req.onerror = () => resolve([]);
            });
        }

        async function getAllLogs() {
            await waitForDB();
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_logs");
                return safeParseJSON(raw, []);
            }
            return new Promise(resolve => {
                const tx = storage.db.transaction("logs", "readonly");
                const req = tx.objectStore("logs").getAll();
                req.onsuccess = () => resolve(req.result || []);
                req.onerror = () => resolve([]);
            });
        }

        async function clearDataStores() {
            await waitForDB();
            if (storage.mode === "local") {
                localStorage.removeItem("msos_cases");
                localStorage.removeItem("msos_logs");
                return;
            }
            const tx = storage.db.transaction(["cases", "logs"], "readwrite");
            tx.objectStore("cases").clear();
            tx.objectStore("logs").clear();
            return new Promise(resolve => {
                tx.oncomplete = () => resolve();
            });
        }

        async function updateStats() {
            const cases = await getAllCases();
            const logs = await getAllLogs();
            appState.stats.cases = cases.length;
            appState.stats.logs = logs.length;
            elements.statCases.textContent = String(appState.stats.cases);
            elements.statLogs.textContent = String(appState.stats.logs);
        }

        function levenshteinDistance(a, b) {
            const matrix = Array.from({ length: b.length + 1 }, () => []);
            for (let i = 0; i <= b.length; i++) matrix[i][0] = i;
            for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
            for (let i = 1; i <= b.length; i++) {
                for (let j = 1; j <= a.length; j++) {
                    if (b.charAt(i - 1) === a.charAt(j - 1)) {
                        matrix[i][j] = matrix[i - 1][j - 1];
                    } else {
                        matrix[i][j] = Math.min(
                            matrix[i - 1][j - 1] + 1,
                            matrix[i][j - 1] + 1,
                            matrix[i - 1][j] + 1
                        );
                    }
                }
            }
            return matrix[b.length][a.length];
        }

        function extractJSON(text) {
            const firstBrace = text.indexOf("{");
            const lastBrace = text.lastIndexOf("}");
            if (firstBrace === -1 || lastBrace === -1) {
                throw new Error("No JSON found in response");
            }
            return text.substring(firstBrace, lastBrace + 1);
        }

        function validateProxyUrl(value) {
            if (!value) return { ok: false };
            try {
                const url = new URL(value, window.location.origin);
                const isSameOrigin = url.origin === window.location.origin && window.location.origin !== "null";
                if (!isSameOrigin) {
                    return { ok: false, reason: "same_origin_required" };
                }
                if (url.protocol !== "https:" && url.protocol !== "http:") {
                    return { ok: false, reason: "protocol" };
                }
                return { ok: true, url: url.toString() };
            } catch (error) {
                return { ok: false, reason: "invalid" };
            }
        }

        async function callAI(objection, contexts) {
            const { apiProvider, apiKey, modelName, proxyUrl, department, storePolicy } = appState.settings;
            if (!apiKey && !proxyUrl) {
                throw new Error("API Key oder Proxy URL erforderlich");
            }
            if (appState.settings.apiKeyLocked) {
                throw new Error("API Key gesperrt");
            }

            const contextMods = [];
            if (contexts.includes("hurry")) contextMods.push("- Kunde ist eilig: Ultra-kurze Antworten, max 2 Sätze pro Abschnitt");
            if (contexts.includes("duo")) contextMods.push("- Kunde ist Paar/Gruppe: Inkludiere beide Personen ('Sie beide', 'für Sie gemeinsam')");
            if (contexts.includes("easy")) contextMods.push("- Kunde will es einfach: Keine Technik-Details, nur Nutzen. Metaphern verwenden");
            if (contexts.includes("techie")) contextMods.push("- Kunde ist technikaffin: Specs erlaubt, aber immer mit Nutzen verknüpfen");

            const systemPrompt = `ROLE: High-End Retail Sales Expert (Austria). Abteilung: ${department}

OUTPUT: STRICT JSON ONLY. NO preamble, NO markdown, NO text before or after the JSON object.

LOGIC (The "Expert Matrix"):
1. VOSS: Start with Labeling/Empathy ("Versteh ich...").
2. CHALLENGER: Reframe the problem (Price -> Cost of Ownership).
3. KAHNEMAN: Anchor high prices down to daily costs.
4. CIALDINI: Use "Alternative Close" (A oder B?), never "Yes/No".

GUARDRAILS:
- Social Proof: General only ("Viele Kundinnen und Kunden..."). Never invent statistics.
- Scarcity: Only if Store Policy has explicit date. Store Policy: "${storePolicy || "keine Aktionen definiert"}"
- Transparency: Mandatory "Abo-Check" if subscription involved. If price unknown: status = "transparency_missing_details"
- Tone: Austrian Professional, natural, short sentences.

KONTEXT-MUTATIONEN:
${contextMods.join("\n")}

OUTPUT FORMAT (STRICT JSON):
{
  "meta": {
    "status": "success | error | check_datasheet | transparency_missing_details",
    "pattern": "price | trust | control | risk | uncertainty | comparison | subscription_aversion",
    "safety": "clean | transparency_required | fact_check_needed"
  },
  "ui": {
    "color": "success | warning | error",
    "icon": "shield | clock | tag | info"
  },
  "content": {
    "quick": {
      "entry": "Einstieg (empathisch, validierend)",
      "anchor": "Anker (Social Proof, Vertrauen)",
      "question": "Frage (öffnet Dialog)",
      "bridge": "Brücke (Mehrwert aufzeigen)",
      "close": "Abschluss (Kontrolle zurückgeben)"
    },
    "smart": {
      "text": "Kurzes, natürliches Verkaufsskript (max 4 Sätze)",
      "closing": "Abschlussfrage"
    },
    "coach": {
      "diagnosis": "Psychologische Einwand-Analyse",
      "strategy": "Strategie-Empfehlung",
      "behavioral_fix": "Verhaltensfix (konkreter Tipp)",
      "drill": ["Übung 1", "Übung 2"]
    }
  }
}`;

            let apiUrl;
            let headers;
            let body;
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 15000);

            if (proxyUrl) {
                const validated = validateProxyUrl(proxyUrl);
                if (!validated.ok) {
                    throw new Error("Proxy URL muss Same-Origin sein");
                }
                apiUrl = validated.url;
                headers = { "Content-Type": "application/json" };
                body = JSON.stringify({ provider: apiProvider, prompt: systemPrompt, objection });
            } else if (apiProvider === "openai") {
                apiUrl = "https://api.openai.com/v1/chat/completions";
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${apiKey}`
                };
                body = JSON.stringify({
                    model: modelName || MODEL_DEFAULTS.openai,
                    messages: [
                        { role: "system", content: systemPrompt },
                        { role: "user", content: objection }
                    ],
                    temperature: 0.7
                });
            } else if (apiProvider === "groq") {
                apiUrl = "https://api.groq.com/openai/v1/chat/completions";
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${apiKey}`
                };
                body = JSON.stringify({
                    model: modelName || MODEL_DEFAULTS.groq,
                    messages: [
                        { role: "system", content: systemPrompt },
                        { role: "user", content: objection }
                    ],
                    temperature: 0.7
                });
            } else {
                throw new Error(`Unbekannter API Provider: ${apiProvider}`);
            }

            const response = await fetch(apiUrl, {
                method: "POST",
                headers,
                body,
                signal: controller.signal,
                referrerPolicy: "no-referrer",
                credentials: "omit"
            });

            clearTimeout(timeout);

            if (!response.ok) {
                throw new Error(`API Error: ${response.status}`);
            }

            const data = await response.json();
            const rawContent = data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content : "";
            const content = extractJSON(rawContent);
            const parsed = JSON.parse(content);
            parsed.id = "ai_" + Date.now() + "_" + Math.random().toString(36).slice(2, 9);
            return parsed;
        }

        function searchSeeds(query) {
            const queryLower = query.toLowerCase();
            const queryWords = queryLower.split(" ").filter(word => word.length > 3);
            return SEED_DATA.find(seed => seed.keywords.some(keyword => {
                return queryWords.some(qw => {
                    if (qw.includes(keyword.toLowerCase()) || keyword.toLowerCase().includes(qw)) {
                        return true;
                    }
                    const distance = levenshteinDistance(qw, keyword.toLowerCase());
                    return distance <= 2;
                });
            }));
        }

        async function handleObjectionSubmit() {
            const objection = elements.objectionInput.value.trim();
            appState.objection = objection;
            if (!objection) {
                haptic([40, 40]);
                showToast("Bitte Einwand eingeben");
                return;
            }

            appState.loading = true;
            setInputBusy(true);
            render();

            try {
                const seedMatch = searchSeeds(objection);
                if (seedMatch) {
                    appState.cards = [seedMatch];
                    await logEvent("seed_match", { cardId: seedMatch.id });
                } else {
                    const localMatch = await searchLocalCases(objection);
                    if (localMatch) {
                        appState.cards = [localMatch];
                        await logEvent("local_match", { cardId: localMatch.id });
                    } else {
                        const aiResponse = await callAI(objection, appState.contexts);
                        appState.cards = [aiResponse];
                        await saveCaseToLibrary(aiResponse);
                        await logEvent("api_call", { provider: appState.settings.apiProvider });
                        await updateStats();
                    }
                }
            } catch (error) {
                appState.cards = [JOKER_CARD];
                await logEvent("error_fallback", { code: error.message });
                showToast("Fehler beim Abruf, Fallback geladen");
            }

            appState.loading = false;
            setInputBusy(false);
            render();
        }

        function setInputBusy(isBusy) {
            elements.micBtn.classList.toggle("processing", isBusy);
            elements.objectionInput.disabled = isBusy;
            elements.submitBtn.disabled = isBusy;
            elements.micBtn.disabled = isBusy || !recognition;
        }

        function resetApp() {
            haptic([40]);
            appState.objection = "";
            appState.contexts = [];
            appState.cards = [];
            elements.objectionInput.value = "";
            elements.contextChips.querySelectorAll(".chip").forEach(chip => {
                chip.setAttribute("aria-pressed", "false");
            });
            updateContextStatus();
            render();
        }

        function renderCards() {
            if (appState.loading) {
                elements.cardsContainer.innerHTML = `
                    <section class="tile loading-state" aria-busy="true">
                        <div class="skeleton-line wide"></div>
                        <div class="skeleton-line"></div>
                        <div class="skeleton-line"></div>
                        <div class="skeleton-line"></div>
                    </section>
                    <section class="tile loading-state" aria-busy="true">
                        <div class="skeleton-line wide"></div>
                        <div class="skeleton-line"></div>
                        <div class="skeleton-line"></div>
                        <div class="skeleton-line"></div>
                    </section>
                `;
                return;
            }

            if (appState.cards.length === 0) {
                elements.cardsContainer.innerHTML = `
                    <section class="tile empty-state">
                        <div class="empty-title">Bereit für Kunden</div>
                        <div class="empty-subtitle">Geben Sie einen Kundeneinwand ein, um sofort eine professionelle Antwort zu erhalten.</div>
                    </section>
                `;
                return;
            }

            const iconMap = {
                shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
                clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
                tag: '<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/>',
                info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
                users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/>'
            };

            const cardsHTML = appState.cards.map(card => {
                const safeId = String(card.id || Date.now()).replace(/[^a-zA-Z0-9_-]/g, "");
                const colorClass = sanitizeEnum(card.ui && card.ui.color, ["success", "warning", "error"], "success");
                const icon = iconMap[card.ui && card.ui.icon] || iconMap.info;
                const quick = card.content && card.content.quick ? card.content.quick : {};
                const smart = card.content && card.content.smart ? card.content.smart : {};
                const coach = card.content && card.content.coach ? card.content.coach : {};
                const drillList = Array.isArray(coach.drill) ? coach.drill : [];
                return `
                    <section class="tile card ${colorClass}">
                        <div class="card-header">
                            <svg class="card-icon" viewBox="0 0 24 24">${icon}</svg>
                            <div class="card-title">Objection Handler</div>
                            <div class="card-badge">${escapeHTML((card.meta && card.meta.pattern) || "trust")}</div>
                        </div>

                        <div class="quick-cues">
                            <div class="cue-block">
                                <div class="cue-label">Einstieg</div>
                                <div class="cue-text">${escapeHTML(quick.entry || "")}</div>
                            </div>
                            <div class="cue-block">
                                <div class="cue-label">Anker</div>
                                <div class="cue-text">${escapeHTML(quick.anchor || "")}</div>
                            </div>
                            <div class="cue-block">
                                <div class="cue-label">Frage</div>
                                <div class="cue-text">${escapeHTML(quick.question || "")}</div>
                            </div>
                        </div>

                        <div class="expandable">
                            <button class="expand-trigger" type="button" aria-expanded="false" aria-controls="smart-${safeId}" data-target="smart-${safeId}">
                                Smart Script
                                <svg class="expand-icon" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
                            </button>
                            <div class="expand-content" id="smart-${safeId}" hidden>
                                <div class="cue-text spacing">${escapeHTML(smart.text || "")}</div>
                                <div class="cue-label">Abschlussfrage</div>
                                <div class="cue-text">${escapeHTML(smart.closing || "")}</div>
                            </div>
                        </div>

                        <div class="expandable">
                            <button class="expand-trigger" type="button" aria-expanded="false" aria-controls="coach-${safeId}" data-target="coach-${safeId}">
                                Coach Mode
                                <svg class="expand-icon" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
                            </button>
                            <div class="expand-content" id="coach-${safeId}" hidden>
                                <div class="coach-block">
                                    <div class="coach-label">Diagnose</div>
                                    <div class="coach-text">${escapeHTML(coach.diagnosis || "")}</div>
                                </div>
                                <div class="coach-block">
                                    <div class="coach-label">Strategie</div>
                                    <div class="coach-text">${escapeHTML(coach.strategy || "")}</div>
                                </div>
                                <div class="coach-block">
                                    <div class="coach-label">Verhaltensfix</div>
                                    <div class="coach-text">${escapeHTML(coach.behavioral_fix || "")}</div>
                                </div>
                                <div class="coach-block">
                                    <div class="coach-label">Übungen</div>
                                    <ul class="drill-list">
                                        ${drillList.map(item => `<li>${escapeHTML(item)}</li>`).join("")}
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <div class="card-actions">
                            <button class="feedback-btn success" type="button" data-feedback="success" data-card="${safeId}">
                                <svg viewBox="0 0 24 24"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3zM7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"/></svg>
                                Erfolgreich
                            </button>
                            <button class="feedback-btn error" type="button" data-feedback="fail" data-card="${safeId}">
                                <svg viewBox="0 0 24 24"><path d="M10 15v4a3 3 0 0 0 3 3l4-9V2H5.72a2 2 0 0 0-2 1.7l-1.38 9a2 2 0 0 0 2 2.3zm7-13h2.67A2.31 2.31 0 0 1 22 4v7a2.31 2.31 0 0 1-2.33 2H17"/></svg>
                                Nicht hilfreich
                            </button>
                        </div>
                    </section>
                `;
            }).join("");

            elements.cardsContainer.innerHTML = cardsHTML;
        }

        function render() {
            elements.deptBadge.textContent = appState.settings.department;
            elements.hudSubtitle.textContent = appState.loading ? "Analyse läuft" : "Bereit";
            updateContextStatus();
            updateTrustStatus();
            updatePolicyTile();
            renderCards();
        }

        function setupSpeechRecognition() {
            const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
            if (!SpeechRecognition) {
                elements.micBtn.disabled = true;
                elements.micBtn.setAttribute("aria-disabled", "true");
                return;
            }
            recognition = new SpeechRecognition();
            recognition.lang = "de-AT";
            recognition.interimResults = false;
            recognition.continuous = false;

            recognition.onresult = (event) => {
                const text = event.results[0][0].transcript;
                appState.objection = text;
                elements.objectionInput.value = text;
                haptic([40, 30, 40]);
                handleObjectionSubmit();
            };

            recognition.onend = () => {
                elements.micBtn.classList.remove("recording");
                elements.micBtn.setAttribute("aria-pressed", "false");
            };

            recognition.onerror = () => {
                elements.micBtn.classList.remove("recording");
                elements.micBtn.classList.remove("processing");
                elements.micBtn.setAttribute("aria-pressed", "false");
                showToast("Spracheingabe fehlgeschlagen");
            };
        }

        async function encryptSecret(secret, passphrase) {
            if (!window.crypto || !window.crypto.subtle) {
                throw new Error("Crypto not supported");
            }
            const enc = new TextEncoder();
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
            const key = await window.crypto.subtle.deriveKey(
                { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
                keyMaterial,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt"]
            );
            const cipher = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(secret));
            return {
                cipher: btoa(String.fromCharCode(...new Uint8Array(cipher))),
                iv: btoa(String.fromCharCode(...iv)),
                salt: btoa(String.fromCharCode(...salt))
            };
        }

        async function decryptSecret(encrypted, passphrase, iv, salt) {
            if (!window.crypto || !window.crypto.subtle) {
                throw new Error("Crypto not supported");
            }
            const enc = new TextEncoder();
            const data = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
            const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
            const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
            const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
            const key = await window.crypto.subtle.deriveKey(
                { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
                keyMaterial,
                { name: "AES-GCM", length: 256 },
                false,
                ["decrypt"]
            );
            const plain = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, key, data);
            return new TextDecoder().decode(plain);
        }

        async function handleLockToggle() {
            const isLocked = appState.settings.apiKeyLocked;
            if (!isLocked) {
                const passphrase = elements.passphraseInput.value.trim();
                const keyValue = elements.apiKey.value.trim();
                if (!passphrase) {
                    showToast("Passphrase fehlt");
                    return;
                }
                if (!keyValue) {
                    showToast("API Key fehlt");
                    return;
                }
                try {
                    const encrypted = await encryptSecret(keyValue, passphrase);
                    appState.settings.apiKeyEncrypted = encrypted.cipher;
                    appState.settings.apiKeyIv = encrypted.iv;
                    appState.settings.apiKeySalt = encrypted.salt;
                    appState.settings.apiKeyLocked = true;
                    appState.settings.apiKey = "";
                    elements.apiKey.value = "";
                    elements.lockStatus.textContent = "Lock aktiv";
                    elements.lockToggleBtn.textContent = "Passphrase-Lock deaktivieren";
                    showToast("Key gesperrt");
                    await saveSettings(buildPersistedSettings());
                    updateTrustStatus();
                } catch (error) {
                    showToast("Passphrase-Lock fehlgeschlagen");
                }
            } else {
                appState.settings.apiKeyLocked = false;
                appState.settings.apiKeyEncrypted = "";
                appState.settings.apiKeyIv = "";
                appState.settings.apiKeySalt = "";
                elements.lockStatus.textContent = "Lock deaktiviert";
                elements.lockToggleBtn.textContent = "Passphrase-Lock aktivieren";
                showToast("Lock deaktiviert");
                await saveSettings(buildPersistedSettings());
                updateTrustStatus();
            }
        }

        async function handleUnlock() {
            if (!appState.settings.apiKeyLocked) {
                showToast("Key ist nicht gesperrt");
                return;
            }
            const passphrase = elements.passphraseInput.value.trim();
            if (!passphrase) {
                showToast("Passphrase fehlt");
                return;
            }
            try {
                const decrypted = await decryptSecret(
                    appState.settings.apiKeyEncrypted,
                    passphrase,
                    appState.settings.apiKeyIv,
                    appState.settings.apiKeySalt
                );
                appState.settings.apiKey = decrypted;
                elements.lockStatus.textContent = "Key entsperrt (Session)";
                showToast("Key entsperrt");
                updateTrustStatus();
            } catch (error) {
                showToast("Passphrase falsch");
            }
        }

        async function exportData() {
            const settings = buildPersistedSettings();
            const cases = await getAllCases();
            const logs = await getAllLogs();
            return {
                version: APP_VERSION,
                exportDate: new Date().toISOString(),
                settings,
                cases,
                logs
            };
        }

        async function importData(file) {
            const raw = await file.text();
            const parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== "object") {
                throw new Error("Invalid import");
            }

            const settings = sanitizeImportSettings(parsed.settings);
            const cases = Array.isArray(parsed.cases) ? parsed.cases.map(sanitizeCaseItem).filter(Boolean) : [];
            const logs = Array.isArray(parsed.logs) ? parsed.logs.map(sanitizeLogItem).filter(Boolean) : [];

            if (settings) {
                appState.settings = { ...appState.settings, ...settings };
                applyTheme(appState.settings.themeMode, false);
                if (appState.settings.densityMode) {
                    applyDensity(appState.settings.densityMode, appState.settings.densityUserSet, false);
                }
                await saveSettings(buildPersistedSettings());
            }

            if (storage.mode === "local") {
                const existingCases = await getAllCases();
                const existingLogs = await getAllLogs();
                localStorage.setItem("msos_cases", JSON.stringify([...existingCases, ...cases]));
                localStorage.setItem("msos_logs", JSON.stringify([...existingLogs, ...logs]));
            } else {
                const tx = storage.db.transaction(["cases", "logs"], "readwrite");
                const caseStore = tx.objectStore("cases");
                cases.forEach(item => caseStore.put(item));
                const logStore = tx.objectStore("logs");
                logs.forEach(item => logStore.add(item));
                await new Promise(resolve => {
                    tx.oncomplete = () => resolve();
                });
            }
            await updateStats();
        }

        async function verifyLibraryHash(buffer) {
            if (!window.crypto || !window.crypto.subtle) {
                return false;
            }
            const hashBuffer = await window.crypto.subtle.digest("SHA-256", buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashBase64 = btoa(String.fromCharCode(...hashArray));
            return hashBase64 === LIBRARY_SHA256;
        }

        async function syncLibrary(manual = false) {
            if (!navigator.onLine) {
                setSyncStatus("offline", "Offline");
                if (manual) {
                    showToast("Offline – Sync pausiert");
                }
                return;
            }
            setSyncStatus("syncing", "Syncing");
            try {
                const response = await fetch(LIBRARY_URL, {
                    cache: "no-store",
                    credentials: "omit",
                    referrerPolicy: "no-referrer"
                });
                if (!response.ok) {
                    throw new Error("Sync failed");
                }
                const buffer = await response.arrayBuffer();
                const hashOk = await verifyLibraryHash(buffer);
                if (!hashOk) {
                    throw new Error("Integrity failed");
                }
                const text = new TextDecoder().decode(buffer);
                const data = JSON.parse(text);
                if (!Array.isArray(data)) {
                    throw new Error("Format invalid");
                }
                if (storage.mode === "local") {
                    const existing = await getAllCases();
                    const byId = new Map(existing.map(item => [item.id, item]));
                    data.forEach(item => {
                        const sanitized = sanitizeCaseItem(item);
                        if (sanitized) {
                            sanitized.isMaster = true;
                            byId.set(sanitized.id, sanitized);
                        }
                    });
                    localStorage.setItem("msos_cases", JSON.stringify(Array.from(byId.values())));
                } else {
                    const tx = storage.db.transaction("cases", "readwrite");
                    const store = tx.objectStore("cases");
                    data.forEach(item => {
                        const sanitized = sanitizeCaseItem(item);
                        if (sanitized) {
                            sanitized.isMaster = true;
                            store.put(sanitized);
                        }
                    });
                    await new Promise(resolve => {
                        tx.oncomplete = () => resolve();
                    });
                }
                appState.ui.lastSync = new Date().toISOString();
                setSyncStatus("ok", "Sync OK");
                updateSyncTime();
                await updateStats();
                if (manual) {
                    showToast("Sync abgeschlossen");
                }
            } catch (error) {
                setSyncStatus("error", "Sync Fehler");
                if (manual) {
                    showToast("Sync fehlgeschlagen");
                }
            }
        }

        function setupViewportHandling() {
            if (!window.visualViewport) return;
            const update = () => {
                const offset = Math.max(0, window.innerHeight - window.visualViewport.height - window.visualViewport.offsetTop);
                document.documentElement.style.setProperty("--keyboard-offset", `${Math.round(offset)}px`);
            };
            window.visualViewport.addEventListener("resize", update, { passive: true });
            window.visualViewport.addEventListener("scroll", update, { passive: true });
            update();
        }

        function setupControlBarObserver() {
            if (!elements.controlBar) return;
            const update = () => {
                document.documentElement.style.setProperty("--control-bar-height", `${elements.controlBar.offsetHeight}px`);
            };
            update();
            if ("ResizeObserver" in window) {
                controlBarObserver = new ResizeObserver(update);
                controlBarObserver.observe(elements.controlBar);
            }
        }

        function setupEvents() {
            elements.resetBtn.addEventListener("click", (event) => {
                event.stopPropagation();
                resetApp();
            });

            elements.settingsBtn.addEventListener("click", () => {
                openSettings();
            });

            elements.closeSettingsBtn.addEventListener("click", () => {
                closeModal(elements.settingsModal);
            });

            elements.settingsModal.addEventListener("click", (event) => {
                if (event.target === elements.settingsModal) {
                    closeModal(elements.settingsModal);
                }
            });

            elements.confirmModal.addEventListener("click", (event) => {
                if (event.target === elements.confirmModal) {
                    closeModal(elements.confirmModal);
                }
            });

            elements.themeToggleBtn.addEventListener("click", () => {
                const cycle = ["auto", "light", "dark"];
                const current = appState.settings.themeMode;
                const next = cycle[(cycle.indexOf(current) + 1) % cycle.length];
                applyTheme(next);
                updateTrustStatus();
            });

            elements.densityToggleBtn.addEventListener("click", () => {
                const next = appState.settings.densityMode === "compact" ? "comfortable" : "compact";
                applyDensity(next, true);
            });

            elements.syncBtn.addEventListener("click", () => {
                syncLibrary(true);
            });

            elements.stealthBtn.addEventListener("click", async () => {
                const confirmed = await confirmAction({
                    title: "Stealth aktivieren?",
                    message: "Display wird abgedunkelt. Zweimal tippen oder ESC beendet den Modus.",
                    confirmLabel: "Aktivieren"
                });
                if (confirmed) {
                    setStealthMode(true);
                }
            });

            elements.contextChips.addEventListener("click", (event) => {
                const chip = event.target.closest(".chip");
                if (!chip) return;
                const context = chip.dataset.context;
                const index = appState.contexts.indexOf(context);
                if (index > -1) {
                    appState.contexts.splice(index, 1);
                    chip.setAttribute("aria-pressed", "false");
                } else {
                    appState.contexts.push(context);
                    chip.setAttribute("aria-pressed", "true");
                }
                updateContextStatus();
            });

            elements.objectionInput.addEventListener("input", (event) => {
                appState.objection = event.target.value;
            });

            elements.objectionInput.addEventListener("keydown", (event) => {
                if (event.key === "Enter" && !event.isComposing) {
                    event.preventDefault();
                    handleObjectionSubmit();
                }
            });

            elements.submitBtn.addEventListener("click", () => {
                handleObjectionSubmit();
            });

            elements.micBtn.addEventListener("click", () => {
                if (!recognition) {
                    showToast("Spracheingabe nicht unterstützt");
                    return;
                }
                if (elements.micBtn.classList.contains("recording")) {
                    recognition.stop();
                    return;
                }
                elements.micBtn.classList.add("recording");
                elements.micBtn.setAttribute("aria-pressed", "true");
                recognition.start();
            });

            elements.cardsContainer.addEventListener("click", (event) => {
                const trigger = event.target.closest(".expand-trigger");
                if (trigger) {
                    const targetId = trigger.dataset.target;
                    const content = document.getElementById(targetId);
                    const icon = trigger.querySelector(".expand-icon");
                    const isOpen = trigger.getAttribute("aria-expanded") === "true";
                    trigger.setAttribute("aria-expanded", String(!isOpen));
                    content.classList.toggle("open", !isOpen);
                    content.hidden = isOpen;
                    icon.classList.toggle("open", !isOpen);
                }

                const feedbackBtn = event.target.closest(".feedback-btn");
                if (feedbackBtn) {
                    const feedback = feedbackBtn.dataset.feedback;
                    const cardId = feedbackBtn.dataset.card;
                    logEvent("feedback", { cardId, feedback });
                    showToast(feedback === "success" ? "Feedback gespeichert" : "Danke für Ihr Feedback");
                }
            });

            elements.apiProvider.addEventListener("change", () => {
                const previous = appState.settings.apiProvider;
                const next = elements.apiProvider.value;
                const previousDefault = MODEL_DEFAULTS[previous];
                const currentModel = elements.modelName.value.trim();
                if (!currentModel || currentModel === previousDefault) {
                    elements.modelName.value = MODEL_DEFAULTS[next];
                }
            });

            elements.lockToggleBtn.addEventListener("click", () => {
                handleLockToggle();
            });

            elements.unlockBtn.addEventListener("click", () => {
                handleUnlock();
            });

            elements.exportBtn.addEventListener("click", async () => {
                const confirmed = await confirmAction({
                    title: "Export starten?",
                    message: "Export enthält Settings, Cases und Logs. API Key nur, wenn nicht gesperrt.",
                    confirmLabel: "Exportieren"
                });
                if (!confirmed) return;
                const data = await exportData();
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const anchor = document.createElement("a");
                anchor.href = url;
                anchor.download = `mehic_sales_os_export_${Date.now()}.json`;
                anchor.click();
                URL.revokeObjectURL(url);
                showToast("Export abgeschlossen");
            });

            elements.importBtn.addEventListener("click", () => {
                elements.importFile.value = "";
                elements.importFile.click();
            });

            elements.importFile.addEventListener("change", async (event) => {
                const file = event.target.files[0];
                if (!file) return;
                const confirmed = await confirmAction({
                    title: "Import starten?",
                    message: "Settings werden überschrieben, Cases/Logs hinzugefügt.",
                    confirmLabel: "Importieren"
                });
                if (!confirmed) return;
                try {
                    await importData(file);
                    showToast("Import abgeschlossen");
                    render();
                } catch (error) {
                    showToast("Import fehlgeschlagen");
                }
            });

            elements.clearBtn.addEventListener("click", async () => {
                const confirmed = await confirmAction({
                    title: "Alle Daten löschen?",
                    message: "Cases und Logs werden dauerhaft entfernt. Dieser Schritt ist irreversibel.",
                    confirmLabel: "Löschen"
                });
                if (!confirmed) return;
                await clearDataStores();
                resetApp();
                await updateStats();
                showToast("Daten gelöscht");
            });

            elements.saveSettingsBtn.addEventListener("click", async () => {
                appState.settings.apiProvider = elements.apiProvider.value;
                appState.settings.modelName = elements.modelName.value.trim() || MODEL_DEFAULTS[appState.settings.apiProvider];
                const proxyValue = elements.proxyUrl.value.trim();
                const proxyCheck = validateProxyUrl(proxyValue);
                if (proxyValue && !proxyCheck.ok) {
                    showToast("Proxy nur Same-Origin erlaubt");
                    appState.settings.proxyUrl = "";
                    elements.proxyUrl.value = "";
                } else {
                    appState.settings.proxyUrl = proxyValue;
                }
                appState.settings.department = elements.department.value;
                appState.settings.storePolicy = elements.storePolicy.value.trim();
                if (!appState.settings.apiKeyLocked) {
                    appState.settings.apiKey = elements.apiKey.value.trim();
                }
                const themeMode = document.querySelector("input[name='themeMode']:checked");
                const densityMode = document.querySelector("input[name='densityMode']:checked");
                if (themeMode) applyTheme(themeMode.value, false);
                if (densityMode) applyDensity(densityMode.value, true, false);
                await saveSettings(buildPersistedSettings());
                updatePolicyTile();
                updateTrustStatus();
                render();
                showToast("Einstellungen gespeichert");
                closeModal(elements.settingsModal);
            });

            elements.themeAuto.addEventListener("change", () => applyTheme("auto"));
            elements.themeLight.addEventListener("change", () => applyTheme("light"));
            elements.themeDark.addEventListener("change", () => applyTheme("dark"));

            elements.densityCompact.addEventListener("change", () => applyDensity("compact", true));
            elements.densityComfortable.addEventListener("change", () => applyDensity("comfortable", true));

            window.addEventListener("online", updateOnlineStatus, { passive: true });
            window.addEventListener("offline", updateOnlineStatus, { passive: true });

            document.addEventListener("keydown", (event) => {
                if (event.key === "Escape") {
                    if (elements.confirmModal.classList.contains("open")) {
                        closeModal(elements.confirmModal);
                        return;
                    }
                    if (elements.settingsModal.classList.contains("open")) {
                        closeModal(elements.settingsModal);
                        return;
                    }
                    if (appState.stealthMode) {
                        setStealthMode(false);
                    }
                }

                if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
                    event.preventDefault();
                    elements.objectionInput.focus();
                }
                if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "t") {
                    event.preventDefault();
                    elements.themeToggleBtn.click();
                }
                if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "d") {
                    event.preventDefault();
                    elements.densityToggleBtn.click();
                }
                if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
                    event.preventDefault();
                    openSettings();
                }
            });

            window.addEventListener("popstate", () => {
                if (ignoreNextPop) {
                    ignoreNextPop = false;
                    return;
                }
                const activeModalId = modalStack[modalStack.length - 1];
                if (activeModalId) {
                    const activeModal = document.getElementById(activeModalId);
                    if (activeModal) {
                        closeModal(activeModal, true);
                    }
                }
            });

            const themeListener = () => {
                if (appState.settings.themeMode === "auto") {
                    applyTheme("auto", false);
                }
            };
            if (themeMedia.addEventListener) {
                themeMedia.addEventListener("change", themeListener);
            } else if (themeMedia.addListener) {
                themeMedia.addListener(themeListener);
            }

            const motionListener = () => {
                updateTrustStatus();
            };
            if (reduceMotionMedia.addEventListener) {
                reduceMotionMedia.addEventListener("change", motionListener);
            } else if (reduceMotionMedia.addListener) {
                reduceMotionMedia.addListener(motionListener);
            }

            window.addEventListener("resize", () => {
                if (densityResizeRaf) {
                    cancelAnimationFrame(densityResizeRaf);
                }
                densityResizeRaf = requestAnimationFrame(() => {
                    if (!appState.settings.densityUserSet) {
                        const nextDensity = computeDensity(window.innerWidth);
                        if (nextDensity !== appState.settings.densityMode) {
                            applyDensity(nextDensity, false);
                        }
                    }
                    densityResizeRaf = null;
                });
            });
        }

        function openSettings() {
            elements.apiProvider.value = appState.settings.apiProvider;
            elements.apiKey.value = appState.settings.apiKeyLocked ? "" : appState.settings.apiKey;
            elements.modelName.value = appState.settings.modelName;
            elements.proxyUrl.value = appState.settings.proxyUrl;
            elements.department.value = appState.settings.department;
            elements.storePolicy.value = appState.settings.storePolicy;
            elements.lockStatus.textContent = appState.settings.apiKeyLocked ? "Lock aktiv" : "Lock deaktiviert";
            elements.lockToggleBtn.textContent = appState.settings.apiKeyLocked ? "Passphrase-Lock deaktivieren" : "Passphrase-Lock aktivieren";

            elements.themeAuto.checked = appState.settings.themeMode === "auto";
            elements.themeLight.checked = appState.settings.themeMode === "light";
            elements.themeDark.checked = appState.settings.themeMode === "dark";

            elements.densityCompact.checked = appState.settings.densityMode === "compact";
            elements.densityComfortable.checked = appState.settings.densityMode === "comfortable";

            openModal(elements.settingsModal);
        }

        function setupWakeLockReacquisition() {
            document.addEventListener("visibilitychange", async () => {
                if (document.visibilityState === "visible") {
                    await requestWakeLock();
                }
            });
        }

        let wakeLock = null;

        async function requestWakeLock() {
            if (!("wakeLock" in navigator)) return;
            try {
                wakeLock = await navigator.wakeLock.request("screen");
            } catch (error) {
                wakeLock = null;
            }
        }

        async function init() {
            cacheElements();
            await initDB();
            const savedSettings = await loadSettings();
            if (savedSettings) {
                appState.settings = { ...appState.settings, ...savedSettings };
            }

            const preferredDensity = appState.settings.densityMode || computeDensity(window.innerWidth);
            applyDensity(preferredDensity, appState.settings.densityUserSet, false);
            applyTheme(appState.settings.themeMode, false);

            setupEvents();
            setupSpeechRecognition();
            setupViewportHandling();
            setupControlBarObserver();
            setupStealthOverlay();
            setupWakeLockReacquisition();
            updateOnlineStatus();
            updatePolicyTile();
            updateTrustStatus();
            render();
            await updateStats();
            requestWakeLock();

            elements.buildInfo.textContent = `Build: ${BUILD_SIGNATURE}`;
            syncLibrary(false);
        }

        init();
    </script>
</body>
</html>
```

BLOCK 3: PATCH CSS komplett
```css
        *,
        *::before,
        *::after {
            box-sizing: border-box;
        }

        html {
            height: 100%;
            text-size-adjust: 100%;
        }

        :root {
            --font-sans: system-ui, -apple-system, "SF Pro Text", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
            --font-mono: ui-monospace, "SF Mono", Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;

            --color-bg: #F3F4F6;
            --color-surface: #FFFFFF;
            --color-elevated: #FFFFFF;
            --color-border: rgba(0, 0, 0, 0.06);
            --color-divider: rgba(0, 0, 0, 0.08);
            --color-text-primary: #111827;
            --color-text-secondary: #6B7280;
            --color-text-muted: #9CA3AF;
            --color-accent: #E3000F;
            --color-danger: #DC2626;
            --color-warning: #F59E0B;
            --color-success: #10B981;
            --color-glass: rgba(255, 255, 255, 0.72);
            --color-glass-border: rgba(255, 255, 255, 0.35);
            --color-focus: rgba(227, 0, 15, 0.35);
            --color-selection: rgba(227, 0, 15, 0.18);
            --color-hover: rgba(17, 24, 39, 0.04);
            --color-pressed: rgba(17, 24, 39, 0.08);
            --color-toast: #111827;
            --color-toast-text: #FFFFFF;
            --color-skeleton-base: #E5E7EB;
            --color-skeleton-shine: #F3F4F6;
            --color-scrollbar-thumb: rgba(17, 24, 39, 0.25);
            --color-scrollbar-track: rgba(17, 24, 39, 0.08);
            --color-backdrop: rgba(0, 0, 0, 0.6);

            --shadow-1: 0 1px 2px rgba(0, 0, 0, 0.06);
            --shadow-2: 0 8px 24px rgba(0, 0, 0, 0.08);
            --shadow-3: 0 20px 48px rgba(0, 0, 0, 0.12);

            --radius-1: 10px;
            --radius-2: 14px;
            --radius-3: 18px;
            --radius-pill: 999px;

            --space-1: 4px;
            --space-2: 8px;
            --space-3: 12px;
            --space-4: 16px;
            --space-5: 20px;
            --space-6: 24px;
            --space-7: 32px;
            --space-8: 40px;

            --tap-min: 44px;
            --font-size-base: 16px;
            --tile-padding: 24px;
            --control-bar-padding: 20px;
            --input-height: 54px;

            --easing-standard: cubic-bezier(0.2, 0.8, 0.2, 1);
            --duration-fast: 120ms;
            --duration-medium: 240ms;
            --duration-slow: 360ms;
            --outline-offset: 2px;

            --safe-top: env(safe-area-inset-top);
            --safe-bottom: env(safe-area-inset-bottom);
            --safe-left: env(safe-area-inset-left);
            --safe-right: env(safe-area-inset-right);

            --keyboard-offset: 0px;
            --control-bar-height: 140px;
        }

        html[data-theme="dark"] {
            --color-bg: #09090B;
            --color-surface: #18181B;
            --color-elevated: #1F1F23;
            --color-border: #27272A;
            --color-divider: rgba(255, 255, 255, 0.08);
            --color-text-primary: #FAFAFA;
            --color-text-secondary: #A1A1AA;
            --color-text-muted: #71717A;
            --color-accent: #E3000F;
            --color-danger: #F43F5E;
            --color-warning: #FBBF24;
            --color-success: #34D399;
            --color-glass: rgba(24, 24, 27, 0.7);
            --color-glass-border: rgba(255, 255, 255, 0.08);
            --color-focus: rgba(227, 0, 15, 0.45);
            --color-selection: rgba(227, 0, 15, 0.28);
            --color-hover: rgba(250, 250, 250, 0.06);
            --color-pressed: rgba(250, 250, 250, 0.12);
            --color-toast: #F8FAFC;
            --color-toast-text: #0B0B0D;
            --color-skeleton-base: #27272A;
            --color-skeleton-shine: #1F1F23;
            --color-scrollbar-thumb: rgba(250, 250, 250, 0.25);
            --color-scrollbar-track: rgba(250, 250, 250, 0.08);

            --shadow-1: 0 1px 2px rgba(0, 0, 0, 0.4);
            --shadow-2: 0 10px 30px rgba(0, 0, 0, 0.5);
            --shadow-3: 0 24px 60px rgba(0, 0, 0, 0.6);
        }

        html[data-density="compact"] {
            --tile-padding: 18px;
            --control-bar-padding: 16px;
            --font-size-base: 14px;
            --input-height: 46px;
        }

        html[data-density="comfortable"] {
            --tile-padding: 24px;
            --control-bar-padding: 20px;
            --font-size-base: 16px;
            --input-height: 54px;
        }

        body {
            margin: 0;
            font-family: var(--font-sans);
            font-size: var(--font-size-base);
            line-height: 1.6;
            font-variant-numeric: tabular-nums;
            background: var(--color-bg);
            color: var(--color-text-primary);
            -webkit-font-smoothing: antialiased;
            text-rendering: optimizeLegibility;
            overflow-x: hidden;
            min-height: 100dvh;
            display: flex;
            flex-direction: column;
        }

        ::selection {
            background: var(--color-selection);
        }

        a {
            color: inherit;
        }

        button,
        input,
        select,
        textarea {
            font: inherit;
            color: inherit;
        }

        button {
            background: none;
            border: none;
            padding: 0;
            cursor: pointer;
            touch-action: manipulation;
        }

        button:disabled,
        input:disabled,
        select:disabled,
        textarea:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        button:focus-visible,
        input:focus-visible,
        select:focus-visible,
        textarea:focus-visible,
        a:focus-visible,
        [tabindex="0"]:focus-visible {
            outline: 2px solid transparent;
            box-shadow: 0 0 0 3px var(--color-focus);
            outline-offset: var(--outline-offset);
        }

        .skip-link {
            position: absolute;
            left: -999px;
            top: 0;
            background: var(--color-accent);
            color: #FFFFFF;
            padding: var(--space-2) var(--space-4);
            border-radius: var(--radius-2);
            z-index: 5000;
        }

        .skip-link:focus {
            left: var(--space-4);
            top: calc(var(--space-4) + var(--safe-top));
        }

        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            border: 0;
        }

        .header {
            position: sticky;
            top: 0;
            z-index: 200;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: var(--space-4);
            padding: calc(var(--space-4) + var(--safe-top)) calc(var(--space-6) + var(--safe-right)) var(--space-4) calc(var(--space-6) + var(--safe-left));
            background: var(--color-glass);
            border-bottom: 1px solid var(--color-divider);
            box-shadow: var(--shadow-1);
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
        }

        .logo-container {
            display: flex;
            align-items: center;
            gap: var(--space-3);
        }

        .logo-svg {
            width: 44px;
            height: 44px;
        }

        .logo-text {
            font-size: 18px;
            font-weight: 800;
            letter-spacing: -0.3px;
            color: var(--color-text-primary);
        }

        .logo-text span {
            font-weight: 300;
            color: var(--color-text-secondary);
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: var(--space-2);
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            padding: 6px 12px;
            border-radius: var(--radius-pill);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            min-height: var(--tap-min);
        }

        .status-pill[data-status="online"] .status-dot {
            background: var(--color-success);
        }

        .status-pill[data-status="offline"] .status-dot {
            background: var(--color-danger);
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }

        .dept-badge {
            padding: 6px 12px;
            border-radius: var(--radius-pill);
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            background: var(--color-accent);
            color: #FFFFFF;
            min-height: var(--tap-min);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--shadow-1);
        }

        .toggle-btn {
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            padding: 8px 12px;
            border-radius: var(--radius-pill);
            border: 1px solid var(--color-border);
            background: var(--color-surface);
            min-height: var(--tap-min);
            transition: background var(--duration-fast) var(--easing-standard), border var(--duration-fast) var(--easing-standard);
        }

        .toggle-btn:hover {
            background: var(--color-hover);
        }

        .toggle-btn:active {
            background: var(--color-pressed);
        }

        .toggle-btn svg {
            width: 18px;
            height: 18px;
            stroke: var(--color-text-primary);
            fill: none;
            stroke-width: 2;
        }

        .toggle-label {
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            color: var(--color-text-secondary);
            white-space: nowrap;
        }

        .icon-btn {
            width: var(--tap-min);
            height: var(--tap-min);
            border-radius: var(--radius-2);
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: transform var(--duration-fast) var(--easing-standard), background var(--duration-fast) var(--easing-standard);
        }

        .icon-btn:hover {
            background: var(--color-hover);
        }

        .icon-btn:active {
            transform: scale(0.98);
            background: var(--color-pressed);
        }

        .icon-btn svg {
            width: 18px;
            height: 18px;
            stroke: var(--color-text-primary);
            fill: none;
            stroke-width: 2.2;
            stroke-linecap: round;
            stroke-linejoin: round;
        }

        .offline-banner {
            display: none;
            align-items: center;
            justify-content: center;
            gap: var(--space-2);
            padding: var(--space-2) var(--space-4);
            background: rgba(220, 38, 38, 0.12);
            color: var(--color-danger);
            font-weight: 700;
            font-size: 13px;
            letter-spacing: 0.3px;
            border-bottom: 1px solid var(--color-divider);
        }

        .offline-banner.show {
            display: flex;
        }

        .stage {
            flex: 1;
            overflow-y: auto;
            padding: var(--space-6);
            padding-bottom: calc(var(--control-bar-height) + var(--keyboard-offset) + var(--space-6) + var(--safe-bottom));
            overscroll-behavior: contain;
        }

        .bento-grid {
            display: grid;
            gap: var(--space-5);
            grid-template-columns: 1fr;
        }

        .tile {
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-3);
            padding: var(--tile-padding);
            box-shadow: var(--shadow-1);
            position: relative;
        }

        .tile.glass {
            background: var(--color-glass);
            border: 1px solid var(--color-glass-border);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
        }

        .tile-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: var(--space-3);
            margin-bottom: var(--space-4);
        }

        .tile-title {
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-secondary);
        }

        .tile-subtitle {
            font-size: 20px;
            font-weight: 800;
            color: var(--color-text-primary);
            margin-top: var(--space-2);
        }

        .tile-desc {
            font-size: 14px;
            color: var(--color-text-secondary);
        }

        .stat-grid {
            display: grid;
            gap: var(--space-4);
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
        }

        .stat {
            display: flex;
            flex-direction: column;
            gap: var(--space-1);
        }

        .stat-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-muted);
            font-weight: 700;
        }

        .stat-value {
            font-size: 20px;
            font-weight: 800;
            color: var(--color-text-primary);
        }

        .pill-row {
            display: flex;
            flex-wrap: wrap;
            gap: var(--space-2);
            margin-top: var(--space-4);
        }

        .pill {
            padding: 6px 10px;
            border-radius: var(--radius-pill);
            border: 1px solid var(--color-border);
            font-size: 12px;
            font-weight: 600;
            color: var(--color-text-secondary);
            background: var(--color-elevated);
        }

        .sync-indicator {
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            padding: 6px 12px;
            border-radius: var(--radius-pill);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            border: 1px solid var(--color-border);
            background: var(--color-elevated);
            white-space: nowrap;
        }

        .sync-indicator[data-status="syncing"] {
            color: var(--color-warning);
            border-color: rgba(245, 158, 11, 0.4);
        }

        .sync-indicator[data-status="ok"] {
            color: var(--color-success);
            border-color: rgba(16, 185, 129, 0.4);
        }

        .sync-indicator[data-status="error"],
        .sync-indicator[data-status="offline"] {
            color: var(--color-danger);
            border-color: rgba(220, 38, 38, 0.4);
        }

        .shortcut-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: var(--space-3);
            padding: var(--space-2) 0;
            border-bottom: 1px solid var(--color-divider);
        }

        .shortcut-row:last-child {
            border-bottom: none;
        }

        .shortcut-key {
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: 700;
            padding: 4px 8px;
            border-radius: var(--radius-1);
            background: var(--color-elevated);
            border: 1px solid var(--color-border);
        }

        .bento-cards {
            display: contents;
        }

        .card {
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: "";
            position: absolute;
            left: 0;
            top: 0;
            width: 4px;
            height: 100%;
            background: var(--color-accent);
        }

        .card.success::before {
            background: var(--color-success);
        }

        .card.warning::before {
            background: var(--color-warning);
        }

        .card.error::before {
            background: var(--color-danger);
        }

        .card-header {
            display: flex;
            align-items: center;
            gap: var(--space-3);
            margin-bottom: var(--space-4);
        }

        .card-icon {
            width: 28px;
            height: 28px;
            stroke: var(--color-accent);
            fill: none;
            stroke-width: 2.2;
        }

        .card-title {
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-secondary);
        }

        .card-badge {
            margin-left: auto;
            padding: 4px 8px;
            border-radius: var(--radius-1);
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            background: var(--color-elevated);
            border: 1px solid var(--color-border);
            color: var(--color-text-secondary);
        }

        .quick-cues {
            display: grid;
            gap: var(--space-4);
        }

        .cue-label {
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            color: var(--color-text-muted);
            margin-bottom: var(--space-2);
        }

        .cue-text {
            font-size: 14px;
            color: var(--color-text-primary);
        }

        .cue-text.spacing {
            margin-bottom: var(--space-3);
        }

        .expandable {
            margin-top: var(--space-4);
            padding-top: var(--space-4);
            border-top: 1px solid var(--color-divider);
        }

        .expand-trigger {
            display: flex;
            align-items: center;
            justify-content: space-between;
            width: 100%;
            padding: var(--space-2) 0;
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-primary);
        }

        .expand-trigger:hover {
            color: var(--color-text-secondary);
        }

        .expand-icon {
            width: 18px;
            height: 18px;
            stroke: currentColor;
            fill: none;
            stroke-width: 2.2;
            transition: transform var(--duration-medium) var(--easing-standard);
        }

        .expand-icon.open {
            transform: rotate(180deg);
        }

        .expand-content {
            overflow: hidden;
            max-height: 0;
            opacity: 0;
            transition: max-height var(--duration-slow) var(--easing-standard), opacity var(--duration-medium) var(--easing-standard);
        }

        .expand-content.open {
            max-height: 2000px;
            opacity: 1;
            padding-top: var(--space-3);
        }

        .coach-block {
            margin-bottom: var(--space-4);
        }

        .coach-label {
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-accent);
            margin-bottom: var(--space-2);
        }

        .coach-text {
            font-size: 13px;
            color: var(--color-text-primary);
        }

        .drill-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .drill-list li {
            padding-left: 18px;
            position: relative;
            font-size: 13px;
            color: var(--color-text-secondary);
            margin-bottom: var(--space-2);
        }

        .drill-list li::before {
            content: "→";
            position: absolute;
            left: 0;
            color: var(--color-accent);
            font-weight: 900;
        }

        .card-actions {
            margin-top: var(--space-4);
            padding-top: var(--space-4);
            border-top: 1px solid var(--color-divider);
            display: grid;
            gap: var(--space-3);
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
        }

        .feedback-btn {
            padding: 10px;
            border-radius: var(--radius-2);
            border: 1px solid var(--color-border);
            background: var(--color-elevated);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: var(--space-2);
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }

        .feedback-btn.success {
            color: var(--color-success);
            border-color: rgba(16, 185, 129, 0.4);
        }

        .feedback-btn.error {
            color: var(--color-danger);
            border-color: rgba(220, 38, 38, 0.4);
        }

        .feedback-btn svg {
            width: 16px;
            height: 16px;
            stroke: currentColor;
            fill: none;
            stroke-width: 2.2;
        }

        .empty-state,
        .loading-state {
            text-align: center;
            padding: var(--space-7) var(--space-4);
        }

        .empty-title {
            font-size: 20px;
            font-weight: 800;
            color: var(--color-text-primary);
            margin-bottom: var(--space-2);
        }

        .empty-subtitle {
            font-size: 14px;
            color: var(--color-text-secondary);
        }

        .skeleton-line {
            height: 14px;
            border-radius: var(--radius-pill);
            background: linear-gradient(90deg, var(--color-skeleton-base), var(--color-skeleton-shine), var(--color-skeleton-base));
            background-size: 200% 100%;
            animation: shimmer 1.4s infinite;
            margin-bottom: var(--space-2);
        }

        .skeleton-line.wide {
            height: 18px;
        }

        @keyframes shimmer {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        .control-bar {
            position: fixed;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: 300;
            padding: var(--control-bar-padding);
            padding-bottom: calc(var(--control-bar-padding) + var(--safe-bottom));
            background: var(--color-glass);
            border-top: 1px solid var(--color-divider);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            box-shadow: var(--shadow-2);
            transform: translateY(calc(-1 * var(--keyboard-offset)));
        }

        .context-chips {
            display: flex;
            gap: var(--space-2);
            overflow-x: auto;
            padding-bottom: var(--space-2);
            margin-bottom: var(--space-3);
            scrollbar-width: none;
        }

        .context-chips::-webkit-scrollbar {
            display: none;
        }

        .chip {
            min-height: var(--tap-min);
            padding: 8px 14px;
            border-radius: var(--radius-pill);
            border: 1px solid var(--color-border);
            background: var(--color-surface);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.2px;
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            white-space: nowrap;
            transition: transform var(--duration-fast) var(--easing-standard), background var(--duration-fast) var(--easing-standard);
        }

        .chip[aria-pressed="true"] {
            background: var(--color-accent);
            color: #FFFFFF;
            border-color: var(--color-accent);
        }

        .chip svg {
            width: 16px;
            height: 16px;
            stroke: currentColor;
            fill: none;
            stroke-width: 2.2;
        }

        .input-area {
            display: grid;
            gap: var(--space-3);
            grid-template-columns: 1fr auto auto;
            align-items: center;
        }

        .input-wrapper {
            position: relative;
        }

        .input-field {
            width: 100%;
            min-height: var(--input-height);
            padding: 12px 16px;
            border-radius: var(--radius-2);
            border: 1px solid var(--color-border);
            background: var(--color-surface);
            font-size: 15px;
        }

        .input-field:focus-visible {
            border-color: var(--color-accent);
        }

        .send-btn {
            width: var(--tap-min);
            height: var(--tap-min);
        }

        .mic-fab {
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: var(--color-accent);
            border: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--shadow-2);
            transition: transform var(--duration-fast) var(--easing-standard);
        }

        .mic-fab.recording {
            animation: micPulseRecording 1.4s infinite;
        }

        .mic-fab.processing {
            background: var(--color-warning);
        }

        .mic-fab svg {
            width: 22px;
            height: 22px;
            stroke: #FFFFFF;
            fill: none;
            stroke-width: 2.2;
        }

        @keyframes micPulseRecording {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.04); }
        }

        .modal {
            display: none;
            position: fixed;
            inset: 0;
            background: var(--color-backdrop);
            backdrop-filter: blur(8px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            padding: var(--space-6);
        }

        .modal.open {
            display: flex;
        }

        .modal-content {
            background: var(--color-surface);
            border-radius: var(--radius-3);
            padding: var(--space-6);
            max-width: 560px;
            width: 100%;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: var(--shadow-3);
            border: 1px solid var(--color-border);
        }

        .modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: var(--space-5);
        }

        .modal-title {
            font-size: 22px;
            font-weight: 800;
            color: var(--color-text-primary);
        }

        .close-btn {
            width: var(--tap-min);
            height: var(--tap-min);
            border-radius: var(--radius-2);
            background: var(--color-elevated);
            border: 1px solid var(--color-border);
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .form-group {
            margin-bottom: var(--space-5);
        }

        .form-label {
            display: block;
            font-size: 12px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--color-text-secondary);
            margin-bottom: var(--space-2);
        }

        .form-input,
        .form-select,
        .form-textarea {
            width: 100%;
            padding: 12px 14px;
            border-radius: var(--radius-2);
            border: 1px solid var(--color-border);
            background: var(--color-elevated);
            font-size: 14px;
        }

        .form-textarea {
            min-height: 90px;
            resize: vertical;
        }

        .helper-text {
            font-size: 12px;
            color: var(--color-text-muted);
            margin-top: var(--space-2);
        }

        .warning-box {
            display: flex;
            gap: var(--space-2);
            padding: var(--space-3);
            border-radius: var(--radius-2);
            background: rgba(245, 158, 11, 0.12);
            border: 1px solid rgba(245, 158, 11, 0.3);
            margin-top: var(--space-3);
        }

        .warning-box svg {
            width: 18px;
            height: 18px;
            stroke: var(--color-warning);
            stroke-width: 2.2;
        }

        .warning-text {
            font-size: 12px;
            color: var(--color-text-secondary);
        }

        .segmented {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: var(--space-2);
        }

        .segmented-option {
            position: relative;
            display: block;
        }

        .segmented-option input {
            position: absolute;
            opacity: 0;
            inset: 0;
        }

        .segmented-option span {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 10px 12px;
            border-radius: var(--radius-2);
            border: 1px solid var(--color-border);
            background: var(--color-elevated);
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            min-height: var(--tap-min);
        }

        .segmented-option input:checked + span {
            border-color: var(--color-accent);
            color: var(--color-accent);
            background: rgba(227, 0, 15, 0.08);
        }

        .btn-group {
            display: grid;
            gap: var(--space-3);
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            margin-top: var(--space-3);
        }

        .btn {
            padding: 12px 16px;
            border-radius: var(--radius-2);
            font-size: 13px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            border: 1px solid transparent;
            min-height: var(--tap-min);
        }

        .btn-primary {
            background: var(--color-accent);
            color: #FFFFFF;
        }

        .btn-secondary {
            background: var(--color-elevated);
            color: var(--color-text-primary);
            border-color: var(--color-border);
        }

        .btn-danger {
            background: var(--color-danger);
            color: #FFFFFF;
        }

        .toast {
            position: fixed;
            bottom: calc(var(--control-bar-height) + var(--space-4));
            left: 50%;
            transform: translateX(-50%) translateY(20px);
            opacity: 0;
            pointer-events: none;
            padding: 14px 20px;
            border-radius: var(--radius-2);
            background: var(--color-toast);
            color: var(--color-toast-text);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.3px;
            transition: opacity var(--duration-medium) var(--easing-standard), transform var(--duration-medium) var(--easing-standard);
            z-index: 4000;
        }

        .toast.show {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }

        .footer {
            text-align: center;
            padding: var(--space-3);
            font-size: 11px;
            color: var(--color-text-muted);
            border-top: 1px solid var(--color-divider);
            background: var(--color-surface);
        }

        .build-info {
            margin-top: var(--space-1);
            font-size: 10px;
            font-family: var(--font-mono);
            color: var(--color-text-muted);
        }

        .stealth-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.92);
            backdrop-filter: blur(24px);
            display: none;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            gap: var(--space-4);
            z-index: 5000;
            text-align: center;
            color: #FFFFFF;
        }

        .stealth-overlay.active {
            display: flex;
        }

        .stealth-icon {
            width: 72px;
            height: 72px;
            stroke: #FFFFFF;
            stroke-width: 1.6;
            opacity: 0.5;
        }

        .stealth-text {
            font-size: 16px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            color: rgba(255, 255, 255, 0.8);
        }

        .stealth-hint {
            font-size: 12px;
            color: rgba(255, 255, 255, 0.6);
        }

        @media (min-width: 720px) {
            .bento-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .tile--wide {
                grid-column: span 2;
            }
        }

        @media (min-width: 1024px) {
            .bento-grid {
                grid-template-columns: repeat(3, minmax(0, 1fr));
            }

            .tile--hero {
                grid-column: span 2;
            }

            .tile--tall {
                grid-row: span 2;
            }
        }

        @media (min-width: 1280px) {
            .bento-grid {
                grid-template-columns: repeat(4, minmax(0, 1fr));
            }

            .tile--hero {
                grid-column: span 2;
            }
        }

        @media (max-width: 680px) {
            .header {
                padding: calc(var(--space-3) + var(--safe-top)) var(--space-4) var(--space-3) var(--space-4);
            }

            .input-area {
                grid-template-columns: 1fr auto;
            }

            .send-btn {
                display: none;
            }

            .toggle-label {
                display: none;
            }
        }

        @media (hover: hover) and (pointer: fine) {
            .stage::-webkit-scrollbar {
                width: 10px;
            }

            .stage::-webkit-scrollbar-thumb {
                background: var(--color-scrollbar-thumb);
                border-radius: var(--radius-pill);
            }

            .stage::-webkit-scrollbar-track {
                background: var(--color-scrollbar-track);
            }
        }

        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        }
```

BLOCK 4: PATCH JS komplett
```javascript
        const APP_VERSION = "2026.1.0-rc1";
        const BUILD_DATE = "2026-01-18";
        const BUILD_SIGNATURE = `MEHIC_SALES_OS_RC_${APP_VERSION}__${BUILD_DATE}`;

        const DB_NAME = "MehicSalesOS_DB";
        const DB_VERSION = 2;
        const LIBRARY_URL = "./library.json";
        const LIBRARY_SHA256 = "pM/qq9A97C8i/Bgtyx2UG/8gtFdRzlangPRZbIYFbUQ=";

        const MODEL_DEFAULTS = {
            openai: "gpt-4o-mini",
            groq: "llama-3.3-70b-versatile"
        };

        const appState = {
            objection: "",
            contexts: [],
            cards: [],
            loading: false,
            stealthMode: false,
            lastFocused: null,
            settings: {
                apiProvider: "openai",
                apiKey: "",
                apiKeyEncrypted: "",
                apiKeyIv: "",
                apiKeySalt: "",
                apiKeyLocked: false,
                modelName: "gpt-4o-mini",
                proxyUrl: "",
                department: "TV",
                storePolicy: "",
                themeMode: "auto",
                densityMode: "",
                densityUserSet: false
            },
            ui: {
                online: navigator.onLine,
                syncStatus: "idle",
                lastSync: null
            },
            stats: {
                cases: 0,
                logs: 0
            }
        };

        const storage = {
            mode: "indexeddb",
            db: null,
            ready: false
        };

        const toastQueue = [];
        let toastActive = false;
        let recognition = null;
        let modalHistoryActive = false;
        let ignoreNextPop = false;
        let reduceMotionMedia = window.matchMedia("(prefers-reduced-motion: reduce)");
        let themeMedia = window.matchMedia("(prefers-color-scheme: dark)");
        let controlBarObserver = null;
        let densityResizeRaf = null;
        const modalStack = [];

        const elements = {};

        const SEED_DATA = [
            {
                id: "seed_1",
                objection: "zu teuer",
                keywords: ["teuer", "preis", "kostet", "viel", "hoch", "expensive"],
                meta: { status: "success", pattern: "price", safety: "clean" },
                ui: { color: "success", icon: "tag" },
                content: {
                    quick: {
                        entry: "Ich verstehe, dass der Preis im ersten Moment hoch erscheint.",
                        anchor: "Viele Kundinnen und Kunden haben anfangs dieselbe Reaktion und sind dann sehr zufrieden mit ihrer Entscheidung.",
                        question: "Darf ich Ihnen kurz zeigen, was dieses Gerät von günstigeren Modellen unterscheidet?",
                        bridge: "Langfristig gesehen investieren Sie hier in Qualität, die sich rechnet.",
                        close: "Wenn wir gemeinsam schauen, welche Features Sie wirklich brauchen, finden wir das beste Preis-Leistungs-Verhältnis für Sie."
                    },
                    smart: {
                        text: "Verstehe ich absolut. Preis ist wichtig. Lassen Sie uns kurz vergleichen: Das günstigere Modell hat X, unser Modell bietet zusätzlich Y und Z. Das bedeutet für Sie konkret [Vorteile]. Viele Kundinnen und Kunden entscheiden sich letztlich für die höhere Investition, weil sie langfristig profitieren.",
                        closing: "Möchten Sie beide Modelle nebeneinander sehen, damit Sie selbst entscheiden können?"
                    },
                    coach: {
                        diagnosis: "Preiseinwand ist oft ein Kontrolleinwand. Kunde sucht Rechtfertigung für Investition.",
                        strategy: "Nicht verteidigen, sondern Wert aufbauen. Von Preis auf Wert shiften.",
                        behavioral_fix: "Anchor-Technik: 'Viele Kundinnen und Kunden...' schafft Social Proof. Frage am Ende gibt Kontrolle zurück.",
                        drill: [
                            "Üben: 'Verstehe ich. Darf ich fragen, was Ihnen an diesem Modell gefällt?' (Commitment verstärken)",
                            "Üben: Preisvergleich immer mit konkretem Mehrwert verknüpfen, nie nur Zahlen nennen"
                        ]
                    }
                }
            },
            {
                id: "seed_2",
                objection: "keine versicherung",
                keywords: ["versicherung", "garantie", "schutz", "abo", "absicherung"],
                meta: { status: "success", pattern: "subscription_aversion", safety: "transparency_required" },
                ui: { color: "warning", icon: "shield" },
                content: {
                    quick: {
                        entry: "Verstehe ich vollkommen, Versicherungen sind nicht jedermanns Sache.",
                        anchor: "Viele Kundinnen und Kunden denken anfangs ähnlich, bis sie die erste Reparatur brauchen.",
                        question: "Darf ich Ihnen transparent zeigen, was genau abgedeckt wäre und wie sich das rechnet?",
                        bridge: "Wichtig: Sie entscheiden natürlich selbst. Mir geht es nur darum, dass Sie alle Infos haben.",
                        close: "Wenn wir einmal durchrechnen, können Sie in Ruhe entscheiden, ob es sich für Sie lohnt."
                    },
                    smart: {
                        text: "Alles klar, kein Problem. Viele verzichten darauf und kommen dann doch zurück. Die Versicherung deckt [konkrete Leistungen] ab. Das bedeutet: [Beispiel Schadensfall]. Hinweis: Alle Konditionen stehen transparent im Vertrag, keine versteckten Kosten.",
                        closing: "Möchten Sie die Unterlagen mitnehmen und in Ruhe entscheiden?"
                    },
                    coach: {
                        diagnosis: "Versicherungs-Aversion ist häufig. Oft fehlt Vertrauen oder Transparenz.",
                        strategy: "Transparenz vor Verkauf. Konkrete Beispiele statt Angstmache.",
                        behavioral_fix: "Niemals Druck aufbauen. 'Sie entscheiden' gibt Kontrolle zurück und baut Vertrauen auf.",
                        drill: [
                            "Üben: Schadensfall-Beispiel parat haben (konkret, realistisch, keine Übertreibung)",
                            "Üben: Kosten transparent darstellen (monatlich UND jährlich nennen)"
                        ]
                    }
                }
            },
            {
                id: "seed_3",
                objection: "muss überlegen",
                keywords: ["überlegen", "bedenkzeit", "später", "nachdenken", "warten"],
                meta: { status: "success", pattern: "uncertainty", safety: "clean" },
                ui: { color: "success", icon: "clock" },
                content: {
                    quick: {
                        entry: "Natürlich, das ist eine wichtige Entscheidung. Nehmen Sie sich ruhig Zeit.",
                        anchor: "Viele Kundinnen und Kunden gehen das genauso an und überlegen in Ruhe.",
                        question: "Darf ich fragen, worüber Sie noch nachdenken möchten? Vielleicht kann ich noch etwas klären?",
                        bridge: "Mir ist wichtig, dass Sie sich sicher fühlen mit Ihrer Entscheidung.",
                        close: "Wenn Sie mögen, reserviere ich das Gerät für Sie, damit Sie in Ruhe überlegen können, ohne dass es weg ist."
                    },
                    smart: {
                        text: "Absolut verständlich. Ist eine Investition und die sollte gut überlegt sein. Viele vergleichen erst noch online oder besprechen es zu Hause. Gibt es noch einen speziellen Punkt, den ich klären kann?",
                        closing: "Möchten Sie, dass ich das Gerät für 24 Stunden reserviere?"
                    },
                    coach: {
                        diagnosis: "Bedenkzeit ist legitim, aber oft versteckt sich ein ungelöster Einwand dahinter.",
                        strategy: "Respektieren, aber nachfragen. Offene Frage stellen, um echten Grund zu finden.",
                        behavioral_fix: "Reservierungs-Offer gibt Kontrolle und schafft sanften Commitment-Anker ohne Druck.",
                        drill: [
                            "Üben: 'Worüber möchten Sie noch nachdenken?' (offene Frage, kein Druck)",
                            "Üben: Reservierungsangebot als Service-Geste positionieren, nicht als Druck"
                        ]
                    }
                }
            }
        ];

        const JOKER_CARD = {
            id: "joker",
            meta: { status: "success", pattern: "trust", safety: "clean" },
            ui: { color: "success", icon: "info" },
            content: {
                quick: {
                    entry: "Ich verstehe Ihre Bedenken vollkommen.",
                    anchor: "Viele Kundinnen und Kunden stellen diese Frage, und das ist auch richtig so.",
                    question: "Darf ich Ihnen erklären, wie wir das bei uns handhaben?",
                    bridge: "Mir ist wichtig, dass Sie sich gut informiert fühlen.",
                    close: "Lassen Sie uns gemeinsam schauen, was für Sie die beste Lösung ist."
                },
                smart: {
                    text: "Das ist eine berechtigte Frage. In meiner Erfahrung hilft es, wenn wir das ganz konkret durchgehen. Viele Kundinnen und Kunden sind dann beruhigt.",
                    closing: "Welche Informationen brauchen Sie noch, um sich sicher zu fühlen?"
                },
                coach: {
                    diagnosis: "Unbekannter Einwand. Empathie und Nachfragen ist der Schlüssel.",
                    strategy: "Aktives Zuhören, offene Fragen stellen, Vertrauen aufbauen.",
                    behavioral_fix: "Niemals defensive Position. Kunde hat immer einen guten Grund für seinen Einwand.",
                    drill: [
                        "Üben: Pausentechnik - 2 Sekunden warten nach Kundenaussage, dann erst antworten",
                        "Üben: 'Verstehe ich richtig, dass...' (Reformulierung zum Validieren)"
                    ]
                }
            }
        };

        function cacheElements() {
            elements.header = document.getElementById("header");
            elements.stage = document.getElementById("stage");
            elements.themeColorMeta = document.getElementById("themeColorMeta");
            elements.onlineStatus = document.getElementById("onlineStatus");
            elements.onlineStatusLabel = document.getElementById("onlineStatusLabel");
            elements.deptBadge = document.getElementById("deptBadge");
            elements.themeToggleBtn = document.getElementById("themeToggleBtn");
            elements.themeToggleLabel = document.getElementById("themeToggleLabel");
            elements.densityToggleBtn = document.getElementById("densityToggleBtn");
            elements.densityToggleLabel = document.getElementById("densityToggleLabel");
            elements.syncBtn = document.getElementById("syncBtn");
            elements.stealthBtn = document.getElementById("stealthBtn");
            elements.resetBtn = document.getElementById("resetBtn");
            elements.settingsBtn = document.getElementById("settingsBtn");
            elements.offlineBanner = document.getElementById("offlineBanner");
            elements.cardsContainer = document.getElementById("cardsContainer");
            elements.objectionInput = document.getElementById("objectionInput");
            elements.submitBtn = document.getElementById("submitBtn");
            elements.micBtn = document.getElementById("micBtn");
            elements.contextChips = document.getElementById("contextChips");
            elements.controlBar = document.getElementById("controlBar");
            elements.buildInfo = document.getElementById("buildInfo");
            elements.toast = document.getElementById("toast");
            elements.settingsModal = document.getElementById("settingsModal");
            elements.closeSettingsBtn = document.getElementById("closeSettingsBtn");
            elements.saveSettingsBtn = document.getElementById("saveSettingsBtn");
            elements.apiProvider = document.getElementById("apiProvider");
            elements.apiKey = document.getElementById("apiKey");
            elements.passphraseInput = document.getElementById("passphraseInput");
            elements.lockToggleBtn = document.getElementById("lockToggleBtn");
            elements.unlockBtn = document.getElementById("unlockBtn");
            elements.lockStatus = document.getElementById("lockStatus");
            elements.modelName = document.getElementById("modelName");
            elements.proxyUrl = document.getElementById("proxyUrl");
            elements.department = document.getElementById("department");
            elements.storePolicy = document.getElementById("storePolicy");
            elements.exportBtn = document.getElementById("exportBtn");
            elements.importBtn = document.getElementById("importBtn");
            elements.importFile = document.getElementById("importFile");
            elements.clearBtn = document.getElementById("clearBtn");
            elements.confirmModal = document.getElementById("confirmModal");
            elements.confirmTitle = document.getElementById("confirmTitle");
            elements.confirmMessage = document.getElementById("confirmMessage");
            elements.confirmConfirmBtn = document.getElementById("confirmConfirmBtn");
            elements.confirmCancelBtn = document.getElementById("confirmCancelBtn");
            elements.confirmCloseBtn = document.getElementById("confirmCloseBtn");
            elements.stealthOverlay = document.getElementById("stealthOverlay");
            elements.themeAuto = document.getElementById("themeAuto");
            elements.themeLight = document.getElementById("themeLight");
            elements.themeDark = document.getElementById("themeDark");
            elements.densityCompact = document.getElementById("densityCompact");
            elements.densityComfortable = document.getElementById("densityComfortable");
            elements.hudSubtitle = document.getElementById("hudSubtitle");
            elements.statCases = document.getElementById("statCases");
            elements.statLogs = document.getElementById("statLogs");
            elements.statMode = document.getElementById("statMode");
            elements.statTheme = document.getElementById("statTheme");
            elements.statDensity = document.getElementById("statDensity");
            elements.statContext = document.getElementById("statContext");
            elements.policyTitle = document.getElementById("policyTitle");
            elements.policyText = document.getElementById("policyText");
            elements.trustKeyStatus = document.getElementById("trustKeyStatus");
            elements.trustProxyStatus = document.getElementById("trustProxyStatus");
            elements.trustMotionStatus = document.getElementById("trustMotionStatus");
            elements.syncIndicator = document.getElementById("syncIndicator");
            elements.syncTitle = document.getElementById("syncTitle");
            elements.syncDesc = document.getElementById("syncDesc");
            elements.syncTime = document.getElementById("syncTime");
        }

        function escapeHTML(value) {
            return String(value)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        }

        function sanitizeString(value, maxLength = 200) {
            if (typeof value !== "string") return "";
            return value.trim().slice(0, maxLength);
        }

        function sanitizeEnum(value, allowed, fallback) {
            if (allowed.includes(value)) return value;
            return fallback;
        }

        function sanitizeArray(values, maxLength = 50) {
            if (!Array.isArray(values)) return [];
            return values.map(item => sanitizeString(item, maxLength)).filter(Boolean);
        }

        function safeParseJSON(raw, fallback) {
            if (!raw) return fallback;
            try {
                return JSON.parse(raw);
            } catch (error) {
                return fallback;
            }
        }

        function showToast(message, options = {}) {
            const entry = {
                message: sanitizeString(message, 160),
                duration: options.duration || 3000
            };
            toastQueue.push(entry);
            if (!toastActive) {
                displayNextToast();
            }
        }

        function displayNextToast() {
            if (toastQueue.length === 0) {
                toastActive = false;
                return;
            }
            toastActive = true;
            const { message, duration } = toastQueue.shift();
            elements.toast.textContent = message;
            elements.toast.classList.add("show");
            setTimeout(() => {
                elements.toast.classList.remove("show");
                setTimeout(displayNextToast, 250);
            }, duration);
        }

        function haptic(pattern = [40]) {
            if ("vibrate" in navigator) {
                navigator.vibrate(pattern);
            }
        }

        function updateThemeColorMeta() {
            const color = getComputedStyle(document.documentElement).getPropertyValue("--color-bg").trim();
            elements.themeColorMeta.setAttribute("content", color || "#000000");
        }

        function resolveTheme(mode) {
            if (mode === "auto") {
                return themeMedia.matches ? "dark" : "light";
            }
            return mode;
        }

        function applyTheme(mode, persist = true) {
            appState.settings.themeMode = mode;
            const resolved = resolveTheme(mode);
            document.documentElement.setAttribute("data-theme", resolved);
            elements.themeToggleLabel.textContent = `Theme: ${mode === "auto" ? "Auto" : resolved.charAt(0).toUpperCase() + resolved.slice(1)}`;
            elements.statTheme.textContent = `Theme: ${mode === "auto" ? "Auto" : resolved.charAt(0).toUpperCase() + resolved.slice(1)}`;
            updateThemeColorMeta();
            if (persist) {
                saveSettings(buildPersistedSettings());
            }
        }

        function computeDensity(width) {
            return width >= 900 ? "compact" : "comfortable";
        }

        function applyDensity(mode, userSet = false, persist = true) {
            appState.settings.densityMode = mode;
            if (userSet) {
                appState.settings.densityUserSet = true;
            }
            document.documentElement.setAttribute("data-density", mode);
            const label = mode === "compact" ? "Kompakt" : "Comfort";
            elements.densityToggleLabel.textContent = `Dichte: ${label}`;
            elements.statDensity.textContent = `Dichte: ${label}`;
            if (persist) {
                saveSettings(buildPersistedSettings());
            }
        }

        function updateContextStatus() {
            const label = appState.contexts.length ? appState.contexts.join(", ") : "Neutral";
            elements.statContext.textContent = `Kontext: ${label}`;
        }

        function updateTrustStatus() {
            const keyStatus = appState.settings.apiKeyLocked ? "Key: Locked" : appState.settings.apiKey ? "Key: Aktiv" : "Key: Nicht gesetzt";
            elements.trustKeyStatus.textContent = keyStatus;
            const proxyValid = validateProxyUrl(appState.settings.proxyUrl);
            const proxyStatus = proxyValid.ok ? "Proxy: Aktiv" : "Proxy: Aus";
            elements.trustProxyStatus.textContent = proxyStatus;
            elements.trustMotionStatus.textContent = reduceMotionMedia.matches ? "Motion: Reduced" : "Motion: Standard";
        }

        function updatePolicyTile() {
            const policy = appState.settings.storePolicy.trim();
            if (policy) {
                elements.policyTitle.textContent = "Aktive Policy";
                elements.policyText.textContent = policy;
            } else {
                elements.policyTitle.textContent = "Keine Aktion aktiv";
                elements.policyText.textContent = "Trage im Settings-Panel aktuelle Aktionen ein, um Scarcity sicher zu nutzen.";
            }
        }

        function updateOnlineStatus() {
            appState.ui.online = navigator.onLine;
            elements.onlineStatus.dataset.status = appState.ui.online ? "online" : "offline";
            elements.onlineStatusLabel.textContent = appState.ui.online ? "Online" : "Offline";
            elements.statMode.textContent = appState.ui.online ? "Online" : "Offline";
            elements.offlineBanner.classList.toggle("show", !appState.ui.online);
            if (!appState.ui.online) {
                setSyncStatus("offline", "Offline");
            }
        }

        function setSyncStatus(status, label) {
            appState.ui.syncStatus = status;
            elements.syncIndicator.dataset.status = status;
            elements.syncIndicator.textContent = label || status;
            elements.syncTitle.textContent = label || status;
        }

        function updateSyncTime() {
            if (!appState.ui.lastSync) {
                elements.syncTime.textContent = "–";
                return;
            }
            const date = new Date(appState.ui.lastSync);
            elements.syncTime.textContent = date.toLocaleString("de-AT", { hour: "2-digit", minute: "2-digit" });
        }

        function buildPersistedSettings() {
            const settings = { ...appState.settings };
            if (settings.apiKeyLocked) {
                settings.apiKey = "";
            }
            return settings;
        }

        function setAppInert(isInert) {
            const targets = [elements.header, elements.stage, elements.controlBar, document.querySelector("footer")];
            targets.forEach(target => {
                if (!target) return;
                if (isInert) {
                    target.setAttribute("aria-hidden", "true");
                } else {
                    target.removeAttribute("aria-hidden");
                }
            });
        }

        function openModal(modal) {
            appState.lastFocused = document.activeElement;
            modal.classList.add("open");
            modal.setAttribute("aria-hidden", "false");
            setAppInert(true);
            trapFocus(modal);
            if (!modalStack.includes(modal.id)) {
                modalStack.push(modal.id);
            }
            if (modalStack.length === 1 && !modalHistoryActive) {
                history.pushState({ modal: modal.id }, "");
                modalHistoryActive = true;
            }
        }

        function closeModal(modal, fromPopstate = false) {
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            releaseFocusTrap(modal);
            const index = modalStack.indexOf(modal.id);
            if (index > -1) {
                modalStack.splice(index, 1);
            }
            setAppInert(modalStack.length > 0);
            if (appState.lastFocused) {
                appState.lastFocused.focus();
            }
            if (modalHistoryActive && !fromPopstate && modalStack.length === 0) {
                ignoreNextPop = true;
                history.back();
            }
            if (modalStack.length === 0) {
                modalHistoryActive = false;
            }
        }

        function trapFocus(modal) {
            const focusable = modal.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
            if (!focusable.length) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            modal._focusHandler = (event) => {
                if (event.key !== "Tab") return;
                if (event.shiftKey && document.activeElement === first) {
                    event.preventDefault();
                    last.focus();
                } else if (!event.shiftKey && document.activeElement === last) {
                    event.preventDefault();
                    first.focus();
                }
            };
            modal.addEventListener("keydown", modal._focusHandler);
            first.focus();
        }

        function releaseFocusTrap(modal) {
            if (modal._focusHandler) {
                modal.removeEventListener("keydown", modal._focusHandler);
                modal._focusHandler = null;
            }
        }

        function confirmAction({ title, message, confirmLabel }) {
            return new Promise(resolve => {
                elements.confirmTitle.textContent = title;
                elements.confirmMessage.textContent = message;
                elements.confirmConfirmBtn.textContent = confirmLabel || "Bestätigen";

                const handleConfirm = () => {
                    cleanup();
                    resolve(true);
                };

                const handleCancel = () => {
                    cleanup();
                    resolve(false);
                };

                const cleanup = () => {
                    elements.confirmConfirmBtn.removeEventListener("click", handleConfirm);
                    elements.confirmCancelBtn.removeEventListener("click", handleCancel);
                    elements.confirmCloseBtn.removeEventListener("click", handleCancel);
                    closeModal(elements.confirmModal);
                };

                elements.confirmConfirmBtn.addEventListener("click", handleConfirm);
                elements.confirmCancelBtn.addEventListener("click", handleCancel);
                elements.confirmCloseBtn.addEventListener("click", handleCancel);
                openModal(elements.confirmModal);
            });
        }

        function setStealthMode(enabled) {
            appState.stealthMode = enabled;
            elements.stealthOverlay.classList.toggle("active", enabled);
            elements.stealthOverlay.setAttribute("aria-hidden", String(!enabled));
            if (enabled) {
                elements.stealthOverlay.focus();
            }
        }

        function setupStealthOverlay() {
            let lastTap = 0;
            elements.stealthOverlay.addEventListener("click", () => {
                const now = Date.now();
                if (now - lastTap < 350) {
                    setStealthMode(false);
                }
                lastTap = now;
            });
        }

        function sanitizeImportSettings(settings) {
            if (!settings || typeof settings !== "object") return null;
            return {
                apiProvider: sanitizeEnum(settings.apiProvider, ["openai", "groq"], "openai"),
                apiKey: sanitizeString(settings.apiKey, 200),
                apiKeyEncrypted: sanitizeString(settings.apiKeyEncrypted, 2000),
                apiKeyIv: sanitizeString(settings.apiKeyIv, 200),
                apiKeySalt: sanitizeString(settings.apiKeySalt, 200),
                apiKeyLocked: Boolean(settings.apiKeyLocked),
                modelName: sanitizeString(settings.modelName, 80) || MODEL_DEFAULTS.openai,
                proxyUrl: sanitizeString(settings.proxyUrl, 200),
                department: sanitizeString(settings.department, 40) || "TV",
                storePolicy: sanitizeString(settings.storePolicy, 400),
                themeMode: sanitizeEnum(settings.themeMode, ["auto", "light", "dark"], "auto"),
                densityMode: sanitizeEnum(settings.densityMode, ["compact", "comfortable"], ""),
                densityUserSet: Boolean(settings.densityUserSet)
            };
        }

        function sanitizeCaseItem(item) {
            if (!item || typeof item !== "object") return null;
            const safeId = sanitizeString(item.id || `import_${Date.now()}`, 80);
            const quick = item.content && item.content.quick ? item.content.quick : {};
            const smart = item.content && item.content.smart ? item.content.smart : {};
            const coach = item.content && item.content.coach ? item.content.coach : {};
            return {
                id: safeId,
                objection: sanitizeString(item.objection, 200),
                keywords: sanitizeArray(item.keywords, 40),
                timestamp: sanitizeString(item.timestamp, 60) || new Date().toISOString(),
                meta: {
                    status: sanitizeEnum(item.meta && item.meta.status, ["success", "error", "check_datasheet", "transparency_missing_details"], "success"),
                    pattern: sanitizeString(item.meta && item.meta.pattern, 40) || "trust",
                    safety: sanitizeEnum(item.meta && item.meta.safety, ["clean", "transparency_required", "fact_check_needed"], "clean")
                },
                ui: {
                    color: sanitizeEnum(item.ui && item.ui.color, ["success", "warning", "error"], "success"),
                    icon: sanitizeEnum(item.ui && item.ui.icon, ["shield", "clock", "tag", "info", "users"], "info")
                },
                content: {
                    quick: {
                        entry: sanitizeString(quick.entry, 400),
                        anchor: sanitizeString(quick.anchor, 400),
                        question: sanitizeString(quick.question, 400),
                        bridge: sanitizeString(quick.bridge, 400),
                        close: sanitizeString(quick.close, 400)
                    },
                    smart: {
                        text: sanitizeString(smart.text, 600),
                        closing: sanitizeString(smart.closing, 400)
                    },
                    coach: {
                        diagnosis: sanitizeString(coach.diagnosis, 400),
                        strategy: sanitizeString(coach.strategy, 400),
                        behavioral_fix: sanitizeString(coach.behavioral_fix, 400),
                        drill: sanitizeArray(coach.drill, 200)
                    }
                },
                isMaster: Boolean(item.isMaster)
            };
        }

        function sanitizeLogItem(log) {
            if (!log || typeof log !== "object") return null;
            return {
                id: sanitizeString(log.id, 80) || undefined,
                timestamp: sanitizeString(log.timestamp, 60) || new Date().toISOString(),
                type: sanitizeString(log.type, 40) || "event",
                objection: sanitizeString(log.objection, 200),
                contexts: sanitizeArray(log.contexts, 40),
                data: log.data && typeof log.data === "object" ? log.data : {}
            };
        }

        function initDB() {
            return new Promise(resolve => {
                if (!("indexedDB" in window)) {
                    storage.mode = "local";
                    storage.ready = true;
                    resolve();
                    return;
                }
                const request = indexedDB.open(DB_NAME, DB_VERSION);
                request.onerror = () => {
                    storage.mode = "local";
                    storage.ready = true;
                    resolve();
                };
                request.onsuccess = () => {
                    storage.db = request.result;
                    storage.ready = true;
                    resolve();
                };
                request.onupgradeneeded = (event) => {
                    const db = event.target.result;
                    if (!db.objectStoreNames.contains("settings")) {
                        db.createObjectStore("settings", { keyPath: "id" });
                    }
                    if (!db.objectStoreNames.contains("cases")) {
                        db.createObjectStore("cases", { keyPath: "id" });
                    }
                    if (!db.objectStoreNames.contains("logs")) {
                        db.createObjectStore("logs", { keyPath: "id", autoIncrement: true });
                    }
                };
            });
        }

        function waitForDB() {
            return new Promise(resolve => {
                if (storage.ready) {
                    resolve();
                    return;
                }
                const interval = setInterval(() => {
                    if (storage.ready) {
                        clearInterval(interval);
                        resolve();
                    }
                }, 50);
            });
        }

        async function saveSettings(settings) {
            await waitForDB();
            if (storage.mode === "local") {
                localStorage.setItem("msos_settings", JSON.stringify(settings));
                return;
            }
            const tx = storage.db.transaction("settings", "readwrite");
            tx.objectStore("settings").put({ id: "main", ...settings });
            return new Promise(resolve => {
                tx.oncomplete = () => resolve();
            });
        }

        async function loadSettings() {
            await waitForDB();
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_settings");
                return safeParseJSON(raw, null);
            }
            return new Promise(resolve => {
                const tx = storage.db.transaction("settings", "readonly");
                const req = tx.objectStore("settings").get("main");
                req.onsuccess = () => resolve(req.result || null);
                req.onerror = () => resolve(null);
            });
        }

        async function saveCaseToLibrary(caseData) {
            await waitForDB();
            const baseKeywords = appState.objection.toLowerCase().split(" ").filter(word => word.length > 3);
            const synonymMap = {
                teuer: ["preis", "kostet", "hoch", "viel", "expensive"],
                versicherung: ["garantie", "schutz", "absicherung", "abo"],
                überlegen: ["bedenkzeit", "später", "nachdenken", "warten"],
                rabatt: ["nachlass", "discount", "günstiger", "reduzierung"],
                vergleichen: ["andere", "konkurrenz", "woanders"],
                qualität: ["hochwertig", "premium", "gut"],
                lieferung: ["versand", "transport", "zustellung"],
                garantie: ["gewährleistung", "rückgabe", "umtausch"]
            };

            const enhancedKeywords = [...new Set([
                ...baseKeywords,
                ...baseKeywords.flatMap(keyword => synonymMap[keyword] || [])
            ])];

            const item = {
                id: "case_" + Date.now() + "_" + Math.random().toString(36).slice(2, 9),
                objection: appState.objection,
                keywords: enhancedKeywords,
                timestamp: new Date().toISOString(),
                ...caseData
            };

            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_cases");
                const data = safeParseJSON(raw, []);
                data.push(item);
                localStorage.setItem("msos_cases", JSON.stringify(data));
                return;
            }

            const tx = storage.db.transaction("cases", "readwrite");
            tx.objectStore("cases").put(item);
            return new Promise(resolve => {
                tx.oncomplete = () => resolve();
            });
        }

        async function searchLocalCases(query) {
            await waitForDB();
            const queryLower = query.toLowerCase();
            const queryWords = queryLower.split(" ").filter(word => word.length > 3);
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_cases");
                const results = safeParseJSON(raw, []);
                return findBestMatch(results, queryWords);
            }
            return new Promise((resolve, reject) => {
                const tx = storage.db.transaction("cases", "readonly");
                const store = tx.objectStore("cases");
                const request = store.getAll();
                request.onsuccess = () => {
                    resolve(findBestMatch(request.result, queryWords));
                };
                request.onerror = () => reject(request.error);
            });
        }

        function findBestMatch(results, queryWords) {
            return results.find(item => {
                const keywords = Array.isArray(item.keywords) ? item.keywords : [];
                return keywords.some(keyword => {
                    return queryWords.some(qw => {
                        if (qw.includes(keyword.toLowerCase()) || keyword.toLowerCase().includes(qw)) {
                            return true;
                        }
                        const distance = levenshteinDistance(qw, keyword.toLowerCase());
                        return distance <= 2;
                    });
                });
            }) || null;
        }

        async function logEvent(type, data) {
            await waitForDB();
            const log = {
                timestamp: new Date().toISOString(),
                type,
                objection: appState.objection,
                contexts: [...appState.contexts],
                data: data || {}
            };
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_logs");
                const logs = safeParseJSON(raw, []);
                logs.push(log);
                localStorage.setItem("msos_logs", JSON.stringify(logs));
                return;
            }
            const tx = storage.db.transaction("logs", "readwrite");
            tx.objectStore("logs").add(log);
            return new Promise(resolve => {
                tx.oncomplete = () => resolve();
            });
        }

        async function getAllCases() {
            await waitForDB();
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_cases");
                return safeParseJSON(raw, []);
            }
            return new Promise(resolve => {
                const tx = storage.db.transaction("cases", "readonly");
                const req = tx.objectStore("cases").getAll();
                req.onsuccess = () => resolve(req.result || []);
                req.onerror = () => resolve([]);
            });
        }

        async function getAllLogs() {
            await waitForDB();
            if (storage.mode === "local") {
                const raw = localStorage.getItem("msos_logs");
                return safeParseJSON(raw, []);
            }
            return new Promise(resolve => {
                const tx = storage.db.transaction("logs", "readonly");
                const req = tx.objectStore("logs").getAll();
                req.onsuccess = () => resolve(req.result || []);
                req.onerror = () => resolve([]);
            });
        }

        async function clearDataStores() {
            await waitForDB();
            if (storage.mode === "local") {
                localStorage.removeItem("msos_cases");
                localStorage.removeItem("msos_logs");
                return;
            }
            const tx = storage.db.transaction(["cases", "logs"], "readwrite");
            tx.objectStore("cases").clear();
            tx.objectStore("logs").clear();
            return new Promise(resolve => {
                tx.oncomplete = () => resolve();
            });
        }

        async function updateStats() {
            const cases = await getAllCases();
            const logs = await getAllLogs();
            appState.stats.cases = cases.length;
            appState.stats.logs = logs.length;
            elements.statCases.textContent = String(appState.stats.cases);
            elements.statLogs.textContent = String(appState.stats.logs);
        }

        function levenshteinDistance(a, b) {
            const matrix = Array.from({ length: b.length + 1 }, () => []);
            for (let i = 0; i <= b.length; i++) matrix[i][0] = i;
            for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
            for (let i = 1; i <= b.length; i++) {
                for (let j = 1; j <= a.length; j++) {
                    if (b.charAt(i - 1) === a.charAt(j - 1)) {
                        matrix[i][j] = matrix[i - 1][j - 1];
                    } else {
                        matrix[i][j] = Math.min(
                            matrix[i - 1][j - 1] + 1,
                            matrix[i][j - 1] + 1,
                            matrix[i - 1][j] + 1
                        );
                    }
                }
            }
            return matrix[b.length][a.length];
        }

        function extractJSON(text) {
            const firstBrace = text.indexOf("{");
            const lastBrace = text.lastIndexOf("}");
            if (firstBrace === -1 || lastBrace === -1) {
                throw new Error("No JSON found in response");
            }
            return text.substring(firstBrace, lastBrace + 1);
        }

        function validateProxyUrl(value) {
            if (!value) return { ok: false };
            try {
                const url = new URL(value, window.location.origin);
                const isSameOrigin = url.origin === window.location.origin && window.location.origin !== "null";
                if (!isSameOrigin) {
                    return { ok: false, reason: "same_origin_required" };
                }
                if (url.protocol !== "https:" && url.protocol !== "http:") {
                    return { ok: false, reason: "protocol" };
                }
                return { ok: true, url: url.toString() };
            } catch (error) {
                return { ok: false, reason: "invalid" };
            }
        }

        async function callAI(objection, contexts) {
            const { apiProvider, apiKey, modelName, proxyUrl, department, storePolicy } = appState.settings;
            if (!apiKey && !proxyUrl) {
                throw new Error("API Key oder Proxy URL erforderlich");
            }
            if (appState.settings.apiKeyLocked) {
                throw new Error("API Key gesperrt");
            }

            const contextMods = [];
            if (contexts.includes("hurry")) contextMods.push("- Kunde ist eilig: Ultra-kurze Antworten, max 2 Sätze pro Abschnitt");
            if (contexts.includes("duo")) contextMods.push("- Kunde ist Paar/Gruppe: Inkludiere beide Personen ('Sie beide', 'für Sie gemeinsam')");
            if (contexts.includes("easy")) contextMods.push("- Kunde will es einfach: Keine Technik-Details, nur Nutzen. Metaphern verwenden");
            if (contexts.includes("techie")) contextMods.push("- Kunde ist technikaffin: Specs erlaubt, aber immer mit Nutzen verknüpfen");

            const systemPrompt = `ROLE: High-End Retail Sales Expert (Austria). Abteilung: ${department}

OUTPUT: STRICT JSON ONLY. NO preamble, NO markdown, NO text before or after the JSON object.

LOGIC (The "Expert Matrix"):
1. VOSS: Start with Labeling/Empathy ("Versteh ich...").
2. CHALLENGER: Reframe the problem (Price -> Cost of Ownership).
3. KAHNEMAN: Anchor high prices down to daily costs.
4. CIALDINI: Use "Alternative Close" (A oder B?), never "Yes/No".

GUARDRAILS:
- Social Proof: General only ("Viele Kundinnen und Kunden..."). Never invent statistics.
- Scarcity: Only if Store Policy has explicit date. Store Policy: "${storePolicy || "keine Aktionen definiert"}"
- Transparency: Mandatory "Abo-Check" if subscription involved. If price unknown: status = "transparency_missing_details"
- Tone: Austrian Professional, natural, short sentences.

KONTEXT-MUTATIONEN:
${contextMods.join("\n")}

OUTPUT FORMAT (STRICT JSON):
{
  "meta": {
    "status": "success | error | check_datasheet | transparency_missing_details",
    "pattern": "price | trust | control | risk | uncertainty | comparison | subscription_aversion",
    "safety": "clean | transparency_required | fact_check_needed"
  },
  "ui": {
    "color": "success | warning | error",
    "icon": "shield | clock | tag | info"
  },
  "content": {
    "quick": {
      "entry": "Einstieg (empathisch, validierend)",
      "anchor": "Anker (Social Proof, Vertrauen)",
      "question": "Frage (öffnet Dialog)",
      "bridge": "Brücke (Mehrwert aufzeigen)",
      "close": "Abschluss (Kontrolle zurückgeben)"
    },
    "smart": {
      "text": "Kurzes, natürliches Verkaufsskript (max 4 Sätze)",
      "closing": "Abschlussfrage"
    },
    "coach": {
      "diagnosis": "Psychologische Einwand-Analyse",
      "strategy": "Strategie-Empfehlung",
      "behavioral_fix": "Verhaltensfix (konkreter Tipp)",
      "drill": ["Übung 1", "Übung 2"]
    }
  }
}`;

            let apiUrl;
            let headers;
            let body;
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 15000);

            if (proxyUrl) {
                const validated = validateProxyUrl(proxyUrl);
                if (!validated.ok) {
                    throw new Error("Proxy URL muss Same-Origin sein");
                }
                apiUrl = validated.url;
                headers = { "Content-Type": "application/json" };
                body = JSON.stringify({ provider: apiProvider, prompt: systemPrompt, objection });
            } else if (apiProvider === "openai") {
                apiUrl = "https://api.openai.com/v1/chat/completions";
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${apiKey}`
                };
                body = JSON.stringify({
                    model: modelName || MODEL_DEFAULTS.openai,
                    messages: [
                        { role: "system", content: systemPrompt },
                        { role: "user", content: objection }
                    ],
                    temperature: 0.7
                });
            } else if (apiProvider === "groq") {
                apiUrl = "https://api.groq.com/openai/v1/chat/completions";
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${apiKey}`
                };
                body = JSON.stringify({
                    model: modelName || MODEL_DEFAULTS.groq,
                    messages: [
                        { role: "system", content: systemPrompt },
                        { role: "user", content: objection }
                    ],
                    temperature: 0.7
                });
            } else {
                throw new Error(`Unbekannter API Provider: ${apiProvider}`);
            }

            const response = await fetch(apiUrl, {
                method: "POST",
                headers,
                body,
                signal: controller.signal,
                referrerPolicy: "no-referrer",
                credentials: "omit"
            });

            clearTimeout(timeout);

            if (!response.ok) {
                throw new Error(`API Error: ${response.status}`);
            }

            const data = await response.json();
            const rawContent = data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content : "";
            const content = extractJSON(rawContent);
            const parsed = JSON.parse(content);
            parsed.id = "ai_" + Date.now() + "_" + Math.random().toString(36).slice(2, 9);
            return parsed;
        }

        function searchSeeds(query) {
            const queryLower = query.toLowerCase();
            const queryWords = queryLower.split(" ").filter(word => word.length > 3);
            return SEED_DATA.find(seed => seed.keywords.some(keyword => {
                return queryWords.some(qw => {
                    if (qw.includes(keyword.toLowerCase()) || keyword.toLowerCase().includes(qw)) {
                        return true;
                    }
                    const distance = levenshteinDistance(qw, keyword.toLowerCase());
                    return distance <= 2;
                });
            }));
        }

        async function handleObjectionSubmit() {
            const objection = elements.objectionInput.value.trim();
            appState.objection = objection;
            if (!objection) {
                haptic([40, 40]);
                showToast("Bitte Einwand eingeben");
                return;
            }

            appState.loading = true;
            setInputBusy(true);
            render();

            try {
                const seedMatch = searchSeeds(objection);
                if (seedMatch) {
                    appState.cards = [seedMatch];
                    await logEvent("seed_match", { cardId: seedMatch.id });
                } else {
                    const localMatch = await searchLocalCases(objection);
                    if (localMatch) {
                        appState.cards = [localMatch];
                        await logEvent("local_match", { cardId: localMatch.id });
                    } else {
                        const aiResponse = await callAI(objection, appState.contexts);
                        appState.cards = [aiResponse];
                        await saveCaseToLibrary(aiResponse);
                        await logEvent("api_call", { provider: appState.settings.apiProvider });
                        await updateStats();
                    }
                }
            } catch (error) {
                appState.cards = [JOKER_CARD];
                await logEvent("error_fallback", { code: error.message });
                showToast("Fehler beim Abruf, Fallback geladen");
            }

            appState.loading = false;
            setInputBusy(false);
            render();
        }

        function setInputBusy(isBusy) {
            elements.micBtn.classList.toggle("processing", isBusy);
            elements.objectionInput.disabled = isBusy;
            elements.submitBtn.disabled = isBusy;
            elements.micBtn.disabled = isBusy || !recognition;
        }

        function resetApp() {
            haptic([40]);
            appState.objection = "";
            appState.contexts = [];
            appState.cards = [];
            elements.objectionInput.value = "";
            elements.contextChips.querySelectorAll(".chip").forEach(chip => {
                chip.setAttribute("aria-pressed", "false");
            });
            updateContextStatus();
            render();
        }

        function renderCards() {
            if (appState.loading) {
                elements.cardsContainer.innerHTML = `
                    <section class="tile loading-state" aria-busy="true">
                        <div class="skeleton-line wide"></div>
                        <div class="skeleton-line"></div>
                        <div class="skeleton-line"></div>
                        <div class="skeleton-line"></div>
                    </section>
                    <section class="tile loading-state" aria-busy="true">
                        <div class="skeleton-line wide"></div>
                        <div class="skeleton-line"></div>
                        <div class="skeleton-line"></div>
                        <div class="skeleton-line"></div>
                    </section>
                `;
                return;
            }

            if (appState.cards.length === 0) {
                elements.cardsContainer.innerHTML = `
                    <section class="tile empty-state">
                        <div class="empty-title">Bereit für Kunden</div>
                        <div class="empty-subtitle">Geben Sie einen Kundeneinwand ein, um sofort eine professionelle Antwort zu erhalten.</div>
                    </section>
                `;
                return;
            }

            const iconMap = {
                shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
                clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
                tag: '<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/>',
                info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
                users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/>'
            };

            const cardsHTML = appState.cards.map(card => {
                const safeId = String(card.id || Date.now()).replace(/[^a-zA-Z0-9_-]/g, "");
                const colorClass = sanitizeEnum(card.ui && card.ui.color, ["success", "warning", "error"], "success");
                const icon = iconMap[card.ui && card.ui.icon] || iconMap.info;
                const quick = card.content && card.content.quick ? card.content.quick : {};
                const smart = card.content && card.content.smart ? card.content.smart : {};
                const coach = card.content && card.content.coach ? card.content.coach : {};
                const drillList = Array.isArray(coach.drill) ? coach.drill : [];
                return `
                    <section class="tile card ${colorClass}">
                        <div class="card-header">
                            <svg class="card-icon" viewBox="0 0 24 24">${icon}</svg>
                            <div class="card-title">Objection Handler</div>
                            <div class="card-badge">${escapeHTML((card.meta && card.meta.pattern) || "trust")}</div>
                        </div>

                        <div class="quick-cues">
                            <div class="cue-block">
                                <div class="cue-label">Einstieg</div>
                                <div class="cue-text">${escapeHTML(quick.entry || "")}</div>
                            </div>
                            <div class="cue-block">
                                <div class="cue-label">Anker</div>
                                <div class="cue-text">${escapeHTML(quick.anchor || "")}</div>
                            </div>
                            <div class="cue-block">
                                <div class="cue-label">Frage</div>
                                <div class="cue-text">${escapeHTML(quick.question || "")}</div>
                            </div>
                        </div>

                        <div class="expandable">
                            <button class="expand-trigger" type="button" aria-expanded="false" aria-controls="smart-${safeId}" data-target="smart-${safeId}">
                                Smart Script
                                <svg class="expand-icon" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
                            </button>
                            <div class="expand-content" id="smart-${safeId}" hidden>
                                <div class="cue-text spacing">${escapeHTML(smart.text || "")}</div>
                                <div class="cue-label">Abschlussfrage</div>
                                <div class="cue-text">${escapeHTML(smart.closing || "")}</div>
                            </div>
                        </div>

                        <div class="expandable">
                            <button class="expand-trigger" type="button" aria-expanded="false" aria-controls="coach-${safeId}" data-target="coach-${safeId}">
                                Coach Mode
                                <svg class="expand-icon" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
                            </button>
                            <div class="expand-content" id="coach-${safeId}" hidden>
                                <div class="coach-block">
                                    <div class="coach-label">Diagnose</div>
                                    <div class="coach-text">${escapeHTML(coach.diagnosis || "")}</div>
                                </div>
                                <div class="coach-block">
                                    <div class="coach-label">Strategie</div>
                                    <div class="coach-text">${escapeHTML(coach.strategy || "")}</div>
                                </div>
                                <div class="coach-block">
                                    <div class="coach-label">Verhaltensfix</div>
                                    <div class="coach-text">${escapeHTML(coach.behavioral_fix || "")}</div>
                                </div>
                                <div class="coach-block">
                                    <div class="coach-label">Übungen</div>
                                    <ul class="drill-list">
                                        ${drillList.map(item => `<li>${escapeHTML(item)}</li>`).join("")}
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <div class="card-actions">
                            <button class="feedback-btn success" type="button" data-feedback="success" data-card="${safeId}">
                                <svg viewBox="0 0 24 24"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3zM7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"/></svg>
                                Erfolgreich
                            </button>
                            <button class="feedback-btn error" type="button" data-feedback="fail" data-card="${safeId}">
                                <svg viewBox="0 0 24 24"><path d="M10 15v4a3 3 0 0 0 3 3l4-9V2H5.72a2 2 0 0 0-2 1.7l-1.38 9a2 2 0 0 0 2 2.3zm7-13h2.67A2.31 2.31 0 0 1 22 4v7a2.31 2.31 0 0 1-2.33 2H17"/></svg>
                                Nicht hilfreich
                            </button>
                        </div>
                    </section>
                `;
            }).join("");

            elements.cardsContainer.innerHTML = cardsHTML;
        }

        function render() {
            elements.deptBadge.textContent = appState.settings.department;
            elements.hudSubtitle.textContent = appState.loading ? "Analyse läuft" : "Bereit";
            updateContextStatus();
            updateTrustStatus();
            updatePolicyTile();
            renderCards();
        }

        function setupSpeechRecognition() {
            const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
            if (!SpeechRecognition) {
                elements.micBtn.disabled = true;
                elements.micBtn.setAttribute("aria-disabled", "true");
                return;
            }
            recognition = new SpeechRecognition();
            recognition.lang = "de-AT";
            recognition.interimResults = false;
            recognition.continuous = false;

            recognition.onresult = (event) => {
                const text = event.results[0][0].transcript;
                appState.objection = text;
                elements.objectionInput.value = text;
                haptic([40, 30, 40]);
                handleObjectionSubmit();
            };

            recognition.onend = () => {
                elements.micBtn.classList.remove("recording");
                elements.micBtn.setAttribute("aria-pressed", "false");
            };

            recognition.onerror = () => {
                elements.micBtn.classList.remove("recording");
                elements.micBtn.classList.remove("processing");
                elements.micBtn.setAttribute("aria-pressed", "false");
                showToast("Spracheingabe fehlgeschlagen");
            };
        }

        async function encryptSecret(secret, passphrase) {
            if (!window.crypto || !window.crypto.subtle) {
                throw new Error("Crypto not supported");
            }
            const enc = new TextEncoder();
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
            const key = await window.crypto.subtle.deriveKey(
                { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
                keyMaterial,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt"]
            );
            const cipher = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(secret));
            return {
                cipher: btoa(String.fromCharCode(...new Uint8Array(cipher))),
                iv: btoa(String.fromCharCode(...iv)),
                salt: btoa(String.fromCharCode(...salt))
            };
        }

        async function decryptSecret(encrypted, passphrase, iv, salt) {
            if (!window.crypto || !window.crypto.subtle) {
                throw new Error("Crypto not supported");
            }
            const enc = new TextEncoder();
            const data = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
            const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
            const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
            const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
            const key = await window.crypto.subtle.deriveKey(
                { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
                keyMaterial,
                { name: "AES-GCM", length: 256 },
                false,
                ["decrypt"]
            );
            const plain = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, key, data);
            return new TextDecoder().decode(plain);
        }

        async function handleLockToggle() {
            const isLocked = appState.settings.apiKeyLocked;
            if (!isLocked) {
                const passphrase = elements.passphraseInput.value.trim();
                const keyValue = elements.apiKey.value.trim();
                if (!passphrase) {
                    showToast("Passphrase fehlt");
                    return;
                }
                if (!keyValue) {
                    showToast("API Key fehlt");
                    return;
                }
                try {
                    const encrypted = await encryptSecret(keyValue, passphrase);
                    appState.settings.apiKeyEncrypted = encrypted.cipher;
                    appState.settings.apiKeyIv = encrypted.iv;
                    appState.settings.apiKeySalt = encrypted.salt;
                    appState.settings.apiKeyLocked = true;
                    appState.settings.apiKey = "";
                    elements.apiKey.value = "";
                    elements.lockStatus.textContent = "Lock aktiv";
                    elements.lockToggleBtn.textContent = "Passphrase-Lock deaktivieren";
                    showToast("Key gesperrt");
                    await saveSettings(buildPersistedSettings());
                    updateTrustStatus();
                } catch (error) {
                    showToast("Passphrase-Lock fehlgeschlagen");
                }
            } else {
                appState.settings.apiKeyLocked = false;
                appState.settings.apiKeyEncrypted = "";
                appState.settings.apiKeyIv = "";
                appState.settings.apiKeySalt = "";
                elements.lockStatus.textContent = "Lock deaktiviert";
                elements.lockToggleBtn.textContent = "Passphrase-Lock aktivieren";
                showToast("Lock deaktiviert");
                await saveSettings(buildPersistedSettings());
                updateTrustStatus();
            }
        }

        async function handleUnlock() {
            if (!appState.settings.apiKeyLocked) {
                showToast("Key ist nicht gesperrt");
                return;
            }
            const passphrase = elements.passphraseInput.value.trim();
            if (!passphrase) {
                showToast("Passphrase fehlt");
                return;
            }
            try {
                const decrypted = await decryptSecret(
                    appState.settings.apiKeyEncrypted,
                    passphrase,
                    appState.settings.apiKeyIv,
                    appState.settings.apiKeySalt
                );
                appState.settings.apiKey = decrypted;
                elements.lockStatus.textContent = "Key entsperrt (Session)";
                showToast("Key entsperrt");
                updateTrustStatus();
            } catch (error) {
                showToast("Passphrase falsch");
            }
        }

        async function exportData() {
            const settings = buildPersistedSettings();
            const cases = await getAllCases();
            const logs = await getAllLogs();
            return {
                version: APP_VERSION,
                exportDate: new Date().toISOString(),
                settings,
                cases,
                logs
            };
        }

        async function importData(file) {
            const raw = await file.text();
            const parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== "object") {
                throw new Error("Invalid import");
            }

            const settings = sanitizeImportSettings(parsed.settings);
            const cases = Array.isArray(parsed.cases) ? parsed.cases.map(sanitizeCaseItem).filter(Boolean) : [];
            const logs = Array.isArray(parsed.logs) ? parsed.logs.map(sanitizeLogItem).filter(Boolean) : [];

            if (settings) {
                appState.settings = { ...appState.settings, ...settings };
                applyTheme(appState.settings.themeMode, false);
                if (appState.settings.densityMode) {
                    applyDensity(appState.settings.densityMode, appState.settings.densityUserSet, false);
                }
                await saveSettings(buildPersistedSettings());
            }

            if (storage.mode === "local") {
                const existingCases = await getAllCases();
                const existingLogs = await getAllLogs();
                localStorage.setItem("msos_cases", JSON.stringify([...existingCases, ...cases]));
                localStorage.setItem("msos_logs", JSON.stringify([...existingLogs, ...logs]));
            } else {
                const tx = storage.db.transaction(["cases", "logs"], "readwrite");
                const caseStore = tx.objectStore("cases");
                cases.forEach(item => caseStore.put(item));
                const logStore = tx.objectStore("logs");
                logs.forEach(item => logStore.add(item));
                await new Promise(resolve => {
                    tx.oncomplete = () => resolve();
                });
            }
            await updateStats();
        }

        async function verifyLibraryHash(buffer) {
            if (!window.crypto || !window.crypto.subtle) {
                return false;
            }
            const hashBuffer = await window.crypto.subtle.digest("SHA-256", buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashBase64 = btoa(String.fromCharCode(...hashArray));
            return hashBase64 === LIBRARY_SHA256;
        }

        async function syncLibrary(manual = false) {
            if (!navigator.onLine) {
                setSyncStatus("offline", "Offline");
                if (manual) {
                    showToast("Offline – Sync pausiert");
                }
                return;
            }
            setSyncStatus("syncing", "Syncing");
            try {
                const response = await fetch(LIBRARY_URL, {
                    cache: "no-store",
                    credentials: "omit",
                    referrerPolicy: "no-referrer"
                });
                if (!response.ok) {
                    throw new Error("Sync failed");
                }
                const buffer = await response.arrayBuffer();
                const hashOk = await verifyLibraryHash(buffer);
                if (!hashOk) {
                    throw new Error("Integrity failed");
                }
                const text = new TextDecoder().decode(buffer);
                const data = JSON.parse(text);
                if (!Array.isArray(data)) {
                    throw new Error("Format invalid");
                }
                if (storage.mode === "local") {
                    const existing = await getAllCases();
                    const byId = new Map(existing.map(item => [item.id, item]));
                    data.forEach(item => {
                        const sanitized = sanitizeCaseItem(item);
                        if (sanitized) {
                            sanitized.isMaster = true;
                            byId.set(sanitized.id, sanitized);
                        }
                    });
                    localStorage.setItem("msos_cases", JSON.stringify(Array.from(byId.values())));
                } else {
                    const tx = storage.db.transaction("cases", "readwrite");
                    const store = tx.objectStore("cases");
                    data.forEach(item => {
                        const sanitized = sanitizeCaseItem(item);
                        if (sanitized) {
                            sanitized.isMaster = true;
                            store.put(sanitized);
                        }
                    });
                    await new Promise(resolve => {
                        tx.oncomplete = () => resolve();
                    });
                }
                appState.ui.lastSync = new Date().toISOString();
                setSyncStatus("ok", "Sync OK");
                updateSyncTime();
                await updateStats();
                if (manual) {
                    showToast("Sync abgeschlossen");
                }
            } catch (error) {
                setSyncStatus("error", "Sync Fehler");
                if (manual) {
                    showToast("Sync fehlgeschlagen");
                }
            }
        }

        function setupViewportHandling() {
            if (!window.visualViewport) return;
            const update = () => {
                const offset = Math.max(0, window.innerHeight - window.visualViewport.height - window.visualViewport.offsetTop);
                document.documentElement.style.setProperty("--keyboard-offset", `${Math.round(offset)}px`);
            };
            window.visualViewport.addEventListener("resize", update, { passive: true });
            window.visualViewport.addEventListener("scroll", update, { passive: true });
            update();
        }

        function setupControlBarObserver() {
            if (!elements.controlBar) return;
            const update = () => {
                document.documentElement.style.setProperty("--control-bar-height", `${elements.controlBar.offsetHeight}px`);
            };
            update();
            if ("ResizeObserver" in window) {
                controlBarObserver = new ResizeObserver(update);
                controlBarObserver.observe(elements.controlBar);
            }
        }

        function setupEvents() {
            elements.resetBtn.addEventListener("click", (event) => {
                event.stopPropagation();
                resetApp();
            });

            elements.settingsBtn.addEventListener("click", () => {
                openSettings();
            });

            elements.closeSettingsBtn.addEventListener("click", () => {
                closeModal(elements.settingsModal);
            });

            elements.settingsModal.addEventListener("click", (event) => {
                if (event.target === elements.settingsModal) {
                    closeModal(elements.settingsModal);
                }
            });

            elements.confirmModal.addEventListener("click", (event) => {
                if (event.target === elements.confirmModal) {
                    closeModal(elements.confirmModal);
                }
            });

            elements.themeToggleBtn.addEventListener("click", () => {
                const cycle = ["auto", "light", "dark"];
                const current = appState.settings.themeMode;
                const next = cycle[(cycle.indexOf(current) + 1) % cycle.length];
                applyTheme(next);
                updateTrustStatus();
            });

            elements.densityToggleBtn.addEventListener("click", () => {
                const next = appState.settings.densityMode === "compact" ? "comfortable" : "compact";
                applyDensity(next, true);
            });

            elements.syncBtn.addEventListener("click", () => {
                syncLibrary(true);
            });

            elements.stealthBtn.addEventListener("click", async () => {
                const confirmed = await confirmAction({
                    title: "Stealth aktivieren?",
                    message: "Display wird abgedunkelt. Zweimal tippen oder ESC beendet den Modus.",
                    confirmLabel: "Aktivieren"
                });
                if (confirmed) {
                    setStealthMode(true);
                }
            });

            elements.contextChips.addEventListener("click", (event) => {
                const chip = event.target.closest(".chip");
                if (!chip) return;
                const context = chip.dataset.context;
                const index = appState.contexts.indexOf(context);
                if (index > -1) {
                    appState.contexts.splice(index, 1);
                    chip.setAttribute("aria-pressed", "false");
                } else {
                    appState.contexts.push(context);
                    chip.setAttribute("aria-pressed", "true");
                }
                updateContextStatus();
            });

            elements.objectionInput.addEventListener("input", (event) => {
                appState.objection = event.target.value;
            });

            elements.objectionInput.addEventListener("keydown", (event) => {
                if (event.key === "Enter" && !event.isComposing) {
                    event.preventDefault();
                    handleObjectionSubmit();
                }
            });

            elements.submitBtn.addEventListener("click", () => {
                handleObjectionSubmit();
            });

            elements.micBtn.addEventListener("click", () => {
                if (!recognition) {
                    showToast("Spracheingabe nicht unterstützt");
                    return;
                }
                if (elements.micBtn.classList.contains("recording")) {
                    recognition.stop();
                    return;
                }
                elements.micBtn.classList.add("recording");
                elements.micBtn.setAttribute("aria-pressed", "true");
                recognition.start();
            });

            elements.cardsContainer.addEventListener("click", (event) => {
                const trigger = event.target.closest(".expand-trigger");
                if (trigger) {
                    const targetId = trigger.dataset.target;
                    const content = document.getElementById(targetId);
                    const icon = trigger.querySelector(".expand-icon");
                    const isOpen = trigger.getAttribute("aria-expanded") === "true";
                    trigger.setAttribute("aria-expanded", String(!isOpen));
                    content.classList.toggle("open", !isOpen);
                    content.hidden = isOpen;
                    icon.classList.toggle("open", !isOpen);
                }

                const feedbackBtn = event.target.closest(".feedback-btn");
                if (feedbackBtn) {
                    const feedback = feedbackBtn.dataset.feedback;
                    const cardId = feedbackBtn.dataset.card;
                    logEvent("feedback", { cardId, feedback });
                    showToast(feedback === "success" ? "Feedback gespeichert" : "Danke für Ihr Feedback");
                }
            });

            elements.apiProvider.addEventListener("change", () => {
                const previous = appState.settings.apiProvider;
                const next = elements.apiProvider.value;
                const previousDefault = MODEL_DEFAULTS[previous];
                const currentModel = elements.modelName.value.trim();
                if (!currentModel || currentModel === previousDefault) {
                    elements.modelName.value = MODEL_DEFAULTS[next];
                }
            });

            elements.lockToggleBtn.addEventListener("click", () => {
                handleLockToggle();
            });

            elements.unlockBtn.addEventListener("click", () => {
                handleUnlock();
            });

            elements.exportBtn.addEventListener("click", async () => {
                const confirmed = await confirmAction({
                    title: "Export starten?",
                    message: "Export enthält Settings, Cases und Logs. API Key nur, wenn nicht gesperrt.",
                    confirmLabel: "Exportieren"
                });
                if (!confirmed) return;
                const data = await exportData();
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const anchor = document.createElement("a");
                anchor.href = url;
                anchor.download = `mehic_sales_os_export_${Date.now()}.json`;
                anchor.click();
                URL.revokeObjectURL(url);
                showToast("Export abgeschlossen");
            });

            elements.importBtn.addEventListener("click", () => {
                elements.importFile.value = "";
                elements.importFile.click();
            });

            elements.importFile.addEventListener("change", async (event) => {
                const file = event.target.files[0];
                if (!file) return;
                const confirmed = await confirmAction({
                    title: "Import starten?",
                    message: "Settings werden überschrieben, Cases/Logs hinzugefügt.",
                    confirmLabel: "Importieren"
                });
                if (!confirmed) return;
                try {
                    await importData(file);
                    showToast("Import abgeschlossen");
                    render();
                } catch (error) {
                    showToast("Import fehlgeschlagen");
                }
            });

            elements.clearBtn.addEventListener("click", async () => {
                const confirmed = await confirmAction({
                    title: "Alle Daten löschen?",
                    message: "Cases und Logs werden dauerhaft entfernt. Dieser Schritt ist irreversibel.",
                    confirmLabel: "Löschen"
                });
                if (!confirmed) return;
                await clearDataStores();
                resetApp();
                await updateStats();
                showToast("Daten gelöscht");
            });

            elements.saveSettingsBtn.addEventListener("click", async () => {
                appState.settings.apiProvider = elements.apiProvider.value;
                appState.settings.modelName = elements.modelName.value.trim() || MODEL_DEFAULTS[appState.settings.apiProvider];
                const proxyValue = elements.proxyUrl.value.trim();
                const proxyCheck = validateProxyUrl(proxyValue);
                if (proxyValue && !proxyCheck.ok) {
                    showToast("Proxy nur Same-Origin erlaubt");
                    appState.settings.proxyUrl = "";
                    elements.proxyUrl.value = "";
                } else {
                    appState.settings.proxyUrl = proxyValue;
                }
                appState.settings.department = elements.department.value;
                appState.settings.storePolicy = elements.storePolicy.value.trim();
                if (!appState.settings.apiKeyLocked) {
                    appState.settings.apiKey = elements.apiKey.value.trim();
                }
                const themeMode = document.querySelector("input[name='themeMode']:checked");
                const densityMode = document.querySelector("input[name='densityMode']:checked");
                if (themeMode) applyTheme(themeMode.value, false);
                if (densityMode) applyDensity(densityMode.value, true, false);
                await saveSettings(buildPersistedSettings());
                updatePolicyTile();
                updateTrustStatus();
                render();
                showToast("Einstellungen gespeichert");
                closeModal(elements.settingsModal);
            });

            elements.themeAuto.addEventListener("change", () => applyTheme("auto"));
            elements.themeLight.addEventListener("change", () => applyTheme("light"));
            elements.themeDark.addEventListener("change", () => applyTheme("dark"));

            elements.densityCompact.addEventListener("change", () => applyDensity("compact", true));
            elements.densityComfortable.addEventListener("change", () => applyDensity("comfortable", true));

            window.addEventListener("online", updateOnlineStatus, { passive: true });
            window.addEventListener("offline", updateOnlineStatus, { passive: true });

            document.addEventListener("keydown", (event) => {
                if (event.key === "Escape") {
                    if (elements.confirmModal.classList.contains("open")) {
                        closeModal(elements.confirmModal);
                        return;
                    }
                    if (elements.settingsModal.classList.contains("open")) {
                        closeModal(elements.settingsModal);
                        return;
                    }
                    if (appState.stealthMode) {
                        setStealthMode(false);
                    }
                }

                if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
                    event.preventDefault();
                    elements.objectionInput.focus();
                }
                if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "t") {
                    event.preventDefault();
                    elements.themeToggleBtn.click();
                }
                if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "d") {
                    event.preventDefault();
                    elements.densityToggleBtn.click();
                }
                if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
                    event.preventDefault();
                    openSettings();
                }
            });

            window.addEventListener("popstate", () => {
                if (ignoreNextPop) {
                    ignoreNextPop = false;
                    return;
                }
                const activeModalId = modalStack[modalStack.length - 1];
                if (activeModalId) {
                    const activeModal = document.getElementById(activeModalId);
                    if (activeModal) {
                        closeModal(activeModal, true);
                    }
                }
            });

            const themeListener = () => {
                if (appState.settings.themeMode === "auto") {
                    applyTheme("auto", false);
                }
            };
            if (themeMedia.addEventListener) {
                themeMedia.addEventListener("change", themeListener);
            } else if (themeMedia.addListener) {
                themeMedia.addListener(themeListener);
            }

            const motionListener = () => {
                updateTrustStatus();
            };
            if (reduceMotionMedia.addEventListener) {
                reduceMotionMedia.addEventListener("change", motionListener);
            } else if (reduceMotionMedia.addListener) {
                reduceMotionMedia.addListener(motionListener);
            }

            window.addEventListener("resize", () => {
                if (densityResizeRaf) {
                    cancelAnimationFrame(densityResizeRaf);
                }
                densityResizeRaf = requestAnimationFrame(() => {
                    if (!appState.settings.densityUserSet) {
                        const nextDensity = computeDensity(window.innerWidth);
                        if (nextDensity !== appState.settings.densityMode) {
                            applyDensity(nextDensity, false);
                        }
                    }
                    densityResizeRaf = null;
                });
            });
        }

        function openSettings() {
            elements.apiProvider.value = appState.settings.apiProvider;
            elements.apiKey.value = appState.settings.apiKeyLocked ? "" : appState.settings.apiKey;
            elements.modelName.value = appState.settings.modelName;
            elements.proxyUrl.value = appState.settings.proxyUrl;
            elements.department.value = appState.settings.department;
            elements.storePolicy.value = appState.settings.storePolicy;
            elements.lockStatus.textContent = appState.settings.apiKeyLocked ? "Lock aktiv" : "Lock deaktiviert";
            elements.lockToggleBtn.textContent = appState.settings.apiKeyLocked ? "Passphrase-Lock deaktivieren" : "Passphrase-Lock aktivieren";

            elements.themeAuto.checked = appState.settings.themeMode === "auto";
            elements.themeLight.checked = appState.settings.themeMode === "light";
            elements.themeDark.checked = appState.settings.themeMode === "dark";

            elements.densityCompact.checked = appState.settings.densityMode === "compact";
            elements.densityComfortable.checked = appState.settings.densityMode === "comfortable";

            openModal(elements.settingsModal);
        }

        function setupWakeLockReacquisition() {
            document.addEventListener("visibilitychange", async () => {
                if (document.visibilityState === "visible") {
                    await requestWakeLock();
                }
            });
        }

        let wakeLock = null;

        async function requestWakeLock() {
            if (!("wakeLock" in navigator)) return;
            try {
                wakeLock = await navigator.wakeLock.request("screen");
            } catch (error) {
                wakeLock = null;
            }
        }

        async function init() {
            cacheElements();
            await initDB();
            const savedSettings = await loadSettings();
            if (savedSettings) {
                appState.settings = { ...appState.settings, ...savedSettings };
            }

            const preferredDensity = appState.settings.densityMode || computeDensity(window.innerWidth);
            applyDensity(preferredDensity, appState.settings.densityUserSet, false);
            applyTheme(appState.settings.themeMode, false);

            setupEvents();
            setupSpeechRecognition();
            setupViewportHandling();
            setupControlBarObserver();
            setupStealthOverlay();
            setupWakeLockReacquisition();
            updateOnlineStatus();
            updatePolicyTile();
            updateTrustStatus();
            render();
            await updateStats();
            requestWakeLock();

            elements.buildInfo.textContent = `Build: ${BUILD_SIGNATURE}`;
            syncLibrary(false);
        }

        init();
```

BLOCK 5: Testplan + QA Gates + Sources

Testplan
- Smoke harness: `tests/smoke.test.html` (PASS/FAIL UI).
- Functional: Theme/Density toggles, Settings speichern, Input → Antwort, Expanders, Feedback, Export/Import, Clear mit Confirm.
- Offline: Offline Banner + Sync status, Sync Button offline.
- Security: CSP Level 2 hash check, Proxy same-origin block.
- A11y: Keyboard-Only navigation, Focus trap, `aria-expanded` changes.
- Mobile: iOS keyboard overlay, Android back button.

QA Gates
- No console errors on load.
- WCAG 2.2 AA focus + keyboard nav.
- Sync integrity verification passes or fails safely.
- No destructive action ohne Confirm.
- Reduced Motion respected.
- Smoke harness ohne FAIL.

Quellen (max 10)
- CSP (MDN): https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- WCAG 2.2: https://www.w3.org/TR/WCAG22/
- ARIA APG: https://www.w3.org/WAI/ARIA/apg/
- prefers-reduced-motion (MDN): https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion
- Safe Areas in Web Content (Apple): https://developer.apple.com/documentation/webkit/safari_tools_and_features/supporting_safe_areas_in_web_content
- VisualViewport API (MDN): https://developer.mozilla.org/en-US/docs/Web/API/VisualViewport
- Web Vitals (web.dev): https://web.dev/vitals/
- Viewport units (MDN): https://developer.mozilla.org/en-US/docs/Web/CSS/length#viewport-percentage-lengths
