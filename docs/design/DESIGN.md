# ReconMind frontend design

This folder is the approved design for the ReconMind localhost frontend. It is
reference material only. Nothing here is served by the app.

* `DESIGN.md` (this file) is the source of truth for colors, type, components,
  motion, copy and safety rules.
* `screens/*.html` are the approved mockups, one per screen. They are written in
  a design tool's template format (`<x-dc>`, `<sc-for>`, `<sc-if>`, `{{holes}}`
  and a `class Component extends DCLogic` script). Copy their look, layout,
  CSS and copy. Do not copy the template syntax or the script format. The data
  in them is sample data; the real app shows real results.

| Mockup | Screen | Route in the app |
| --- | --- | --- |
| 01_Main.html | New scan | `#/new` |
| 02_LiveRun.html | Live run | `#/live/<job id>` |
| 03_Report.html | Network report | `#/report/<run id>` |
| 04_Targets.html | Targets workspace | `#/targets` |
| 05_AnalystReport.html | Write your own report | `#/write/<target>` |
| 06_Batch.html | Host list summary | `#/hosts/<batch id>` |
| 07_CodeReport.html | Code scan report | `#/report/<run id>` (kind code) |
| 08_System.html | System check | `#/system` |
| 09_States.html | Problem states, shown inside the other screens | none |
| 10_PdfReport.html | PDF export layout (white, letter size) | server side |

## 1. Look and feel

Dark, clean, professional. Black, grey and red only, plus the severity colors.
Frosted glass panels on a near black background, a few slow ambient effects,
and motion that answers what the user does. No emoji, no stock gradients
behind text, no marketing copy.

## 2. Color tokens

Put these on `:root` as CSS custom properties and use only the tokens.

```css
--bg:            #070708;   /* page background */
--glass-top:     rgba(30,30,33,.62);
--glass-bottom:  rgba(15,15,17,.58);
--line:          rgba(255,255,255,.11);  /* panel border */
--line-soft:     rgba(255,255,255,.07);  /* row dividers */
--field:         rgba(10,10,11,.6);      /* input background */
--text:          #D4D4D8;   /* body text */
--text-strong:   #F4F4F5;   /* headings, values */
--text-muted:    #8E8E96;   /* labels, help */
--text-dim:      #66666E;   /* timestamps, placeholders */
--red:           #E5484D;   /* primary accent */
--red-light:     #FF5A5F;   /* links, focus ring */
--red-soft:      #FF7A7F;   /* glows, small accents */
--red-deep:      #B4232A;   /* gradient end */
--live:          #FF4D4F;   /* something is running right now */
--sev-critical:  #FF6B5E;
--sev-high:      #F79A4B;
--sev-medium:    #E9D267;
--sev-low:       #BDBDC2;
--sev-none:      #3A3A40;   /* open port with no finding */
--cell-off:      #2A2A2F;   /* empty heat meter cell */
--warn:          #E9D267;   /* warnings, same as medium */
```

Rules:
* Red means the main action, the current selection, something live, or
  critical. Never decoration.
* Severity is never shown by color alone. Always pair it with the word or the
  heat meter (section 5.8).
* Body text on the background must keep at least 4.5:1 contrast.

## 3. Type

* **Archivo** (Google Fonts, variable width and weight:
  `family=Archivo:wdth,wght@62..125,400..800`) for everything.
  Headings use `font-stretch: 125%` and weight 800 with
  `letter-spacing: -0.03em`. Body 15px, line height 1.55.
* **IBM Plex Mono** (400, 500) only for real machine output: commands, tool
  output, evidence, code, CVSS vectors, file paths.
* Always include system fallbacks (`system-ui, sans-serif` and `monospace`) so
  the app still looks right with no internet.
* Page titles: `clamp(36px, 5vw, 60px)`. Section titles 18 to 22px.
  Labels 13px weight 650 in `--text-muted`.
* Numbers that line up (ports, counts, times) use
  `font-variant-numeric: tabular-nums`.
* Sentence case everywhere. No ALL CAPS labels (the only exception is the
  CONFIDENTIAL stamp in the PDF).

## 4. Layout

* Top bar, 68px tall, frosted: logo on the left, nav (New scan, Live run,
  Targets, Host lists, System), and a scope pill on the right
  ("Scope locked to 4 lab networks", count read from the server).
* Content max width 1080 to 1200px, centered, side padding
  `clamp(16px, 4vw, 48px)`.
* Panels are glass cards (section 5.1) with 18px radius, 24 to 34px padding,
  24px gaps between them.
* Every page works down to phone width: rows wrap, wide tables scroll inside
  their own box, nothing scrolls the page sideways.

## 5. Components

### 5.1 Glass panel
```css
background: linear-gradient(180deg, var(--glass-top), var(--glass-bottom));
border: 1px solid var(--line);
border-radius: 18px;
backdrop-filter: blur(16px);
box-shadow: inset 0 1px 0 rgba(255,255,255,.05), 0 24px 60px -24px rgba(0,0,0,.7);
```

### 5.2 Background layer (fixed, behind everything, pointer-events none)
1. Two large soft radial glows: red at 15% opacity top left, deep red at 12%
   bottom right. Each drifts slowly (22s and 27s, alternate).
2. A dot grid (1px dots every 28px, white at 14%) masked to fade out from the
   top left.
3. Three sonar rings expanding from the logo position, 7.5s each, started
   2.5s apart, fading to nothing.
4. Four faint vertical column lines across the content width, fading out
   toward the bottom.

### 5.3 Logo
A dot with three arcs (a sonar ping) in red, then "ReconMind" in Archivo 800,
125% width. The three arcs pulse in sequence (2.4s loop, 0.25s apart).

### 5.4 Nav item
Grey text, a 2px red gradient underline that springs out from the center on
hover (to 35%) and fully on the active item, with a soft red glow. The Live
run item shows a pulsing `--live` dot while a scan runs.

### 5.5 Buttons
* **Primary:** red gradient (`--red` to `--red-deep`), white bold text, 8px
  radius, red glow shadow. On the right edge a dark 34px square holding the
  arrow "↗" that nudges up and right on hover. A light sheen sweeps across on
  hover. Lifts 2px on hover.
* **Quiet:** transparent with a 1px white 20% border; border brightens on
  hover.
* **Stop / danger:** red text on a faint red background with a red border.
* All buttons are at least 44px tall. Real `<button>` and `<a>` elements only.

### 5.6 Segmented control
A track with equal columns and one glowing pill behind the active option
that slides to the picked option with a slight overshoot
(`cubic-bezier(.3,1.35,.5,1)`, 0.5s). Disabled options at 30% opacity.

### 5.7 Preset card
Radio dot plus name and one line description. The selected card gets a thin
red light that keeps circling its border (a conic gradient border rotating
over 4s) and a faint red tint. Cards lift 3px on hover.

### 5.8 Heat meter (severity)
Four small vertical cells (5 by 16px, 2px apart). Critical fills 4, high 3,
medium 2, low 1, in that severity's color; empty cells use `--cell-off`.
Always next to the severity word or with an aria-label.

### 5.9 Checkbox and toggle
Custom checkbox: 22px rounded square; when checked it fills with the red
gradient and the check mark pops in with a bounce. Toggle switch: 50 by 28px
track that turns red, knob slides with a bounce.

### 5.10 Fields
Dark field background, 1px border, 10px radius, 44px minimum height. On focus
the border turns `--red-light` with a soft red ring and glow. Every field has
a real `<label>`.

### 5.11 Port spectrum (the signature element)
A strip from port 1 to 65535 on a log scale
(`x = log10(port) / log10(65536)`). Each open port is a thin bar; its height
and color show the worst finding on that port (critical tallest, no finding
shortest in `--sev-none`). Axis labels 1, 10, 100, 1,000, 10,000, 65,535.
Hover a bar to see "21 ftp, critical". Bars grow in from the bottom on load,
staggered. Used large on the report, small as a thumbnail on scan rows and
host rows.

### 5.12 Radar (Live run only)
A circle with three rings and crosshairs. A beam in `--live` red
(conic gradient trail plus a bright leading line) sweeps clockwise every 4s.
Each open port found so far is a dot placed clockwise from the top by the same
log scale. A dot flashes exactly when the beam passes over it
(animation delay = its angle fraction times 4s).

### 5.13 Feed (Last scan on New scan)
Timestamped event pills along a dashed vertical line, the newest is a
highlighted card with a red border and glow, the top findings with severity
badges, and an arrow button that opens the report.

## 6. Motion

* One page load sequence: panels fade up from a slight blur
  (0.8s, `cubic-bezier(.2,.8,.2,1)`), staggered about 0.06s apart.
* Page titles get one light sweep across the text after load.
* Counts count up once on load.
* Expanding rows (findings) open smoothly by animating
  `grid-template-rows` from `0fr` to `1fr`.
* Spinners and pulses only while something is actually running.
* Never fake a percentage progress bar for work with unknown length. Show the
  step list with elapsed time instead.
* Respect `prefers-reduced-motion: reduce`: turn every animation and
  transition off.

## 7. Copy

Plain, direct, sentence case, active voice. Say what happened, what it means
for the results, and what to do next. Never apologize, never be vague.

Action descriptions (use exactly):

| id | Name | Tool | Description |
| --- | --- | --- | --- |
| surface | Surface Map | nmap | Scans the target with nmap to find which TCP ports are open and which service and version runs on each. Always runs. |
| exploits | Exploit Hunt | searchsploit | Searches Exploit-DB for public exploits that match each service and version nmap found, marks whether the version match is exact, and flags services that are risky just by being exposed. |
| cves | CVE Intel | NVD | Looks up each service version in the NVD database and lists its known CVEs with CVSS scores. Flags any that CISA lists as actively exploited. |
| web | Web Fingerprint | httpx | Connects to each web port and identifies the web server, frameworks and technologies in use, plus which security headers are missing. |
| paths | Hidden Paths | ffuf | Requests a list of common file and folder names on each web port to find pages that exist but are not linked, such as admin panels. |
| vulns | Vuln Probe | nuclei | Runs nuclei templates against web services to confirm known vulnerabilities and misconfigurations. Safe templates only, no DoS or fuzzing. |
| crypto | Crypto Check | testssl.sh | Tests every TLS port, including STARTTLS, for outdated protocol versions, weak ciphers and certificate problems. |
| smb | SMB Recon | enum4linux-ng | Connects to SMB without a password and lists the shares, users, groups and domain details an anonymous user can see. |

Presets (the actions, ports and nuclei mode come from
`reconmind/core/scan_plan.py`, never hard coded in the frontend):

| id | Name | Description |
| --- | --- | --- |
| quick | Quick | Scans the top 1000 ports, then checks each service for public exploits and known CVEs. |
| standard | Standard | Scans the top 1000 ports and runs all 8 actions. Nuclei only runs templates that match the technology it detects. |
| full | Full report | Scans all 65535 ports and runs all 8 actions with every safe nuclei template. One host at a time. |

## 8. Safety rules for the frontend (required)

1. **Tool output is untrusted.** Banners, HTTP titles, share names, file
   paths and code come from the target. Never put server or user data into
   `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write`. Build
   the DOM with `createElement` and set text with `textContent`.
2. The server binds to 127.0.0.1 only.
3. The server checks the Host header (127.0.0.1 or localhost) to block DNS
   rebinding.
4. Every state changing request needs the header `X-ReconMind: 1` and a JSON
   body. There is no CORS, so other websites cannot send it.
5. A strict Content Security Policy: scripts only from the app itself, no
   inline scripts.
6. The frontend never decides what is allowed. The authorization gate in
   `reconmind/core/authorization.py` and the scan plan checks run on the
   server for every request, and again inside the CLI.
7. The allowlist and denylist are shown read only. The app has no way to
   change them.
