# SecureVault — Design Reference

> Source-of-truth design document generated from the codebase at
> `src/PasswordManager.App/wwwroot/css/app.css`, the `.razor` components under
> `src/PasswordManager.App/Components/`, and the domain models in
> `src/PasswordManager.Core/`. Every value below exists in the repo today —
> no invented tokens, no placeholder copy.

---

## 1. Product

**Name:** SecureVault
**ApplicationId:** `com.securevault.app`
**Tagline (login screen):** "Local-first, PGP-encrypted vault"
**Secondary framing (Key Management page):** "Your PGP keys and the public keys you can encrypt files for"

**What it is in one sentence (derived from the unlock flow and `VaultEntry` hierarchy):**
A local, offline-first password and file vault where every secret is wrapped in
PGP and the user owns their own key pair.

**Surface area (the ten things a user can do, in dashboard order — `Dashboard.razor`):**
1. How PGP works — tutorial
2. Key management — generate, import, export, publish public keys
3. Encrypt files — single-file PGP encrypt/decrypt
4. Encrypt directories — zip + PGP an entire folder
5. Passwords — login credentials with optional TOTP
6. Secure notes — encrypted free-form text
7. Cards — credit and debit cards
8. Password generator — cryptographically strong passwords
9. Vault audit — detect weak, reused or expired credentials
10. Import / export — CSV and Bitwarden JSON

---

## 2. Native shape of the product

This is **not** a timeline, a graph, or a pipeline. It is a **catalog of
secrets** organized into three first-class entry types, surrounded by **tools
that act on those secrets** and **a key-trust system** that lets the catalog
extend to external files and external people.

The data model in `Core/Models/VaultEntry.cs` declares three derived types via
JSON polymorphism:

```csharp
[JsonPolymorphic(TypeDiscriminatorPropertyName = "$type")]
[JsonDerivedType(typeof(PasswordEntry), "password")]
[JsonDerivedType(typeof(SecureNote),   "note")]
[JsonDerivedType(typeof(CardEntry),    "card")]
public abstract class VaultEntry { Id, Label, Tags[], CreationTime, LastUpdateTime, ExpireTime, IsDeleted, DeletedAt }
```

Every entry shares **tags, expiration, and soft-delete**. Designs should treat
those as cross-cutting affordances, not per-type features.

**What dominates the page**: the unlock card and (after login) the **10-tile
dashboard**. The vault list view is the densest information surface; everything
else is single-purpose tooling.

---

## 3. Design tokens

All tokens defined in `wwwroot/css/app.css`. Use these names verbatim.

### 3.1 Color — surfaces

| Token | Value | Use |
|---|---|---|
| `--bg-primary` | `#0f1117` | App background, page background |
| `--bg-secondary` | `#1a1d27` | Sidebar, unlock card, modal |
| `--bg-card` | `#22263a` | Cards, stat cards, dashboard tiles, toast |
| `--bg-input` | `#181b28` | Inputs, secondary button, flow boxes |
| `--border` | `#2a2e3f` | Hairlines between elements |
| `--shadow` | `0 4px 24px rgba(0,0,0,0.25)` | Floating panels |

### 3.2 Color — text

| Token | Value | Use |
|---|---|---|
| `--text-primary` | `#e8e8f0` | Body, headings, input value |
| `--text-secondary` | `#9ca3b0` | Subtitles, descriptions, table cells |
| `--text-muted` | `#636b7a` | Hints, placeholders, fingerprints, scrollbar |

### 3.3 Color — accent and status

| Token | Value | Use |
|---|---|---|
| `--accent` | `#6c63ff` | Brand, primary CTAs, active nav, focus, links |
| `--accent-hover` | `#5a52e0` | Primary button hover |
| `--accent-light` | `rgba(108,99,255,0.15)` | Nav hover, tags, accent flow boxes |
| `--success` | `#22c55e` | Success alerts, strength 7–8, success badge |
| `--warning` | `#f59e0b` | Warning alerts, strength 5–6, medium severity |
| `--danger` | `#ef4444` | Errors, critical severity, lock-vault hover |
| `--danger-hover` | `#dc2626` | Danger button hover |

### 3.4 Color — semantic severity (audit & strength)

Defined alongside the audit issue rendering and strength meter.

| Severity | Class | Color |
|---|---|---|
| Critical | `.badge-critical` | `var(--danger)` `#ef4444` |
| High | `.badge-high` | `#f97316` |
| Medium | `.badge-medium` | `var(--warning)` `#f59e0b` (on `#1a1d27` text) |
| Low | `.badge-low` | `#3b82f6` |
| Success | `.badge-success` | `var(--success)` `#22c55e` |

Strength meter — 8 discrete scores:

| Score | Color |
|---|---|
| 1–2 | `var(--danger)` |
| 3–4 | `#f97316` |
| 5–6 | `var(--warning)` |
| 7–8 | `var(--success)` |

### 3.5 Color — dashboard tile fills (only place a tile uses its own hue)

From `Dashboard.razor`, one per concern at 18% opacity:

| Tile | RGBA |
|---|---|
| PGP tutorial | `rgba(99,102,241,0.18)` |
| Key management | `rgba(245,158,11,0.18)` |
| Encrypt files | `rgba(34,197,94,0.18)` |
| Encrypt directories | `rgba(59,130,246,0.18)` |
| Passwords | `rgba(108,99,255,0.18)` |
| Secure notes | `rgba(236,72,153,0.18)` |
| Cards | `rgba(20,184,166,0.18)` |
| Password generator | `rgba(168,85,247,0.18)` |
| Vault audit | `rgba(239,68,68,0.18)` |
| Import / export | `rgba(251,146,60,0.18)` |

### 3.6 Radius

| Token | Value | Use |
|---|---|---|
| `--radius` | `10px` | Cards, alerts, inputs |
| `--radius-sm` | `6px` | Buttons, tabs, small alerts |
| `16px` (literal) | — | Unlock card, modal |
| `50%` | — | Step number, info-tooltip trigger |
| `100px` | — | Tags, badges (pill shape) |

### 3.7 Type

**Family** (declared on `html, body, #app`): `'Segoe UI', 'Open Sans', sans-serif`
**Monospace** (passwords, code, fingerprints): `'Consolas', 'Courier New', monospace`

**Type scale** (sizes that actually appear in the codebase):

| rem | Used by |
|---|---|
| `0.68rem` | Nav section title |
| `0.7rem` | Badge |
| `0.72rem` | Tag, sidebar brand small |
| `0.78rem` | Button-sm, stat label, hint, fingerprint path |
| `0.82rem` | Card subtitle, form label, btn-lock |
| `0.85rem` | Default button, alert, modal action, totp timer |
| `0.88rem` | Nav link, form-control, card body, password value, page-header p |
| `0.9rem` | Tip list, btn-icon |
| `0.92rem` | Tutorial step content |
| `0.95rem` | Card title, key card title, step number |
| `1rem` | Tile title, nav icon |
| `1.1rem` | Empty state h3, tutorial step h2 |
| `1.15rem` | Sidebar brand h2, modal h2 |
| `1.3rem` | Generator preview |
| `1.4rem` | Unlock card h1 |
| `1.5rem` | Page header h1 |
| `1.8rem` | Stat value |
| `2rem` | TOTP code (letter-spacing 6px) |

**Weight**: 500 (form labels, buttons, tabs), 600 (card title, tile title), 700 (h1, sidebar brand, step number, stat value).

### 3.8 Spacing scale

Observed values across the codebase (px): `4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 24, 28, 32, 40, 48`.
The main grid is **8-aligned with 2/4/6 used for tight inline pairs**.

### 3.9 Transition

`all 0.15s` is the default interaction transition (nav, button, input).
Card border on hover: `border-color 0.15s`.
Dashboard tile hover: `all 0.18s` plus `translateY(-2px)` and `box-shadow 0 8px 24px rgba(0,0,0,0.2)`.

### 3.10 Scrollbar

6px wide. Track transparent. Thumb `var(--border)`, hover `var(--text-muted)`.

---

## 4. Layout

### 4.1 App shell (locked state)

```
+------------------------------------------+
|                                          |
|        +----------------------+          |
|        |   SecureVault        |          |
|        |   subtitle           |          |
|        |   [Sign in | Create] |          |
|        |   ... form ...       |          |
|        +----------------------+          |
|                                          |
+------------------------------------------+
```

- Container fills viewport, content centered.
- Card: `width: 420px`, `padding: 40px`, `border-radius: 16px`, `background: var(--bg-secondary)`, `box-shadow: var(--shadow)`.

### 4.2 App shell (unlocked state)

```
+----------+-------------------------------+
| Sidebar  | Main content                  |
| 240px    | flex:1, padding 28px 32px     |
| brand    |                               |
| nav      | <ErrorBoundary>               |
| (5 sect) |   page                        |
| ...      | </ErrorBoundary>              |
| footer   |                               |
| [Lock]   |                               |
+----------+-------------------------------+
+ ToastHost (fixed, bottom-right, z=1000)
```

Sidebar width collapses to `60px` at `max-width: 768px` and the section
titles/link labels disappear; only icon slots remain.

### 4.3 Sidebar navigation (real labels and groupings)

```
[ Brand: "SecureVault" / "<username> · <email>" ]

  Dashboard               (no section title)

LEARN
  PGP Tutorial

KEYS & FILES
  Key Management
  Encrypt Files
  Encrypt Directories

VAULT
  Passwords
  Secure Notes
  Cards

TOOLS
  Generator
  Audit
  Import/Export

[ footer: "Lock vault" button ]
```

Active state: solid `var(--accent)` background, white text.
Hover: `var(--accent-light)` background, `var(--text-primary)` text.

---

## 5. Components

Every component below already exists. Re-design without renaming.

### 5.1 Card (`.card`)

- Background `var(--bg-card)`, border `1px solid var(--border)`, `border-radius: var(--radius)` (10px).
- Padding `18px 20px`, margin-bottom `12px`.
- Hover: border becomes `var(--accent)`.
- **Anatomy:** `.card-header` (flex space-between, margin-bottom 10px) + `.card-body`.
- **Header children:** `.card-title` (600, 0.95rem) + `.card-subtitle` (0.82rem, secondary text), and a right-side actions cluster.

### 5.2 Buttons

| Variant | Background | Text | Border |
|---|---|---|---|
| `.btn.btn-primary` | `var(--accent)` | white | none |
| `.btn.btn-secondary` | `var(--bg-input)` | `var(--text-primary)` | `1px solid var(--border)` |
| `.btn.btn-danger` | `var(--danger)` | white | none |
| `.btn-icon` | transparent | `var(--text-secondary)` | `1px solid var(--border)` |
| `.btn-lock` | transparent | `var(--text-secondary)` | `1px solid var(--border)` |

Default size: `padding 9px 18px`, `font-size 0.85rem`, `font-weight 500`, `border-radius var(--radius-sm)`.
`.btn-sm`: `padding 5px 12px`, `font-size 0.78rem`.

**Iconography rule (project decision):** action buttons currently display **text labels** (`Show / Hide / Copy / Edit / Delete / 2FA`). A future icon set from Flaticon will live in `<IconSlot />`, which already reserves 18×18px (`lg` = 28×28, `xl` = 40×40). **Do not introduce emoji.**

### 5.3 Form control (`.form-control`)

- Full-width, `padding 10px 14px`, background `var(--bg-input)`.
- Border `1px solid var(--border)`, radius `var(--radius-sm)`.
- Focus border becomes `var(--accent)`.
- Placeholder color `var(--text-muted)`.
- Label sits above (`.form-group label`, 0.82rem, secondary). Labels can host an `<InfoTooltip>` inline.

### 5.4 PasswordField (custom component)

`Components/Shared/PasswordField.razor`. Renders the `.input-group` pattern:
text/password input + persistent "Show / Hide" toggle button. The toggle is
project-local — do **not** rely on the browser's native eye icon.

### 5.5 InfoTooltip

`Components/Shared/InfoTooltip.razor`. Small circular `i` (italic Georgia,
0.7rem, 16×16px, `var(--accent)` background, white text). Hover/focus reveals
a 280px bubble above the trigger:

- Background `var(--bg-card)`, border `1px solid var(--border)`, radius `var(--radius-sm)`.
- Padding `10px 12px`, font 0.8rem, line-height 1.5.
- Triangle indicator at bottom.

### 5.6 IconSlot

`Components/Shared/IconSlot.razor`. Empty `<span>` reserving icon space.
Default 18×18px; `lg` 28×28; `xl` 40×40. Real SVG/Flaticon glyphs will be
slotted later — every layout must already reserve the box.

### 5.7 Tag (`.tag`)

Pill, `padding 2px 10px`, `background var(--accent-light)`, `color var(--accent)`, 0.72rem, weight 500.

### 5.8 Badge (`.badge.badge-*`)

Pill, `padding 3px 10px`, 0.7rem, weight 600, uppercase, letter-spacing 0.5px. See §3.4 for color mapping.

### 5.9 Alert (`.alert.alert-{info|success|warning|danger}`)

`padding 12px 16px`, radius `var(--radius-sm)`, font 0.85rem. Tinted background
at 10% of the status color over a 30% border of the same color, body text at a
lighter tint (`#93bbfd`, `#86efac`, `#fcd34d`, `#fca5a5`).

### 5.10 Toast (`.toast`)

Fixed bottom-right, `min-width 280px`, `max-width 420px`, `padding 12px 14px`.
4px left border colored by kind: success → `var(--success)`, error → `var(--danger)`, info → `#3b82f6`, warning → `var(--warning)`. Includes an icon (`✓ ✕ ℹ ⚠`), body, and `×` close button. Animates in via `translateX(20px)` over 0.2s. Auto-dismisses (3.5s default, 5s for errors).

### 5.11 Modal (`.modal-backdrop` + `.modal`)

- Backdrop: `position: fixed; inset: 0`, `rgba(0,0,0,0.6)`, flex-centered, `z-index: 100`.
- Modal: `width: 480px`, `max-width: 90vw`, `max-height: 85vh`, scroll inside, padding 28px, radius 16px.
- Footer (`.modal-actions`): flex end, gap 10px.

### 5.12 Stat card (`.stat-card`)

`text-align: center`, padding `16px 20px`. Value at `1.8rem / 700`; label at `0.78rem / var(--text-muted)`. Used in the Audit page header (4 in a row).

### 5.13 Empty state

`.empty-state` → centered, padding `48px 24px`, color `var(--text-muted)`.
- Icon container (now `<IconSlot CssClass="xl" />`) at top.
- `h3` `1.1rem` `var(--text-secondary)`.
- `p` `0.85rem`.

### 5.14 Password value / masked

`.password-value` — monospace, `var(--accent)`, letter-spacing 0.5px.
`.password-masked` — render as `••••••••••••` (or `•••• •••• •••• ••••` for card numbers, `•••` for CVV).

### 5.15 Strength meter

4px-tall track (`var(--border)`) + fill colored by score (§3.4). Width = `score * 12.5%`. CSS transition 0.3s on width + background.

### 5.16 TOTP viewer

- Code: `2rem`, monospace, letter-spacing **6px**, `var(--accent)`, centered.
- Timer text: `0.85rem`, `var(--text-muted)`, centered. Format: `"<n> s remaining"`.
- Bar: 3px tall. **The fill uses a 30-second CSS animation on `transform: scaleX`** with `transform-origin: left center`, **not** a recurring width update. Re-keys on each new code so the animation restarts; `animation-delay: -Xs` syncs it to the live time-step on open.

### 5.17 Tabs (used on Sign in / Create account, Encrypt File, Encrypt Directory)

Container `.tab-bar` — `display:flex`, background `var(--bg-input)`, radius `var(--radius-sm)`, padding 4px. Each `.tab-btn` flex:1, transparent, `var(--text-secondary)`. Active tab: `var(--accent)` background, white text.

### 5.18 PathPicker

`Components/Shared/PathPicker.razor`. `.input-group` (text input + secondary
button). Three modes:

- `File` — button label "Attach file" — opens native file picker for an existing file.
- `Folder` — button label "Choose folder" — opens native folder picker.
- `SaveFile` — button label "Save as..." — opens native "Save As" dialog. Takes a `SuggestedFileName`.

Placeholder text **must always be a concrete example path** (e.g.
`C:\Users\jane\Documents\secret.pdf`), never an instruction like
"Path to file".

---

## 6. Pages

Each page has a `.page-header` with `h1` (1.5rem / 700) and a one-line `p`
(0.88rem / secondary). Below are the real titles, subtitles, and primary
actions.

### 6.1 `/` — Sign in / Create account

- Centered unlock card.
- Title: **SecureVault**
- Subtitle: **Local-first, PGP-encrypted vault**
- Tab bar: `Sign in` | `Create account`. If no accounts exist, default to Create.
- **Sign in fields:** Username or email; Master passphrase (with `<InfoTooltip>` containing 3 bullets); primary button `Sign in` / `Signing in...`. Bottom footnote when local accounts exist: "Existing accounts on this device: ...".
- **Create account fields:** Username; Email; Master passphrase + tooltip with 5 bullets; Confirm passphrase. Footnote: "Your vault is created automatically in this device's app data folder."

### 6.2 `/dashboard`

- H1 dynamic: `"Welcome back, <username>"`.
- Sub: `"What would you like to do today?"`.
- Grid: `repeat(auto-fill, minmax(240px, 1fr))`, gap 16px.
- Each tile is an `<a>` with: 48×48px tinted icon container (§3.5 colors) → 1rem/600 title → 0.82rem secondary description. Hover: border `var(--accent)`, lift -2px.
- **Use the exact 10 titles/descriptions in §1.**

### 6.3 `/tutorial`

Vertical stack of `.tutorial-step` rows, each is a circle step-number (36×36px,
`var(--accent)`, white, 700) + `.step-content` card. Six steps with these
exact headings (already in code, do not paraphrase):

1. You own a key pair (Public key / Private key cards — green/red tint)
2. Your private key is protected by your passphrase (flow diagram)
3. Encryption flow (two-row vertical flow diagram)
4. The vault file itself is a PGP-encrypted blob
5. Tips for your master passphrase (5-item bullet list)
6. The key directory (CTAs: "Open Key Management", "Try encrypting a file")

Max width 880px.

### 6.4 `/keys` — Key management

Three vertical sections separated by `.section-title` rules:

1. **Your keys** — single card with username, email, paths to `public_key.asc` and `private_key.asc`, action row: `Export my public key`, `Add to my contact directory`, `Publish to keys.openpgp.org`.
2. **Public keyservers** — card with `Search a contact's key by email` (input + Search button). Results appear as success alert with a label input and `Add to my contact directory` button.
3. **Contact directory** — header with count (n), info card explaining the directory, single button `Import contact key from file`. List of contact cards (label + fingerprint + path) with `Delete` button. Empty state when zero.

Two modals: import-from-file and publish-to-server.

### 6.5 `/encrypt-file` and `/encrypt-directory`

Same anatomy. Tab bar `Encrypt` / `Decrypt` (max 260–360px wide). Below, a single card containing the form:

- **Encrypt tab:** input via PathPicker (file or folder), Recipient `<select>` (always lists "Myself (<username>)" first, then contacts), optional Output via PathPicker in SaveFile mode (auto-suggested filename), primary button `Encrypt file` / `Encrypt directory`.
- **Decrypt tab:** input via PathPicker filtered to `.pgp .asc .gpg`, master passphrase via `PasswordField`, optional Output via SaveFile/Folder picker, primary button `Decrypt file` / `Decrypt directory`.

Result alert below the form, danger or success kind. Loading text: `Encrypting...` / `Decrypting...` / `Extracting...`.

**Size limits** (hard enforced in `FileEncryptionService`):
- Files: **200 MB max**
- Directories: **1 GB max**
- Error message format: `"File is too large (348 MB). Maximum supported size is 200 MB."`

### 6.6 `/vault` — Passwords

- Header row: H1 `Passwords` + `<n> entries in your vault` subtitle, right-aligned primary button `Add password`.
- Search input full-width, placeholder `"github.com, jane.doe, work..."`.
- Empty state if 0 entries.
- Each entry is a `.card`:
    - Title = `Site` (e.g. `github.com`).
    - Subtitle = `Username` + `(Email)` if present.
    - Actions cluster (flex, gap 6px, wraps): `2FA` (only if `TotpSecret` not null), `Show`/`Hide`, `Copy`, `Edit`, `Delete` (danger).
    - Body: `.password-field` shows `••••••••••••` masked or monospaced accent-colored value when revealed.
    - If `Tags.Count > 0`, render `.tag-group` (margin-top 8px) with each tag as `.tag`.
- **Add/Edit modal** fields, in order: Site, Username, Email (optional), Password (with Show/Hide toggle + `Generate` button using shared `GeneratorPreferences`, plus strength meter when not empty), Tags (comma-separated), TOTP secret (with `<InfoTooltip>` explaining 2FA).

### 6.7 `/vault/notes` — Secure notes

Same shell as Passwords. Card title = `Title` of the note. When revealed,
body shows `<pre>` with the decrypted content (whitespace preserved, font
0.85rem, `var(--text-primary)`). Modal form fields: Title, Content (textarea
rows=6), Tags. Placeholders use concrete examples:
`"Recovery codes for Google"`, `"Backup recovery codes:\n1234-5678\n9012-3456"`,
`"2fa, backup"`.

### 6.8 `/vault/cards` — Cards

Card title = `CardholderName`. Subtitle = `"Expires MM/YYYY"`. Masked view:
`"Number: •••• •••• •••• ••••"` and `"CVV: •••"`. Revealed view shows monospaced accent values.
Modal fields: Cardholder Name, then a 2-column grid for `Card Number` + `CVV`, another 2-column grid for `Expiry Month` (1–12) + `Expiry Year` (2024–2040).

### 6.9 `/generator` — Password generator

Single card. Top: large monospace preview (`1.3rem`, accent, centered, on
`var(--bg-input)` panel). Below: strength bar + `"Strength score: <n> / 8"`.
Actions row: `Generate new` (primary), `Copy` (secondary).

Controls (2-column grid):
- Left: `Length: <n>` with range slider (8–64, accent-colored).
- Right: 4 checkboxes — Uppercase (A-Z), Lowercase (a-z), Digits (0-9), Special characters.

Below: `Exclude characters` text input with `<InfoTooltip>` explaining lookalikes like `0/O`, `1/l/I`.

**These preferences are shared via `GeneratorPreferences` singleton** — when
the user presses `Generate` inside the Vault modal, the same options apply.

### 6.10 `/audit` — Vault audit

Initial: centered `Run Audit` primary button.
After run:

- 4-stat row (`.grid-4` of `.stat-card`): Total Passwords (default color), Weak (danger), Reused (`#f97316`), Expired (warning).
- If no issues: green success alert "No security issues found. Your vault is in great shape!"
- Otherwise: table with columns `Entry | Issue | Severity | Details`, ordered by severity descending. Severity cell uses `.badge.badge-{severity-lowercase}`.
- Footer: `Re-run Audit` secondary button.

### 6.11 `/import-export`

Two-column grid (`.grid-2`):
- **Export card:** explanatory copy ("Export your passwords to CSV format. The exported file contains plaintext passwords."), button `Export to CSV`. On success a green alert with the saved path.
- **Import card:** Format `<select>` (`CSV` | `Bitwarden JSON`), File path via PathPicker (extensions `.csv .json .txt`), `Import` button. Result alert (danger or success).

---

## 7. Voice & terminology

Use these terms verbatim. No synonyms.

| Concept (code) | UI label |
|---|---|
| `VaultEntry` (abstract) | Vault entry |
| `PasswordEntry` | Password |
| `SecureNote` | Secure note |
| `CardEntry` | Card |
| `Tags` | Tags |
| `ExpireTime` | Expiration / Expires |
| `IsDeleted` | Moved to trash (soft delete) |
| `Passphrase` | Master passphrase (never "master password") |
| `IPgpService` keys | Public key / Private key |
| `IKeyDirectoryService` | Contact directory |
| `TotpSecret` | TOTP secret / 2FA |
| `IVaultAuditor` issues | `WeakPassword`, `ReusedPassword`, `ExpiredEntry`, `NoExpiration` (display as: Weak, Reused, Expired, No expiration) |
| `AuditSeverity` | `Low`, `Medium`, `High`, `Critical` |

**Error messages**: keep the existing format — actionable, terse, end with a period.
Examples already in the repo:
- `"Username is required."`
- `"Passphrase must be at least 8 characters."`
- `"Passphrases do not match."`
- `"No account found with that username or email."`
- `"Incorrect passphrase."`
- `"File is too large (348 MB). Maximum supported size is 200 MB."`

**Placeholders are always concrete examples**, never instructions:
- `jane.doe  or  jane@example.com`
- `caballo_correcto_batería_grapa`
- `JBSWY3DPEHPK3PXP`
- `C:\Users\jane\Documents\secret.pdf`
- `Alice Johnson`
- `github.com`

**Toast copy** (already used):
- `"Password copied to clipboard."`
- `"Entry added."` / `"Entry updated."` / `"Entry moved to trash."`
- `"Your public key is now in your contact directory."`
- `"Welcome to SecureVault!"`

---

## 8. Iconography policy

There are **no emoji** anywhere in the UI today and none should be added.

Every place that will eventually carry an icon already renders an empty
`<IconSlot />` reserving the box. When real icons (Flaticon SVGs) are added:

- Sidebar nav: 18×18px monochrome line icons, color inherited from the link.
- Dashboard tiles: 28×28px (`IconSlot lg`) on the tinted 48×48px container.
- Empty states: 40×40px (`IconSlot xl`).
- Action buttons (vault rows, key cards): text labels stay; an optional 14×14px icon may sit **before** the text.

---

## 9. Responsive behavior

Single breakpoint declared in `app.css`: **`max-width: 768px`**.

At ≤768px:
- Sidebar collapses to 60px wide; brand text and section titles hide; only `IconSlot` placeholders remain in nav links.
- Main content padding drops from `28px 32px` to `16px`.
- `.grid-3` and `.grid-4` collapse to 2 columns.

Tutorial page additionally collapses the public/private key pair to 1 column at ≤600px.

---

## 10. State conventions

- **Empty state**: every list view (`/vault`, `/vault/notes`, `/vault/cards`, contact directory) must render an `.empty-state` with `<IconSlot CssClass="xl" />`, an `h3`, and a one-line `p` plus optionally a CTA.
- **Loading state**: buttons swap label to a present-participle ending in `...` (`Signing in...`, `Encrypting...`, `Importing...`, `Searching...`, `Analyzing...`). They remain visible and `disabled`.
- **Error state at field level**: a `.alert.alert-danger` rendered just above the action row inside the form/modal.
- **Error state at page level**: handled by `<ErrorBoundary>` in `MainLayout.razor`; renders a danger alert with "Something went wrong on this page:" + `Try again` button.
- **Success feedback**: `ToastService.Success(...)` from `MauiProgram`-registered singleton. Inline success alerts only when the user must read further (e.g. keyserver search result).

---

## 11. Cryptographic surfaces — design rules

These rules come from the model and should never be violated in the UI:

- **Never show or copy the private key** by itself. The only key UI exposes
  freely is the **public key** (export, publish, share).
- The **master passphrase** appears only inside `<PasswordField>` (with toggle).
  It is never autoflled, never echoed back, never written to a toast.
- `private_key.asc` may be referenced by path (for backup guidance) but not
  rendered as content.
- The Encrypt File/Directory recipient selector must always include the
  current user as the first option, labeled `Myself (<username>)`.
- Strength scores 1–4 should not block save (the user is allowed to be
  unwise) but the meter must be visible whenever a password field is non-empty.

---

## 12. Files this design lives in

- Tokens: `src/PasswordManager.App/wwwroot/css/app.css`
- Shell: `src/PasswordManager.App/Components/Layout/MainLayout.razor`
- Pages: `src/PasswordManager.App/Components/Pages/*.razor`
- Shared components: `src/PasswordManager.App/Components/Shared/{PasswordField,InfoTooltip,IconSlot,PathPicker,ToastHost}.razor`
- Domain shape: `src/PasswordManager.Core/Models/*.cs`
- Services that drive copy (errors): `src/PasswordManager.Infrastructure/Services/*.cs`

When in doubt, the code wins. Update this document if you intentionally diverge.
