# macOS visual rule editor — functional beta

## Operator path

Open **Дополнительно → Правила…**. The native SwiftUI sheet is an isolated
copy of the current JSON profile, validated by the same exported Rust
`fb_validate_json` function as the engine. No WebView and no new routing ABI.

- Add, duplicate (disabled by default), delete, move up/down and enable rules.
- Edit ID, application patterns, hostname wildcards, IPv4/IPv6 CIDRs,
  individual ports and port ranges; select Direct, Block, declared proxy or
  declared chain; choose the default action. First match retains precedence.
- Selection change first validates and stores the previous edited rule into
  the **dialog copy**. An invalid rule leaves selection and accepted draft
  unchanged and shows the Rust/field error.
- **Отмена** discards the entire dialog copy. **Сохранить черновик** checks
  every rule plus the default against strict Rust FFI before updating
  `engine.config`. Changes to live routes require the existing separate
  **Применить профиль** action, which retains the engine's atomic rollback.
- The app selector on the Приложения page is a separate guided workflow;
  enabled app-selection mode may replace the explicit rules on Apply.
  App-origin claims require actual OS signing identity, not a guessed process.

## Acceptance matrix (still required on actual Macs)

| Case | Expected evidence |
|---|---|
| Create, duplicate, reorder and enable | persisted profile, matching Rust first-match route, original rule priority |
| Invalid port 70000, malformed CIDR, unknown proxy | stable previous draft; rejected edit; no live-route change |
| Cancel with unsaved fields; close without Apply | byte-identical parent JSON; still-active route untouched |
| Save draft, Apply during running managed SSH | strict validation, atomic reload, no DIRECT on failure |
| Native NE transparently-selected app | **separate** approved signed Apple NE activation proof |
| Retina, keyboard, focus and VoiceOver | manual real macOS ARM64 + Intel visual/accessibility evidence |

Only exact-head macOS SwiftUI application builds are automated here. An
unsigned hosted package does **not** prove entitlement, system-extension
activation, OS-per-app selection or remote DNS privacy. No 1.0 release claim.
