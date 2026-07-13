# Repository Guidelines

## Project Structure
- Root docs: README.md
- Scheduler: scheds/rust/scx_lavd/src/ (userspace) and scheds/rust/scx_lavd/src/bpf/ (BPF scheduler)
- Hyprland daemon: scheds/rust/scx_lavd/examples/anima_hypr_daemon.rs
- Systemd/services: services/
- Shared Rust workspace: rust/ and lib/

## Build / Format / Docs
- cargo build --release
- cargo fmt
- cargo fmt -- --check

## Coding Conventions
- Format with cargo fmt before committing
- Rust: snake_case for identifiers, PasicalCase for types
- Keep BPF patches minimal and local to scheduler logic
- When editing, match the existing code style in the file

## Verification
- For scheduler-related changes, describe how you validated behavior
- For BPF changes, consider verifier and runtime impact
- Run relevant workspace checks before opening a PR

## Commits & PRs
- Use concise, present-tense commit messages explaining behavior change
- Keep commits focused on one concern
- PRs should summarize the change, rationale, affected paths, and how it was tested

## SOP: Tool Routing for Codebase Exploration

> Start with native harness tools (`glob`, `grep`, `read`, `lsp`, `ast_grep`),
> then fall back to `jcodemunch` MCP hooks when the query crosses file or
> language boundaries, needs a hierarchical view, or is a structural-smell /
> refactor query. `Index, then search, then read full files only as needed.`

### 1. Directory listing

*Use* `glob` for one-shot directory listing — it sorts by mtime, honors `.gitignore`
by default (`gitignore: false` to surface `.env*`/build outputs), and takes a
semicolon-delimited list to scan several roots at once. `read` on a directory path
also lists entries when you need depth-limiting.
*MCP hook* `mcp__jcodemunch_list_content` (repo handle) is for **indexed** repos
and shines when you need to enumerate code **and** docs (TOML, Markdown,
Dockerfile) as one tree — e.g. finding where a scheduling constant is documented
in `README.md` and referenced in `src/bpf/` in a single pass.

### 2. Text and symbol search

*Try* `grep` first — it supports Rust regex + PCRE2 (`pattern`, `case` flag,
`selector` for line ranges like `"50-100"`, context lines), scope it with
`path` (semicolon-delimited list: `src; tests`). For symbol-aware lookups
(definition, type, implementation, hover, rename), use `lsp` — it follows
shadowing, re-exports, and cross-file callsites that text search misses. For
structural patterns (calls, declarations, nested shapes) use `ast_grep`.
*MCP hooks* — `mcp__jcodemunch_search_units` (semantic + cross-language) when
the repo is indexed; `mcp__jcodemunch_search_text` for regex over indexed
content; `mcp__jcodemunch_search_columns` for dbt/SQLMesh model columns.

### 3. Outline / signature drill-down

*Use* `read` with a line selector (`file.rs:50-200`, `:50+150`, `:raw` for
verbatim) for targeted file sections; `lsp` `symbols` for a file's or
workspace's symbol list.
*MCP hooks* — `mcp__jcodemunch_get_outline` (per-file),
`mcp__jcodemunch_get_repo_map` (token-budgeted PageRank-ranked signature map of
the whole repo), `mcp__jcodemunch_get_unit_context` (per-symbol capsule with
callers/callees) — these beat big-file `read` when you need every struct and
inline function in `main.bpf.c` without reading the whole translation unit.

### 4. Symbol-level context (callers / callees / references)

*Start* with `lsp` — `references`, `definition`, `type_definition`,
`implementation`, `rename`, `code_actions`. It is symbol-aware and finds callers
that text search silently drops. Use `ast_grep` for structural callsite
patterns across many files.
*MCP hooks* — `mcp__jcodemunch_get_blast_radius` (all files affected by a
change, with risk scores), `mcp__jcodemunch_get_call_hierarchy` (incoming /
outgoing N levels, optional `impact` subtree), `mcp__jcodemunch_find_references`
(with `call_depth` and `include_decisions`). These win when a symbol touches ten
-plus files, when you need cross-repo importers (`cross_repo: true`), or when you
need a pre-rewrite impact subtree. Example: tracing every callsite depending on a
BPF map update in `anima.bpf.c` is one blast-radius call versus `lsp references`
plus several greps.

### 5. Dead code and refactoring

*For renames and signature changes* use `lsp` `rename` / `rename_file` —
**never** `ast_edit` or hand-edits for a cross-file rename, since text renames
silently drop callsites. Use `ast_edit` for structural codemods (rewrites where
shape matters more than text).
*MCP hooks* — `mcp__jcodemunch_plan_refactoring` produces `{old_text, new_text}`
blocks for rename/move/extract/signature changes; `mcp__jcodemunch_check_safe`
(`mode: "delete"` / `"edit"`) before deleting or changing a symbol;
`mcp__jcodemunch_get_dead_code_v` for likely-dead functions (three-signal
confidence); `mcp__jcodemunch_find_similar_symbols` to spot duplicate LAVD
helpers hoistable into `lib/`. Use `lsp` `code_actions` for import fixes and
quick-factors before editing by hand.

### 6. Structural anti-pattern and interface scan

*For preset anti-patterns and language-agnostic structural scans* use
`mcp__jcodemunch_search_ast` — `category: "all"|"security"|"complexity"|
"error_handling"|"performance"|"maintenance"` runs preset detectors
(empty_catch, bare_except, deeply_nested, nested_loops, god_function, eval_exec,
hardcoded_secret, todo_fixme, magic_number, reassigned_param) across `.bpf.c`,
Rust, and BPF C in one pass; supply a custom `pattern` for a one-off AST query.
*For interface / abstract-method implementations* use
`mcp__jcodemunch_find_implementations` (ranks by PageRank × byte length,
classifies subclass_override / interface_impl / duck_typed / decorator_handler).
*For single-language shape queries* prefer `ast_grep` directly.

### 7. Runtime diagnostics, debugging, and profiling

*For live programs* use the `debug` tool (`launch` / `attach`, breakpoints,
`step_over`/`step_in`/`step_out`, `threads`/`stack_trace`/`variables`) — this is
the harness debugger, not a shell session.
*MCP hooks for ingested traces* — `mcp__jcodemunch_import_runtime_signal`
(`source: "otel"|"sql_log"|"stack_log"`) ingests a trace file;
`mcp__jcodemunch_find_hot_paths` (top-N by hit count, with p50/p95 latency)
ranks symbols by runtime cost — use both when tuning BPF scheduler overhead on
real workloads. `mcp__jcodemunch_get_symbol_complexity` (cyclomatic, nesting,
params), `mcp__jcodemunch_get_repo_health` (dead-code %, complexity, cycles), and
`mcp__jcodemunch_get_tectonic_map` (module topology) for pre-rewrite triage.

### Rules of thumb

1. **Native first.** `glob` for paths, `grep` for text, `read` for file
   bodies, `lsp` for symbol intelligence, `ast_grep` for single-language
   structure, `debug` for runtime state. Reach for `jcodemunch` only when the
   query crosses file or language boundaries, needs a hierarchical view, or is a
   structural-smell / refactor query.
2. **`lsp` before text search for exported symbols.** References, renames, and
   definitions MUST go through `lsp` — text tools miss shadowed / re-exported
   callsites. `ast_edit` / hand-edits for a cross-file rename are forbidden when
   `lsp` `rename` applies.
3. **`ast_grep` before regex for syntax shape.** If the pattern is a call,
   declaration, or nesting shape, `ast_grep` is correct and `grep` is lossy.
4. **Feed MCP context to patches.** Wrap `find_references` / `get_blast_radius`
   output into every file edit so downstream reviewers see the provenance chain.
5. **Alias usage by intent.** Before each MCP hit, add one line:
   _"why `_hook_` > native: <one-line reason>."_ This keeps your SOP honest
   and explainable to new contributors.
