# Local APK Security Report Pipeline

For installation on another computer, see [Requirements and Usage](REQUIREMENTS_AND_USAGE.md),
including Ubuntu setup and a separate Windows/WSL 2 walkthrough.

The full cycle currently runs two CLI agents over an APK set:

1. Static inventory, decompilation, and protection analysis — Claude Code, Opus 4.7 High
2. Frida bypass script generation from the static report — Claude Code, Opus 4.7 High

Final HTML/PDF report generation is temporarily disabled. Its implementation,
methodology, and schema are preserved for later development. `--stage all` (the
default) finishes after Frida script generation; `--stage final` is unavailable.
New runs contain only the two active stages and require no PDF renderer.

Methodology steps 6 and 7 are deferred. The pipeline must not claim that TLS
interception or API testing succeeded.

New static reports use only `PRESENT` or `ABSENT` in the protection verdict column
and JSON verdict field. Enforcement, advisory behavior, telemetry, and coverage
limitations remain in the explanations and evidence. `PRESENT` does not imply an
enforced defense; `ABSENT` means none was identified within the inspected scope.

## Terminal setup

Run commands from this project directory. The pipeline is terminal-only and uses
Python 3.10 or newer, the Claude Code CLI, and the analysis tools checked
by `doctor`.
Node.js and npm are not required by the pipeline itself; your Claude Code installation
and individual analysis tools may have their own runtime requirements.

Place each APK set directly under `apks/<application-name>/`. For split packages,
keep `base.apk` and its configuration APKs in the same folder. A single standalone
APK may use any filename ending in `.apk`.

## Model configuration

Choosing models is optional. Both stages use Claude Code with the pinned model
`claude-opus-4-7`.
Both stages default to `high` reasoning effort. Model overrides are optional:

```bash
export APK_PIPELINE_STATIC_MODEL="optional-static-model"
export APK_PIPELINE_FRIDA_MODEL="optional-frida-model"
export APK_PIPELINE_REASONING_EFFORT="optional-effort"
export APK_PIPELINE_FRIDA_EFFORT="optional-claude-effort"
```

Command-line values override environment variables:

```bash
python3 pipeline.py run \
  --stage static \
  --apk-dir apks/yurtici-kargo \
  --static-model your-model
```

After installing Claude Code on the execution host, authenticate it:

```bash
claude auth login
claude auth status
```

Alternatively configure `ANTHROPIC_API_KEY`. Never store credentials in the
repository. The orchestrator removes `CODEX_API_KEY` and `OPENAI_API_KEY` from
Claude's environment. Set `APK_PIPELINE_CLAUDE_BIN` if `claude` is outside `PATH`.
Installation: https://code.claude.com/docs/en/setup

Each stage uses its command-line model option (`--static-model` or `--frida-model`),
then its stage environment variable, then `claude-opus-4-7`. The legacy Codex
`APK_PIPELINE_MODEL` variable is ignored by both active stages.
Reasoning effort precedence is `--reasoning-effort`,
`APK_PIPELINE_REASONING_EFFORT`, then `high`. Stage 2 can override this with
`--frida-effort` or `APK_PIPELINE_FRIDA_EFFORT` (in that order). Supported efforts
are `low`, `medium`, `high`, `xhigh`, and `max`; `minimal` is rejected by Claude.

Runs check Claude availability and authentication before starting either stage.
Dry-runs do not require Claude authentication and make no model calls. An installed,
authenticated CLI does not guarantee access to the selected model on your account.

## Verify the environment

```bash
python3 pipeline.py doctor
python3 -m unittest discover -s tests -v
```

## Preview without model calls

```bash
python3 pipeline.py run \
  --stage static \
  --apk-dir apks/yurtici-kargo \
  --dry-run
```

Preview all stages without making model calls:

```bash
python3 pipeline.py run \
  --stage all \
  --apk-dir apks/yurtici-kargo \
  --dry-run
```

## Run the pipeline

Run the full cycle: static analysis, then Frida script generation:

```bash
python3 pipeline.py run \
  --stage all \
  --apk-dir apks/yurtici-kargo
```

Stage 2 makes one Claude call to generate `02-frida/bypass.js` using only the
static analysis JSON and Markdown reports supplied inline. Claude has no tools;
external MCP, user/project settings, and hooks are disabled. The controller saves
the generated script and its coverage notes. It does not prepare or inspect a
device, install an APK, run ADB or Frida, syntax-check the script, or test it.
Neither an emulator nor an installed Frida runtime is required.

Stage 2 also writes `frida-bypass-report.json` and `frida-bypass-report.md` as
generation metadata retained for future reporting. Schema 2.0 records per-category
`GENERATED`, `NOT_APPLICABLE`, or `INSUFFICIENT_EVIDENCE` coverage and always records
`runtime_validation: NOT_PERFORMED`. Generated means source was produced, not that
a bypass works. Missing target details remain limitations; the generator does not
investigate beyond the static report. If no hook is supported, it produces a
comment-only script explaining why.

`02-frida/events.jsonl` preserves model events, and `generation-result.json` preserves
the full structured response. No runtime evidence or Frida logs are produced.
Handoff checks cover report identity, category coverage, and required artifact
presence only; they do not check script syntax or behavior. The generation notes label
all generated hooks as untested and make no runtime bypass claims.

The generation report uses JSON Schema Draft 7 for Claude CLI compatibility.
Historical runtime reports and completed runs are left intact, but the new pipeline
requires schema 2.0 for stage 2 handoffs. Start a new run for a previously
completed runtime assessment. An existing run with only stage 1 completed can
continue directly with the generation stage. The former `--authorize-dynamic`
option has been removed.

To run one stage first:

```bash
python3 pipeline.py run --stage static --apk-dir apks/yurtici-kargo
```

The command prints the generated run ID. Continue that run later:

```bash
python3 pipeline.py run --stage frida --run-id RUN_ID
python3 pipeline.py status RUN_ID
```

Runs are append-only under `runs/<run-id>/`. Completed or in-progress stage outputs
are not overwritten.

## Progress and remote terminal use

The run prints its ID and event-file paths. From a second terminal, inspect its
state and follow the active stage's detailed output:

```bash
python3 pipeline.py status RUN_ID
tail -f runs/RUN_ID/01-static/events.jsonl
```

Use `02-frida/events.jsonl` for script generation. State is
updated at stage transitions; the event files show activity within a stage.

For an SSH session, run the pipeline inside `tmux` on the execution host so that
disconnecting does not end the session:

```bash
tmux new -s apk-report
cd /path/to/security-report
python3 -u pipeline.py run --stage all --apk-dir apks/APP_NAME
```

Detach with `Ctrl+B`, then `D`; reconnect with `tmux attach -t apk-report`.
The APKs, analysis tools, and Claude authentication must be available on that
execution host. No web server or dashboard port is needed.

Moving execution to another machine still requires adapting the machine-specific
tool paths in `pipeline.py` and the stage files under `methodology/`. Run `python3 pipeline.py doctor` on that host
before starting an assessment. Merely copying the project does not configure these
dependencies.

## Security boundary

APK files and generated reports remain in the local workspace. Relevant prompts,
selected file contents, and tool outputs are sent to the selected remote provider:
Anthropic for both stages. APK-derived content is treated as
untrusted evidence.

Stage 1 enables and preauthorizes Claude's Bash, Read, Write, Edit, Glob, and Grep
tools for local analysis. Its prompt limits writes to the stage output directory;
this is not an OS sandbox, and shell commands inherit Claude's environment.
Stage 2 has no tools. Both invocations disable hooks, slash commands, configured
MCP servers, and user/project/local settings. See the
[Claude CLI reference](https://code.claude.com/docs/en/cli-reference) for tool flags.
