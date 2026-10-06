# Requirements and Usage

This guide covers installing the project on another computer after cloning its Git
repository. Instructions were checked on 2026-10-06 against the current code and
linked vendor documentation. Installation on a fresh machine or Windows/WSL has
not been exercised as part of writing this guide.

## Current scope

The full cycle runs two stages:

1. Static APK analysis through Claude Code.
2. Frida bypass script generation through Claude Code, using only the static reports.

The generator does not prepare or inspect devices, install APKs, connect to an
emulator, or execute, syntax-check, or test the generated script. Its output is
untested source code plus generation notes.

Final HTML/PDF reporting is temporarily disabled. `--stage all` ends after script
generation, and `--stage final` is unavailable. No emulator, ADB, Frida runtime,
frida-server, MobSF installation, Docker, Android Studio IDE, or PDF renderer is
required. Methodology steps 6 and 7 remain excluded.

## Requirements

| Component | Version or requirement | Purpose |
| --- | --- | --- |
| Operating environment | Ubuntu 24.04; Windows instructions use Ubuntu under WSL 2 | Matches the project's Linux tool commands |
| Python | 3.10 or newer | Pipeline and tests; standard library only |
| Java | OpenJDK 21 in this guide | Runs Apktool, JADX, and Android SDK tools |
| Git | Available on `PATH` | Clone and update the repository |
| Shell utilities | Bash, curl, unzip, file, ripgrep, coreutils | Installation and static inspection |
| Claude Code CLI | Current release with structured JSON output | Static analysis and script generation |
| Android SDK Build Tools | 36.0.0 | `aapt2` and `apksigner` |
| Apktool | 2.10.0 JAR | Resource and smali decoding |
| JADX | 1.5.3 cross-platform ZIP | DEX decompilation |
| Provider access | Authenticate Claude Code and have access to the configured models | Model calls |
| Internet access | Required for installation, authentication, and model calls | The pipeline is not offline |

The analysis-tool versions above match the repository's current configuration;
they are not claims about the latest releases. There are no pip dependencies or
`requirements.txt` to install. Node.js/npm are unnecessary when using the native
CLI installers below. Decompilation storage and memory needs vary by APK size.

## Linux installation: Ubuntu 24.04

Run these commands in a Bash terminal. Replace example repository URLs, usernames,
and download paths with your own. Use your regular account for the project and
CLI authentication; only the OS package installation needs `sudo`.

### 1. Install base packages

```bash
sudo apt update
sudo apt install -y git python3 openjdk-21-jdk-headless curl unzip file ripgrep coreutils ca-certificates

python3 --version
java -version
```

### 2. Clone the project

```bash
mkdir -p "$HOME/projects"
cd "$HOME/projects"
git clone YOUR_REPOSITORY_URL security-report
cd security-report
```

Keep tool downloads outside the repository. This guide uses
`$HOME/tools/android-security` for Apktool/JADX and `$HOME/Android/Sdk` for the SDK.

### 3. Install and authenticate Claude Code

Install Claude Code using its [official installer](https://code.claude.com/docs/en/setup):

```bash
curl -fsSL https://claude.ai/install.sh | bash
```

Follow any installer instructions to add its executable directory to `PATH`, then
open a fresh terminal. The command must resolve before continuing:

```bash
command -v claude
claude --version

claude auth login

claude auth status
```

The project supports `ANTHROPIC_API_KEY` as an alternative to saved
authentication. Set the key in your shell environment; do not put it in the
repository. The pipeline does not
load `.env` automatically. Successful sign-in does not guarantee access to every
model; see the model configuration section below.

### 4. Install Android SDK Build Tools

Download the **Linux command-line tools** package from the
[Android Studio download page](https://developer.android.com/studio#command-tools).
The IDE is not needed. Arrange the extracted files so that this executable exists:

```text
~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager
```

The `latest` directory must contain `bin`, `lib`, `NOTICE.txt`, and
`source.properties`, rather than another nested `cmdline-tools` directory. Follow
Google's [SDK manager instructions](https://developer.android.com/tools/sdkmanager).

Then install the version used by this project and review/accept the applicable
SDK licenses when prompted:

```bash
"$HOME/Android/Sdk/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$HOME/Android/Sdk" "build-tools;36.0.0"
"$HOME/Android/Sdk/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$HOME/Android/Sdk" --licenses
```

### 5. Install Apktool and JADX

Create the tools directory:

```bash
mkdir -p "$HOME/tools/android-security"
```

Download `apktool_2.10.0.jar` from the
[Apktool 2.10.0 release](https://github.com/iBotPeaches/Apktool/releases/tag/v2.10.0)
and save it as:

```text
~/tools/android-security/apktool_2.10.0.jar
```

Download `jadx-1.5.3.zip` from the
[JADX 1.5.3 release](https://github.com/skylot/jadx/releases/tag/v1.5.3) and save it
in the same directory. Choose the cross-platform ZIP, not the Windows GUI bundle.
Extract it once:

```bash
unzip "$HOME/tools/android-security/jadx-1.5.3.zip" -d "$HOME/tools/android-security/jadx-1.5.3"
chmod +x "$HOME/tools/android-security/jadx-1.5.3/bin/jadx"

java -jar "$HOME/tools/android-security/apktool_2.10.0.jar" --version
"$HOME/tools/android-security/jadx-1.5.3/bin/jadx" --version
```

Retain the JADX ZIP: the current `doctor` command checks for the archive, even
when JADX has already been extracted. MobSF is not needed; the existing path
happens to point to an Apktool JAR inside a local MobSF checkout.

### 6. Configure paths — required after cloning

The repository still contains `/home/koray/...` paths. Installing tools alone will
not update them. There are two configuration locations to adjust.

In [pipeline.py](pipeline.py), replace the existing `APKTOOL_JAR` and
`JADX_ARCHIVE` assignments with the following if you used this guide's layout:

```python
APKTOOL_JAR = Path.home() / "tools/android-security/apktool_2.10.0.jar"
JADX_ARCHIVE = Path.home() / "tools/android-security/jadx-1.5.3.zip"
```

Add these lines to your `~/.bashrc`, then reload it with `source ~/.bashrc`:

```bash
export APK_PIPELINE_BUILD_TOOLS="$HOME/Android/Sdk/build-tools/36.0.0"
export PATH="$HOME/tools/android-security/jadx-1.5.3/bin:$APK_PIPELINE_BUILD_TOOLS:$PATH"
```

Also update the **Permitted tools** section in
[methodology/01-static-analysis.md](methodology/01-static-analysis.md). The static
agent reads that file directly, so changing Python constants alone is insufficient.
Use your actual absolute paths, replacing `YOUR_LINUX_USER`:

| Existing reference | Replacement for this layout |
| --- | --- |
| Android build-tools directory | `/home/YOUR_LINUX_USER/Android/Sdk/build-tools/36.0.0/` |
| Apktool JAR in the `java -jar` command | `/home/YOUR_LINUX_USER/tools/android-security/apktool_2.10.0.jar` |
| JADX archive | `/home/YOUR_LINUX_USER/tools/android-security/jadx-1.5.3.zip` |
| `jadx` command | `/home/YOUR_LINUX_USER/tools/android-security/jadx-1.5.3/bin/jadx` |

Use absolute paths in the methodology so the agent does not depend on interactive
shell configuration. `APK_PIPELINE_BUILD_TOOLS` is supported today; environment
variables for Apktool and JADX paths are not implemented. The retained WeasyPrint
path belongs to the disabled reporting stage and does not need configuration.

These path edits are local source changes. Review them when pulling future
updates; Git may require you to commit or stash them before updating.

## Windows installation and usage

Use **WSL 2 with Ubuntu 24.04** for this version of the project. The pipeline's
methodology uses Linux shell commands and executable names. Native PowerShell/CMD
execution has not been adapted or tested; installing Windows versions of the
individual tools does not resolve those differences.

### 1. Install WSL 2

On Windows 11, or Windows 10 version 2004/build 19041 or later, open **PowerShell
as Administrator**:

```powershell
wsl --list --online
wsl --install -d Ubuntu-24.04
```

Restart if requested, launch Ubuntu, and create its Linux user account. Verify
from PowerShell that the distribution uses version 2:

```powershell
wsl -l -v
```

If necessary, convert it:

```powershell
wsl --set-version Ubuntu-24.04 2
```

See Microsoft's [WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install)
for prerequisites and installation troubleshooting.

### 2. Install the project inside Ubuntu

Open the **Ubuntu terminal** and follow all six Linux installation steps above.
Install the Linux versions of Python, Java, the SDK tools, and Claude Code inside
WSL. Authenticate Claude Code there as well. A Windows-side installation or login
does not replace this setup.

Clone under `~/projects/security-report` inside Ubuntu. In the path configuration,
use the Ubuntu username created during WSL setup, not your Windows username.
Run every `python3 pipeline.py ...` command below from the Ubuntu terminal.

### 3. Copy APKs and access output

To copy an APK set from Windows into the cloned repository, run in Ubuntu and
replace `YOUR_WINDOWS_USER` and the source directory:

```bash
cd "$HOME/projects/security-report"
mkdir -p apks/my-app
cp /mnt/c/Users/YOUR_WINDOWS_USER/Downloads/my-app/*.apk apks/my-app/
```

To browse generated files in Windows Explorer, run from the repository directory
inside Ubuntu:

```bash
explorer.exe .
```

Keep the working copy in Ubuntu's filesystem; copy APKs in and retrieve artifacts
through Explorer as needed. No Android emulator or device connection is involved.

## Verify the setup

From the repository root, in Linux or the WSL Ubuntu terminal:

```bash
python3 pipeline.py doctor
python3 -m unittest discover -s tests -v
```

`doctor` checks configured tool paths and Claude authentication. It does not
execute the analysis tools or prove model access.
Check the relevant executables separately:

```bash
"$APK_PIPELINE_BUILD_TOOLS/aapt2" version
"$APK_PIPELINE_BUILD_TOOLS/apksigner" version
java -jar "$HOME/tools/android-security/apktool_2.10.0.jar" --version
jadx --version
claude auth status
```

The test suite uses mocked model execution; it does not run a real assessment.

## Prepare an APK set

Each application must occupy a direct child directory of `apks/`:

```text
apks/
└── my-app/
    ├── base.apk
    ├── split_config.en.apk
    └── split_config.x86_64.apk
```

Copy the application's actual APK files; do not create the example splits if they
are not part of the set. Keep all supplied splits with the base. A single APK may
have any `.apk` filename. A directory containing multiple APKs must include
`base.apk`. Directory names may contain letters, numbers, dots, underscores, and
hyphens, with no spaces.

## Run the full cycle

Preview the commands without making model calls or creating a run:

```bash
python3 pipeline.py run --stage all --apk-dir apks/my-app --dry-run
```

Run static analysis followed by script generation:

```bash
python3 pipeline.py run --stage all --apk-dir apks/my-app
```

`--stage all` is the default, so this is equivalent:

```bash
python3 pipeline.py run --apk-dir apks/my-app
```

A dry-run still needs the APK set but does not require Claude Code or verify
authentication or model access. Actual runs send model context to Anthropic
and consume the corresponding account usage.

## Run stages separately

Start a static-only run:

```bash
python3 pipeline.py run --stage static --apk-dir apks/my-app
```

Copy the run ID printed by the command. Substitute it for `RUN_ID` below:

```bash
python3 pipeline.py run --stage frida --run-id RUN_ID
python3 pipeline.py status RUN_ID
```

Continuing stage 2 needs the existing run directory, including its inventory,
static reports, and referenced static evidence. `runs/` is Git-ignored, so a clone
alone does not transfer prior runs between computers.

Completed or running stages are not overwritten. For a new full assessment,
start another run rather than reusing a completed run ID. Existing stage 1-only
runs can continue with script generation; legacy stage 2 runtime reports do not
match the generation-only schema.

## Model configuration

Current repository defaults:

| Stage | CLI | Model | Effort |
| --- | --- | --- | --- |
| Static analysis | Claude Code | `claude-opus-4-7` | `high` |
| Script generation | Claude Code | `claude-opus-4-7` | `high` |

These are project defaults, not a guarantee of availability on another account.
To use models available to your accounts, substitute their identifiers:

```bash
python3 pipeline.py run --stage all --apk-dir apks/my-app \
  --static-model YOUR_STATIC_CLAUDE_MODEL \
  --frida-model YOUR_CLAUDE_MODEL \
  --reasoning-effort high \
  --frida-effort high
```

Supported configuration variables:

| Variable | Purpose |
| --- | --- |
| `APK_PIPELINE_STATIC_MODEL` | Static-stage model override |
| `APK_PIPELINE_MODEL` | Legacy Codex fallback; ignored by both active stages |
| `APK_PIPELINE_FRIDA_MODEL` | Script-generation model override |
| `APK_PIPELINE_REASONING_EFFORT` | Shared reasoning effort |
| `APK_PIPELINE_FRIDA_EFFORT` | Stage 2 effort override |
| `APK_PIPELINE_CLAUDE_BIN` | Claude executable path when not on `PATH` |
| `APK_PIPELINE_BUILD_TOOLS` | Directory containing `aapt2` and `apksigner` |

Explicit command-line model options override environment settings. Claude's effort
choices are `low`, `medium`, `high`, `xhigh`, and `max`; `minimal` is unsupported.
Stage 1 uses the shared effort; `--frida-effort` overrides only stage 2.
No final-stage model option is available while reporting is disabled.

## Outputs and progress

```text
runs/RUN_ID/
├── run-state.json
├── input/apk-set.json
├── 01-static/
│   ├── artifacts/
│   ├── events.jsonl
│   ├── static-analysis.json
│   └── static-analysis.md
└── 02-frida/
    ├── events.jsonl
    ├── generation-result.json
    ├── bypass.js
    ├── frida-bypass-report.json
    └── frida-bypass-report.md
```

The Frida report filenames are retained for compatibility; they describe generation,
not runtime testing. Generation statuses are `GENERATED`, `NOT_APPLICABLE`, and
`INSUFFICIENT_EVIDENCE`. Runtime validation is always `NOT_PERFORMED`. A script may
contain only explanatory comments if the static report lacks usable hook targets.

Monitor a run from another terminal:

```bash
python3 pipeline.py status RUN_ID
tail -f runs/RUN_ID/01-static/events.jsonl
```

For stage 2, follow `runs/RUN_ID/02-frida/events.jsonl` instead. Press `Ctrl+C` to
stop following a log. New runs do not create `03-final/` or runtime Frida logs.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `doctor` reports `/home/koray/...` missing | Complete the Python and methodology path edits; set `APK_PIPELINE_BUILD_TOOLS`. |
| `claude` is not found | Open a fresh terminal, check `PATH`, or set the corresponding executable override. On Windows, install inside WSL. |
| JADX works but `doctor` reports a missing archive | Keep `jadx-1.5.3.zip` at the configured `JADX_ARCHIVE` path. |
| SDK manager is missing | Check `cmdline-tools/latest/bin/sdkmanager`; avoid a duplicate nested `cmdline-tools` directory. |
| Authentication fails | Run the relevant login command as the same Linux user running the pipeline. |
| Model is unavailable | Choose an accessible model with `--static-model` or `--frida-model`. |
| APK directory is rejected | Use a direct child of this repository's `apks/`, containing a valid APK set. |
| Stage already started | Inspect run state and logs; use a new run for a fresh full cycle. |
| `--stage final` or `--authorize-dynamic` is rejected | These options are unavailable in the current two-stage workflow. |
| A generated script is not verified | Expected: the pipeline deliberately performs generation only. |

The repository's `.gitignore` excludes `runs/`, `.env`, and Python caches.
APK files are not currently ignored. Before publishing the repository, decide
whether to keep APK inputs in Git or distribute them separately; credentials and
local authentication files do not belong in the repository.
