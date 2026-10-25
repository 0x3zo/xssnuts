<div align="center">

# XSSNUTS

### Browser-verified XSS scanning from a URL list

**10 payloads · 5 selected per URL · Live JSON saving**

Developed and maintained by **0x3zo**

[GitHub](https://github.com/0x3zo) · [X / Twitter](https://x.com/0x3zoo)

</div>

---

## About

XSSNUTS is a Python command-line tool for checking URL parameters for reflected Cross-Site Scripting (XSS). It probes reflections and requires execution of a unique callback in an isolated browser before saving a finding.

Use only on systems you own or have explicit permission to test.

## Features

- Scan HTTP/HTTPS URLs from a text file.
- Select 5 distinct payloads from a pool of 10 per URL: 3 basic probes and 2 random context-breakout probes.
- Reuse the selected payloads across the URL's parameters.
- Verify candidates through headless Microsoft Edge using Playwright.
- Preserve Content Security Policy and content type during verification.
- Show a single animated status line with progress, elapsed time, and colored counters.
- Save confirmed findings after every completed URL.
- Replace JSON output atomically, retry temporary file locks, and preserve recovery snapshots if replacement fails.
- Log unexpected application failures to `xssnuts-error.log`.

## Requirements

- Windows 10/11 and an ANSI-capable terminal.
- Python 3.10+; development checks used Python 3.14.
- Git and Microsoft Edge installed.
- Python packages: `requests` and `playwright`.

The current browser launcher uses the `msedge` channel. Playwright's bundled Chromium alone does not satisfy that requirement.

## Install from GitHub

The commands below assume publication as `0x3zo/xssnuts`. Change the clone URL if the repository owner or name differs.

```powershell
git clone https://github.com/0x3zo/xssnuts.git
cd xssnuts

py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install requests playwright
.\.venv\Scripts\python.exe xssnuts.py --help
```

No virtual environment activation is required when using the interpreter path above.

## Quick start

Create `urls.txt` with one authorized URL per line:

```text
https://your-lab.example/search?q=test
https://your-lab.example/page?id=1
```

Run:

```powershell
.\.venv\Scripts\python.exe xssnuts.py urls.txt
```

With dependencies already installed in your Python environment:

```powershell
python xssnuts.py urls.txt
```

The default output is `results.json` in the current working directory. Each run starts a new results file; copy previous results elsewhere to retain them.

## Examples

Custom output:

```powershell
python xssnuts.py urls.txt -o confirmed.json
```

Concurrency, request timeout, and delay:

```powershell
python xssnuts.py urls.txt -c 3 -t 15 -d 0.5
```

Try all 10 payloads:

```powershell
python xssnuts.py urls.txt --max-payloads 0
```

Try 3 payloads:

```powershell
python xssnuts.py urls.txt --max-payloads 3
```

## Options

| Option | Default | Description |
| --- | --- | --- |
| `input` | Required | Text file with one URL per line. |
| `-o`, `--output` | `results.json` | Output JSON path; parent directory must exist. |
| `-c`, `--concurrency` | `5` | Concurrent URL workers. |
| `-t`, `--timeout` | `10` | Request timeout in seconds. |
| `-d`, `--delay` | `0` | Request delay in seconds, also used by host scheduling. |
| `--max-payloads` | `5` | Distinct payloads per URL, reused per parameter. `0` selects all 10; values above 10 are capped at 10. |
| `--skip-dom` | Off | Skip static DOM pattern analysis. |
| `--skip-prompt` | On | Compatibility flag; interactive prompting is disabled by default. |
| `--headers` | Built-in | Custom raw headers. |
| `-h`, `--help` | — | Display help. |

The CLI also exposes `--proxy` and `--encode base64`. The proxy flag requires `core.config.proxies`, which is absent from the standalone folder. Base64 is a legacy parser option and does not provide full payload encoding support.

The payload count is not a request limit: probes and confirmation need additional requests. Parameters without detected reflection do not proceed to payload testing.

## Status counters

| Counter | Color | Meaning |
| --- | --- | --- |
| `VULN` | Green | URLs with browser-confirmed findings. |
| `NOT VULN` | Red | No execution confirmed by this scan; not a guarantee that the application is free of XSS. |
| `ERROR` | Yellow | URL scans that failed, such as connection or browser errors. |

Redirected output receives a final summary instead of continuously animated updates.

## Results

Only confirmed vulnerable entries are saved. Each entry contains:

- `url`: input URL.
- `vulnerable`: `true`.
- `findings`: confirmed parameter, probe payload, request URL, verification method, and callback name.

The names `xssnuts_<random-id>` are unique verification callbacks. They replace `alert`, `confirm`, or `prompt` to distinguish probe execution from the page's existing scripts. These callbacks exist in the verification browser; copying a saved probe URL into a normal browser may not display a popup.

An output file containing `[]` means no confirmed findings have been saved for that run.

## Verification limits

Verification replays captured HTML in an isolated context and blocks subsequent network requests. It can miss cases requiring external JavaScript, authentication state, delayed application behavior, or DOM-only data flows.

Static DOM patterns alone do not mark a URL vulnerable. The scanner focuses on query parameters and tries a `q` parameter when a target has no parameters.

## Troubleshooting

- **Browser launch fails:** Install Microsoft Edge and install `playwright` with the same Python interpreter used to run XSSNUTS.
- **Unexpected stop:** Read `xssnuts-error.log` beside `xssnuts.py` for the full traceback.
- **Output file locked:** Temporary locks are retried. If replacement still fails, the error message identifies a `.xssnuts-*.json` recovery snapshot.
- **Broken colors or characters:** Use an ANSI-capable terminal and a font supporting Unicode block characters.

## Author and credits

**Project customization and maintenance: 0x3zo**

- GitHub: [@0x3zo](https://github.com/0x3zo)
- X / Twitter: [@0x3zoo](https://x.com/0x3zoo)

© 2026 **0x3zo** — project-specific modifications, presentation, and documentation.

The source identifies portions of its scanning logic as adapted from [XSStrike](https://github.com/s0md3v/XSStrike). Credit for upstream work remains with its original authors. Retain applicable upstream copyright notices and license terms when distributing derived code.

This README does not assign a new license to upstream code. Document the repository's distribution terms in a compatible license before release.

