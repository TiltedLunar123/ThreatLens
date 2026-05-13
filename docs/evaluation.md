# Evaluation

ThreatLens ships with three synthetic sample datasets (see the `Evaluation`
section in the project README). Synthetic data is useful for unit and
integration testing but is not a stand-in for realistic adversary
telemetry. This document describes how to evaluate ThreatLens against the
public **EVTX-ATTACK-SAMPLES** corpus and how to interpret the results.

## The corpus

[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) is
a community-maintained collection of real Windows event logs that
demonstrate specific MITRE ATT&CK techniques. Each subdirectory is named
after a technique (for example `LM_AdminShareAccess`, `Persistence_New_Service`,
`Credential_Access_LSASS_dumping`). The files are real, not synthetic, and
they cover a wide range of Windows audit policies and Sysmon
configurations.

The corpus is **not vendored** in this repo. It is distributed under its
own license and is best consumed as a git checkout:

```bash
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
```

## Running the evaluation

The repo ships a helper script that runs ThreatLens against every `.evtx`
file in the corpus and produces a markdown report grouped by technique
directory.

```bash
# From the ThreatLens checkout, with python-evtx installed
pip install -e ".[evtx]"

python scripts/evaluate_evtx_attack_samples.py \
    --corpus /path/to/EVTX-ATTACK-SAMPLES \
    --sigma-rules rules/sigma_starter \
    --output docs/evaluation_results.md
```

Arguments:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--corpus` | required | Local clone of EVTX-ATTACK-SAMPLES |
| `--sigma-rules` | `rules/sigma_starter` | Sigma directory to layer on top of built-ins |
| `--output` | `docs/evaluation_results.md` | Where to write the markdown report |
| `--limit` | 0 | Cap the number of files scanned (useful for smoke testing) |

The generated report contains three artifacts:

1. **Summary**: total files, files with at least one alert, total alerts,
   total events analyzed, scan wall time.
2. **Detection rate by technique directory**: for each subdirectory in
   the corpus, the table reports the number of `.evtx` files, the number
   of files that produced at least one alert, the percentage hit rate,
   and the total alert count.
3. **Per-file detail** (when `--verbose` is passed, future work).

## How to read the results

The corpus is curated so that every `.evtx` file is *expected* to surface
malicious activity. A high files-with-alerts rate is good, but raw alert
counts are not directly comparable to other tools because each tool
defines an "alert" differently. Hayabusa and Chainsaw emit one alert per
matched Sigma rule per event. ThreatLens groups matched events into
correlated alerts when a built-in detector applies (for example, eight
4625 failed logons collapse into one Brute-Force alert, not eight
isolated Sigma matches).

When comparing tools, prefer the **files-with-alerts rate** as the
detection signal and use raw alert counts only to assess noise.

## Caveats

- The corpus is dominated by Windows event logs. Linux, macOS, and
  network coverage in ThreatLens is exercised through the syslog and CEF
  parsers but not through this evaluation.
- Some `.evtx` files require the `python-evtx` extra. The script falls
  back to recording an error per file rather than aborting if the parser
  cannot read a particular file.
- The Sigma starter pack bundled with the project is intentionally
  narrow. For a broader sweep, point `--sigma-rules` at a checkout of
  [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

## Reproducing in CI

The evaluation is not wired into CI by default because it requires
network access to clone the corpus and a non-trivial runtime
(approximately 10 to 20 minutes on a developer laptop for the full
corpus). To run it on demand inside a GitHub Actions workflow:

```yaml
- name: Clone EVTX-ATTACK-SAMPLES
  run: git clone --depth=1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git /tmp/corpus

- name: Evaluate
  run: python scripts/evaluate_evtx_attack_samples.py --corpus /tmp/corpus

- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: evaluation-report
    path: docs/evaluation_results.md
```
