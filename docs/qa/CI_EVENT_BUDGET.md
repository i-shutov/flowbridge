# GitHub Actions event budget — no duplicate feature-branch matrices

2026-10-29. The main cross-platform matrix has five expensive jobs:
Rust on Windows, macOS and Linux, plus real Windows GUI/NSIS and
macOS .pkg builds. Before this change, every feature-branch commit with
an open PR triggered both `push` and `pull_request` workflows, running
those five jobs **twice on the same SHA**. Several CI investigation
iterations exhausted runner availability while waiting for both copies.

## Accepted dispatch rules

| Event | Main Rust/native CI | WDK driver build | Native DNS |
| --- | --- | --- | --- |
| Push to `main` | Yes, unless only ignored paths changed | When WFP driver paths changed | When relevant DNS/native paths changed |
| New/update feature PR | Yes, once per head/merge-ref update | If driver paths changed | If relevant DNS/native paths changed |
| Direct push to feature branch without PR | No | No | No |
| Manual workflow dispatch | Yes | Yes | Yes |

Feature code should be committed to its working branch, then a PR opened
before claiming CI acceptance. If the branch has no PR yet, **there is no
automatic build from its ordinary push**; this is intentional and must not
be misrepresented as coverage. The source commit SHA shown in the PR must
match the successful, completed GitHub Actions run, including native
Windows GUI/package and macOS package jobs.

The Linux real-OpenSSH stress harness remains in the main matrix on PR
runs. The optional manual `ssh_churn=1000/10000` workflow dispatch is
isolated by event and run ID from the routine `main` push matrix, so
a long operator-triggered soak cannot accidentally cancel a regular
build or another independent manual experiment. Automatic ordinary
push/PR runs for the *same ref and event type* still cancel superseded
commits, retaining fail-fast feedback and avoiding stale artifacts.

The authorized Windows loaded-driver WFP VM and real DPI VM workflows
stay **manual-only**. Nothing in this change enables privileged test
runners for untrusted pull requests, modifies driver signing, changes
the app's network behavior, or claims system-level acceptance.

## QA

- Verify feature PR with Rust/core + Windows installed GUI/NSIS and macOS
  installed .pkg test artifacts. Check the Actions run SHA exactly.
- Verify main push triggers its corresponding CI once after an accepted
  merge and does not cancel an ongoing manual SSH churn.
- Verify WDK `pull_request` still runs when WFP files change and that
  an unrelated Windows/macOS-only PR does not rebuild WDK.
- Confirm no feature-branch `push` event jobs are created when the PR
  equivalent is already running.
