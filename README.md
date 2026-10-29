# jenkins-atom-dependency-check-report

Dependency vulnerabilities — port of **dependency-check** (约 12,000) as an atom.

Read-only: the scan is its own process, often a scheduled job. Splitting them lets a pull request fail on a
known critical without paying for an NVD update.

## Build and smoke test

```bash
./build.sh
./tools/smoke.sh
```
