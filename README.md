# jenkins-atom-dependency-check

Dependency vulnerabilities — port of **dependency-check** (约 12,000) as an atom.

Read-only: the scan is its own process, often a scheduled job. Splitting them lets a pull request fail on a
known critical without paying for an NVD update.

## Build and test

```bash
mvn verify
```

`src/test/java/atom/DependencyCheckIT.java` runs the packaged jar against a fixture report: the severity counts, the
default gate, raised limits, an empty report and a truncated one.
