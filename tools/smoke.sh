#!/usr/bin/env bash
# Severities are counted per finding, and only the ones above the limit fail the build.
set -uo pipefail
cd "$(dirname "$0")/.."
./build.sh >/dev/null || { echo "build failed" >&2; exit 1; }
. tools/smoke-lib.sh

report() { # report <dir>
  mkdir -p "$1"
  cat >"$1/dependency-check-report.xml" <<'XML'
<analysis>
  <dependencies>
    <dependency>
      <fileName>log4j-core-2.14.1.jar</fileName>
      <vulnerabilities>
        <vulnerability><name>CVE-2021-44228</name><severity>CRITICAL</severity>
          <cvssv3><baseScore>10.0</baseScore></cvssv3>
          <description>Remote code execution in JNDI lookups.</description></vulnerability>
        <vulnerability><name>CVE-2021-45046</name><severity>HIGH</severity>
          <cvssv3><baseScore>9.0</baseScore></cvssv3>
          <description>Incomplete fix for the above.</description></vulnerability>
      </vulnerabilities>
    </dependency>
    <dependency>
      <fileName>guava-30.1.jar</fileName>
      <vulnerabilities>
        <vulnerability><name>CVE-2020-8908</name><severity>LOW</severity>
          <description>Temporary directory permissions.</description></vulnerability>
      </vulnerabilities>
    </dependency>
  </dependencies>
</analysis>
XML
}

# 1. default gate: one critical trips it
dir="$(mktemp -d)"; report "$dir"
printf '{}' >"$dir/input.json"
run "$dir" >"$dir/log.txt" 2>&1 && fail "a critical finding must fail the default gate"
[ "$(status "$dir")" = "failure" ] || fail "status: $(cat "$dir/output.json")"
[ "$(output "$dir" dependencies)" = "2" ] || fail "dependencies: $(cat "$dir/output.json")"
[ "$(output "$dir" vulnerabilities)" = "3" ] || fail "vulnerabilities: $(cat "$dir/output.json")"
[ "$(output "$dir" critical)" = "1" ] || fail "critical: $(cat "$dir/output.json")"
[ "$(output "$dir" high)" = "1" ] || fail "high: $(cat "$dir/output.json")"
[ -f "$dir/out/dependencies/index.html" ] || fail "no report"
grep -q "CVE-2021-44228" "$dir/out/dependencies/index.html" || fail "the CVE is not listed"

# 2. raising the limits lets the same input through
dir="$(mktemp -d)"; report "$dir"
printf '{"maxCritical": "1", "maxHigh": "1"}' >"$dir/input.json"
run "$dir" >/dev/null 2>&1 || fail "limits of 1/1 must pass: $(cat "$dir/output.json")"

# 3. a report with no dependency is suspicious, not a pass
dir="$(mktemp -d)"
printf '<analysis><dependencies/></analysis>' >"$dir/dependency-check-report.xml"
printf '{}' >"$dir/input.json"
run "$dir" >/dev/null 2>&1 && fail "an empty report must fail"
grep -q "lists no dependency" "$dir/output.json" || fail "message not readable"

echo "smoke ok: severity counts, default gate, raised limits, empty report"
