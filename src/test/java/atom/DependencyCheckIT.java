package atom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jenkinschina.atom.sdk.testing.Atom;
import com.jenkinschina.atom.sdk.testing.AtomResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The dependency-check atom: severities are counted per finding, and only the ones above the limit fail the build.
 *
 * <p>These are the checks {@code tools/smoke.sh} made — the default gate, raised limits, a report with no dependency,
 * and a truncated report that must not read as a clean scan.
 */
class DependencyCheckIT {

    private static final String REPORT = """
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
            """;

    private Atom atom;

    @BeforeEach
    void setUp() throws Exception {
        atom = Atom.of();
    }

    @Test
    @DisplayName("one critical finding trips the default gate, and the counts are per finding")
    void failsOnACriticalFinding() throws Exception {
        AtomResult run = atom.file("dependency-check-report.xml", REPORT)
                .input("{}")
                .run();

        assertNotEquals(0, run.exit(), "a critical finding must fail the default gate:\n" + run.console());
        assertEquals("failure", run.status(), run.toString());
        assertEquals("2", run.field("dependencies"), run.toString());
        assertEquals("3", run.field("vulnerabilities"), run.toString());
        assertEquals("1", run.field("critical"), run.toString());
        assertEquals("1", run.field("high"), run.toString());
        assertTrue(run.exists("out/dependencies/index.html"), "no report written");
        assertTrue(run.file("out/dependencies/index.html").contains("CVE-2021-44228"),
                "the CVE is not listed in the report");
    }

    @Test
    @DisplayName("raising the limits lets the same input through")
    void passesWithRaisedLimits() throws Exception {
        AtomResult run = atom.file("dependency-check-report.xml", REPORT)
                .input("{\"maxCritical\": \"1\", \"maxHigh\": \"1\"}")
                .run();

        run.assertOk();
    }

    @Test
    @DisplayName("a report with no dependency is suspicious, not a pass")
    void refusesAnEmptyReport() throws Exception {
        AtomResult run = atom.file("dependency-check-report.xml", "<analysis><dependencies/></analysis>")
                .input("{}")
                .run();

        assertNotEquals(0, run.exit(), "an empty report must fail");
        assertTrue(run.field("message").contains("lists no dependency"), "message not readable:\n" + run.toString());
    }

    @Test
    @DisplayName("a truncated report fails by name, unless the caller allows unreadable reports")
    void refusesATruncatedReport() throws Exception {
        String good = "<?xml version=\"1.0\"?><analysis "
                + "xmlns=\"https://jeremylong.github.io/DependencyCheck/dependency-check.2.0.xsd\"><dependencies>"
                + "<dependency><vulnerabilities><vulnerability><severity>HIGH</severity></vulnerability>"
                + "</vulnerabilities></dependency></dependencies></analysis>";
        String half = "<?xml version=\"1.0\"?><analysis "
                + "xmlns=\"https://jeremylong.github.io/DependencyCheck/dependency-check.2.0.xsd\"><dependencies>"
                + "<dependency>";

        AtomResult refused = atom.file("good.xml", good)
                .file("half.xml", half)
                .input("{\"pattern\": \"*.xml\", \"maxHigh\": \"5\"}")
                .run();
        assertNotEquals(0, refused.exit(), "a truncated dependency-check report must fail the step");
        assertEquals("40003", refused.field("errorCode"), "expected errorCode 40003:\n" + refused.toString());
        assertTrue(refused.field("message").contains("half.xml"),
                "the failure must name the file:\n" + refused.toString());

        AtomResult tolerated = atom.file("good.xml", good)
                .file("half.xml", half)
                .input("{\"pattern\": \"*.xml\", \"maxHigh\": \"5\", \"allowUnreadableReports\": \"true\"}")
                .run();
        tolerated.assertOk();
    }
}
