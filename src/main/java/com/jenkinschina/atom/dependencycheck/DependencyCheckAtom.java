package com.jenkinschina.atom.dependencycheck;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * OWASP dependency-check as an atom: read the XML the scan wrote and gate the build on what it found.
 *
 * <p>Reads only — the scan itself is a separate process and usually a scheduled job of its own. Splitting them means a
 * pull request can fail on a known critical without paying for a full NVD update.
 */
public class DependencyCheckAtom implements AtomTask {

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        Path workspace = context.getWorkspace();
        String pattern = context.getParam("pattern", "**/dependency-check-report.xml");
        String label = context.getParam("label", "Dependencies");
        String outDir = context.getParam("outputDir", "out/dependencies");
        int maxCritical = Math.max(0, context.getIntParam("maxCritical", 0));
        int maxHigh = context.getIntParam("maxHigh", -1); // -1 = no limit
        int maxTotal = context.getIntParam("maxTotal", -1);

        List<Path> files = find(workspace, pattern);
        if (files.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40001, "no dependency-check report matched " + pattern);
        }

        List<Finding> findings = new ArrayList<>();
        int dependencies = 0;
        List<String> unreadable = new ArrayList<>();
        for (Path file : files) {
            Parsed parsed;
            try {
                parsed = parse(file);
            } catch (RuntimeException e) {
                // a half-written dependency-check-report.xml used to count as "no vulnerabilities"
                unreadable.add(file.getFileName() + ": " + e.getMessage());
                continue;
            }
            findings.addAll(parsed.findings);
            dependencies += parsed.dependencies;
        }
        boolean allowUnreadable = context.getBooleanParam("allowUnreadableReports", false);
        if (!unreadable.isEmpty() && !allowUnreadable) {
            return AtomResult.error(ErrorType.USER, 40003,
                    unreadable.size() + " of " + files.size() + " report(s) could not be parsed: "
                            + unreadable.get(0) + " (set allowUnreadableReports=true to accept this)");
        }
        if (dependencies == 0) {
            return AtomResult.error(ErrorType.USER, 40002, "the report lists no dependency; is it complete?");
        }

        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        for (String severity : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW")) {
            bySeverity.put(severity, 0);
        }
        for (Finding finding : findings) {
            bySeverity.merge(finding.severity(), 1, Integer::sum);
        }
        int critical = bySeverity.get("CRITICAL");
        int high = bySeverity.get("HIGH");

        Path dir = workspace.resolve(outDir);
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("index.html"),
                render(label, pattern, dependencies, bySeverity, findings), StandardCharsets.UTF_8);

        context.log(String.format(Locale.ROOT, "[dependency-check] %d dependencies, %d vulnerabilities "
                + "(%d critical, %d high, %d medium, %d low)",
                dependencies, findings.size(), critical, high, bySeverity.get("MEDIUM"), bySeverity.get("LOW")));

        AtomResult result = AtomResult.success()
                .data("dependencies", String.valueOf(dependencies))
                .data("vulnerabilities", String.valueOf(findings.size()))
                .data("critical", String.valueOf(critical))
                .data("high", String.valueOf(high))
                .data("medium", String.valueOf(bySeverity.get("MEDIUM")))
                .report("report", label, dir.toString(), "index.html");

        boolean over = critical > maxCritical
                || (maxHigh >= 0 && high > maxHigh)
                || (maxTotal >= 0 && findings.size() > maxTotal);
        if (over) {
            return AtomResult.failure(String.format(Locale.ROOT,
                    "%d critical and %d high vulnerabilities (limits: %d critical, %s high)",
                    critical, high, maxCritical, maxHigh < 0 ? "none" : String.valueOf(maxHigh)))
                    .data("dependencies", String.valueOf(dependencies))
                    .data("vulnerabilities", String.valueOf(findings.size()))
                    .data("critical", String.valueOf(critical))
                    .data("high", String.valueOf(high))
                    .report("report", label, dir.toString(), "index.html");
        }
        return result;
    }

    private static Parsed parse(Path file) {
        List<Finding> findings = new ArrayList<>();
        int dependencies = 0;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setExpandEntityReferences(false);
            Document document = factory.newDocumentBuilder().parse(file.toFile());
            Element root = document.getDocumentElement();
            NodeList deps = document.getElementsByTagName("dependency");
            dependencies = deps.getLength();
            for (int i = 0; i < deps.getLength(); i++) {
                Element dependency = (Element) deps.item(i);
                String name = child(dependency, "fileName");
                NodeList vulns = dependency.getElementsByTagName("vulnerability");
                for (int v = 0; v < vulns.getLength(); v++) {
                    Element vuln = (Element) vulns.item(v);
                    String severity = child(vuln, "severity");
                    if (severity.isBlank()) {
                        severity = "UNKNOWN";
                    }
                    findings.add(new Finding(name, child(vuln, "name"), severity.toUpperCase(Locale.ROOT),
                            child(vuln, "cvssv3/baseScore"), abbreviate(child(vuln, "description"))));
                }
            }
            if (root != null && dependencies == 0) {
                dependencies = document.getElementsByTagName("file").getLength();
            }
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(), e);
        }
        return new Parsed(findings, dependencies);
    }

    private static String child(Element parent, String tag) {
        NodeList nodes = parent.getElementsByTagName(tag);
        return nodes.getLength() == 0 ? "" : nodes.item(0).getTextContent().strip();
    }

    private static String abbreviate(String value) {
        if (value == null) {
            return "";
        }
        String oneLine = value.replaceAll("\\s+", " ").strip();
        return oneLine.length() > 160 ? oneLine.substring(0, 160) + "…" : oneLine;
    }

    private static List<Path> find(Path workspace, String pattern) throws java.io.IOException {
        List<PathMatcher> matchers = new ArrayList<>();
        for (String part : pattern.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                matchers.add(FileSystems.getDefault().getPathMatcher("glob:" + trimmed));
            }
        }
        List<Path> found = new ArrayList<>();
        try (var walk = Files.walk(workspace, 12)) {
            walk.filter(Files::isRegularFile)
                    .filter(path -> matchers.stream().anyMatch(m -> m.matches(workspace.relativize(path)) || m.matches(java.nio.file.Path.of("_").resolve(workspace.relativize(path)))
                            || m.matches(path.getFileName())))
                    .sorted()
                    .limit(50)
                    .forEach(found::add);
        }
        return found;
    }

    private static String render(String label, String pattern, int dependencies, Map<String, Integer> bySeverity,
                                 List<Finding> findings) {
        StringBuilder html = new StringBuilder("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        html.append("<title>").append(escape(label)).append("</title><style>")
                .append("body{font-family:-apple-system,'Segoe UI',sans-serif;margin:0;padding:28px;background:#f6f7f9}")
                .append("h1{font-size:22px;margin:0 0 4px}p.meta{color:#6b7280;font-size:13px;margin:0 0 18px}")
                .append(".cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}")
                .append(".card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:12px 16px;min-width:100px}")
                .append(".card b{display:block;font-size:22px}.card span{font-size:12px;color:#6b7280}")
                .append(".critical b{color:#7f1d1d}.high b{color:#b91c1c}")
                .append("table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;font-size:13px}")
                .append("th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #eef0f3;vertical-align:top}")
                .append("th{background:#fafbfc;color:#6b7280}code{font-family:ui-monospace,Menlo,monospace}")
                .append("</style></head><body>");
        html.append("<h1>").append(escape(label)).append("</h1><p class=\"meta\">").append(dependencies)
                .append(" dependencies · <code>").append(escape(pattern)).append("</code></p><div class=\"cards\">");
        bySeverity.forEach((severity, count) -> html.append("<div class=\"card ")
                .append(severity.toLowerCase(Locale.ROOT)).append("\"><b>").append(count).append("</b><span>")
                .append(severity).append("</span></div>"));
        html.append("</div><table><tr><th>Dependency</th><th>Vulnerability</th><th>Severity</th>")
                .append("<th>CVSS</th><th>Description</th></tr>");
        findings.stream()
                .sorted(Comparator.comparingInt((Finding f) -> rank(f.severity())).thenComparing(Finding::cve))
                .limit(300)
                .forEach(finding -> html.append("<tr><td><code>").append(escape(finding.dependency()))
                        .append("</code></td><td>").append(escape(finding.cve())).append("</td><td>")
                        .append(escape(finding.severity())).append("</td><td>").append(escape(finding.cvss()))
                        .append("</td><td>").append(escape(finding.description())).append("</td></tr>"));
        return html.append("</table></body></html>").toString();
    }

    private static int rank(String severity) {
        return switch (severity) {
            case "CRITICAL" -> 0;
            case "HIGH" -> 1;
            case "MEDIUM" -> 2;
            default -> 3;
        };
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private record Finding(String dependency, String cve, String severity, String cvss, String description) {}

    private record Parsed(List<Finding> findings, int dependencies) {}
}
