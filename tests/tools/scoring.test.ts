import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkProject } from "../../src/tools/check-project.js";

describe("check_project scoring", () => {
  it("scores A for clean code", () => {
    const result = checkProject([{ path: "src/clean.ts", content: "const x = 1 + 2;" }]);
    assert(result.includes("Security Score: A"));
  });

  it("scores poorly for critical issues", () => {
    const result = checkProject([
      { path: "src/bad.ts", content: 'const password = "abc"\nconst key = "AKIAIOSFODNN7EXAMPLE"' },
    ]);
    assert(result.includes("Security Score: D") || result.includes("Security Score: F"));
  });

  it("skips unsupported file extensions", () => {
    const result = checkProject([{ path: "style.css", content: "body{}" }]);
    assert(result.includes("Skipped 1 file"));
  });

  it("skips legacy languages removed by hard focus", () => {
    const result = checkProject([
      { path: "legacy.php", content: "<?php echo $_GET['name'];" },
      { path: "legacy.rb", content: "puts params[:name]" },
      { path: "legacy.java", content: "class App {}" },
    ]);
    assert(result.includes("Files scanned: 0"));
    assert(result.includes("Skipped 3 files"));
  });

  it("reports correct file count", () => {
    const result = checkProject([
      { path: "a.ts", content: "const x = 1;" },
      { path: "b.ts", content: "const y = 2;" },
    ]);
    assert(result.includes("Files scanned: 2"));
  });
});
