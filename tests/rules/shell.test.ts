import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { shellRules } from "../../src/data/rules/shell.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = shellRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("Shell Rules", () => {
  describe("VG530 - Pipe to shell execution", () => {
    it("detects curl | bash", () => {
      testRule("VG530", "curl http://example.com/script.sh | bash", true);
    });
    it("detects curl -sSL | sh", () => {
      testRule("VG530", "curl -sSL https://get.docker.com | sh", true);
    });
    it("detects wget | bash", () => {
      testRule("VG530", "wget -qO- https://example.com/install.sh | bash", true);
    });
    it("ignores curl to file", () => {
      testRule("VG530", "curl -o script.sh https://example.com/install.sh", false);
    });
    it("ignores wget to file", () => {
      testRule("VG530", "wget https://example.com/install.sh", false);
    });
    it("detects base64 decode piped to bash", () => {
      testRule("VG530", 'echo "payload" | base64 -d | bash', true);
    });
    it("detects base64 --decode piped to sh", () => {
      testRule("VG530", "base64 --decode payload.txt | sh", true);
    });
  });

  describe("VG531 - Dangerous file permissions", () => {
    it("detects chmod 777", () => {
      testRule("VG531", "chmod 777 /etc/passwd", true);
    });
    it("detects chmod 666", () => {
      testRule("VG531", "chmod 666 /tmp/data.txt", true);
    });
    it("ignores chmod 755", () => {
      testRule("VG531", "chmod 755 script.sh", false);
    });
    it("ignores chmod 644", () => {
      testRule("VG531", "chmod 644 config.txt", false);
    });
  });

  describe("VG502 - Destructive rm command", () => {
    it("detects rm -rf /", () => {
      testRule("VG502", "rm -rf / ", true);
    });
    it("detects rm -rf /*", () => {
      testRule("VG502", "rm -rf /*", true);
    });
    it("detects rm -rf /etc", () => {
      testRule("VG502", "rm -rf /etc", true);
    });
    it("detects rm -rf $VAR/", () => {
      testRule("VG502", "rm -rf $DIR/", true);
    });
    it("ignores rm -rf ./build", () => {
      testRule("VG502", "rm -rf ./build", false);
    });
    it("ignores rm -rf node_modules", () => {
      testRule("VG502", "rm -rf node_modules", false);
    });
  });

  describe("VG533 - Password in command line", () => {
    it("detects echo password | sudo -S", () => {
      testRule("VG533", 'echo "password123" | sudo -S apt install foo', true);
    });
    it("detects mysql -p with password", () => {
      testRule("VG533", "mysql -u root -pMySecret123 mydb", true);
    });
    it("ignores sudo without password pipe", () => {
      testRule("VG533", "sudo apt install nginx", false);
    });
  });

  describe("VG534 - Unsafe eval in shell", () => {
    it("detects eval $cmd", () => {
      testRule("VG534", 'eval "$cmd"', true);
    });
    it("detects eval ${command}", () => {
      testRule("VG534", "eval ${command}", true);
    });
    it("ignores eval without variable", () => {
      testRule("VG534", 'eval "echo hello"', false);
    });
  });
});
