import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { reactNativeRules } from "../../src/data/rules/react-native.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = reactNativeRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("React Native / Expo Rules", () => {
  // VG700: AsyncStorage Sensitive Data
  it("VG700: detects token in AsyncStorage", () => {
    testRule("VG700", 'await AsyncStorage.setItem("authToken", jwt)', true);
  });
  it("VG700: detects password in AsyncStorage", () => {
    testRule("VG700", 'AsyncStorage.setItem("password", pw)', true);
  });
  it("VG700: allows non-sensitive AsyncStorage", () => {
    testRule("VG700", 'AsyncStorage.setItem("theme", "dark")', false);
  });

  // VG701: Deep Link Auth Bypass
  it("VG701: detects deep link with token", () => {
    testRule("VG701", 'Linking.addEventListener("url", (event) => { const token = parseUrl(event.url).token; })', true);
  });
  it("VG701: allows deep link without auth params", () => {
    testRule("VG701", 'Linking.addEventListener("url", (event) => { navigate(event.url); })', false);
  });

  // VG702: Expo Push Token Exposure
  it("VG702: detects push token in console.log", () => {
    testRule("VG702", 'console.log("Push token:", expoPushToken)', true);
  });
  it("VG702: detects push token in analytics", () => {
    testRule("VG702", 'analytics.track("registered", { pushToken: token })', true);
  });

  // VG703: Hardcoded Secrets in EAS Config
  it("VG703: detects hardcoded secret in env block", () => {
    testRule("VG703", '"env": { "API_SECRET": "sk_live_abc123def456" }', true);
  });

  // VG704: WebView JavaScript Injection
  it("VG704: detects javaScriptEnabled true", () => {
    testRule("VG704", '<WebView source={{ uri: url }} javaScriptEnabled={true} />', true);
  });

  // VG706: Hardcoded API URL
  it("VG706: detects hardcoded API URL", () => {
    testRule("VG706", 'const apiUrl = "https://api.myapp.com/v1"', true);
  });
  it("VG706: allows localhost", () => {
    testRule("VG706", 'const apiUrl = "http://localhost:3000/api"', false);
  });
  it("VG706: allows env var", () => {
    testRule("VG706", "const apiUrl = process.env.EXPO_PUBLIC_API_URL", false);
  });

  // VG707: Disabled ATS
  it("VG707: detects disabled ATS", () => {
    testRule("VG707", 'NSAppTransportSecurity: { NSAllowsArbitraryLoads: true }', true);
  });

  // VG708: Sensitive Data in Expo Config
  it("VG708: detects secret in extra block", () => {
    testRule("VG708", 'extra: { API_SECRET: "sk_live_supersecretkey123" }', true);
  });

  // VG709: React Native Bridge Sensitive Data
  it("VG709: detects token through NativeModules", () => {
    testRule("VG709", 'NativeModules.Auth.setCredentials(token, secret)', true);
  });
});
