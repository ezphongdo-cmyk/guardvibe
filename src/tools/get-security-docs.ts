import { frameworkGuides } from "../data/framework-guides.js";

export function getSecurityDocs(topic: string): string {
  const normalizedTopic = topic.toLowerCase().trim();

  // Try exact topic match first
  const exactMatch = frameworkGuides.find(
    (guide) => guide.topic === normalizedTopic
  );
  if (exactMatch) return exactMatch.content;

  // Try keyword match
  const keywordMatches = frameworkGuides
    .map((guide) => {
      const score = guide.keywords.reduce((acc, keyword) => {
        if (normalizedTopic.includes(keyword)) return acc + 2;
        if (keyword.includes(normalizedTopic)) return acc + 1;
        return acc;
      }, 0);
      return { guide, score };
    })
    .filter((m) => m.score > 0)
    .sort((a, b) => b.score - a.score);

  if (keywordMatches.length > 0) {
    // Return the best match, or multiple if scores are close
    const best = keywordMatches[0];
    const results = keywordMatches.filter(
      (m) => m.score >= best.score * 0.7
    );

    if (results.length === 1) {
      return results[0].guide.content;
    }

    // Multiple relevant guides
    return [
      `# Security Guides for "${topic}"`,
      ``,
      `Found ${results.length} relevant guides:`,
      ``,
      ...results.map(
        (r) => `---\n\n${r.guide.content}`
      ),
    ].join("\n");
  }

  // No match - return available topics
  const availableTopics = frameworkGuides
    .map((g) => `- **${g.topic}**: ${g.title}`)
    .join("\n");

  return [
    `# No Guide Found for "${topic}"`,
    ``,
    `I don't have a specific security guide for that topic yet.`,
    ``,
    `## Available Topics:`,
    availableTopics,
    ``,
    `## General Security Tips:`,
    `1. Validate all user input with schemas (zod, joi, pydantic)`,
    `2. Use parameterized queries for database access`,
    `3. Hash passwords with bcrypt (12+ salt rounds)`,
    `4. Set security headers (helmet for Express)`,
    `5. Keep dependencies updated (npm audit)`,
    `6. Use environment variables for secrets`,
    `7. Add rate limiting to auth endpoints`,
    `8. Set secure cookie flags (httpOnly, secure, sameSite)`,
  ].join("\n");
}
