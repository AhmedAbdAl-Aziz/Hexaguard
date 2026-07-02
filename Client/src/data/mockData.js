/** Fuzzy tech-stack matching (mirrors backend alert dispatcher logic). */
export function checkStackMatch(tech, stack) {
  const normalized = tech.toLowerCase().trim();
  return stack.some((s) => {
    const item = s.toLowerCase().trim();
    return normalized === item || normalized.includes(item) || item.includes(normalized);
  });
}
