// Product catalog helpers: match what the AI or the customer wrote to YOUR products and prices.
import { normalizeText, containsWord } from "./tunisia.js";

export function parseAliases(text) {
  return String(text || "")
    .split(/[,;\n،]/)
    .map(s => s.trim())
    .filter(Boolean);
}

function keysFor(product) {
  return [product.name, ...parseAliases(product.aliases)]
    .map(normalizeText)
    .filter(Boolean);
}

// Returns the catalog product the text refers to, or null.
// - exact name/alias match wins
// - otherwise the text must contain a known name/alias (longest wins)
// - otherwise the text may be a part of exactly ONE product name ("robe" -> "Robe Lina");
//   if several products fit, it stays unmatched so a human decides.
export function matchProduct(text, products) {
  const n = normalizeText(text);
  if (!n || !products?.length) return null;

  let best = null;
  let bestScore = 0;
  const partial = new Set();

  for (const product of products) {
    for (const key of keysFor(product)) {
      let score = 0;
      if (n === key) score = 10000 + key.length;
      else if (containsWord(n, key)) score = key.length;
      else if (n.length >= 3 && containsWord(key, n)) partial.add(product);

      if (score > bestScore) {
        best = product;
        bestScore = score;
      }
    }
  }

  if (best) return best;
  return partial.size === 1 ? [...partial][0] : null;
}

// One line per product, for the AI prompt.
export function catalogForPrompt(products, limit = 60) {
  return (products || []).slice(0, limit).map(p => {
    const aliases = parseAliases(p.aliases).slice(0, 8);
    const name = String(p.name).slice(0, 80);
    return aliases.length ? `- ${name} (also called: ${aliases.join(", ")})` : `- ${name}`;
  }).join("\n");
}
