// Shared helpers for Tunisian text: digits, phone numbers, cities.
// Pure functions, no dependencies.

const ARABIC_DIGITS = "٠١٢٣٤٥٦٧٨٩";
const PERSIAN_DIGITS = "۰۱۲۳۴۵۶۷۸۹";

export function normalizeDigits(value) {
  return String(value ?? "").replace(/[٠-٩۰-۹]/g, digit => {
    const a = ARABIC_DIGITS.indexOf(digit);
    if (a !== -1) return String(a);
    const p = PERSIAN_DIGITS.indexOf(digit);
    return p !== -1 ? String(p) : digit;
  });
}

// Lowercase, no accents, no Arabic diacritics, unified Arabic letter variants.
export function normalizeText(value) {
  return normalizeDigits(value)
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")        // Latin accents
    .replace(/[ً-ٰٟـ]/g, "") // Arabic diacritics and tatweel
    .replace(/[أإآٱ]/g, "ا")
    .replace(/ى/g, "ي")
    .replace(/ة/g, "ه")
    .replace(/\s+/g, " ")
    .trim();
}

export function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// True when `needle` appears in `haystack` as a whole word (Latin) or substring (Arabic).
export function containsWord(haystack, needle) {
  if (!needle) return false;
  if (/[a-z0-9]/.test(needle)) {
    return new RegExp(`(^|[^a-z0-9])${escapeRegExp(needle)}($|[^a-z0-9])`).test(haystack);
  }
  return haystack.includes(needle);
}

// --------------------------------------------------
// PHONE NUMBERS
// --------------------------------------------------

// Returns digits only, without the Tunisian country code.
export function normalizePhone(value) {
  let digits = normalizeDigits(value).replace(/\D/g, "");
  if (digits.startsWith("00216")) digits = digits.slice(5);
  else if (digits.startsWith("216") && digits.length === 11) digits = digits.slice(3);
  return digits;
}

// Tunisian numbers have 8 digits and start with 2-7 or 9.
export function isValidTnPhone(digits) {
  return /^[2-79]\d{7}$/.test(String(digits));
}

export function formatPhone(digits) {
  const d = String(digits || "");
  return /^\d{8}$/.test(d) ? `${d.slice(0, 2)} ${d.slice(2, 5)} ${d.slice(5)}` : d;
}

export function digitsOnly(value) {
  return normalizeDigits(value).replace(/\D/g, "");
}

// Finds the customer's phone number in free text. Returns null when there is none
// or when several different numbers make it ambiguous.
export function detectPhone(message) {
  const text = normalizeDigits(message);
  const candidates = [];

  // Number written right after a phone keyword gets priority.
  const contextual = text.match(
    /(?:num(?:ero|rou)?|tel(?:ephone|éphone)?|tél|phone|mobile|whatsapp|نمرو|نمرة|نمره|رقم|رقمي|هاتف|تليفون)\s*[:\-]?\s*((?:\+?\s?216[\s.\-]?|00216[\s.\-]?)?(?:\d[\s.\-]?){7}\d)(?!\d)/i
  );
  if (contextual) {
    const n = normalizePhone(contextual[1]);
    if (isValidTnPhone(n)) return n;
  }

  const re = /(?<!\d)((?:\+?\s?216[\s.\-]?|00216[\s.\-]?)?(?:\d[\s.\-]?){7}\d)(?!\d)/g;
  for (const m of text.matchAll(re)) {
    const n = normalizePhone(m[1]);
    if (isValidTnPhone(n) && !candidates.includes(n)) candidates.push(n);
  }

  return candidates.length === 1 ? candidates[0] : null;
}

// --------------------------------------------------
// CITIES (governorates + common districts mapped to their governorate)
// --------------------------------------------------

const CITY_ALIASES = [
  ["Tunis", ["tunis", "تونس", "la marsa", "marsa", "المرسى", "carthage", "قرطاج", "bardo", "باردو",
    "la goulette", "goulette", "حلق الوادي", "menzah", "المنزه", "lac 1", "lac 2", "les berges du lac", "el omrane", "omrane", "ezzouhour", "سيدي بوسعيد", "sidi bou said"]],
  ["Ariana", ["ariana", "اريانه", "soukra", "السكره", "raoued", "رواد", "ennasr", "النصر", "ghazela", "kalaat el andalous"]],
  ["Ben Arous", ["ben arous", "بن عروس", "mourouj", "el mourouj", "المروج", "rades", "radès", "رادس", "hammam lif", "حمام الانف",
    "ezzahra", "الزهراء", "megrine", "مقرين", "fouchana", "فوشانه", "mornag", "مرناق"]],
  ["Manouba", ["manouba", "منوبه", "denden", "douar hicher", "oued ellil", "mornaguia"]],
  ["Nabeul", ["nabeul", "نابل", "hammamet", "الحمامات", "kelibia", "قليبيه", "korba", "قربه", "dar chaabane", "grombalia", "قروميليه", "menzel temime", "soliman", "سليمان"]],
  ["Zaghouan", ["zaghouan", "زغوان"]],
  ["Bizerte", ["bizerte", "bizerta", "بنزرت", "menzel bourguiba", "منزل بورقيبه", "mateur", "ماطر", "ras jebel"]],
  ["Beja", ["beja", "باجه", "testour", "تستور", "medjez el bab"]],
  ["Jendouba", ["jendouba", "جندوبه", "tabarka", "طبرقه", "ain draham", "عين دراهم"]],
  ["Le Kef", ["le kef", "kef", "الكاف"]],
  ["Siliana", ["siliana", "سليانه"]],
  ["Sousse", ["sousse", "soussa", "سوسه", "hammam sousse", "حمام سوسه", "msaken", "مساكن", "akouda", "اكودة", "akouda", "kalaa kebira", "القلعه الكبيره", "khzema", "khezama", "port el kantaoui", "sahloul", "enfidha", "النفيضه"]],
  ["Monastir", ["monastir", "المنستير", "moknine", "المكنين", "ksar hellal", "قصر هلال", "jemmal", "جمال", "ksibet el mediouni", "skanes"]],
  ["Mahdia", ["mahdia", "المهديه", "chebba", "الشابه", "ksour essaf", "قصور الساف", "el jem", "الجم"]],
  ["Sfax", ["sfax", "صفاقس", "sakiet ezzit", "ساقية الزيت", "sakiet eddaier", "ساقية الداير", "gremda", "قرمدة", "route gremda"]],
  ["Kairouan", ["kairouan", "القيروان"]],
  ["Kasserine", ["kasserine", "القصرين"]],
  ["Sidi Bouzid", ["sidi bouzid", "سيدي بوزيد"]],
  ["Gabes", ["gabes", "قابس", "mareth", "مارث"]],
  ["Medenine", ["medenine", "مدنين", "djerba", "jerba", "جربه", "houmt souk", "zarzis", "جرجيس", "ben gardane", "بن قردان"]],
  ["Tataouine", ["tataouine", "تطاوين"]],
  ["Gafsa", ["gafsa", "قفصه"]],
  ["Tozeur", ["tozeur", "توزر"]],
  ["Kebili", ["kebili", "قبلي", "douz", "دوز"]]
];

export const GOVERNORATES = CITY_ALIASES.map(([city]) => city);

// Longest alias first so "ben arous" wins over shorter overlaps.
const ALIAS_INDEX = CITY_ALIASES
  .flatMap(([city, aliases]) => aliases.map(alias => [normalizeText(alias), city]))
  .sort((a, b) => b[0].length - a[0].length);

export function detectCity(text) {
  const normalized = normalizeText(text);
  if (!normalized) return null;
  for (const [alias, city] of ALIAS_INDEX) {
    if (containsWord(normalized, alias)) return city;
  }
  return null;
}
