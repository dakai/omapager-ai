// Sensitive-value detection for notification text.
//
// This is the rule layer of a redactor, not a model: it finds credential and
// personal-data shapes in a string and reports where they are. It never
// decides what to do with them — the caller picks between marking them in the
// UI and replacing them outright — and it never rewrites a row by itself.
//
// Two things it must not do, both learned from the notification body it runs
// on: allocate unboundedly (every rule is anchored on a literal marker first,
// so a 32 KB body costs a handful of indexOf calls) and guess (a keyword with
// no digit-bearing shape next to it is not a secret; `Claude Code` and `412`
// are ordinary text).
//
// The Python store carries an independent implementation of the same shapes.
// They are deliberately separate: a bug in one must not be able to make a
// secret reach disk and the screen at once, and the two disagreeing is what
// the corpus tests exist to catch.
.pragma library

var MAX_TEXT = 32768
var MAX_MARKS = 64

// The masked stand-in. Fixed length and fixed content, so a masked value
// cannot be used to compare two notifications against each other.
var MASK = "\u2022\u2022\u2022\u2022\u2022\u2022"

// A rule is `markers` first: the literal that must appear for the pattern to
// be worth running. `bound` is the character class a match may not touch.
var RULES = [
  { kind: "PRIVATE_KEY", mark: ["PRIVATE KEY"],
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,16384}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/ },
  { kind: "API_KEY", mark: ["sk-"],
    re: /\bsk-(?:ant-|proj-|or-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/ },
  { kind: "API_KEY", mark: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-"],
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,})\b/ },
  { kind: "API_KEY", mark: ["AIza"], re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { kind: "API_KEY", mark: ["xox"], re: /\bxox[abposr]-[0-9A-Za-z-]{10,}\b/ },
  { kind: "API_KEY", mark: ["_live_"], re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/ },
  { kind: "API_KEY", mark: ["AKIA", "ASIA"], re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: "API_KEY", mark: ["hf_", "gsk_", "xai-", "npm_", "pypi-", "dop_v1_"],
    re: /\b(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|dop_v1_[a-f0-9]{64})\b/ },
  { kind: "TOKEN", mark: ["eyJ"],
    re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  // A credential inside a connection URL, including the user-less form Redis
  // uses. Only the secret group is masked; the user and host stay readable.
  { kind: "PASSWORD", mark: ["://"],
    re: /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s:@/?#"'<>]*:([^\s@/?#"'<>]{3,})@/,
    group: 1 },
  { kind: "EMAIL", mark: ["@"],
    re: /\b[A-Za-z0-9.!#$&'*+\/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b/ },
  { kind: "IBAN", mark: [],
    re: /\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b/,
    ok: looksLikeIban },
  { kind: "CARD", mark: [], re: /\b(?:[0-9]{4}[ -]){3}[0-9]{4}\b/, ok: luhn },
  { kind: "CARD", mark: [], re: /\b[0-9]{13,19}\b/, ok: luhn },
  { kind: "PHONE", mark: ["+", "(", " "],
    re: /(?:\+|00)[0-9][0-9 ().-]{7,20}[0-9]/ },
]

// Letters used by IBANs; a match that is all digits is not one.
function looksLikeIban(value) {
  var digits = 0
  for (var i = 0; i < value.length; i++) if (value.charCodeAt(i) >= 48 && value.charCodeAt(i) <= 57) digits++
  return digits >= 8
}

// Luhn is what separates a card number from a long run of digits. Sixteen
// digits that fail it are a tracking number, an ID, or a build hash.
function luhn(value) {
  var digits = value.replace(/[^0-9]/g, "")
  if (digits.length < 13 || digits.length > 19) return false
  var sum = 0, double = false
  for (var i = digits.length - 1; i >= 0; i--) {
    var n = digits.charCodeAt(i) - 48
    if (double) { n *= 2; if (n > 9) n -= 9 }
    sum += n
    double = !double
  }
  return sum % 10 === 0
}

function bounded(value) {
  return typeof value === "string" ? value.slice(0, MAX_TEXT) : ""
}

// Where the interesting values are. Returns spans sorted by start, never
// overlapping: a later rule cannot re-mask something already found, which is
// what keeps one credential from being reported twice under two kinds.
function scan(text, extraWords) {
  var body = bounded(text)
  if (!body) return []
  var words = []
  if (extraWords && extraWords.length) {
    for (var w = 0; w < extraWords.length && w < 32; w++) {
      var word = String(extraWords[w] || "")
      if (word.length >= 3 && word.length <= 128) words.push(word)
    }
  }
  var spans = []
  for (var r = 0; r < RULES.length; r++) {
    var rule = RULES[r]
    if (!markerPresent(body, rule.mark)) continue
    var re = new RegExp(rule.re.source, rule.re.flags.indexOf("g") >= 0 ? rule.re.flags : rule.re.flags + "g")
    var match
    while ((match = re.exec(body)) !== null) {
      if (spans.length >= MAX_MARKS) break
      var start = rule.group ? match.index + match[0].indexOf(match[rule.group]) : match.index
      var end = start + String(rule.group ? match[rule.group] : match[0]).length
      if (rule.ok && !rule.ok(body.slice(start, end))) continue
      if (!free(spans, start, end)) continue
      spans.push({ start: start, end: end, kind: rule.kind })
      if (match[0].length === 0) re.lastIndex++
    }
  }
  for (var i = 0; i < words.length && spans.length < MAX_MARKS; i++) {
    var at = body.indexOf(words[i])
    while (at >= 0 && spans.length < MAX_MARKS) {
      if (free(spans, at, at + words[i].length)) spans.push({ start: at, end: at + words[i].length, kind: "WORD" })
      at = body.indexOf(words[i], at + words[i].length)
    }
  }
  spans.sort(function (a, b) { return a.start - b.start })
  return spans
}

function markerPresent(body, markers) {
  if (!markers || markers.length === 0) return true
  for (var i = 0; i < markers.length; i++) if (body.indexOf(markers[i]) >= 0) return true
  return false
}

function free(spans, start, end) {
  for (var i = 0; i < spans.length; i++) {
    if (start < spans[i].end && end > spans[i].start) return false
  }
  return true
}

// Replace every span with the fixed mask. `kind` is appended only when the
// caller asks for it: a card that says "•••••• (API key)" tells you what was
// hidden without telling you what it was.
function apply(text, spans, label) {
  var body = bounded(text)
  var out = "", at = 0
  for (var i = 0; i < spans.length; i++) {
    var span = spans[i]
    if (span.start < at || span.end > body.length) continue
    out += body.slice(at, span.start) + MASK + (label ? " (" + span.kind + ")" : "")
    at = span.end
  }
  return out + body.slice(at)
}

// One call for callers that do not care where the values were.
function redact(text, extraWords, label) {
  var spans = scan(text, extraWords)
  return spans.length ? apply(text, spans, label) : bounded(text)
}

function count(text, extraWords) { return scan(text, extraWords).length }
