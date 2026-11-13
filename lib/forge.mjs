// Read a YARA Forge rule package and pick the rule sets on the allow-list.
//
// A package (packages/<name>/yara-rules-<name>.yar in a YARA Forge release)
// is one text file: a header comment, the `import` lines, then for each
// source repository a "YARA Rule Set" comment (name, URL, commit, rule
// count, full LICENSE text) followed by that repository's rules.

const SECTION_START = '/*\n * YARA Rule Set\n'
const HEADER_END = '\n */\n'
const LICENSE_LINE = '\n * LICENSE\n'
const RULE_START = /^(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)/gm

// Text that must appear in a section's LICENSE block for each license id.
const LICENSE_MARKERS = {
  MIT: ['Permission is hereby granted, free of charge'],
  'BSD-2-Clause': ['Redistribution and use in source and binary forms'],
  'BSD-3-Clause': ['Redistribution and use in source and binary forms', 'Neither the name'],
  'Apache-2.0': ['Apache License', 'Version 2.0']
}

// Text that must not appear: copyleft, attribution-at-use or non-open licenses.
const FORBIDDEN_LICENSE_TEXT = [
  /GNU (?:Affero |Lesser )?General Public License/i,
  /Detection Rule License/i,
  /Creative Commons/i,
  /ShareAlike/i,
  /Elastic License/i
]

function headerField(text, label) {
  const m = text.match(new RegExp(`^ \\* ${label}:[ \\t]*(.*?)[ \\t]*$`, 'm'))
  return m ? m[1] : null
}

/** Split the rules part of a section into whole rules, in file order. */
export function splitRules(body) {
  const starts = [...body.matchAll(RULE_START)].map((m) => ({ index: m.index, name: m[1] }))
  return starts.map((s, i) => {
    const end = i + 1 < starts.length ? starts[i + 1].index : body.length
    return { name: s.name, text: `${body.slice(s.index, end).trimEnd()}\n` }
  })
}

function parseLicense(header) {
  const at = header.indexOf(LICENSE_LINE)
  if (at < 0) return ''
  return header
    .slice(at + LICENSE_LINE.length)
    .split('\n')
    .map((line) => line.replace(/^ \*(?: |$)/, ''))
    .join('\n')
    .trim()
}

function parseSection(chunk) {
  const end = chunk.indexOf(HEADER_END)
  if (end < 0) throw new Error('Rule set header is not closed')
  const header = chunk.slice(0, end)
  const fieldsPart = header.split(LICENSE_LINE)[0]
  const name = headerField(fieldsPart, 'Repository Name')
  if (!name) throw new Error('Rule set header has no repository name')
  const declared = headerField(fieldsPart, 'Number of Rules')
  return {
    name,
    repository: headerField(fieldsPart, 'Repository'),
    commit: headerField(fieldsPart, 'Git Commit'),
    declaredCount: declared === null ? null : Number(declared),
    license: parseLicense(header),
    rules: splitRules(chunk.slice(end + HEADER_END.length))
  }
}

/** Parse one YARA Forge package file. */
export function parsePackage(input) {
  const text = input.replace(/\r\n/g, '\n')
  const first = text.indexOf(SECTION_START)
  if (first < 0) throw new Error('No rule sets found in the package')

  const head = text.slice(0, first)
  const sections = []
  for (let pos = first; pos >= 0; ) {
    const next = text.indexOf(SECTION_START, pos + SECTION_START.length)
    sections.push(parseSection(text.slice(pos, next < 0 ? undefined : next)))
    pos = next
  }

  return {
    name: headerField(head, 'Name'),
    forgeVersion: headerField(head, 'YARA-Forge Version'),
    creationDate: headerField(head, 'Creation Date'),
    imports: [...head.matchAll(/^import\s+"([^"]+)"\s*$/gm)].map((m) => m[1]),
    sections
  }
}

function normalizeUrl(url) {
  return String(url ?? '')
    .trim()
    .toLowerCase()
    .replace(/\/+$/, '')
}

function checkLicense(sourceName, licenseId, text) {
  const markers = LICENSE_MARKERS[licenseId]
  if (!markers) throw new Error(`${sourceName}: license id ${licenseId} is not on the permitted list`)
  const missing = markers.filter((m) => !text.includes(m))
  if (missing.length > 0) {
    throw new Error(
      `${sourceName}: license text no longer matches ${licenseId} (missing "${missing[0]}")`
    )
  }
  const forbidden = FORBIDDEN_LICENSE_TEXT.find((re) => re.test(text))
  if (forbidden) {
    throw new Error(`${sourceName}: license text mentions a non-permitted license (${forbidden})`)
  }
}

/**
 * Return the allowed sections, in allow-list order. Throws instead of
 * silently dropping or adding rules when the upstream package changed.
 */
export function selectSources(packages, allowList) {
  const seen = new Map()
  return allowList.sources.map((source) => {
    const pkg = packages[source.package]
    if (!pkg) throw new Error(`${source.name}: package "${source.package}" was not loaded`)

    const matches = pkg.sections.filter((s) => s.name === source.name)
    if (matches.length === 0) {
      throw new Error(`${source.name}: rule set not found in the ${source.package} package`)
    }
    if (matches.length > 1) {
      throw new Error(`${source.name}: ${matches.length} rule sets share this name`)
    }
    const section = matches[0]

    if (normalizeUrl(section.repository) !== normalizeUrl(source.repository)) {
      throw new Error(
        `${source.name}: repository changed to ${section.repository} (expected ${source.repository})`
      )
    }
    checkLicense(source.name, source.license, section.license)
    if (section.rules.length === 0) throw new Error(`${source.name}: no rules`)
    if (section.rules.length !== section.declaredCount) {
      throw new Error(
        `${source.name}: parsed ${section.rules.length} rules but the header says ${section.declaredCount}`
      )
    }
    for (const r of section.rules) {
      const other = seen.get(r.name)
      if (other) throw new Error(`Rule ${r.name} appears in both ${other} and ${source.name}`)
      seen.set(r.name, source.name)
    }

    return { source, section, imports: pkg.imports }
  })
}
