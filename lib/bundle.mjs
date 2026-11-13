// Turn the selected rule sets into the release assets:
//   rules-bundle.json        the format BoadAIcleaner validates (yara-rules-store.ts)
//   manifest.json            version and hashes, so the app can skip unchanged bundles
//   THIRD-PARTY-LICENSES.md  every source's license text

import { createHash } from 'node:crypto'

/** The app rejects a rule file whose content is longer than this (yara-rules-store.ts). */
export const MAX_APP_FILE_BYTES = 1024 * 1024

export const BUNDLE_FILE = 'rules-bundle.json'

function sha256(text) {
  return createHash('sha256').update(text).digest('hex')
}

function fileHeader(entry, meta, part, parts) {
  const { source, section } = entry
  return [
    '/*',
    ` * BoadAIcleaner YARA rules: ${source.name}`,
    ` * Source: ${source.repository} (commit ${section.commit})`,
    ` * License: ${source.license} (see THIRD-PARTY-LICENSES.md)`,
    ` * Packaged from YARA Forge release ${meta.forgeTag} (${source.package} package)`,
    ...(parts > 1 ? [` * Part ${part} of ${parts}`] : []),
    ' */',
    '',
    ...entry.imports.map((m) => `import "${m}"`),
    '',
    ''
  ].join('\n')
}

/** Greedy split of rules into groups whose text fits `budget` characters. */
function groupRules(rules, budget, sourceName) {
  const groups = []
  let current = []
  let size = 0
  for (const r of rules) {
    const len = r.text.length + 1
    if (len > budget) {
      throw new Error(`${sourceName}: rule ${r.name} (${r.text.length} chars) does not fit one file`)
    }
    if (size + len > budget && current.length > 0) {
      groups.push(current)
      current = []
      size = 0
    }
    current.push(r)
    size += len
  }
  if (current.length > 0) groups.push(current)
  return groups
}

/**
 * One .yar file per source, split at rule boundaries when the source is
 * larger than maxFileChars. Each file repeats the imports so it also
 * compiles on its own (the app compiles file by file when a bulk compile fails).
 */
export function buildRuleFiles(selected, { maxFileChars, ...meta }) {
  if (!(maxFileChars > 0) || maxFileChars > MAX_APP_FILE_BYTES) {
    throw new Error(`maxFileChars must be between 1 and ${MAX_APP_FILE_BYTES}`)
  }
  const files = []
  for (const entry of selected) {
    // Reserve room for the longest header ("Part NN of NN").
    const headerRoom = fileHeader(entry, meta, 99, 99).length
    const groups = groupRules(entry.section.rules, maxFileChars - headerRoom, entry.source.name)
    groups.forEach((group, i) => {
      const filename =
        groups.length === 1
          ? `${entry.source.file}.yar`
          : `${entry.source.file}-${String(i + 1).padStart(2, '0')}.yar`
      const content =
        fileHeader(entry, meta, i + 1, groups.length) + group.map((r) => r.text).join('\n')
      if (content.length > maxFileChars || Buffer.byteLength(content) > MAX_APP_FILE_BYTES) {
        throw new Error(`${filename} is larger than the file limit`)
      }
      files.push({ filename, content, source: entry.source.name, ruleNames: group.map((r) => r.name) })
    })
  }
  return files
}

/** Same hash as computeBundleHash in the app: contents joined in filename order. */
export function computeBundleHash(rules) {
  const sorted = [...rules].sort((a, b) =>
    a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0
  )
  return sha256(sorted.map((r) => r.content).join(''))
}

/** Build rules-bundle.json and manifest.json. Same input gives the same bytes. */
export function buildRelease(selected, files, meta) {
  const hash = computeBundleHash(files)
  const version = `${meta.forgeTag}-${hash.slice(0, 8)}`
  const updatedAt = new Date(`${meta.creationDate}T00:00:00Z`).toISOString()

  const bundle = {
    version,
    updatedAt,
    sha256: hash,
    rules: files.map((f) => ({ filename: f.filename, content: f.content }))
  }
  const bundleJson = JSON.stringify(bundle)

  const manifest = {
    schema: 1,
    version,
    updatedAt,
    sha256: hash,
    ruleCount: files.reduce((n, f) => n + f.ruleNames.length, 0),
    fileCount: files.length,
    bundle: { file: BUNDLE_FILE, bytes: Buffer.byteLength(bundleJson), sha256: sha256(bundleJson) },
    forge: { release: meta.forgeTag, version: meta.forgeVersion },
    sources: selected.map(({ source, section }) => ({
      name: source.name,
      license: source.license,
      repository: source.repository,
      commit: section.commit,
      package: source.package,
      rules: section.rules.length,
      files: files.filter((f) => f.source === source.name).map((f) => f.filename)
    }))
  }

  return { bundle, bundleJson, manifest }
}

export function renderLicenses(selected, meta) {
  const parts = [
    '# Third-party licenses',
    '',
    `The YARA rules in this release come from the open-source repositories below. They were collected by [YARA Forge](https://github.com/YARAHQ/yara-forge) release ${meta.forgeTag}, which renames rules and adds metadata fields (score, quality, source_url and others). This repository then keeps only the listed repositories and splits large rule sets into several files. No other change is made to the rules.`,
    '',
    'Each rule set stays under its own license, reproduced in full below.',
    ''
  ]
  for (const { source, section } of selected) {
    parts.push(
      `## ${source.name}`,
      '',
      `- Repository: ${source.repository}`,
      `- Version: commit ${section.commit}`,
      `- License: ${source.license}`,
      `- Rules: ${section.rules.length}`,
      '',
      '```text',
      section.license,
      '```',
      ''
    )
  }
  return parts.join('\n')
}

export function renderReleaseNotes(manifest) {
  return [
    `YARA rules from YARA Forge release ${manifest.forge.release}: ${manifest.ruleCount} rules in ${manifest.fileCount} files.`,
    '',
    '| Source | License | Rules |',
    '| --- | --- | --- |',
    ...manifest.sources.map((s) => `| [${s.name}](${s.repository}) | ${s.license} | ${s.rules} |`),
    '',
    `Bundle SHA-256 (app hash): \`${manifest.sha256}\``,
    ''
  ].join('\n')
}
