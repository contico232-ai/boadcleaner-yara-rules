#!/usr/bin/env node
// Build the release assets from a downloaded YARA Forge release.
//
//   node scripts/build.mjs --core <yara-rules-core.yar> --extended <yara-rules-extended.yar> \
//     --forge-tag 20261108 --out dist
//
// Writes dist/rules-bundle.json, dist/manifest.json, dist/THIRD-PARTY-LICENSES.md
// and dist/RELEASE-NOTES.md. Exits non-zero if anything does not check out,
// including a rule file that YARA-X (the engine the app uses) cannot compile.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import { createRequire } from 'node:module'
import { parsePackage, selectSources } from '../lib/forge.mjs'
import {
  buildRuleFiles,
  buildRelease,
  renderLicenses,
  renderReleaseNotes,
  BUNDLE_FILE
} from '../lib/bundle.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const { values: args } = parseArgs({
  options: {
    core: { type: 'string' },
    extended: { type: 'string' },
    'forge-tag': { type: 'string' },
    out: { type: 'string', default: 'dist' },
    sources: { type: 'string', default: join(root, 'sources.json') }
  }
})
for (const key of ['core', 'extended', 'forge-tag']) {
  if (!args[key]) {
    console.error(`Missing --${key}`)
    process.exit(2)
  }
}
if (!/^\d{8}$/.test(args['forge-tag'])) {
  console.error(`--forge-tag must look like 20261108, got ${args['forge-tag']}`)
  process.exit(2)
}

const allowList = JSON.parse(readFileSync(args.sources, 'utf-8'))
const packages = {
  core: parsePackage(readFileSync(args.core, 'utf-8')),
  extended: parsePackage(readFileSync(args.extended, 'utf-8'))
}
const core = packages.core
const meta = {
  forgeTag: args['forge-tag'],
  forgeVersion: core.forgeVersion,
  creationDate: core.creationDate
}
if (!/^\d{4}-\d{2}-\d{2}$/.test(meta.creationDate ?? '')) {
  throw new Error(`Unexpected package creation date: ${meta.creationDate}`)
}

const selected = selectSources(packages, allowList)
const files = buildRuleFiles(selected, { ...meta, maxFileChars: allowList.maxFileChars })

// Compile the way the app does: every file on its own (its fallback path),
// then all files joined with "\n" (its normal path).
const require = createRequire(import.meta.url)
const yarax = require('@litko/yara-x')
for (const f of files) {
  try {
    yarax.compile(f.content)
  } catch (err) {
    throw new Error(`${f.filename} does not compile: ${String(err.message ?? err).split('\n')[0]}`)
  }
}
const started = Date.now()
yarax.compile(files.map((f) => f.content).join('\n'))
const compileMs = Date.now() - started

const { bundleJson, manifest } = buildRelease(selected, files, meta)

mkdirSync(args.out, { recursive: true })
writeFileSync(join(args.out, BUNDLE_FILE), bundleJson)
writeFileSync(join(args.out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
writeFileSync(join(args.out, 'THIRD-PARTY-LICENSES.md'), renderLicenses(selected, meta))
writeFileSync(join(args.out, 'RELEASE-NOTES.md'), renderReleaseNotes(manifest))

console.log(
  `Built ${manifest.version}: ${manifest.ruleCount} rules in ${manifest.fileCount} files, ` +
    `${(manifest.bundle.bytes / 1024 / 1024).toFixed(1)} MB, combined compile ${compileMs} ms`
)
for (const s of manifest.sources) {
  console.log(`  ${s.name.padEnd(16)} ${s.license.padEnd(13)} ${String(s.rules).padStart(5)}  ${s.files.join(', ')}`)
}
