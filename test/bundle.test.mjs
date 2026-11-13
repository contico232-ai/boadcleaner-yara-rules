import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { parsePackage, selectSources } from '../lib/forge.mjs'
import {
  buildRuleFiles,
  computeBundleHash,
  buildRelease,
  renderLicenses,
  MAX_APP_FILE_BYTES
} from '../lib/bundle.mjs'
import { samplePackages, sampleAllowList } from './fixtures.mjs'

const META = { forgeTag: '20261108', forgeVersion: '0.9.1', creationDate: '2026-11-08' }

function selected(allowList = sampleAllowList) {
  const pkgs = Object.fromEntries(
    Object.entries(samplePackages()).map(([k, v]) => [k, parsePackage(v)])
  )
  return selectSources(pkgs, allowList)
}

test('buildRuleFiles writes one file per source with its imports and header', () => {
  const files = buildRuleFiles(selected(), { ...META, maxFileChars: 900000 })

  assert.deepEqual(
    files.map((f) => f.filename),
    ['beta.yar', 'alpha.yar']
  )
  const beta = files[0]
  assert.match(beta.content, /^\/\*\n \* BoadAIcleaner YARA rules: Beta\n/)
  assert.match(beta.content, / \* License: MIT \(see THIRD-PARTY-LICENSES\.md\)\n/)
  assert.match(beta.content, / \* Source: https:\/\/github\.com\/example\/beta \(commit def456\)\n/)
  assert.match(beta.content, /\nimport "pe"\nimport "math"\n/)
  assert.equal((beta.content.match(/^rule /gm) || []).length, 3)
  assert.deepEqual(beta.ruleNames, ['BETA_One', 'BETA_Two', 'BETA_Three'])
})

test('buildRuleFiles splits a large source at rule boundaries', () => {
  const files = buildRuleFiles(selected(), { ...META, maxFileChars: 450 })
  const betaFiles = files.filter((f) => f.source === 'Beta')

  assert.ok(betaFiles.length > 1, 'expected Beta to be split')
  assert.deepEqual(
    betaFiles.map((f) => f.filename),
    betaFiles.map((_, i) => `beta-${String(i + 1).padStart(2, '0')}.yar`)
  )
  for (const f of betaFiles) {
    assert.ok(f.content.length <= 450, `${f.filename} is ${f.content.length} chars`)
    assert.match(f.content, /\nimport "pe"\nimport "math"\n/)
    assert.match(f.content, new RegExp(` \\* Part ${betaFiles.indexOf(f) + 1} of ${betaFiles.length}\\n`))
  }
  assert.deepEqual(
    betaFiles.flatMap((f) => f.ruleNames),
    ['BETA_One', 'BETA_Two', 'BETA_Three']
  )
})

test('buildRuleFiles fails when a single rule cannot fit the limit', () => {
  assert.throws(() => buildRuleFiles(selected(), { ...META, maxFileChars: 300 }), /does not fit/)
})

test('buildRuleFiles never exceeds the app limit in bytes', () => {
  assert.equal(MAX_APP_FILE_BYTES, 1024 * 1024)
  assert.throws(
    () => buildRuleFiles(selected(), { ...META, maxFileChars: MAX_APP_FILE_BYTES + 1 }),
    /maxFileChars/
  )
})

test('computeBundleHash matches the app: contents sorted by filename', () => {
  const rules = [
    { filename: 'b.yar', content: 'B' },
    { filename: 'a.yar', content: 'A' },
    { filename: 'B.yar', content: 'upper' }
  ]
  // Plain code-unit order puts "B.yar" before "a.yar".
  const expected = createHash('sha256').update('upperAB').digest('hex')
  assert.equal(computeBundleHash(rules), expected)
})

test('buildRelease produces the bundle the app validates, and a manifest', () => {
  const sel = selected()
  const files = buildRuleFiles(sel, { ...META, maxFileChars: 900000 })
  const { bundle, bundleJson, manifest } = buildRelease(sel, files, META)

  const sha = computeBundleHash(files)
  assert.equal(bundle.sha256, sha)
  assert.equal(bundle.version, `20261108-${sha.slice(0, 8)}`)
  assert.equal(bundle.updatedAt, '2026-11-08T00:00:00.000Z')
  assert.deepEqual(
    bundle.rules.map((r) => Object.keys(r)),
    bundle.rules.map(() => ['filename', 'content'])
  )
  assert.deepEqual(JSON.parse(bundleJson), bundle)

  assert.equal(manifest.version, bundle.version)
  assert.equal(manifest.sha256, sha)
  assert.equal(manifest.ruleCount, 5)
  assert.equal(manifest.fileCount, 2)
  assert.deepEqual(manifest.bundle, {
    file: 'rules-bundle.json',
    bytes: Buffer.byteLength(bundleJson),
    sha256: createHash('sha256').update(bundleJson).digest('hex')
  })
  assert.deepEqual(manifest.forge, { release: '20261108', version: '0.9.1' })
  assert.deepEqual(manifest.sources[0], {
    name: 'Beta',
    license: 'MIT',
    repository: 'https://github.com/example/beta',
    commit: 'def456',
    package: 'extended',
    rules: 3,
    files: ['beta.yar']
  })
})

test('buildRelease is deterministic for the same input', () => {
  const sel = selected()
  const files = buildRuleFiles(sel, { ...META, maxFileChars: 900000 })
  assert.equal(buildRelease(sel, files, META).bundleJson, buildRelease(sel, files, META).bundleJson)
})

test('renderLicenses lists every source with its full license text', () => {
  const sel = selected()
  const md = renderLicenses(sel, META)

  assert.match(md, /^# Third-party licenses\n/)
  assert.match(md, /YARA Forge/)
  assert.match(md, /## Beta\n/)
  assert.match(md, /## Alpha\n/)
  assert.match(md, /Permission is hereby granted, free of charge/)
  assert.match(md, /Redistribution and use in source and binary forms/)
  assert.match(md, /commit def456/)
  assert.doesNotMatch(md, /GNU General Public License/)
})
