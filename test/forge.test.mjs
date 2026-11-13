import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parsePackage, splitRules, selectSources } from '../lib/forge.mjs'
import {
  forgePackage,
  section,
  rule,
  LICENSES,
  samplePackages,
  sampleAllowList
} from './fixtures.mjs'

test('parsePackage reads the package header, imports and every rule set', () => {
  const { core } = samplePackages()
  const pkg = parsePackage(core)

  assert.equal(pkg.name, 'core')
  assert.equal(pkg.forgeVersion, '0.9.1')
  assert.equal(pkg.creationDate, '2026-11-08')
  assert.deepEqual(pkg.imports, ['pe'])
  assert.deepEqual(
    pkg.sections.map((s) => [s.name, s.rules.length]),
    [
      ['Alpha', 2],
      ['Gpl Source', 1]
    ]
  )
  const alpha = pkg.sections[0]
  assert.equal(alpha.repository, 'https://github.com/example/alpha/')
  assert.equal(alpha.commit, 'abc123')
  assert.equal(alpha.declaredCount, 2)
})

test('parsePackage keeps the license text without the comment prefix', () => {
  const { extended } = samplePackages()
  const beta = parsePackage(extended).sections[0]
  assert.equal(beta.license, LICENSES.MIT_TEXT)
})

test('parsePackage accepts CRLF line endings', () => {
  const { core } = samplePackages()
  const pkg = parsePackage(core.replace(/\n/g, '\r\n'))
  assert.equal(pkg.sections[0].rules.length, 2)
})

test('parsePackage rejects text without any rule set', () => {
  assert.throws(() => parsePackage('rule A { condition: true }'), /no rule sets/i)
})

test('splitRules returns each rule whole, private rules included', () => {
  const body = `${rule('A_Helper', { privateRule: true })}\n${rule('A_Main')}`
  const rules = splitRules(body)
  assert.deepEqual(
    rules.map((r) => r.name),
    ['A_Helper', 'A_Main']
  )
  assert.match(rules[0].text, /^private rule A_Helper : FILE\n\{/)
  assert.match(rules[0].text, /\}\n$/)
  assert.match(rules[1].text, /^rule A_Main/)
})

test('selectSources picks the allowed sections from the named package', () => {
  const pkgs = Object.fromEntries(
    Object.entries(samplePackages()).map(([k, v]) => [k, parsePackage(v)])
  )
  const selected = selectSources(pkgs, sampleAllowList)

  assert.deepEqual(
    selected.map((s) => [s.source.name, s.section.rules.map((r) => r.name)]),
    [
      ['Beta', ['BETA_One', 'BETA_Two', 'BETA_Three']],
      // core, so ALPHA_Extra from the extended package is not taken
      ['Alpha', ['ALPHA_One', 'ALPHA_Two']]
    ]
  )
  assert.deepEqual(selected[0].imports, ['pe', 'math'])
  assert.deepEqual(selected[1].imports, ['pe'])
})

function parsedWith(sections, name = 'core') {
  return { [name]: parsePackage(forgePackage({ name, sections })) }
}

const alphaOnly = {
  maxFileChars: 900000,
  sources: [sampleAllowList.sources[1]]
}

test('selectSources fails when an allowed source is missing', () => {
  const pkgs = parsedWith([
    section({
      name: 'Other',
      repo: 'https://github.com/example/other',
      license: LICENSES.MIT_TEXT,
      rules: [rule('O_One')]
    })
  ])
  assert.throws(() => selectSources(pkgs, alphaOnly), /Alpha.*not found/)
})

test('selectSources fails when the repository URL changed', () => {
  const pkgs = parsedWith([
    section({
      name: 'Alpha',
      repo: 'https://github.com/someone-else/alpha',
      license: LICENSES.BSD_TEXT,
      rules: [rule('A_One')]
    })
  ])
  assert.throws(() => selectSources(pkgs, alphaOnly), /repository/i)
})

test('selectSources fails when the license text no longer matches', () => {
  const pkgs = parsedWith([
    section({
      name: 'Alpha',
      repo: 'https://github.com/example/alpha',
      license: LICENSES.MIT_TEXT,
      rules: [rule('A_One')]
    })
  ])
  assert.throws(() => selectSources(pkgs, alphaOnly), /license/i)
})

test('selectSources fails when the license text names a copyleft license', () => {
  const pkgs = parsedWith([
    section({
      name: 'Alpha',
      repo: 'https://github.com/example/alpha',
      license: `${LICENSES.BSD_TEXT}\n\nParts are under the GNU General Public License.`,
      rules: [rule('A_One')]
    })
  ])
  assert.throws(() => selectSources(pkgs, alphaOnly), /license/i)
})

test('selectSources fails when the parsed rule count differs from the header', () => {
  const pkgs = parsedWith([
    section({
      name: 'Alpha',
      repo: 'https://github.com/example/alpha',
      license: LICENSES.BSD_TEXT,
      count: 3,
      rules: [rule('A_One'), rule('A_Two')]
    })
  ])
  assert.throws(() => selectSources(pkgs, alphaOnly), /2 rules.*3/)
})

test('selectSources fails on a rule name used by two sources', () => {
  const pkgs = {
    core: parsePackage(
      forgePackage({
        sections: [
          section({
            name: 'Alpha',
            repo: 'https://github.com/example/alpha',
            license: LICENSES.BSD_TEXT,
            rules: [rule('SAME_Name')]
          })
        ]
      })
    ),
    extended: parsePackage(
      forgePackage({
        name: 'extended',
        sections: [
          section({
            name: 'Beta',
            repo: 'https://github.com/example/beta',
            license: LICENSES.MIT_TEXT,
            rules: [rule('SAME_Name')]
          })
        ]
      })
    )
  }
  assert.throws(() => selectSources(pkgs, sampleAllowList), /SAME_Name/)
})
