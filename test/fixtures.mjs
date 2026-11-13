// Small YARA Forge-shaped packages for the tests. The layout mirrors a real
// release: a package header, the import lines, then one comment block per
// source repository ("YARA Rule Set") followed by that repository's rules.

const MIT_TEXT = `Copyright (c) 2020 Example Corp

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software, to deal in the Software without restriction.`

const BSD_TEXT = `BSD 2-Clause License

Copyright (c) 2023, Example

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:`

const GPL_TEXT = `This program is free software: you can redistribute it under the terms of the
GNU General Public License as published by the Free Software Foundation.`

export function section({ name, repo, commit = 'abc123', count, license, rules }) {
  const [firstLicenseLine, ...restLicense] = license.split('\n')
  return [
    '/*',
    ' * YARA Rule Set',
    ` * Repository Name: ${name}`,
    ` * Repository: ${repo}`,
    ' * Retrieval Date: 2026-11-08',
    ` * Git Commit: ${commit}`,
    ` * Number of Rules: ${count ?? rules.length}`,
    ' * Skipped: 0 (age), 0 (quality), 0 (score), 0 (importance)',
    ' *',
    ' * ',
    ' * LICENSE',
    ' * ',
    ` * ${firstLicenseLine}`,
    ...restLicense,
    ' */',
    ...rules,
    ''
  ].join('\n')
}

export function rule(name, { privateRule = false, body = '"x"' } = {}) {
  return `${privateRule ? 'private ' : ''}rule ${name} : FILE
{
\tmeta:
\t\tdescription = "Detects ${name}"
\t\tscore = 75

\tstrings:
\t\t$a = ${body}

\tcondition:
\t\t$a
}
`
}

export function forgePackage({ name = 'core', imports = ['pe'], sections }) {
  return [
    '/*',
    ' * YARA-Forge YARA Rule Package',
    ' * https://github.com/YARAHQ/yara-forge',
    ' * ',
    ' * Rule Package Information',
    ` * Name: ${name} `,
    ` * Description: Default YARA Rule Package - ${name}`,
    ' * YARA-Forge Version: 0.9.1',
    ' * Creation Date: 2026-11-08',
    ' * Number of Rules: 3',
    ' */',
    '',
    ...imports.map((m) => `import "${m}"`),
    '',
    '',
    ...sections
  ].join('\n')
}

export const LICENSES = { MIT_TEXT, BSD_TEXT, GPL_TEXT }

/** A core + extended pair with two allowed sources and one GPL source. */
export function samplePackages() {
  const core = forgePackage({
    name: 'core',
    sections: [
      section({
        name: 'Alpha',
        repo: 'https://github.com/example/alpha/',
        license: BSD_TEXT,
        rules: [rule('ALPHA_One'), rule('ALPHA_Two')]
      }),
      section({
        name: 'Gpl Source',
        repo: 'https://github.com/example/gpl',
        license: GPL_TEXT,
        rules: [rule('GPL_One')]
      })
    ]
  })
  const extended = forgePackage({
    name: 'extended',
    imports: ['pe', 'math'],
    sections: [
      section({
        name: 'Beta',
        repo: 'https://github.com/example/beta',
        commit: 'def456',
        license: MIT_TEXT,
        rules: [rule('BETA_One'), rule('BETA_Two'), rule('BETA_Three')]
      }),
      section({
        name: 'Alpha',
        repo: 'https://github.com/example/alpha/',
        license: BSD_TEXT,
        rules: [rule('ALPHA_One'), rule('ALPHA_Two'), rule('ALPHA_Extra')]
      })
    ]
  })
  return { core, extended }
}

export const sampleAllowList = {
  maxFileChars: 900000,
  sources: [
    {
      name: 'Beta',
      package: 'extended',
      license: 'MIT',
      repository: 'https://github.com/example/beta',
      file: 'beta'
    },
    {
      name: 'Alpha',
      package: 'core',
      license: 'BSD-2-Clause',
      repository: 'https://github.com/example/alpha',
      file: 'alpha'
    }
  ]
}
