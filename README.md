# BoadAIcleaner YARA rules

Weekly YARA rule bundle for BoadAIcleaner. Each release takes the newest [YARA Forge](https://github.com/YARAHQ/yara-forge) release and keeps only rule sets under the MIT, BSD or Apache-2.0 license.

## Release assets

| File | Contents |
| --- | --- |
| `rules-bundle.json` | `{ version, updatedAt, sha256, rules: [{ filename, content }] }`, the format the app validates. `sha256` is taken over the rule contents joined in filename order. |
| `manifest.json` | Version, the same `sha256`, the byte size and SHA-256 of `rules-bundle.json`, and the rule count per source. The app reads this first and skips the download when nothing changed. |
| `THIRD-PARTY-LICENSES.md` | Every source with its repository, commit and full license text. |

The newest assets are always at `https://github.com/<owner>/<repo>/releases/latest/download/<file>`.

## Sources

`sources.json` is the allow-list. Rules come from the YARA Forge `core` package, except ReversingLabs, which YARA Forge only ships in `extended`.

| Source | License | Package |
| --- | --- | --- |
| [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules) | MIT | extended |
| [DitekSHen](https://github.com/ditekshen/detection) | BSD-2-Clause | core |
| [FireEye-RT](https://github.com/mandiant/red_team_tool_countermeasures) | BSD-2-Clause | core |
| [Volexity](https://github.com/volexity/threat-intel) | BSD-2-Clause | core |
| [GCTI](https://github.com/chronicle/GCTI) | Apache-2.0 | core |
| [ESET](https://github.com/eset/malware-ioc) | BSD-2-Clause | core |
| [Trellix ARC](https://github.com/advanced-threat-research/Yara-Rules) | Apache-2.0 | core |
| [WithSecureLabs](https://github.com/WithSecureLabs/iocs) | BSD-2-Clause | core |
| [Elceef](https://github.com/elceef/yara-rulz) | MIT | core |

The build stops instead of publishing when an allowed source is missing, its repository URL changed, its license text no longer matches the expected license (or mentions GPL, DRL, Creative Commons or the Elastic License), its rule count differs from the YARA Forge header, two sources share a rule name, or any rule file fails to compile with YARA-X.

## How a release is built

`.github/workflows/weekly-release.yml` runs every Monday at 03:00 UTC and on demand:

1. Download the newest YARA Forge release (`core` and `extended` zips).
2. `node scripts/build.mjs` keeps the allowed rule sets, writes one `.yar` file per source (split at rule boundaries below 900,000 characters, since the app accepts at most 1 MB per file), and compiles every file alone and all files together with `@litko/yara-x`, the engine the app uses.
3. Publish a release tagged `<forge tag>-<first 8 hex of sha256>` only if `sha256` differs from the latest release.

Build locally:

```sh
npm ci
npm test
node scripts/build.mjs --core yara-rules-core.yar --extended yara-rules-extended.yar --forge-tag 20261108 --out dist
```

## Licenses

The rules keep their own licenses, listed in `THIRD-PARTY-LICENSES.md` in every release. This is not legal advice; the license checks only compare the license text that YARA Forge records for each rule set.
