# Third-Party Notices

Shannon incorporates and adapts material from third-party open-source projects.

Shannon as a whole is distributed under the GNU Affero General Public License,
version 3.0 (see LICENSE). Third-party material incorporated into Shannon
remains subject to the attribution and notice requirements of its own license.

## Noto CJK fonts

The report template bundles the unmodified Noto Sans CJK Regular and Bold font
collections (Sans version 2.004), including their Chinese monospace faces.

Project: https://github.com/notofonts/noto-cjk
Copyright: 2010-2012 Google Corporation
License: SIL Open Font License, Version 1.1

The applicable license is reproduced at `LICENSES/OFL-Noto-CJK.txt` and beside
the bundled font files in `apps/worker/templates/typst/assets/fonts/OFL.txt`.

## Pi

Shannon uses Pi as part of its agent framework.

Project: https://github.com/earendil-works/pi
License: MIT

Copyright (c) 2025 Mario Zechner

The applicable license is reproduced at `LICENSES/MIT-Pi.txt`.

## Mantis

Portions of Shannon's Capella agentic SAST implementation, specifically the
agent prompts, are derived from the Mantis project.

- Project:         https://github.com/google/mantis
- Upstream commit: 876a0c8c6b92c92f34e0041b7dbbc0e4cccddc52
- Retrieved:       2026-08-25
- License:         Apache License, Version 2.0

The Apache License, Version 2.0 is reproduced at LICENSES/Apache-2.0.txt.

The Mantis-derived files are individually marked with a provenance header and
reside under:

- apps/worker/prompts/partials/      (capella-*.hbs prompt partials)
- apps/worker/prompts/sast/capella/  (prompt templates)

The Mantis-derived material has been substantially modified by Keygraph
for use within Shannon, including adaptation to Shannon's agent
architecture and the Pi agent framework.

Copyright and attribution notices from the original Mantis material
remain the property of their respective copyright holders.

Modifications:
Copyright © 2026 Keygraph, Inc.

## Java security rule models

The `find_security_candidates` rule set
(`apps/worker/src/services/java-security/data/java-security-rules.json`) is
curated by this project and distributed under the same AGPL-3.0-or-later terms
as Shannon (each rule records `origin.repository: "shannon:curated"`).

The build-time importer
(`apps/worker/src/services/java-security/import/rules-importer.ts`,
`scripts/import-java-security-rules.mjs`) can convert upstream models from:

- CodeQL Java library models — https://github.com/github/codeql (MIT)
- Tai-e taint configuration — https://github.com/pascal-lab/Tai-e (Apache-2.0)
- Find Security Bugs — https://github.com/find-sec-bugs/find-sec-bugs (LGPL-3.0)

Imported rules are advisory until reviewed. Any imported rule that is committed
must have its upstream commit and license locked in the rule's `origin`, and
only redistributable rule text may be committed; unfamiliar or restricted
material must be represented by reference only. No upstream model text ships in
this repository by default.
