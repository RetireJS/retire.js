---
name: retire-add-ast-query
description: Add an AST query for a JavaScript library to the retire.js vulnerability database. Given a library name, downloads multiple versions, analyzes the code structure where the version string is assigned, writes an ASTronomical XPath-like query anchored with library-specific identifiers, tests the query locally, adds it to jsrepository-ast.js, and runs validate/test-detection. Use this skill whenever adding an AST-based version detection query to retire.js.
---

# retire-add-ast-query

This skill adds an ASTronomical query for a JavaScript library to the retire.js AST detection system. It downloads real files from CDNs, reads the code structure around version assignments, builds a query anchored to library-specific identifiers, tests it locally with `astronomical`, and validates with `test-detection.js`.

The repo is at `/Users/erlend/code/github/RetireJS/retire.js`. All file edits and validation commands run there.

## Overview

AST queries detect the library version by traversing the JavaScript AST rather than matching raw text. Queries must be anchored to library-specific identifiers on sibling or parent nodes — otherwise they'll fire on unrelated files that happen to have a `version` assignment. The query returns the version string directly (no `§§version§§` placeholder needed — the Literal node's value is the result).

All queries live in `repository/jsrepository-ast.js` (a CommonJS module). After editing it, run `./convertToVersioned` to propagate to the versioned JSON files used at runtime.

## Step 1 — CDN Lookup

Fetch library metadata from cdnjs:

```
https://api.cdnjs.com/libraries/{NAME}?fields=name,versions,filename,description
```

or jsdelivr if not on cdnjs:

```
https://data.jsdelivr.com/v1/packages/npm/{NAME}
```

Note the `filename` field (minified name) and derive the non-minified name (strip `.min`). Record the full list of versions.

## Step 2 — Select Versions

Pick 4–5 versions spread across history: 1 early (not the very first), 2–3 middle, and the latest.

## Step 3 — Download Files

```bash
mkdir -p /tmp/retire-ast-{NAME}
# For each VERSION:
curl -sL "https://cdnjs.cloudflare.com/ajax/libs/{NAME}/{VERSION}/{MIN_FILENAME}" \
  -o /tmp/retire-ast-{NAME}/{VERSION}.min.js
curl -sL "https://cdnjs.cloudflare.com/ajax/libs/{NAME}/{VERSION}/{UNMIN_FILENAME}" \
  -o /tmp/retire-ast-{NAME}/{VERSION}.js
```

Verify each downloaded successfully (non-zero, not an HTML 404 page):
```bash
ls -la /tmp/retire-ast-{NAME}/
head -3 /tmp/retire-ast-{NAME}/{VERSION}.js
```

If cdnjs returns 404, fall back to jsDelivr:
```bash
curl -sL "https://cdn.jsdelivr.net/npm/{NAME}@{VERSION}/dist/{FILENAME}" \
  -o /tmp/retire-ast-{NAME}/{VERSION}.js
```

## Step 4 — Find Version Strings

Grep each downloaded file for the exact version number:
```bash
grep -n "1\.2\.3" /tmp/retire-ast-{NAME}/{VERSION}.js
grep -n "1\.2\.3" /tmp/retire-ast-{NAME}/{VERSION}.min.js
```

For single-line minified files where grep context flags fail, use Python:
```bash
python3 -c "
import re
with open('/tmp/retire-ast-{NAME}/{VERSION}.min.js', 'r', errors='replace') as f:
    content = f.read()
for m in re.findall(r'.{0,100}1\.2\.3.{0,100}', content)[:5]:
    print(m)
"
```

## Step 5 — Understand the Code Pattern

Read 10–20 lines around each version occurrence in non-minified files:
```bash
grep -n "1\.2\.3" /tmp/retire-ast-{NAME}/{VERSION}.js
# Then:
sed -n '${LINE_MINUS_10},${LINE_PLUS_10}p' /tmp/retire-ast-{NAME}/{VERSION}.js
```

Identify two things:
1. **What node holds the version**: e.g. `x.VERSION = "1.2.3"` (AssignmentExpression → right → Literal), `{version: "1.2.3"}` (ObjectExpression → Property → value → Literal), `var version = "1.2.3"` (VariableDeclarator → init → Literal)
2. **Library-specific anchors nearby**: an identifier that uniquely identifies this library. The anchor must appear in the same block/expression as the version assignment — or inside a method body of the same object.

**Anchor quality, best to worst:**
- **Gold**: an identifier that contains the library name — e.g. `tinyMCEPreInit`, `isMoment`, `HandlebarsEnvironment`, `__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED`. These cannot match any other library by definition.
- **Good**: a highly domain-specific sibling property or method that wouldn't appear together with a version string in any other library — e.g. `migrateVersion`, `focusedEditor` combined with `majorVersion`.
- **Weak**: generic property names like `releaseDate`, `activeEditor`, `major`, `init`, `build`. These could plausibly appear in other libraries and should only be used in combination with other anchors, never alone.

**Look inside method bodies too.** If the version is in an object literal, scan the body of methods on that same object for library-name identifiers — e.g. `setup() { ... window.tinyMCEPreInit ... }` inside the same ObjectExpression. A `//MemberExpression` or `//Identifier` traversal into a method body provides a much stronger anchor than any generic sibling property name.

Ask yourself: *would this query fire on a file from an unrelated library that happens to assign a version string?* If you're not confident the answer is no, strengthen the anchor.

## Step 6 — Write a Candidate Query

Use ASTronomical syntax to navigate from the root to the version Literal, filtering with library-specific anchors.

### ASTronomical syntax quick reference

| Syntax | Meaning |
|--------|---------|
| `//NodeType` | Descendant at any depth |
| `/NodeType` | Direct child |
| `/:attr` | Named attribute of current node |
| `/$:name` | Resolve identifier binding (follow variable reference) |
| `/$$:name` | Binding or attribute fallback (when value may be variable or literal) |
| `[cond]` | Filter; use `&&`, `\|\|`, `==` |
| `../ ` | Go to parent (use sparingly — causes extra traversal) |
| `/fn:concat(sel1, ".", sel2)` | Concatenate results (for `major.minor.patch`) |

### Common patterns

**Named property assignment in a block with a sibling anchor:**
```
//BlockStatement[
  /ExpressionStatement/AssignmentExpression[/:left/:property/:name == "ANCHOR_PROP"]
]/ExpressionStatement/AssignmentExpression[
  /:left/:property/:name == "version"
]/$$:right/:value
```

**Named object property with a co-occurring sibling property:**
```
//ObjectExpression[
  /Property/:key/:name == "ANCHOR_PROP"
]/Property[/:key/:name == "version"]/:value/:value
```

**Assignment where the object is named directly:**
```
//AssignmentExpression[
  /:left/:object/:name == "LibName" &&
  /:left/:property/:name == "VERSION"
]/:right/:value
```

**Two properties sharing the same object binding (stronger anchor):**
```
//SequenceExpression[
  /AssignmentExpression[/:left/:property/:name == "ANCHOR_PROP"]/:left/$:object ==
  /AssignmentExpression[/:left/:property/:name == "version"]/:left/$:object
]/AssignmentExpression[/:left/:property/:name == "version"]/$$:right/:value
```

**Object with library-name identifier inside a method body (gold anchor):**
```
//ObjectExpression[
  /Property[/:key/:name == "majorVersion"] &&
  /Property[/:key/:name == "setup"]//MemberExpression[/:property/:name == "libraryNamePreInit"]
]/fn:concat(
  /Property[/:key/:name == "majorVersion"]/:value/:value,
  ".",
  /Property[/:key/:name == "minorVersion"]/:value/:value
)
```

Start simple, add anchors until the query is specific enough. Multiple queries in the array are OR'd — add a second entry for a different version era if the code structure changed across major versions.

**If two candidate queries end up nearly identical, stop and suspect an ASTronomical bug instead of writing both.** "Nearly identical" means the same filters/anchors, differing only in the terminal extraction step — e.g. one query ends in `/:value` and works against a plain string `Literal` (`x.version = "1.2.3"`), but a real-world build needs a second, otherwise-identical query ending in `/TemplateElement/:value/:cooked` because that build emits the version as a non-interpolated template literal instead (`` x.version = `1.2.3` ``). A `Literal` and a template literal with no `${}` are semantically the same string — the query *engine* should resolve either transparently, not every library's query author. Duplicating the query per literal-style is a local workaround that only fixes the one library, and this exact shape of gap tends to recur (react, react-dom, moment.js, and ua-parser-js all independently hit it in the same session because one bundler happened to prefer backtick strings).

When you notice this, don't add the duplicate to `jsrepository-ast.js`. Instead:
1. Report the pattern to the user and propose fixing it in ASTronomical itself, at `/Users/erlend/code/github/RetireJS/ASTronomical` (a sibling checkout — confirm it exists before assuming the path).
2. The fix belongs in `src/index.ts`'s attribute-resolution helpers (`getPrimitiveChildren` / `getPrimitiveChildrenOrNodePaths`) — add a fallback so a requested attribute (e.g. `value`) transparently resolves through the alternate AST shape, instead of requiring the query to spell out both shapes.
3. Validate with the engine's own suite (`npm run typecheck && npm test` in the ASTronomical repo) before touching retire.js again, and confirm the *original* (single, non-duplicated) query now matches both shapes.
4. Bumping ASTronomical's version, updating its `CHANGELOG.md`, publishing to npm, and bumping the dependency in `node/package.json` are all separate, more consequential steps (a published package affects every consumer, not just this repo) — check with the user before doing any of them rather than assuming the fix should ship immediately.

## Step 7 — Test the Query Locally

Create a test script:
```javascript
// /tmp/test-ast-query.js
const { multiQuery } = require('/Users/erlend/code/github/RetireJS/retire.js/node/node_modules/astronomical');
const fs = require('fs');
const code = fs.readFileSync(process.argv[2], 'utf8');
const query = `YOUR QUERY HERE`;
const results = multiQuery(code, { version: query });
console.log(JSON.stringify(results.version, null, 2));
```

Run against each downloaded version:
```bash
node /tmp/test-ast-query.js /tmp/retire-ast-{NAME}/{VERSION}.js
node /tmp/test-ast-query.js /tmp/retire-ast-{NAME}/{VERSION}.min.js
```

Expected output: a JSON array containing exactly the version string, e.g. `["1.2.3"]`. If the output is `[]`, the query didn't match — revise it. If it returns multiple values, the anchor is too loose.

Iterate across all tested versions until each returns the correct version string. If an early version has a structurally different pattern, write a second query string.

## Step 8 — Add to jsrepository-ast.js

Edit `repository/jsrepository-ast.js`. Add the library key to `exports.queries` (in alphabetical order is nice but not required):

```javascript
"library-name": [
  /*
  Code pattern this query matches, e.g.:
    LibName.isMoment = function; LibName.version = "1.2.3"
  */
  `//SequenceExpression[
    /AssignmentExpression[/:left/:property/:name == "isMoment"]/:left/$:object ==
    /AssignmentExpression[/:left/:property/:name == "version"]/:left/$:object
  ]/AssignmentExpression[/:left/:property/:name == "version"]/$$:right/:value`,
],
```

If the library already has an entry (added by someone else), append to its array rather than replacing it.

## Step 9 — Update testcases.json if needed

If the library is already in `repository/testcases.json`, check if any of the tested versions have a different code structure that the query can't reach. Add `allowAstMiss` for those versions:

```json
"library-name": {
  "https://cdnjs.cloudflare.com/.../§§version§§/...§§subversion§§.js": {
    "versions": ["1.0.0", "2.0.0", "3.0.0"],
    "subversions": ["", ".min"],
    "allowAstMiss": ["1.0.0"]
  }
}
```

If the library is **not yet** in `testcases.json`, add a minimal entry covering the 3–5 tested versions. Without a `testcases.json` entry, `test-detection.js` won't exercise the AST query.

## Step 10 — Validate and Test

```bash
cd /Users/erlend/code/github/RetireJS/retire.js/repository
./convertToVersioned && ./validate
node test-detection.js {LIBRARY_NAME}
node test-detection.js          # full suite — catch any false positives introduced
```

**Fixing failures:**
- `validate` error: check `jsrepository-ast.js` syntax — it's a JS module, not JSON; look for unclosed template literals or missing commas
- `Did not detect ... using ast`: query doesn't match that version — refine the query (back to Step 7) or add `allowAstMiss` for that version. If the fix you're reaching for is "add a near-duplicate query that only changes how the final value is extracted," stop — see the callout in Step 6 about suspecting an ASTronomical engine gap instead.
- `Detect multiple components using ast`: query is too broad — strengthen the anchor (back to Step 6)

## Step 11 — Report Results

Show:
- The final query string(s) added to `jsrepository-ast.js`
- Which versions were successfully detected via AST
- The timing output from `test-detection.js` (C: content ms, B: AST ms per version)
