#!/usr/bin/env node

// Profiles individual AST queries (repository/jsrepository-ast.js) against the
// largest real library files available, to find which queries contribute the
// most to deepScan's per-file runtime cost.
//
// deepScan (node/src/deepscan.ts) runs every library's AST queries together in
// one shared multiQuery() traversal per scanned file, so an expensive query for
// one library is paid on every file retire.js scans, not just files belonging to
// that library. This script isolates each query and times it individually to
// find the worst offenders.
//
// Usage:
//   node profile-ast-queries.js                # auto-pick the 3 largest cached libraries
//   node profile-ast-queries.js echarts video.js ember   # profile specific libraries
//   node profile-ast-queries.js --count 5 --top 10       # 5 libraries, top 10 queries

const fs = require("fs");
const path = require("path");
const https = require("https");
const testCases = require("./testcases.json");
const repoLib = require("../node/lib/repo.js");
const reporting = require("../node/lib/reporting.js");
const { multiQuery, parseSource } = require("../node/node_modules/astronomical");

const options = { log: reporting.open({}) };

const args = process.argv.slice(2);
let libCount = 3;
let topN = 5;
const explicitLibs = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--count") libCount = parseInt(args[++i], 10);
  else if (args[i] === "--top") topN = parseInt(args[++i], 10);
  else explicitLibs.push(args[i]);
}

if (!fs.existsSync("tmp")) fs.mkdirSync("tmp");

function tmpPathFor(uri) {
  return "tmp/" + uri.replace(/[^a-z0-9.]/gi, "_");
}

function download(uri) {
  return new Promise((resolve, reject) => {
    const p = tmpPathFor(uri);
    if (fs.existsSync(p)) return resolve(fs.readFileSync(p, "utf-8"));
    process.stdout.write(`  Downloading ${uri} ... `);
    https
      .get(uri, (res) => {
        if (res.statusCode != 200) {
          console.log(`failed (${res.statusCode})`);
          return reject(new Error(`status ${res.statusCode}`));
        }
        const chunks = [];
        res.on("data", (d) => chunks.push(d));
        res.on("end", () => {
          const data = Buffer.concat(chunks);
          fs.writeFileSync(p, data);
          console.log("done");
          resolve(data.toString("utf-8"));
        });
      })
      .on("error", reject);
  });
}

// Every concrete (library, uri, size-on-disk-if-cached) combination described
// by testcases.json, so we can rank libraries by the size of their largest file
// without guessing filenames.
function enumerateTestFiles() {
  const files = []; // { library, uri, cachedSize }
  for (const [library, templates] of Object.entries(testCases)) {
    for (const [template, tcontent] of Object.entries(templates)) {
      const versions = (tcontent.versions || []).concat(tcontent.additionalVersions || []);
      const subversions = tcontent.subversions || [""];
      for (const version of versions) {
        for (const sub of subversions) {
          const uri = template.replace(/§§version§§/g, version).replace(/§§subversion§§/g, sub);
          const p = tmpPathFor(uri);
          const cachedSize = fs.existsSync(p) ? fs.statSync(p).size : -1;
          files.push({ library, uri, cachedSize });
        }
      }
    }
  }
  return files;
}

async function pickLibraryFiles() {
  const allFiles = enumerateTestFiles();

  if (explicitLibs.length) {
    const picks = [];
    for (const library of explicitLibs) {
      const candidates = allFiles.filter((f) => f.library === library);
      if (!candidates.length) {
        console.warn(`No testcases entry for "${library}", skipping`);
        continue;
      }
      // Prefer the largest already-cached file; fall back to the first known
      // uri (and download it) if nothing for this library is cached yet.
      candidates.sort((a, b) => b.cachedSize - a.cachedSize);
      picks.push(candidates[0]);
    }
    return picks;
  }

  // Auto-pick: rank libraries by the size of their largest *cached* file, since
  // downloading every candidate just to measure size would be slow. This is
  // "largest known so far" rather than "largest ever possible", which is fine
  // for a profiling tool — run the full test suite first to warm the cache.
  const byLibrary = new Map();
  for (const f of allFiles) {
    if (f.cachedSize < 0) continue;
    const cur = byLibrary.get(f.library);
    if (!cur || f.cachedSize > cur.cachedSize) byLibrary.set(f.library, f);
  }
  const ranked = [...byLibrary.values()].sort((a, b) => b.cachedSize - a.cachedSize);
  if (ranked.length < libCount) {
    console.warn(
      `Only ${ranked.length} libraries have cached files (run test-detection.js first to warm the cache). Using what's available.`
    );
  }
  return ranked.slice(0, libCount);
}

function median(arr) {
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

// Times each query in isolation against a file, re-parsing fresh for every
// call. Reusing one parsed AST object across repeated multiQuery() calls was
// found to corrupt scope-binding resolution ($:object / $:name) on later
// calls, silently invalidating results from the 2nd call onward — always
// re-parse per measurement.
function profileFile(code, astQueries, iterations) {
  const keys = Object.keys(astQueries);
  const costs = {};
  keys.forEach((k) => (costs[k] = []));

  // warmup (JIT + file system caches), still with fresh parses
  for (let i = 0; i < 3; i++) {
    const ast = parseSource(code);
    multiQuery(ast, astQueries);
  }

  for (let iter = 0; iter < iterations; iter++) {
    const order = [...keys].sort(() => Math.random() - 0.5);
    for (const key of order) {
      const ast = parseSource(code);
      const t0 = process.hrtime.bigint();
      multiQuery(ast, { [key]: astQueries[key] });
      const t1 = process.hrtime.bigint();
      costs[key].push(Number(t1 - t0) / 1e6);
    }
  }

  const result = {};
  keys.forEach((k) => (result[k] = median(costs[k])));
  return result;
}

async function main() {
  console.log("Loading repository (jsrepository-v5.json) ...");
  const jsRepo = await repoLib.loadrepositoryFromFile("./jsrepository-v5.json", options);

  const astQueries = {};
  const backMap = {};
  Object.entries(jsRepo).forEach(([name, data]) => {
    (data.extractors.ast || []).forEach((q, i) => {
      astQueries[`${name}_${i}`] = q;
      backMap[`${name}_${i}`] = name;
    });
  });
  console.log(`Loaded ${Object.keys(astQueries).length} AST queries across ${new Set(Object.values(backMap)).size} libraries.\n`);

  const picks = await pickLibraryFiles();
  if (!picks.length) {
    console.error("No candidate library files found. Run test-detection.js first to populate tmp/.");
    process.exit(1);
  }

  console.log("Profiling against:");
  picks.forEach((p) => console.log(`  - ${p.library}: ${p.uri}`));
  console.log();

  const iterations = 8;
  const aggregate = {}; // key -> total ms across all profiled files
  const perFile = {}; // library -> { key -> ms }

  for (const pick of picks) {
    let code;
    try {
      code = await download(pick.uri);
    } catch (e) {
      console.warn(`  Could not obtain ${pick.uri}: ${e.message}, skipping`);
      continue;
    }
    console.log(`Profiling ${pick.library} (${(code.length / 1024).toFixed(0)} KB) ...`);
    const costs = profileFile(code, astQueries, iterations);
    perFile[pick.library] = costs;
    Object.entries(costs).forEach(([key, ms]) => {
      aggregate[key] = (aggregate[key] || 0) + ms;
    });
  }

  const ranked = Object.entries(aggregate).sort((a, b) => b[1] - a[1]);

  console.log(`\n=== Top ${topN} most expensive queries (summed across ${Object.keys(perFile).length} profiled files) ===\n`);
  console.log(
    "Rank  Library".padEnd(24) + "Query idx".padEnd(11) + "Total ms".padStart(10) + "  Per-file breakdown"
  );
  ranked.slice(0, topN).forEach(([key, total], i) => {
    const component = backMap[key];
    const idx = key.slice(component.length + 1);
    const breakdown = Object.keys(perFile)
      .map((lib) => `${lib}=${(perFile[lib][key] || 0).toFixed(2)}ms`)
      .join(", ");
    console.log(
      `${String(i + 1).padEnd(6)}${component.padEnd(18)}${idx.padEnd(11)}${total.toFixed(2).padStart(8)}ms  ${breakdown}`
    );
  });

  const grandTotal = ranked.reduce((s, [, v]) => s + v, 0);
  const topTotal = ranked.slice(0, topN).reduce((s, [, v]) => s + v, 0);
  console.log(
    `\nTop ${topN} account for ${topTotal.toFixed(2)}ms of ${grandTotal.toFixed(2)}ms total isolated query cost (${((100 * topTotal) / grandTotal).toFixed(1)}%).`
  );
}

main().catch((err) => {
  console.error("Failed:", err);
  process.exit(1);
});
