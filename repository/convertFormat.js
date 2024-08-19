const queries = require("./jsrepository-ast.js").queries;
const backdoored = require("./jsrepository-backdoored.json");

function largerThan(a, b, name) {
  if (a == b) return false;
  if (a && !b) return true;
  if (b && !a) return false;
  const aa = a.split(".").map((x) => parseInt(x));
  const bb = b.split(".").map((x) => parseInt(x));
  for (let i = 0; i < aa.length; i++) {
    if (aa[i] > bb[i]) return true;
    if (aa[i] < bb[i]) return false;
  }
  return false;
}

function convertToOldFormat(
  input,
  includeQueries = false,
  includeBackdoored = false,
  includeLicenses = false
) {
  const result = {};
  Object.entries(input).forEach(([key, value]) => {
    const { extractors, vulnerabilities, ...okeys } = value;
    const vulns = [];
    vulnerabilities.forEach((v) => {
      const { ranges, summary, identifiers, info, ...rest } = v;

      ranges.forEach((r) => {
        vulns.push({
          ...r,
          ...rest,
          identifiers: { summary, ...identifiers },
          info,
        });
      });
    });
    vulns.sort((a, b) => {
      if (largerThan(a.below, b.below, "below")) return 1;
      if (largerThan(b.below, a.below, "below")) return -1;
      if (largerThan(a.atOrAbove, b.atOrAbove, "atOrAbove")) return 1;
      if (largerThan(b.atOrAbove, a.atOrAbove, "atOrAbove")) return -1;
      if (a.identifiers.githubID > b.identifiers.githubID) return 1;
      if (a.identifiers.githubID < b.identifiers.githubID) return -1;
      if (a.identifiers.CVE && !b.identifiers.CVE) return 1;
      if (a.identifiers.CVE && a.identifiers.CVE[0] > b.identifiers.CVE[0])
        return 1;
      if (a.identifiers.CVE && a.identifiers.CVE[0] < b.identifiers.CVE[0])
        return -1;

      const aaa = JSON.stringify(a);
      const bbb = JSON.stringify(b);
      if (aaa == bbb) return 0;
      return aaa > bbb ? 1 : -1;
    });

    result[key] = {
      ...okeys,
      vulnerabilities: vulns,
      extractors,
    };
    if (!includeLicenses) {
      delete result[key].licenses;
    }
  });

  if (!includeQueries) return result;

  Object.entries(queries).forEach(([key, value]) => {
    if (!result[key]) throw new Error("Invalid package name:" + key);
    result[key].extractors.ast = value.map((x) => x.replace(/\n/g, " "));
  });
  if (!includeBackdoored) return result;
  return {
    advisories: result,
    backdoored,
  };
}

exports.convertToOldFormat = convertToOldFormat;
