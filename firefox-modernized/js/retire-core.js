(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.retirechrome = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
const deepScan = require("../../node/lib/deepscan.js").deepScan;
const retire = require("../../node/lib/retire.js");
exports.repo = require("../../repository/jsrepository-v3.json");
exports.retire = retire;
exports.deepScan = deepScan;

},{"../../node/lib/deepscan.js":2,"../../node/lib/retire.js":3,"../../repository/jsrepository-v3.json":9}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deepScan = deepScan;
const astronomical_1 = require("astronomical");
const retire_1 = require("./retire");
function deepScan(content, repo) {
    const astQueries = {};
    const backMap = {};
    Object.entries(repo).forEach(([name, data]) => {
        data.extractors.ast?.forEach((query, i) => {
            astQueries[`${name}_${i}`] = query;
            backMap[`${name}_${i}`] = name;
        });
    });
    const results = (0, astronomical_1.multiQuery)(content, astQueries);
    const detected = [];
    Object.entries(results).forEach(([key, value]) => {
        value.forEach((match) => {
            const component = backMap[key];
            if (typeof match !== 'string')
                return;
            detected.push({
                version: match,
                component: component,
                npmname: repo[component].npmname,
                basePurl: repo[component].basePurl,
                detection: 'ast',
            });
        });
    });
    return detected.reduce((acc, cur) => {
        if (acc.some((c) => c.component === cur.component && c.version === cur.version))
            return acc;
        return acc.concat((0, retire_1.check)(cur.component, cur.version, repo));
    }, []);
}

},{"./retire":3,"astronomical":4}],3:[function(require,module,exports){
/*
 * This file is used by the browser plugins and the Cli scanner and thus
 * cannot have any external dependencies (no require)
 */

var exports = exports || {};
exports.version = '5.2.8';

function isDefined(o) {
  return typeof o !== 'undefined';
}

function uniq(results) {
  var keys = {};
  return results.filter(function (r) {
    var k = r.component + ' ' + r.version;
    keys[k] = keys[k] || 0;
    return keys[k]++ === 0;
  });
}

function scan(data, extractor, repo, matcher = simpleMatch) {
  var detected = [];
  for (var component in repo) {
    var extractors = repo[component].extractors[extractor];
    if (!isDefined(extractors)) continue;
    for (var i in extractors) {
      var matches = matcher(extractors[i], data);
      matches.forEach((match) => {
        match = match.replace(/(\.|-)min$/, '');
        detected.push({
          version: match,
          component: component,
          npmname: repo[component].npmname,
          basePurl: repo[component].basePurl,
          detection: extractor,
        });
      });
    }
  }
  return uniq(detected);
}

function simpleMatch(regex, data) {
  var re = new RegExp(regex, 'g');
  const result = [];
  let match;
  while ((match = re.exec(data))) {
    result.push(match[1]);
  }
  return result;
}
function replacementMatch(regex, data) {
  var ar = /^\/(.*[^\\])\/([^\/]+)\/$/.exec(regex);
  var re = new RegExp(ar[1], 'g');
  const result = [];
  let match;
  while ((match = re.exec(data))) {
    var ver = null;
    if (match) {
      ver = match[0].replace(new RegExp(ar[1]), ar[2]);
      result.push(ver);
    }
  }
  return result;
}

function splitAndMatchAll(tokenizer) {
  return function (regex, data) {
    var elm = data.split(tokenizer).pop();
    return simpleMatch('^' + regex + '$', elm);
  };
}

function scanhash(hash, repo) {
  for (var component in repo) {
    var hashes = repo[component].extractors.hashes;
    if (!isDefined(hashes)) continue;
    if (hashes.hasOwnProperty(hash)) {
      return [
        {
          version: hashes[hash],
          component: component,
          npmname: repo[component].npmname,
          basePurl: repo[component].basePurl,
          detection: 'hash',
        },
      ];
    }
  }
  return [];
}

function check(results, repo) {
  for (var r in results) {
    var result = results[r];
    if (!isDefined(repo[result.component])) continue;
    var vulns = repo[result.component].vulnerabilities;
    result.basePurl = repo[result.component].basePurl;
    result.npmname = repo[result.component].npmname;
    for (var i in vulns) {
      if (!isDefined(vulns[i].below) || !isAtOrAbove(result.version, vulns[i].below)) {
        if (isDefined(vulns[i].atOrAbove) && !isAtOrAbove(result.version, vulns[i].atOrAbove)) {
          continue;
        }
        var vulnerability = { info: vulns[i].info, below: vulns[i].below, atOrAbove: vulns[i].atOrAbove };
        if (vulns[i].severity) {
          vulnerability.severity = vulns[i].severity;
        }
        if (vulns[i].identifiers) {
          vulnerability.identifiers = vulns[i].identifiers;
        }
        if (vulns[i].cwe) {
          vulnerability.cwe = vulns[i].cwe;
        }
        result.vulnerabilities = result.vulnerabilities || [];
        result.vulnerabilities.push(vulnerability);
      }
    }
  }
  return results;
}

function isAtOrAbove(version1, version2) {
  var v1 = version1.split(/[\.\-]/g);
  var v2 = version2.split(/[\.\-]/g);
  var l = v1.length > v2.length ? v1.length : v2.length;
  for (var i = 0; i < l; i++) {
    var v1_c = toComparable(v1[i]);
    var v2_c = toComparable(v2[i]);
    if (typeof v1_c !== typeof v2_c) return typeof v1_c === 'number';
    if (v1_c > v2_c) return true;
    if (v1_c < v2_c) return false;
  }
  return true;
}

function toComparable(n) {
  if (!isDefined(n)) return 0;
  if (n.match(/^[0-9]+$/)) {
    return parseInt(n, 10);
  }
  return n;
}

//------- External API -------

exports.check = function (component, version, repo) {
  return check([{ component: component, version: version }], repo);
};

exports.replaceVersion = function (jsRepoJsonAsText) {
  return jsRepoJsonAsText.replace(/§§version§§/g, '[0-9][0-9.a-z_\\\\-]+');
};

exports.isVulnerable = function (results) {
  for (var r in results) {
    if (
      results[r].hasOwnProperty('vulnerabilities') &&
      results[r].vulnerabilities != undefined &&
      results[r].vulnerabilities.length > 0
    )
      return true;
  }
  return false;
};

exports.scanUri = function (uri, repo) {
  var result = scan(uri, 'uri', repo);
  return check(result, repo);
};

exports.scanFileName = function (fileName, repo, includeUri = false) {
  var result = scan(fileName, 'filename', repo, splitAndMatchAll(/[\/\\]/));
  if (includeUri) {
    result = result.concat(scan(fileName.replace(/\\/g, '/'), 'uri', repo));
  }
  return check(result, repo);
};

exports.scanFileContent = function (content, repo, hasher) {
  var normalizedContent = content.toString().replace(/(\r\n|\r)/g, '\n');
  var result = scan(normalizedContent, 'filecontent', repo);
  if (result.length === 0) {
    result = scan(normalizedContent, 'filecontentreplace', repo, replacementMatch);
  }
  if (result.length === 0) {
    result = scanhash(hasher.sha1(normalizedContent), repo);
  }
  return check(result, repo);
};

exports.isAtOrAbove = isAtOrAbove;

},{}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.functions = void 0;
exports.isAvailableFunction = isAvailableFunction;
exports.query = query;
exports.multiQuery = multiQuery;
exports.parseSource = parseSource;
exports.default = createTraverser;
const parseQuery_1 = require("./parseQuery");
const meriyah_1 = require("meriyah");
const nodeutils_1 = require("./nodeutils");
const utils_1 = require("./utils");
const debugLogEnabled = false;
const log = debugLogEnabled ? {
    debug: (...args) => {
        console.debug(...args);
    }
} : undefined;
exports.functions = {
    "join": {
        fn: (result) => {
            if (result.length != 2)
                throw new Error("Invalid number of arugments for join");
            const [values, separators] = result;
            if (separators.length != 1)
                throw new Error("Invalid number of separators for join");
            const separator = separators[0];
            if (typeof separator != "string")
                throw new Error("Separator must be a string");
            if (values.length == 0)
                return [];
            return [values.join(separator)];
        }
    },
    "concat": {
        fn: (result) => {
            if (result.some(x => x.length == 0))
                return [];
            return [result.flat().join("")];
        }
    },
    "first": {
        fn: (result) => {
            if (result.length != 1)
                throw new Error("Invalid number of arugments for first");
            if (result[0].length == 0)
                return [];
            return [result.map(r => r[0])[0]];
        }
    },
    "nthchild": {
        fn: (result) => {
            if (result.length != 2)
                throw new Error("Invalid number of arguments for nthchild");
            if (result[1].length != 1)
                throw new Error("Invalid number of arguments for nthchild");
            const x = result[1][0];
            const number = typeof x == "number" ? x : parseInt(x);
            return [result[0][number]];
        }
    }
};
const functionNames = new Set(Object.keys(exports.functions));
function isAvailableFunction(name) {
    return functionNames.has(name);
}
function breadCrumb(path) {
    if (!debugLogEnabled)
        return "";
    return {
        valueOf() {
            if (path.parentPath == undefined)
                return "@" + path.node.type;
            return breadCrumb(path.parentPath) + "." + (path.parentKey == path.key ? path.key : path.parentKey + "[" + path.key + "]") + "@" + path.node.type;
        }
    };
}
function createQuerier() {
    const traverser = createTraverser();
    const { getChildren, getPrimitiveChildren, getPrimitiveChildrenOrNodePaths, getBinding, createNodePath, traverse } = traverser;
    function createFilter(filter, filterResult) {
        if (filter.type == "and" || filter.type == "or" || filter.type == "equals") {
            return {
                type: filter.type,
                left: createFilter(filter.left, []),
                right: createFilter(filter.right, [])
            };
        }
        else if (filter.type == "literal") {
            const r = [filter.value];
            return {
                node: filter,
                result: r
            };
        }
        return createFNode(filter, filterResult);
    }
    function createFNode(token, result) {
        return {
            node: token,
            result: result
        };
    }
    function addFilterChildrenToState(filter, state) {
        if ("type" in filter && (filter.type == "and" || filter.type == "or" || filter.type == "equals")) {
            addFilterChildrenToState(filter.left, state);
            addFilterChildrenToState(filter.right, state);
        }
        else if ("node" in filter) {
            if (filter.node.type == "child") {
                log?.debug("ADDING FILTER CHILD", filter.node);
                state.child[state.depth + 1].push(filter);
            }
            if (filter.node.type == "descendant") {
                log?.debug("ADDING FILTER DESCENDANT", filter.node);
                state.descendant[state.depth + 1].push(filter);
            }
        }
    }
    function createFNodeAndAddToState(token, result, state) {
        log?.debug("ADDING FNODE", token);
        const fnode = createFNode(token, result);
        if (token.type == "child") {
            state.child[state.depth + 1].push(fnode);
        }
        else if (token.type == "descendant") {
            state.descendant[state.depth + 1].push(fnode);
        }
        return fnode;
    }
    function isMatch(fnode, path) {
        if (fnode.node.attribute) {
            const m = fnode.node.value == path.parentKey || fnode.node.value == path.key;
            if (m)
                log?.debug("ATTR MATCH", fnode.node.value, breadCrumb(path));
            return m;
        }
        if (fnode.node.value == "*") {
            return true;
        }
        const m = fnode.node.value == path.node.type;
        if (m)
            log?.debug("NODE MATCH", fnode.node.value, breadCrumb(path));
        return m;
    }
    function addIfTokenMatch(fnode, path, state) {
        if (!isMatch(fnode, path))
            return;
        state.matches[state.depth].push([fnode, path]);
        if (fnode.node.filter) {
            const filter = createFilter(fnode.node.filter, []);
            const filteredResult = [];
            const f = { filter: filter, qNode: fnode.node, node: path.node, result: filteredResult };
            state.filters[state.depth].push(f);
            let fmap = state.filtersMap[state.depth].get(fnode.node);
            if (!fmap) {
                fmap = [];
                state.filtersMap[state.depth].set(fnode.node, fmap);
            }
            fmap.push(f);
            addFilterChildrenToState(filter, state);
            const child = fnode.node.child;
            if (child) {
                if (child.type == "function") {
                    const fr = addFunction(fnode, child, path, state);
                    state.functionCalls[state.depth].push(fr);
                }
                else {
                    createFNodeAndAddToState(child, filteredResult, state);
                }
            }
        }
        else {
            const child = fnode.node.child;
            if (child?.type == "function") {
                const fr = addFunction(fnode, child, path, state);
                state.functionCalls[state.depth].push(fr);
            }
            else if (child && !fnode.node.binding && !fnode.node.resolve) {
                createFNodeAndAddToState(child, fnode.result, state);
            }
        }
    }
    function addFunction(rootNode, functionCall, path, state) {
        const functionNode = { node: rootNode.node, functionCall: functionCall, parameters: [], result: [] };
        for (const param of functionCall.parameters) {
            if (param.type == "literal") {
                functionNode.parameters.push({ node: param, result: [param.value] });
            }
            else {
                if (param.type == "function") {
                    functionNode.parameters.push(addFunction(functionNode, param, path, state));
                }
                else {
                    functionNode.parameters.push(createFNodeAndAddToState(param, [], state));
                }
            }
        }
        return functionNode;
    }
    function addPrimitiveAttributeIfMatch(fnode, path) {
        if (!fnode.node.attribute || fnode.node.value == undefined)
            return;
        if (fnode.node.child || fnode.node.filter)
            return;
        if (!Object.hasOwn(path.node, fnode.node.value))
            return;
        const nodes = getPrimitiveChildren(fnode.node.value, path);
        if (nodes.length == 0)
            return;
        log?.debug("PRIMITIVE", fnode.node.value, nodes);
        fnode.result.push(...nodes);
    }
    function evaluateFilter(filter, path) {
        log?.debug("EVALUATING FILTER", filter, breadCrumb(path));
        if ("type" in filter) {
            if (filter.type == "and") {
                const left = evaluateFilter(filter.left, path);
                if (left.length == 0) {
                    return [];
                }
                const r = evaluateFilter(filter.right, path);
                return r;
            }
            if (filter.type == "or") {
                const left = evaluateFilter(filter.left, path);
                if (left.length > 0) {
                    return left;
                }
                const r = evaluateFilter(filter.right, path);
                return r;
            }
            if (filter.type == "equals") {
                const left = evaluateFilter(filter.left, path);
                const right = evaluateFilter(filter.right, path);
                const r = left.filter(x => right.includes(x));
                return r;
            }
            throw new Error("Unknown filter type: " + filter.type);
        }
        if (filter.node.type == "parent") {
            const r = resolveFilterWithParent(filter.node, path);
            return r;
        }
        return filter.result;
    }
    function resolveBinding(path) {
        if (!(0, nodeutils_1.isIdentifier)(path.node))
            return undefined;
        log?.debug("RESOLVING BINDING FOR ", path.node);
        const name = path.node.name;
        if (name == undefined || typeof name != "string")
            return undefined;
        //const binding = path.scope.getBinding(name);
        const binding = getBinding(path.scopeId, name);
        if (!binding)
            return undefined;
        log?.debug("THIS IS THE BINDING", binding);
        return binding.path;
    }
    function resolveFilterWithParent(node, path) {
        let startNode = node;
        let startPath = path;
        while (startNode.type == "parent") {
            if (!startNode.child)
                throw new Error("Parent filter must have child");
            if (!startPath.parentPath)
                return [];
            log?.debug("STEP OUT", startNode, breadCrumb(startPath));
            startNode = startNode.child;
            startPath = startPath.parentPath;
        }
        return resolveDirectly(startNode, startPath);
    }
    function isDefined(value) {
        return value != undefined && value != null;
    }
    let subQueryCounter = 0;
    const memo = new Map();
    function resolveDirectly(node, path) {
        let startNode = node;
        const startPath = path;
        let paths = [startPath];
        while (startNode.attribute && startNode.type == "child") {
            const lookup = startNode.value;
            if (!lookup)
                throw new Error("Selector must have a value");
            //log?.debug("STEP IN ", lookup, paths.map(p => breadCrumb(p)));
            const nodes = paths.filter(nodeutils_1.isNodePath).map(n => getPrimitiveChildrenOrNodePaths(lookup, n)).flat();
            //log?.debug("LOOKUP", lookup, path.node.type, nodes.map(n => n.node));
            //console.log(nodes);
            if (nodes.length == 0)
                return [];
            paths = nodes;
            if (startNode.resolve) {
                const resolved = paths.filter(nodeutils_1.isNodePath).map(p => resolveBinding(p)).filter(isDefined).map(p => getChildren("init", p)).flat();
                if (resolved.length > 0)
                    paths = resolved;
            }
            else if (startNode.binding) {
                paths = paths.filter(nodeutils_1.isNodePath).map(p => resolveBinding(p)).filter(isDefined);
            }
            const filter = startNode.filter;
            if (filter) {
                paths = paths.filter(nodeutils_1.isNodePath).filter(p => travHandle({ subquery: filter }, p).subquery.length > 0);
            }
            if (!startNode.child) {
                return paths.map(p => (0, nodeutils_1.isPrimitive)(p) ? p : p.node);
            }
            startNode = startNode.child;
        }
        //log?.debug("DIRECT TRAV RESOLVE", startNode, paths.map(p => breadCrumb(p)));
        const result = [];
        //console.log(paths.length, subQueryCounter);
        for (const path of paths) {
            if ((0, nodeutils_1.isNodePath)(path)) {
                if (memo.has(startNode) && memo.get(startNode).has(path)) {
                    result.push(...memo.get(startNode).get(path));
                }
                else {
                    const subQueryKey = "subquery-" + subQueryCounter++;
                    const subQueryResult = travHandle({ [subQueryKey]: startNode }, path)[subQueryKey];
                    if (!memo.has(startNode))
                        memo.set(startNode, new Map());
                    memo.get(startNode)?.set(path, subQueryResult);
                    result.push(...subQueryResult);
                }
            }
        }
        log?.debug("DIRECT TRAV RESOLVE RESULT", result);
        return result;
    }
    function addResultIfTokenMatch(fnode, path, state) {
        const matchingFilters = [];
        //console.log("FILTERS", state.filters[state.depth].length, state.filtersMap[state.depth].get(fnode.node)?.length);
        const filters = [];
        const nodeFilters = state.filtersMap[state.depth].get(fnode.node);
        if (nodeFilters) {
            for (const f of nodeFilters) {
                if (f.qNode !== fnode.node)
                    continue;
                if (f.node !== path.node)
                    continue;
                filters.push(f);
            }
            for (const f of filters) {
                if (evaluateFilter(f.filter, path).length > 0) {
                    matchingFilters.push(f);
                }
            }
            if (filters.length > 0 && matchingFilters.length == 0)
                return;
        }
        if (fnode.node.resolve) {
            const binding = resolveBinding(path);
            const resolved = binding ? getChildren("init", binding)[0] : undefined;
            if (fnode.node.child) {
                const result = resolveDirectly(fnode.node.child, resolved ?? path);
                fnode.result.push(...result);
            }
            else {
                fnode.result.push(path.node);
            }
        }
        else if (fnode.node.binding) {
            const binding = resolveBinding(path);
            if (binding) {
                if (fnode.node.child) {
                    const result = resolveDirectly(fnode.node.child, binding);
                    fnode.result.push(...result);
                }
                else {
                    fnode.result.push(binding.node);
                }
            }
        }
        else if (!fnode.node.child) {
            fnode.result.push(path.node);
        }
        else if (fnode.node.child.type == "function") {
            const functionCallResult = state.functionCalls[state.depth].find(f => f.node == fnode.node);
            if (!functionCallResult)
                throw new Error("Did not find expected function call for " + fnode.node.child.function);
            resolveFunctionCalls(fnode, functionCallResult, path, state);
        }
        else if (matchingFilters.length > 0) {
            log?.debug("HAS MATCHING FILTER", fnode.result.length, matchingFilters.length, breadCrumb(path));
            fnode.result.push(...matchingFilters.flatMap(f => f.result));
        }
    }
    function resolveFunctionCalls(fnode, functionCallResult, path, state) {
        const parameterResults = [];
        for (const p of functionCallResult.parameters) {
            if ("parameters" in p) {
                resolveFunctionCalls(p, p, path, state);
                parameterResults.push(p.result);
            }
            else {
                parameterResults.push(p.result);
            }
        }
        const functionResult = exports.functions[functionCallResult.functionCall.function].fn(parameterResults);
        log?.debug("PARAMETER RESULTS", functionCallResult.functionCall.function, parameterResults, functionResult);
        fnode.result.push(...functionResult);
    }
    function travHandle(queries, root) {
        const results = Object.fromEntries(Object.keys(queries).map(name => [name, []]));
        const state = {
            depth: 0,
            child: [[], []],
            descendant: [[], []],
            filters: [[], []],
            filtersMap: [new Map(), new Map()],
            matches: [[]],
            functionCalls: [[]]
        };
        for (const [name, node] of Object.entries(queries)) {
            createFNodeAndAddToState(node, results[name], state);
        }
        state.child[state.depth + 1].forEach(fnode => addPrimitiveAttributeIfMatch(fnode, root));
        state.descendant.slice(0, state.depth + 1).forEach(fnodes => fnodes.forEach(fnode => addPrimitiveAttributeIfMatch(fnode, root)));
        traverse(root.node, {
            enter(path, state) {
                //log?.debug("ENTER", breadCrumb(path));
                state.depth++;
                state.child.push([]);
                state.descendant.push([]);
                state.filters.push([]);
                state.filtersMap.push(new Map());
                state.matches.push([]);
                state.functionCalls.push([]);
                for (const fnode of state.child[state.depth]) {
                    addIfTokenMatch(fnode, path, state);
                }
                for (const fnodes of state.descendant.slice(0, state.depth + 1)) {
                    for (const fnode of fnodes) {
                        addIfTokenMatch(fnode, path, state);
                    }
                }
            },
            exit(path, state) {
                log?.debug("EXIT", breadCrumb(path));
                // Check for attributes as not all attributes are visited
                state.child[state.depth + 1].forEach(fnode => addPrimitiveAttributeIfMatch(fnode, path));
                for (const fnodes of state.descendant) {
                    for (const fnode of fnodes) {
                        addPrimitiveAttributeIfMatch(fnode, path);
                    }
                }
                for (const [fNode, path] of state.matches[state.depth]) {
                    addResultIfTokenMatch(fNode, path, state);
                }
                state.depth--;
                state.child.pop();
                state.descendant.pop();
                state.filters.pop();
                state.filtersMap.pop();
                state.matches.pop();
                state.functionCalls.pop();
            }
        }, root.scopeId, state, root);
        return results;
    }
    function beginHandle(queries, path) {
        const rootPath = createNodePath(path, undefined, undefined, undefined, undefined);
        const r = travHandle(queries, rootPath);
        memo.clear();
        return r;
    }
    return {
        beginHandle
    };
}
const defaultKey = "__default__";
function query(code, query, returnAST) {
    const result = multiQuery(code, { [defaultKey]: query }, returnAST);
    if (returnAST) {
        const r = result[defaultKey];
        r.__AST = result.__AST;
        return r;
    }
    return result[defaultKey];
}
function multiQuery(code, namedQueries, returnAST) {
    const start = Date.now();
    const ast = typeof code == "string" ? parseSource(code) : code;
    if (ast == null)
        throw new Error("Could not pase code");
    const queries = Object.fromEntries(Object.entries(namedQueries).map(([name, query]) => [name, (0, parseQuery_1.parse)(query)]));
    const querier = createQuerier();
    const result = querier.beginHandle(queries, ast);
    log?.debug("Query time: ", Date.now() - start);
    if (returnAST) {
        return { ...result, __AST: ast };
    }
    return result;
}
function parseSource(source, optimize = true) {
    const parsingOptions = optimize ? { loc: false, ranges: false } : { loc: true, ranges: true };
    try {
        return (0, meriyah_1.parseScript)(source, { module: true, next: true, ...parsingOptions });
    }
    catch (e) {
        return (0, meriyah_1.parseScript)(source, { module: false, next: true, ...parsingOptions, webcompat: true });
    }
}
function createTraverser() {
    let scopeIdCounter = 0;
    const scopes = new Map();
    let removedScopes = 0;
    const nodePathsCreated = {};
    function createScope(parentScopeId) {
        const id = scopeIdCounter++;
        if (parentScopeId != undefined) {
            scopes.set(id, parentScopeId ?? -1);
        }
        return id;
    }
    function getBinding(scopeId, name) {
        let currentScope = scopes.get(scopeId);
        while (currentScope !== undefined) {
            if (typeof currentScope !== "number") {
                // Full scope: Check for binding
                if (currentScope.bindings[name]) {
                    return currentScope.bindings[name];
                }
                // Move to parent scope
                if (currentScope.parentScopeId === -1)
                    break; // No parent scope
                currentScope = scopes.get(currentScope.parentScopeId);
            }
            else {
                // Lightweight scope: Retrieve parent scope
                if (currentScope === -1 || currentScope == undefined)
                    break; // No parent scope
                currentScope = scopes.get(currentScope);
            }
        }
        return undefined; // Binding not found
    }
    function setBinding(scopeId, name, binding) {
        let scope = scopes.get(scopeId);
        if (typeof scope === "number" || scope === undefined) {
            // Upgrade the lightweight scope to a full scope
            scope = { bindings: {}, id: scopeId, parentScopeId: scope };
            scopes.set(scopeId, scope);
        }
        if (scope && typeof scope !== "number") {
            scope.bindings[name] = binding;
        }
    }
    let pathsCreated = 0;
    function getChildren(key, path) {
        if (key in path.node) {
            const r = path.node[key];
            if (Array.isArray(r)) {
                return r.map((n, i) => createNodePath(n, i, key, path.scopeId, path.functionScopeId, path));
            }
            else if (r != undefined) {
                return [createNodePath(r, key, key, path.scopeId, path.functionScopeId, path)];
            }
        }
        return [];
    }
    function getPrimitiveChildren(key, path) {
        if (key in path.node) {
            const r = path.node[key];
            return (0, utils_1.toArray)(r).filter(utils_1.isDefined).filter(nodeutils_1.isPrimitive);
        }
        return [];
    }
    function getPrimitiveChildrenOrNodePaths(key, path) {
        if (key in path.node) {
            const r = path.node[key];
            if (Array.isArray(r)) {
                return r.map((n, i) => (0, nodeutils_1.isPrimitive)(n) ? n :
                    // isLiteral(n) ? n.value as PrimitiveValue :
                    createNodePath(n, i, key, path.scopeId, path.functionScopeId, path));
            }
            else if (r != undefined) {
                return [
                    (0, nodeutils_1.isPrimitive)(r) ? r :
                        // isLiteral(r) ? r.value as PrimitiveValue :
                        createNodePath(r, key, key, path.scopeId, path.functionScopeId, path)
                ];
            }
        }
        return [];
    }
    function createNodePath(node, key, parentKey, scopeId, functionScopeId, nodePath) {
        if (node.extra?.nodePath) {
            const path = node.extra.nodePath;
            if (nodePath && (0, nodeutils_1.isExportSpecifier)(nodePath.node) && key == "exported" && path.key == "local") {
                //Special handling for "export { someName }" as id is both local and exported
                path.key = "exported";
                path.parentPath = nodePath;
                return path;
            }
            if (key != undefined)
                path.key = typeof (key) == "number" ? key.toString() : key;
            if (parentKey != undefined)
                path.parentKey = parentKey;
            if (nodePath != undefined)
                path.parentPath = nodePath;
            return path;
        }
        const finalScope = ((node.extra && node.extra.scopeId != undefined) ? node.extra.scopeId : scopeId) ?? createScope();
        const finalFScope = ((node.extra && node.extra.functionScopeId != undefined) ? node.extra.functionScopeId : functionScopeId) ?? finalScope;
        const path = {
            node,
            scopeId: finalScope,
            functionScopeId: finalFScope,
            parentPath: nodePath,
            key: typeof (key) == "number" ? key.toString() : key,
            parentKey
        };
        if ((0, nodeutils_1.isNode)(node)) {
            node.extra = node.extra ?? {};
            node.extra.nodePath = path;
            Object.defineProperty(node.extra, "nodePath", { enumerable: false });
        }
        nodePathsCreated[node.type] = (nodePathsCreated[node.type] ?? 0) + 1;
        pathsCreated++;
        return path;
    }
    function registerBinding(stack, scopeId, functionScopeId, key, parentKey) {
        //console.log("x registerBinding?", isIdentifier(node) ? node.name : node.type, parentNode.type, grandParentNode?.type, scopeId, isBinding(node, parentNode, grandParentNode));
        const node = stack[stack.length - 1];
        if (!(0, nodeutils_1.isIdentifier)(node))
            return;
        const parentNode = stack[stack.length - 2];
        if ((0, nodeutils_1.isAssignmentExpression)(parentNode) || (0, nodeutils_1.isMemberExpression)(parentNode) || (0, nodeutils_1.isUpdateExpression)(parentNode) || (0, nodeutils_1.isExportSpecifier)(parentNode))
            return;
        const grandParentNode = stack[stack.length - 3];
        if (!(0, nodeutils_1.isBinding)(node, parentNode, grandParentNode))
            return;
        if (key == "id" && !(0, nodeutils_1.isVariableDeclarator)(parentNode)) {
            setBinding(functionScopeId, node.name, { path: createNodePath(node, undefined, undefined, scopeId, functionScopeId) });
            return;
        }
        if ((0, nodeutils_1.isVariableDeclarator)(parentNode) && (0, nodeutils_1.isVariableDeclaration)(grandParentNode)) {
            if (grandParentNode.kind == "var") {
                setBinding(functionScopeId, node.name, { path: createNodePath(parentNode, undefined, undefined, scopeId, functionScopeId) });
                return;
            }
            else {
                setBinding(scopeId, node.name, { path: createNodePath(parentNode, undefined, undefined, scopeId, functionScopeId) });
                return;
            }
        }
        if ((0, nodeutils_1.isScope)(node, parentNode)) {
            setBinding(scopeId, node.name, { path: createNodePath(node, key, parentKey, scopeId, functionScopeId) });
        } /*else {
          console.log(node.type, parentNode.type, grandParentNode?.type);
        }*/
    }
    let bindingNodesVisited = 0;
    function registerBindings(stack, scopeId, functionScopeId) {
        const node = stack[stack.length - 1];
        if (!(0, nodeutils_1.isNode)(node))
            return;
        if (node.extra?.scopeId != undefined)
            return;
        node.extra = node.extra ?? {};
        node.extra.scopeId = scopeId;
        bindingNodesVisited++;
        const keys = nodeutils_1.VISITOR_KEYS[node.type];
        if (keys.length == 0)
            return;
        let childScopeId = scopeId;
        if ((0, nodeutils_1.isScopable)(node)) {
            childScopeId = createScope(scopeId);
        }
        for (const key of keys) {
            const childNodes = node[key];
            const children = (0, utils_1.toArray)(childNodes).filter(utils_1.isDefined);
            for (const [i, child] of children.entries()) {
                if (!(0, nodeutils_1.isNode)(child))
                    continue;
                const f = key === "body" && ((0, nodeutils_1.isFunctionDeclaration)(node) || (0, nodeutils_1.isFunctionExpression)(node)) ? childScopeId : functionScopeId;
                stack.push(child);
                if ((0, nodeutils_1.isIdentifier)(child)) {
                    const k = Array.isArray(childNodes) ? i : key;
                    registerBinding(stack, childScopeId, f, k, key);
                }
                else {
                    registerBindings(stack, childScopeId, f);
                }
                stack.pop();
            }
        }
        if (childScopeId != scopeId && typeof scopes.get(childScopeId) == "number") { // Scope has not been populated
            scopes.set(childScopeId, scopes.get(scopeId));
            removedScopes++;
        }
    }
    function traverseInner(node, visitor, scopeId, functionScopeId, state, path) {
        const nodePath = path ?? createNodePath(node, undefined, undefined, scopeId, functionScopeId);
        const keys = nodeutils_1.VISITOR_KEYS[node.type] ?? [];
        if (nodePath.parentPath)
            registerBindings([nodePath.parentPath.parentPath?.node, nodePath.parentPath.node, nodePath.node].filter(utils_1.isDefined), nodePath.scopeId, nodePath.functionScopeId);
        for (const key of keys) {
            const childNodes = node[key];
            const children = Array.isArray(childNodes) ? childNodes : childNodes ? [childNodes] : [];
            const nodePaths = [];
            for (const [i, child] of children.entries()) {
                if ((0, nodeutils_1.isNode)(child)) {
                    const childPath = createNodePath(child, Array.isArray(childNodes) ? i : key, key, nodePath.scopeId, nodePath.functionScopeId, nodePath);
                    nodePaths.push(childPath);
                }
            }
            for (const childPath of nodePaths) {
                visitor.enter(childPath, state);
                traverseInner(childPath.node, visitor, nodePath.scopeId, nodePath.functionScopeId, state, childPath);
                visitor.exit(childPath, state);
            }
        }
    }
    const sOut = [];
    function traverse(node, visitor, scopeId, state, path) {
        const fscope = path?.functionScopeId ?? node.extra?.functionScopeId ?? scopeId;
        traverseInner(node, visitor, scopeId, fscope, state, path);
        if (!sOut.includes(scopeIdCounter)) {
            log?.debug("Scopes created", scopeIdCounter, " Scopes removed", removedScopes, "Paths created", pathsCreated, bindingNodesVisited);
            sOut.push(scopeIdCounter);
            const k = Object.fromEntries(Object.entries(nodePathsCreated).sort((a, b) => a[1] - b[1]));
            log?.debug("Node paths created", k);
        }
    }
    return {
        traverse,
        createNodePath,
        getChildren,
        getPrimitiveChildren,
        getPrimitiveChildrenOrNodePaths,
        getBinding
    };
}

},{"./nodeutils":5,"./parseQuery":6,"./utils":7,"meriyah":8}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VISITOR_KEYS = exports.isBinding = exports.isVariableDeclaration = exports.isVariableDeclarator = exports.isFunctionExpression = exports.isFunctionDeclaration = exports.isIdentifier = exports.isMemberExpression = exports.isAssignmentExpression = exports.isUpdateExpression = exports.isPrimitive = exports.isLiteral = exports.isNodePath = exports.isNode = void 0;
exports.isScope = isScope;
exports.isScopable = isScopable;
exports.isExportSpecifier = isExportSpecifier;
const isNode = (candidate) => {
    return typeof candidate === "object" && candidate != null && "type" in candidate;
};
exports.isNode = isNode;
const isNodePath = (candidate) => {
    return typeof candidate === "object" && candidate != null && "node" in candidate;
};
exports.isNodePath = isNodePath;
const isLiteral = (candidate) => {
    return (0, exports.isNode)(candidate) && candidate.type === "Literal";
};
exports.isLiteral = isLiteral;
const isPrimitive = (value) => {
    return typeof value == "string" || typeof value == "number" || typeof value == "boolean";
};
exports.isPrimitive = isPrimitive;
const isUpdateExpression = (value) => {
    return (0, exports.isNode)(value) && value.type === "UpdateExpression";
};
exports.isUpdateExpression = isUpdateExpression;
const isAssignmentExpression = (node) => {
    return node.type === "AssignmentExpression";
};
exports.isAssignmentExpression = isAssignmentExpression;
const isMemberExpression = (node) => {
    return node.type === "MemberExpression";
};
exports.isMemberExpression = isMemberExpression;
const isIdentifier = (node) => {
    return node.type === "Identifier";
};
exports.isIdentifier = isIdentifier;
const isFunctionDeclaration = (node) => {
    return node.type === "FunctionDeclaration";
};
exports.isFunctionDeclaration = isFunctionDeclaration;
const isFunctionExpression = (node) => {
    return node.type === "FunctionExpression";
};
exports.isFunctionExpression = isFunctionExpression;
const isVariableDeclarator = (node) => {
    return node.type === "VariableDeclarator";
};
exports.isVariableDeclarator = isVariableDeclarator;
const isVariableDeclaration = (node) => {
    return node.type === "VariableDeclaration";
};
exports.isVariableDeclaration = isVariableDeclaration;
const isBinding = (node, parentNode, grandParentNode) => {
    if (grandParentNode &&
        node.type === "Identifier" &&
        parentNode.type === "Property" &&
        grandParentNode.type === "ObjectExpression") {
        return false;
    }
    const keys = bindingIdentifiersKeys[parentNode.type] ?? [];
    for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const val = 
        // @ts-expect-error key must present in parent
        parentNode[key];
        if (Array.isArray(val)) {
            if (val.indexOf(node) >= 0)
                return true;
        }
        else {
            if (val === node)
                return true;
        }
    }
    return false;
};
exports.isBinding = isBinding;
const bindingIdentifiersKeys = {
    DeclareClass: ["id"],
    DeclareFunction: ["id"],
    DeclareModule: ["id"],
    DeclareVariable: ["id"],
    DeclareInterface: ["id"],
    DeclareTypeAlias: ["id"],
    DeclareOpaqueType: ["id"],
    InterfaceDeclaration: ["id"],
    TypeAlias: ["id"],
    OpaqueType: ["id"],
    CatchClause: ["param"],
    LabeledStatement: ["label"],
    UnaryExpression: ["argument"],
    AssignmentExpression: ["left"],
    ImportSpecifier: ["local"],
    ImportNamespaceSpecifier: ["local"],
    ImportDefaultSpecifier: ["local"],
    ImportDeclaration: ["specifiers"],
    ExportSpecifier: ["exported"],
    ExportNamespaceSpecifier: ["exported"],
    ExportDefaultSpecifier: ["exported"],
    FunctionDeclaration: ["id", "params"],
    FunctionExpression: ["id", "params"],
    ArrowFunctionExpression: ["params"],
    ObjectMethod: ["params"],
    ClassMethod: ["params"],
    ClassPrivateMethod: ["params"],
    ForInStatement: ["left"],
    ForOfStatement: ["left"],
    ClassDeclaration: ["id"],
    ClassExpression: ["id"],
    RestElement: ["argument"],
    UpdateExpression: ["argument"],
    ObjectProperty: ["value"],
    AssignmentPattern: ["left"],
    ArrayPattern: ["elements"],
    ObjectPattern: ["properties"],
    VariableDeclaration: ["declarations"],
    VariableDeclarator: ["id"],
};
exports.VISITOR_KEYS = {
    ArrayExpression: ["elements"],
    ArrayPattern: ["elements"],
    ArrowFunctionExpression: ["params", "body"],
    AssignmentExpression: ["left", "right"],
    AssignmentPattern: ["left", "right"],
    AwaitExpression: ["argument"],
    BinaryExpression: ["left", "right"],
    BlockStatement: ["body"],
    BreakStatement: [],
    CallExpression: ["callee", "arguments"],
    CatchClause: ["param", "body"],
    ChainExpression: ["expression"],
    ClassBody: ["body"],
    ClassDeclaration: ["id", "superClass", "body"],
    ClassExpression: ["id", "superClass", "body"],
    ConditionalExpression: ["test", "consequent", "alternate"],
    ContinueStatement: [],
    DebuggerStatement: [],
    DoWhileStatement: ["body", "test"],
    EmptyStatement: [],
    ExportAllDeclaration: ["source"],
    ExportDefaultDeclaration: ["declaration"],
    ExportNamedDeclaration: ["declaration", "specifiers", "source"],
    ExportSpecifier: ["local", "exported"],
    ExpressionStatement: ["expression"],
    ForInStatement: ["left", "right", "body"],
    ForOfStatement: ["left", "right", "body"],
    ForStatement: ["init", "test", "update", "body"],
    FunctionDeclaration: ["id", "params", "body"],
    FunctionExpression: ["id", "params", "body"],
    Identifier: [],
    IfStatement: ["test", "consequent", "alternate"],
    ImportAttribute: ["key", "value"],
    ImportDeclaration: ["specifiers", "source"],
    ImportDefaultSpecifier: ["local"],
    ImportNamespaceSpecifier: ["local"],
    ImportSpecifier: ["local", "imported"],
    LabeledStatement: ["label", "body"],
    Literal: [],
    LogicalExpression: ["left", "right"],
    MemberExpression: ["object", "property"],
    MetaProperty: ["meta", "property"],
    MethodDefinition: ["key", "value"],
    NewExpression: ["callee", "arguments"],
    ObjectExpression: ["properties"],
    ObjectPattern: ["properties"],
    Program: ["body"],
    Property: ["key", "value"],
    RestElement: ["argument"],
    ReturnStatement: ["argument"],
    SequenceExpression: ["expressions"],
    SpreadElement: ["argument"],
    Super: [],
    SwitchCase: ["test", "consequent"],
    SwitchStatement: ["discriminant", "cases"],
    TaggedTemplateExpression: ["tag", "quasi"],
    TemplateElement: [],
    TemplateLiteral: ["quasis", "expressions"],
    ThisExpression: [],
    ThrowStatement: ["argument"],
    TryStatement: ["block", "handler", "finalizer"],
    UnaryExpression: ["argument"],
    UpdateExpression: ["argument"],
    VariableDeclaration: ["declarations"],
    VariableDeclarator: ["id", "init"],
    WhileStatement: ["test", "body"],
    WithStatement: ["object", "body"],
    YieldExpression: ["argument"],
    ImportExpression: ["source"],
    Decorator: ["expression"],
    PropertyDefinition: ["key", "value"],
    Import: ["source"],
    JSXAttribute: ["name", "value"],
    JSXNamespacedName: ["namespace", "name"],
    JSXElement: ["openingElement", "closingElement", "children"],
    JSXClosingElement: ["name"],
    JSXOpeningElement: ["name", "attributes"],
    JSXFragment: ["openingFragment", "closingFragment", "children"],
    JSXOpeningFragment: [],
    JSXClosingFragment: [],
    JSXText: [],
    JSXExpressionContainer: ["expression"],
    JSXSpreadChild: ["expression"],
    JSXEmptyExpression: [],
    JSXSpreadAttribute: ["argument"],
    JSXIdentifier: [],
    PrivateIdentifier: [],
    JSXMemberExpression: ["object", "property"],
    ParenthesizedExpression: ["expression"],
    StaticBlock: ["body"],
};
function isBlockStatement(node) { return node.type === "BlockStatement"; }
function isFunction(node) {
    return node.type === "FunctionDeclaration" || node.type === "FunctionExpression";
}
function isCatchClause(node) { return node.type === "CatchClause"; }
function isPattern(node) {
    switch (node.type) {
        case "AssignmentPattern":
        case "ArrayPattern":
        case "ObjectPattern":
            return true;
    }
    return false;
}
function isScope(node, parentNode) {
    if (isBlockStatement(node) && (isFunction(parentNode) || isCatchClause(parentNode))) {
        return false;
    }
    if (isPattern(node) && (isFunction(parentNode) || isCatchClause(parentNode))) {
        return true;
    }
    return (0, exports.isFunctionDeclaration)(parentNode) || (0, exports.isFunctionExpression)(parentNode) || isScopable(node);
}
function isScopable(node) {
    switch (node.type) {
        case "BlockStatement":
        case "CatchClause":
        case "DoWhileStatement":
        case "ForInStatement":
        case "ForStatement":
        case "FunctionDeclaration":
        case "FunctionExpression":
        case "Program":
        case "MethodDefinition":
        case "SwitchStatement":
        case "WhileStatement":
        case "ArrowFunctionExpression":
        case "ClassExpression":
        case "ClassDeclaration":
        case "ForOfStatement":
        case "StaticBlock":
            return true;
    }
    return false;
}
function isExportSpecifier(node) {
    return node.type === "ExportSpecifier";
}

},{}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.tokenize = tokenize;
exports.parse = parse;
const _1 = require(".");
const nodeutils_1 = require("./nodeutils");
const debugLogEnabled = false;
const log = debugLogEnabled ? {
    debug: (...args) => {
        console.debug(...args);
    }
} : undefined;
const supportedIdentifiers = Object.fromEntries(Object.keys(nodeutils_1.VISITOR_KEYS).map(k => [k, k]));
function isIdentifierToken(token) {
    if (token == undefined)
        return false;
    if (token.type != "identifier" && token.type != "wildcard")
        return false;
    if (!token.value)
        return false;
    if (!(token.value in supportedIdentifiers) && token.value != "*") {
        throw new Error("Unsupported identifier: " + token.value);
    }
    ;
    return true;
}
const whitespace = " \n\r\t";
function isCharacter(c) {
    const charcode = c.charCodeAt(0);
    return (charcode >= 65 && charcode <= 90) || (charcode >= 97 && charcode <= 122);
}
function isInteger(c) {
    const charcode = c.charCodeAt(0);
    return (charcode >= 48 && charcode <= 57);
}
function tokenize(input) {
    let s = 0;
    const result = [];
    while (s < input.length) {
        while (whitespace.includes(input[s]))
            s++;
        if (s >= input.length)
            break;
        if (input[s] == "/") {
            if (input[s + 1] == "/") {
                result.push({ type: "descendant" });
                s += 2;
                continue;
            }
            result.push({ type: "child" });
            s++;
            continue;
        }
        if (input[s] == ":") {
            result.push({ type: "attributeSelector" });
            s++;
            continue;
        }
        if (input[s] == "$" && input[s + 1] == "$") {
            result.push({ type: "resolveSelector" });
            s += 2;
            continue;
        }
        if (input[s] == "$") {
            result.push({ type: "bindingSelector" });
            s++;
            continue;
        }
        if (input[s] == "[") {
            result.push({ type: "filterBegin" });
            s++;
            continue;
        }
        if (input[s] == "]") {
            result.push({ type: "filterEnd" });
            s++;
            continue;
        }
        if (input[s] == ",") {
            result.push({ type: "separator" });
            s++;
            continue;
        }
        if (input[s] == "(") {
            result.push({ type: "parametersBegin" });
            s++;
            continue;
        }
        if (input[s] == "f" && input[s + 1] == "n" && input[s + 2] == ":") {
            result.push({ type: "function" });
            s += 3;
            continue;
        }
        if (input[s] == ")") {
            result.push({ type: "parametersEnd" });
            s++;
            continue;
        }
        if (input[s] == "&" && input[s + 1] == "&") {
            result.push({ type: "and" });
            s += 2;
            continue;
        }
        if (input[s] == "|" && input[s + 1] == "|") {
            result.push({ type: "or" });
            s += 2;
            continue;
        }
        if (input[s] == "=" && input[s + 1] == "=") {
            result.push({ type: "eq" });
            s += 2;
            continue;
        }
        if (input[s] == "'" || input[s] == '"') {
            const begin = input[s];
            const start = s;
            s++;
            while (s < input.length && input[s] != begin)
                s++;
            result.push({ type: "literal", value: input.slice(start + 1, s) });
            s++;
            continue;
        }
        if (input[s] == "." && input[s + 1] == ".") {
            result.push({ type: "parent" });
            s += 2;
            continue;
        }
        if (input[s] == "*") {
            result.push({ type: "wildcard", value: "*" });
            s++;
            continue;
        }
        if (isCharacter(input[s])) {
            const start = s;
            while (s < input.length && isCharacter(input[s]))
                s++;
            result.push({ type: "identifier", value: input.slice(start, s) });
            continue;
        }
        if (isInteger(input[s])) {
            const start = s;
            while (s < input.length && isInteger(input[s]))
                s++;
            result.push({ type: "literal", value: input.slice(start, s) });
            continue;
        }
        throw new Error("Unexpected token: " + input[s]);
    }
    return result;
}
function buildFilter(tokens) {
    log?.debug("BUILD FILTER", tokens);
    tokens.shift();
    const p = buildTree(tokens);
    const next = tokens[0];
    if (next.type == "and") {
        return {
            type: "and",
            left: p,
            right: buildFilter(tokens)
        };
    }
    if (next.type == "or") {
        return {
            type: "or",
            left: p,
            right: buildFilter(tokens)
        };
    }
    if (next.type == "eq") {
        const right = buildFilter(tokens);
        if (right.type == "or" || right.type == "and") {
            return {
                type: right.type,
                left: {
                    type: "equals",
                    left: p,
                    right: right.left
                },
                right: right.right
            };
        }
        if (right.type == "equals")
            throw new Error("Unexpected equals in equals");
        return {
            type: "equals",
            left: p,
            right: right
        };
    }
    if (next.type == "filterEnd") {
        tokens.shift();
        return p;
    }
    throw new Error("Unexpected token in filter: " + next?.type);
}
const subNodes = ["child", "descendant"];
function buildTree(tokens) {
    log?.debug("BUILD TREE", tokens);
    if (tokens.length == 0)
        throw new Error("Unexpected end of input");
    const token = tokens.shift();
    if (token == undefined)
        throw new Error("Unexpected end of input");
    if (token.type == "parent") {
        return {
            type: "parent",
            child: buildTree(tokens)
        };
    }
    if (subNodes.includes(token.type)) {
        let next = tokens.shift();
        if (next?.type == "function") {
            const name = tokens.shift();
            if (name == undefined || name.type != "identifier" || name.value == undefined || typeof (name.value) != "string")
                throw new Error("Unexpected token: " + name?.type + ". Expecting function name");
            const value = name.value;
            if (!(0, _1.isAvailableFunction)(value)) {
                throw new Error("Unsupported function: " + name.value);
            }
            return buildFunctionCall(value, tokens);
        }
        if (next?.type == "parent") {
            return { type: "parent", child: buildTree(tokens) };
        }
        const modifiers = [];
        while (next && (next?.type == "attributeSelector" || next?.type == "bindingSelector" || next?.type == "resolveSelector")) {
            modifiers.push(next);
            next = tokens.shift();
        }
        const isAttribute = modifiers.some(m => m.type == "attributeSelector");
        const isBinding = modifiers.some(m => m.type == "bindingSelector");
        const isResolve = modifiers.some(m => m.type == "resolveSelector");
        if (isResolve && isBinding)
            throw new Error("Cannot have both resolve and binding");
        if (!next || !next.value || (!isAttribute && !isIdentifierToken(next)))
            throw new Error("Unexpected or missing token: " + next?.type);
        const identifer = next.value;
        let filter = undefined;
        if (tokens.length > 0 && tokens[0].type == "filterBegin") {
            filter = buildFilter(tokens);
            log?.debug("FILTER", filter, tokens);
        }
        let child = undefined;
        if (tokens.length > 0 && subNodes.includes(tokens[0].type)) {
            child = buildTree(tokens);
        }
        if (typeof (identifer) != "string")
            throw new Error("Identifier must be a string");
        return {
            type: token.type,
            value: identifer,
            attribute: isAttribute,
            binding: isBinding,
            resolve: isResolve,
            filter: filter,
            child: child
        };
    }
    if (token.type == "literal") {
        return {
            type: "literal",
            value: token.value
        };
    }
    throw new Error("Unexpected token: " + token.type);
}
function buildFunctionCall(name, tokens) {
    log?.debug("BUILD FUNCTION", name, tokens);
    const parameters = [];
    const next = tokens.shift();
    if (next?.type != "parametersBegin")
        throw new Error("Unexpected token: " + next?.type);
    while (tokens.length > 0 && tokens[0].type != "parametersEnd") {
        parameters.push(buildTree(tokens));
        if (tokens[0].type == "separator")
            tokens.shift();
    }
    if (tokens.length == 0)
        throw new Error("Unexpected end of input");
    tokens.shift();
    return {
        type: "function",
        function: name,
        parameters: parameters
    };
}
function parse(input) {
    const tokens = tokenize(input);
    const result = buildTree(tokens);
    log?.debug("RESULT", result);
    if (!result)
        throw new Error("No root element found");
    return result;
}

},{".":4,"./nodeutils":5}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toArray = toArray;
exports.isDefined = isDefined;
function toArray(value) {
    return Array.isArray(value) ? value : [value];
}
function isDefined(value) {
    return value != undefined && value != null;
}

},{}],8:[function(require,module,exports){
!function(e,n){"object"==typeof exports&&"undefined"!=typeof module?n(exports):"function"==typeof define&&define.amd?define(["exports"],n):n((e="undefined"!=typeof globalThis?globalThis:e||self).meriyah={})}(this,(function(e){"use strict";const n={0:"Unexpected token",30:"Unexpected token: '%0'",1:"Octal escape sequences are not allowed in strict mode",2:"Octal escape sequences are not allowed in template strings",3:"\\8 and \\9 are not allowed in template strings",4:"Private identifier #%0 is not defined",5:"Illegal Unicode escape sequence",6:"Invalid code point %0",7:"Invalid hexadecimal escape sequence",9:"Octal literals are not allowed in strict mode",8:"Decimal integer literals with a leading zero are forbidden in strict mode",10:"Expected number in radix %0",151:"Invalid left-hand side assignment to a destructible right-hand side",11:"Non-number found after exponent indicator",12:"Invalid BigIntLiteral",13:"No identifiers allowed directly after numeric literal",14:"Escapes \\8 or \\9 are not syntactically valid escapes",15:"Escapes \\8 or \\9 are not allowed in strict mode",16:"Unterminated string literal",17:"Unterminated template literal",18:"Multiline comment was not closed properly",19:"The identifier contained dynamic unicode escape that was not closed",20:"Illegal character '%0'",21:"Missing hexadecimal digits",22:"Invalid implicit octal",23:"Invalid line break in string literal",24:"Only unicode escapes are legal in identifier names",25:"Expected '%0'",26:"Invalid left-hand side in assignment",27:"Invalid left-hand side in async arrow",28:'Calls to super must be in the "constructor" method of a class expression or class declaration that has a superclass',29:"Member access on super must be in a method",31:"Await expression not allowed in formal parameter",32:"Yield expression not allowed in formal parameter",95:"Unexpected token: 'escaped keyword'",33:"Unary expressions as the left operand of an exponentiation expression must be disambiguated with parentheses",123:"Async functions can only be declared at the top level or inside a block",34:"Unterminated regular expression",35:"Unexpected regular expression flag",36:"Duplicate regular expression flag '%0'",37:"%0 functions must have exactly %1 argument%2",38:"Setter function argument must not be a rest parameter",39:"%0 declaration must have a name in this context",40:"Function name may not contain any reserved words or be eval or arguments in strict mode",41:"The rest operator is missing an argument",42:"A getter cannot be a generator",43:"A setter cannot be a generator",44:"A computed property name must be followed by a colon or paren",134:"Object literal keys that are strings or numbers must be a method or have a colon",46:"Found `* async x(){}` but this should be `async * x(){}`",45:"Getters and setters can not be generators",47:"'%0' can not be generator method",48:"No line break is allowed after '=>'",49:"The left-hand side of the arrow can only be destructed through assignment",50:"The binding declaration is not destructible",51:"Async arrow can not be followed by new expression",52:"Classes may not have a static property named 'prototype'",53:"Class constructor may not be a %0",54:"Duplicate constructor method in class",55:"Invalid increment/decrement operand",56:"Invalid use of `new` keyword on an increment/decrement expression",57:"`=>` is an invalid assignment target",58:"Rest element may not have a trailing comma",59:"Missing initializer in %0 declaration",60:"'for-%0' loop head declarations can not have an initializer",61:"Invalid left-hand side in for-%0 loop: Must have a single binding",62:"Invalid shorthand property initializer",63:"Property name __proto__ appears more than once in object literal",64:"Let is disallowed as a lexically bound name",65:"Invalid use of '%0' inside new expression",66:"Illegal 'use strict' directive in function with non-simple parameter list",67:'Identifier "let" disallowed as left-hand side expression in strict mode',68:"Illegal continue statement",69:"Illegal break statement",70:"Cannot have `let[...]` as a var name in strict mode",71:"Invalid destructuring assignment target",72:"Rest parameter may not have a default initializer",73:"The rest argument must the be last parameter",74:"Invalid rest argument",76:"In strict mode code, functions can only be declared at top level or inside a block",77:"In non-strict mode code, functions can only be declared at top level, inside a block, or as the body of an if statement",78:"Without web compatibility enabled functions can not be declared at top level, inside a block, or as the body of an if statement",79:"Class declaration can't appear in single-statement context",80:"Invalid left-hand side in for-%0",81:"Invalid assignment in for-%0",82:"for await (... of ...) is only valid in async functions and async generators",83:"The first token after the template expression should be a continuation of the template",85:"`let` declaration not allowed here and `let` cannot be a regular var name in strict mode",84:"`let \n [` is a restricted production at the start of a statement",86:"Catch clause requires exactly one parameter, not more (and no trailing comma)",87:"Catch clause parameter does not support default values",88:"Missing catch or finally after try",89:"More than one default clause in switch statement",90:"Illegal newline after throw",91:"Strict mode code may not include a with statement",92:"Illegal return statement",93:"The left hand side of the for-header binding declaration is not destructible",94:"new.target only allowed within functions or static blocks",96:"'#' not followed by identifier",102:"Invalid keyword",101:"Can not use 'let' as a class name",100:"'A lexical declaration can't define a 'let' binding",99:"Can not use `let` as variable name in strict mode",97:"'%0' may not be used as an identifier in this context",98:"Await is only valid in async functions",103:"The %0 keyword can only be used with the module goal",104:"Unicode codepoint must not be greater than 0x10FFFF",105:"%0 source must be string",106:"Only a identifier or string can be used to indicate alias",107:"Only '*' or '{...}' can be imported after default",108:"Trailing decorator may be followed by method",109:"Decorators can't be used with a constructor",110:"Can not use `await` as identifier in module or async func",111:"Can not use `await` as identifier in module",112:"HTML comments are only allowed with web compatibility (Annex B)",113:"The identifier 'let' must not be in expression position in strict mode",114:"Cannot assign to `eval` and `arguments` in strict mode",115:"The left-hand side of a for-of loop may not start with 'let'",116:"Block body arrows can not be immediately invoked without a group",117:"Block body arrows can not be immediately accessed without a group",118:"Unexpected strict mode reserved word",119:"Unexpected eval or arguments in strict mode",120:"Decorators must not be followed by a semicolon",121:"Calling delete on expression not allowed in strict mode",122:"Pattern can not have a tail",124:"Can not have a `yield` expression on the left side of a ternary",125:"An arrow function can not have a postfix update operator",126:"Invalid object literal key character after generator star",127:"Private fields can not be deleted",129:"Classes may not have a field called constructor",128:"Classes may not have a private element named constructor",130:"A class field initializer or static block may not contain arguments",131:"Generators can only be declared at the top level or inside a block",132:"Async methods are a restricted production and cannot have a newline following it",133:"Unexpected character after object literal property name",135:"Invalid key token",136:"Label '%0' has already been declared",137:"continue statement must be nested within an iteration statement",138:"Undefined label '%0'",139:"Trailing comma is disallowed inside import(...) arguments",140:"Invalid binding in JSON import",141:"import() requires exactly one argument",142:"Cannot use new with import(...)",143:"... is not allowed in import()",144:"Expected '=>'",145:"Duplicate binding '%0'",146:"Duplicate private identifier #%0",147:"Cannot export a duplicate name '%0'",150:"Duplicate %0 for-binding",148:"Exported binding '%0' needs to refer to a top-level declared variable",149:"Unexpected private field",153:"Numeric separators are not allowed at the end of numeric literals",152:"Only one underscore is allowed as numeric separator",154:"JSX value should be either an expression or a quoted JSX text",155:"Expected corresponding JSX closing tag for %0",156:"Adjacent JSX elements must be wrapped in an enclosing tag",157:"JSX attributes must only be assigned a non-empty 'expression'",158:"'%0' has already been declared",159:"'%0' shadowed a catch clause binding",160:"Dot property must be an identifier",161:"Encountered invalid input after spread/rest argument",162:"Catch without try",163:"Finally without try",164:"Expected corresponding closing tag for JSX fragment",165:"Coalescing and logical operators used together in the same expression must be disambiguated with parentheses",166:"Invalid tagged template on optional chain",167:"Invalid optional chain from super property",168:"Invalid optional chain from new expression",169:'Cannot use "import.meta" outside a module',170:"Leading decorators must be attached to a class declaration",171:"An export name cannot include a lone surrogate, found %0",172:"A string literal cannot be used as an exported binding without `from`",173:"Private fields can't be accessed on super",174:"The only valid meta property for import is 'import.meta'",175:"'import.meta' must not contain escaped characters",176:'cannot use "await" as identifier inside an async function',177:'cannot use "await" in static blocks'};class t extends SyntaxError{constructor(e,t,o,r,a,i,s,...l){const c="["+t+":"+o+"-"+a+":"+i+"]: "+n[s].replace(/%(\d+)/g,((e,n)=>l[n]));super(`${c}`),this.start=e,this.end=r,this.range=[e,r],this.loc={start:{line:t,column:o},end:{line:a,column:i}},this.description=c}}function o(e,n,...o){throw new t(e.tokenIndex,e.tokenLine,e.tokenColumn,e.index,e.line,e.column,n,...o)}function r(e){throw new t(e.tokenIndex,e.tokenLine,e.tokenColumn,e.index,e.line,e.column,e.type,...e.params)}function a(e,n,o,r,a,i,s,...l){throw new t(e,n,o,r,a,i,s,...l)}function i(e,n,o,r,a,i,s){throw new t(e,n,o,r,a,i,s)}function s(e){return!!(1&l[34816+(e>>>5)]>>>e)}const l=((e,n)=>{const t=new Uint32Array(104448);let o=0,r=0;for(;o<3822;){const a=e[o++];if(a<0)r-=a;else{let i=e[o++];2&a&&(i=n[i]),1&a?t.fill(i,r,r+=e[o++]):t[r++]=i}}return t})([-1,2,26,2,27,2,5,-1,0,77595648,3,44,2,3,0,14,2,63,2,64,3,0,3,0,3168796671,0,4294956992,2,1,2,0,2,41,3,0,4,0,4294966523,3,0,4,2,16,2,65,2,0,0,4294836735,0,3221225471,0,4294901942,2,66,0,134152192,3,0,2,0,4294951935,3,0,2,0,2683305983,0,2684354047,2,18,2,0,0,4294961151,3,0,2,2,19,2,0,0,608174079,2,0,2,60,2,7,2,6,0,4286611199,3,0,2,2,1,3,0,3,0,4294901711,2,40,0,4089839103,0,2961209759,0,1342439375,0,4294543342,0,3547201023,0,1577204103,0,4194240,0,4294688750,2,2,0,80831,0,4261478351,0,4294549486,2,2,0,2967484831,0,196559,0,3594373100,0,3288319768,0,8469959,2,203,2,3,0,4093640191,0,660618719,0,65487,0,4294828015,0,4092591615,0,1616920031,0,982991,2,3,2,0,0,2163244511,0,4227923919,0,4236247022,2,71,0,4284449919,0,851904,2,4,2,12,0,67076095,-1,2,72,0,1073741743,0,4093607775,-1,0,50331649,0,3265266687,2,33,0,4294844415,0,4278190047,2,20,2,137,-1,3,0,2,2,23,2,0,2,10,2,0,2,15,2,22,3,0,10,2,74,2,0,2,75,2,76,2,77,2,0,2,78,2,0,2,11,0,261632,2,25,3,0,2,2,13,2,4,3,0,18,2,79,2,5,3,0,2,2,80,0,2151677951,2,29,2,9,0,909311,3,0,2,0,814743551,2,49,0,67090432,3,0,2,2,42,2,0,2,6,2,0,2,30,2,8,0,268374015,2,110,2,51,2,0,2,81,0,134153215,-1,2,7,2,0,2,8,0,2684354559,0,67044351,0,3221160064,2,17,-1,3,0,2,2,53,0,1046528,3,0,3,2,9,2,0,2,54,0,4294960127,2,10,2,6,2,11,0,4294377472,2,12,3,0,16,2,13,2,0,2,82,2,10,2,0,2,83,2,84,2,85,2,210,2,55,0,1048577,2,86,2,14,-1,2,14,0,131042,2,87,2,88,2,89,2,0,2,34,-83,3,0,7,0,1046559,2,0,2,15,2,0,0,2147516671,2,21,3,90,2,2,0,-16,2,91,0,524222462,2,4,2,0,0,4269801471,2,4,3,0,2,2,28,2,16,3,0,2,2,17,2,0,-1,2,18,-16,3,0,206,-2,3,0,692,2,73,-1,2,18,2,10,3,0,8,2,93,2,133,2,0,0,3220242431,3,0,3,2,19,2,94,2,95,3,0,2,2,96,2,0,2,97,2,46,2,0,0,4351,2,0,2,9,3,0,2,0,67043391,0,3909091327,2,0,2,24,2,9,2,20,3,0,2,0,67076097,2,8,2,0,2,21,0,67059711,0,4236247039,3,0,2,0,939524103,0,8191999,2,101,2,102,2,22,2,23,3,0,3,0,67057663,3,0,349,2,103,2,104,2,7,-264,3,0,11,2,24,3,0,2,2,32,-1,0,3774349439,2,105,2,106,3,0,2,2,19,2,107,3,0,10,2,10,2,18,2,0,2,47,2,0,2,31,2,108,2,25,0,1638399,2,183,2,109,3,0,3,2,20,2,26,2,27,2,5,2,28,2,0,2,8,2,111,-1,2,112,2,113,2,114,-1,3,0,3,2,12,-2,2,0,2,29,-3,2,163,-4,2,20,2,0,2,36,0,1,2,0,2,67,2,6,2,12,2,10,2,0,2,115,-1,3,0,4,2,10,2,23,2,116,2,7,2,0,2,117,2,0,2,118,2,119,2,120,2,0,2,9,3,0,9,2,21,2,30,2,31,2,121,2,122,-2,2,123,2,124,2,30,2,21,2,8,-2,2,125,2,30,2,32,-2,2,0,2,39,-2,0,4277137519,0,2269118463,-1,3,20,2,-1,2,33,2,38,2,0,3,30,2,2,35,2,19,-3,3,0,2,2,34,-1,2,0,2,35,2,0,2,35,2,0,2,48,2,0,0,4294950463,2,37,-7,2,0,0,203775,2,57,2,167,2,20,2,43,2,36,2,18,2,37,2,18,2,126,2,21,3,0,2,2,38,0,2151677888,2,0,2,12,0,4294901764,2,144,2,0,2,58,2,56,0,5242879,3,0,2,0,402644511,-1,2,128,2,39,0,3,-1,2,129,2,130,2,0,0,67045375,2,40,0,4226678271,0,3766565279,0,2039759,2,132,2,41,0,1046437,0,6,3,0,2,0,3288270847,0,3,3,0,2,0,67043519,-5,2,0,0,4282384383,0,1056964609,-1,3,0,2,0,67043345,-1,2,0,2,42,2,23,2,50,2,11,2,61,2,38,-5,2,0,2,12,-3,3,0,2,0,2147484671,2,134,0,4190109695,2,52,-2,2,135,0,4244635647,0,27,2,0,2,8,2,43,2,0,2,68,2,18,2,0,2,42,-6,2,0,2,45,2,59,2,44,2,45,2,46,2,47,0,8388351,-2,2,136,0,3028287487,2,48,2,138,0,33259519,2,49,-9,2,21,0,4294836223,0,3355443199,0,134152199,-2,2,69,-2,3,0,28,2,32,-3,3,0,3,2,17,3,0,6,2,50,-81,2,18,3,0,2,2,36,3,0,33,2,25,2,30,3,0,124,2,12,3,0,18,2,38,-213,2,0,2,32,-54,3,0,17,2,42,2,8,2,23,2,0,2,8,2,23,2,51,2,0,2,21,2,52,2,139,2,25,-13,2,0,2,53,-6,3,0,2,-4,3,0,2,0,4294936575,2,0,0,4294934783,-2,0,196635,3,0,191,2,54,3,0,38,2,30,2,55,2,34,-278,2,140,3,0,9,2,141,2,142,2,56,3,0,11,2,7,-72,3,0,3,2,143,0,1677656575,-130,2,26,-16,2,0,2,24,2,38,-16,0,4161266656,0,4071,2,205,-4,2,57,-13,3,0,2,2,58,2,0,2,145,2,146,2,62,2,0,2,147,2,148,2,149,3,0,10,2,150,2,151,2,22,3,58,2,3,152,2,3,59,2,0,4294954999,2,0,-16,2,0,2,92,2,0,0,2105343,0,4160749584,2,177,-34,2,8,2,154,-6,0,4194303871,0,4294903771,2,0,2,60,2,100,-3,2,0,0,1073684479,0,17407,-9,2,18,2,17,2,0,2,32,-14,2,18,2,32,-6,2,18,2,12,-15,2,155,3,0,6,0,8323103,-1,3,0,2,2,61,-37,2,62,2,156,2,157,2,158,2,159,2,160,-105,2,26,-32,3,0,1335,-1,3,0,129,2,32,3,0,6,2,10,3,0,180,2,161,3,0,233,2,162,3,0,18,2,10,-77,3,0,16,2,10,-47,3,0,154,2,6,3,0,130,2,25,-22250,3,0,7,2,25,-6130,3,5,2,-1,0,69207040,3,44,2,3,0,14,2,63,2,64,-3,0,3168731136,0,4294956864,2,1,2,0,2,41,3,0,4,0,4294966275,3,0,4,2,16,2,65,2,0,2,34,-1,2,18,2,66,-1,2,0,0,2047,0,4294885376,3,0,2,0,3145727,0,2617294944,0,4294770688,2,25,2,67,3,0,2,0,131135,2,98,0,70256639,0,71303167,0,272,2,42,2,6,0,32511,2,0,2,49,-1,2,99,2,68,0,4278255616,0,4294836227,0,4294549473,0,600178175,0,2952806400,0,268632067,0,4294543328,0,57540095,0,1577058304,0,1835008,0,4294688736,2,70,2,69,0,33554435,2,131,2,70,2,164,0,131075,0,3594373096,0,67094296,2,69,-1,0,4294828e3,0,603979263,0,654311424,0,3,0,4294828001,0,602930687,2,171,0,393219,0,4294828016,0,671088639,0,2154840064,0,4227858435,0,4236247008,2,71,2,38,-1,2,4,0,917503,2,38,-1,2,72,0,537788335,0,4026531935,-1,0,1,-1,2,33,2,73,0,7936,-3,2,0,0,2147485695,0,1010761728,0,4292984930,0,16387,2,0,2,15,2,22,3,0,10,2,74,2,0,2,75,2,76,2,77,2,0,2,78,2,0,2,12,-1,2,25,3,0,2,2,13,2,4,3,0,18,2,79,2,5,3,0,2,2,80,0,2147745791,3,19,2,0,122879,2,0,2,9,0,276824064,-2,3,0,2,2,42,2,0,0,4294903295,2,0,2,30,2,8,-1,2,18,2,51,2,0,2,81,2,49,-1,2,21,2,0,2,29,-2,0,128,-2,2,28,2,9,0,8160,-1,2,127,0,4227907585,2,0,2,37,2,0,2,50,2,184,2,10,2,6,2,11,-1,0,74440192,3,0,6,-2,3,0,8,2,13,2,0,2,82,2,10,2,0,2,83,2,84,2,85,-3,2,86,2,14,-3,2,87,2,88,2,89,2,0,2,34,-83,3,0,7,0,817183,2,0,2,15,2,0,0,33023,2,21,3,90,2,-17,2,91,0,524157950,2,4,2,0,2,92,2,4,2,0,2,22,2,28,2,16,3,0,2,2,17,2,0,-1,2,18,-16,3,0,206,-2,3,0,692,2,73,-1,2,18,2,10,3,0,8,2,93,0,3072,2,0,0,2147516415,2,10,3,0,2,2,25,2,94,2,95,3,0,2,2,96,2,0,2,97,2,46,0,4294965179,0,7,2,0,2,9,2,95,2,9,-1,0,1761345536,2,98,0,4294901823,2,38,2,20,2,99,2,35,2,100,0,2080440287,2,0,2,34,2,153,0,3296722943,2,0,0,1046675455,0,939524101,0,1837055,2,101,2,102,2,22,2,23,3,0,3,0,7,3,0,349,2,103,2,104,2,7,-264,3,0,11,2,24,3,0,2,2,32,-1,0,2700607615,2,105,2,106,3,0,2,2,19,2,107,3,0,10,2,10,2,18,2,0,2,47,2,0,2,31,2,108,-3,2,109,3,0,3,2,20,-1,3,5,2,2,110,2,0,2,8,2,111,-1,2,112,2,113,2,114,-1,3,0,3,2,12,-2,2,0,2,29,-8,2,20,2,0,2,36,-1,2,0,2,67,2,6,2,30,2,10,2,0,2,115,-1,3,0,4,2,10,2,18,2,116,2,7,2,0,2,117,2,0,2,118,2,119,2,120,2,0,2,9,3,0,9,2,21,2,30,2,31,2,121,2,122,-2,2,123,2,124,2,30,2,21,2,8,-2,2,125,2,30,2,32,-2,2,0,2,39,-2,0,4277075969,2,30,-1,3,20,2,-1,2,33,2,126,2,0,3,30,2,2,35,2,19,-3,3,0,2,2,34,-1,2,0,2,35,2,0,2,35,2,0,2,50,2,98,0,4294934591,2,37,-7,2,0,0,197631,2,57,-1,2,20,2,43,2,37,2,18,0,3,2,18,2,126,2,21,2,127,2,54,-1,0,2490368,2,127,2,25,2,18,2,34,2,127,2,38,0,4294901904,0,4718591,2,127,2,35,0,335544350,-1,2,128,0,2147487743,0,1,-1,2,129,2,130,2,8,-1,2,131,2,70,0,3758161920,0,3,2,132,0,12582911,0,655360,-1,2,0,2,29,0,2147485568,0,3,2,0,2,25,0,176,-5,2,0,2,17,2,192,-1,2,0,2,25,2,209,-1,2,0,0,16779263,-2,2,12,-1,2,38,-5,2,0,2,133,-3,3,0,2,2,55,2,134,0,2147549183,0,2,-2,2,135,2,36,0,10,0,4294965249,0,67633151,0,4026597376,2,0,0,536871935,2,18,2,0,2,42,-6,2,0,0,1,2,59,2,17,0,1,2,46,2,25,-3,2,136,2,36,2,137,2,138,0,16778239,-10,2,35,0,4294836212,2,9,-3,2,69,-2,3,0,28,2,32,-3,3,0,3,2,17,3,0,6,2,50,-81,2,18,3,0,2,2,36,3,0,33,2,25,0,126,3,0,124,2,12,3,0,18,2,38,-213,2,10,-55,3,0,17,2,42,2,8,2,18,2,0,2,8,2,18,2,60,2,0,2,25,2,50,2,139,2,25,-13,2,0,2,73,-6,3,0,2,-4,3,0,2,0,67583,-1,2,107,-2,0,11,3,0,191,2,54,3,0,38,2,30,2,55,2,34,-278,2,140,3,0,9,2,141,2,142,2,56,3,0,11,2,7,-72,3,0,3,2,143,2,144,-187,3,0,2,2,58,2,0,2,145,2,146,2,62,2,0,2,147,2,148,2,149,3,0,10,2,150,2,151,2,22,3,58,2,3,152,2,3,59,2,2,153,-57,2,8,2,154,-7,2,18,2,0,2,60,-4,2,0,0,1065361407,0,16384,-9,2,18,2,60,2,0,2,133,-14,2,18,2,133,-6,2,18,0,81919,-15,2,155,3,0,6,2,126,-1,3,0,2,0,2063,-37,2,62,2,156,2,157,2,158,2,159,2,160,-138,3,0,1335,-1,3,0,129,2,32,3,0,6,2,10,3,0,180,2,161,3,0,233,2,162,3,0,18,2,10,-77,3,0,16,2,10,-47,3,0,154,2,6,3,0,130,2,25,-28386,2,0,0,1,-1,2,55,2,0,0,8193,-21,2,201,0,10255,0,4,-11,2,69,2,182,-1,0,71680,-1,2,174,0,4292900864,0,268435519,-5,2,163,-1,2,173,-1,0,6144,-2,2,46,-1,2,168,-1,0,2147532800,2,164,2,170,0,8355840,-2,0,4,-4,2,198,0,205128192,0,1333757536,0,2147483696,0,423953,0,747766272,0,2717763192,0,4286578751,0,278545,2,165,0,4294886464,0,33292336,0,417809,2,165,0,1327482464,0,4278190128,0,700594195,0,1006647527,0,4286497336,0,4160749631,2,166,0,201327104,0,3634348576,0,8323120,2,166,0,202375680,0,2678047264,0,4293984304,2,166,-1,0,983584,0,48,0,58720273,0,3489923072,0,10517376,0,4293066815,0,1,2,213,2,167,2,0,0,2089,0,3221225552,0,201359520,2,0,-2,0,256,0,122880,0,16777216,2,163,0,4160757760,2,0,-6,2,179,-11,0,3263218176,-1,0,49664,0,2160197632,0,8388802,-1,0,12713984,-1,2,168,2,186,2,187,-2,2,175,-20,0,3758096385,-2,2,169,2,195,2,94,2,180,0,4294057984,-2,2,176,2,172,0,4227874816,-2,2,169,-1,2,170,-1,2,181,2,55,0,4026593280,0,14,0,4292919296,-1,2,178,0,939588608,-1,0,805306368,-1,2,55,2,171,2,172,2,173,2,211,2,0,-2,0,8192,-4,0,267386880,-1,0,117440512,0,7168,-1,2,170,2,168,2,174,2,188,-16,2,175,-1,0,1426112704,2,176,-1,2,196,0,271581216,0,2149777408,2,25,2,174,2,55,0,851967,2,189,-1,2,177,2,190,-4,2,178,-20,2,98,2,208,-56,0,3145728,2,191,-10,0,32505856,-1,2,179,-1,0,2147385088,2,94,1,2155905152,2,-3,2,176,2,0,0,67108864,-2,2,180,-6,2,181,2,25,0,1,-1,0,1,-1,2,182,-3,2,126,2,69,-2,2,100,-2,0,32704,2,55,-915,2,183,-1,2,207,-10,2,194,-5,2,185,-6,0,3759456256,2,19,-1,2,184,-1,2,185,-2,0,4227874752,-3,0,2146435072,2,186,-2,0,1006649344,2,55,-1,2,94,0,201375744,-3,0,134217720,2,94,0,4286677377,0,32896,-1,2,178,-3,0,4227907584,-349,0,65520,0,1920,2,167,3,0,264,-11,2,173,-2,2,187,2,0,0,520617856,0,2692743168,0,36,-3,0,524280,-13,2,193,-1,0,4294934272,2,25,2,187,-1,2,215,0,2158720,-3,2,186,0,1,-4,2,55,0,3808625411,0,3489628288,0,4096,0,1207959680,0,3221274624,2,0,-3,2,188,0,120,0,7340032,-2,2,189,2,4,2,25,2,176,3,0,4,2,186,-1,2,190,2,167,-1,0,8176,2,170,2,188,0,1073741824,-1,0,4290773232,2,0,-4,2,176,2,197,0,15728640,2,167,-1,2,174,-1,0,134250480,0,4720640,0,3825467396,-1,2,180,-9,2,94,2,181,0,4294967040,2,137,0,4160880640,3,0,2,0,704,0,1849688064,2,191,-1,2,55,0,4294901887,2,0,0,130547712,0,1879048192,2,212,3,0,2,-1,2,192,2,193,-1,0,17829776,0,2025848832,0,4261477888,-2,2,0,-1,0,4286580608,-1,0,29360128,2,200,0,16252928,0,3791388672,2,130,3,0,2,-2,2,206,2,0,-1,2,107,-1,0,66584576,-1,2,199,-1,0,448,0,4294918080,3,0,6,2,55,-1,0,4294755328,0,4294967267,2,7,-1,2,174,2,187,2,25,2,98,2,25,2,194,2,94,-2,0,245760,2,195,-1,2,163,2,202,0,4227923456,-1,2,196,2,174,2,94,-3,0,4292870145,0,262144,-1,2,95,2,0,0,1073758848,2,197,-1,0,4227921920,2,198,0,68289024,0,528402016,0,4292927536,0,46080,2,191,0,4265609306,0,4294967289,-2,0,268435456,2,95,-2,2,199,3,0,5,-1,2,200,2,176,2,0,-2,0,4227923936,2,67,-1,2,187,2,197,2,99,2,168,2,178,2,204,3,0,5,-1,2,167,3,0,3,-2,0,2146959360,0,9440640,0,104857600,0,4227923840,3,0,2,0,768,2,201,2,28,-2,2,174,-2,2,202,-1,2,169,2,98,3,0,5,-1,0,4227923964,0,512,0,8388608,2,203,2,183,2,193,0,4286578944,3,0,2,0,1152,0,1266679808,2,199,0,576,0,4261707776,2,98,3,0,9,2,169,0,131072,0,939524096,2,188,3,0,2,2,16,-1,0,2147221504,-28,2,187,3,0,3,-3,0,4292902912,-6,2,99,3,0,81,2,25,-2,2,107,-33,2,18,2,181,-124,2,188,-18,2,204,3,0,213,-1,2,187,3,0,54,-17,2,169,2,55,2,205,-1,2,55,2,197,0,4290822144,-2,0,67174336,0,520093700,2,18,3,0,13,-1,2,187,3,0,6,-2,2,188,3,0,3,-2,0,30720,-1,0,32512,3,0,2,0,4294770656,-191,2,185,-38,2,181,2,8,2,206,3,0,278,0,2417033215,-9,0,4294705144,0,4292411391,0,65295,-11,2,167,3,0,72,-3,0,3758159872,0,201391616,3,0,123,-7,2,187,-13,2,180,3,0,2,-1,2,173,2,207,-3,2,99,2,0,-7,2,181,-1,0,384,-1,0,133693440,-3,2,208,-2,2,110,3,0,3,3,180,2,-2,2,94,2,169,3,0,4,-2,2,196,-1,2,163,0,335552923,2,209,-1,0,538974272,0,2214592512,0,132e3,-10,0,192,-8,2,210,-21,0,134213632,2,162,3,0,34,2,55,0,4294965279,3,0,6,0,100663424,0,63524,-1,2,214,2,152,3,0,3,-1,0,3221282816,0,4294917120,3,0,9,2,25,2,211,-1,2,212,3,0,14,2,25,2,187,3,0,6,2,25,2,213,3,0,15,0,2147520640,-6,0,4286578784,2,0,-2,0,1006694400,3,0,24,2,36,-1,0,4292870144,3,0,2,0,1,2,176,3,0,6,2,209,0,4110942569,0,1432950139,0,2701658217,0,4026532864,0,4026532881,2,0,2,47,3,0,8,-1,2,178,-2,2,180,0,98304,0,65537,2,181,-5,2,214,2,0,2,37,2,202,2,167,0,4294770176,2,110,3,0,4,-30,2,192,0,3758153728,-3,0,125829120,-2,2,187,0,4294897664,2,178,-1,2,199,-1,2,174,0,4026580992,2,95,2,0,-10,2,180,0,3758145536,0,31744,-1,0,1610628992,0,4261477376,-4,2,215,-2,2,187,3,0,32,-1335,2,0,-129,2,187,-6,2,176,-180,0,65532,-233,2,177,-18,2,176,3,0,77,-16,2,176,3,0,47,-154,2,170,-130,2,18,3,0,22250,-7,2,18,3,0,6128],[4294967295,4294967291,4092460543,4294828031,4294967294,134217726,4294903807,268435455,2147483647,1048575,1073741823,3892314111,134217727,1061158911,536805376,4294910143,4294901759,32767,4294901760,262143,536870911,8388607,4160749567,4294902783,4294918143,65535,67043328,2281701374,4294967264,2097151,4194303,255,67108863,4294967039,511,524287,131071,63,127,3238002687,4294549487,4290772991,33554431,4294901888,4286578687,67043329,4294705152,4294770687,67043583,1023,15,2047999,67043343,67051519,16777215,2147483648,4294902e3,28,4292870143,4294966783,16383,67047423,4294967279,262083,20511,41943039,493567,4294959104,603979775,65536,602799615,805044223,4294965206,8191,1031749119,4294917631,2134769663,4286578493,4282253311,4294942719,33540095,4294905855,2868854591,1608515583,265232348,534519807,2147614720,1060109444,4093640016,17376,2139062143,224,4169138175,4294909951,4286578688,4294967292,4294965759,535511039,4294966272,4294967280,32768,8289918,4294934399,4294901775,4294965375,1602223615,4294967259,4294443008,268369920,4292804608,4294967232,486341884,4294963199,3087007615,1073692671,4128527,4279238655,4294902015,4160684047,4290246655,469499899,4294967231,134086655,4294966591,2445279231,3670015,31,4294967288,4294705151,3221208447,4294902271,4294549472,4294921215,4095,4285526655,4294966527,4294966143,64,4294966719,3774873592,1877934080,262151,2555904,536807423,67043839,3758096383,3959414372,3755993023,2080374783,4294835295,4294967103,4160749565,4294934527,4087,2016,2147446655,184024726,2862017156,1593309078,268434431,268434414,4294901763,4294901761,536870912,2952790016,202506752,139264,4026531840,402653184,4261412864,63488,1610612736,4227922944,49152,65280,3233808384,3221225472,65534,61440,57152,4293918720,4290772992,25165824,57344,4227915776,4278190080,3758096384,4227858432,4160749568,3758129152,4294836224,4194304,251658240,196608,4294963200,2143289344,2097152,64512,417808,4227923712,12582912,50331648,65528,65472,4294967168,15360,4294966784,65408,4294965248,16,12288,4294934528,2080374784,2013265920,4294950912,524288]);function c(e){return e.column++,e.currentChar=e.source.charCodeAt(++e.index)}function u(e){const n=e.currentChar;if(55296!=(64512&n))return 0;const t=e.source.charCodeAt(e.index+1);return 56320!=(64512&t)?0:65536+((1023&n)<<10)+(1023&t)}function d(e,n){e.currentChar=e.source.charCodeAt(++e.index),e.flags|=1,4&n||(e.column=0,e.line++)}function g(e){e.flags|=1,e.currentChar=e.source.charCodeAt(++e.index),e.column=0,e.line++}function k(e){return e<65?e-48:e-65+10&15}function p(e){switch(e){case 134283266:return"NumericLiteral";case 134283267:return"StringLiteral";case 86021:case 86022:return"BooleanLiteral";case 86023:return"NullLiteral";case 65540:return"RegularExpression";case 67174408:case 67174409:case 131:return"TemplateLiteral";default:return 143360&~e?4096&~e?"Punctuator":"Keyword":"Identifier"}}const f=[0,0,0,0,0,0,0,0,0,0,1032,0,0,2056,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8192,0,3,0,0,8192,0,0,0,256,0,33024,0,0,242,242,114,114,114,114,114,114,594,594,0,0,16384,0,0,0,0,67,67,67,67,67,67,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,1,0,0,4099,0,71,71,71,71,71,71,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,16384,0,0,0,0],m=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0],b=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0];function h(e){return e<=127?m[e]>0:s(e)}function x(e){return e<=127?b[e]>0:function(e){return!!(1&l[0+(e>>>5)]>>>e)}(e)||8204===e||8205===e}const T=["SingleLine","MultiLine","HTMLOpen","HTMLClose","HashbangComment"];function y(e,n,t,r,a,i,s,l){return 512&r&&o(e,0),C(e,n,t,a,i,s,l)}function C(e,n,t,o,r,a,i){const{index:s}=e;for(e.tokenIndex=e.index,e.tokenLine=e.line,e.tokenColumn=e.column;e.index<e.end;){if(8&f[e.currentChar]){const t=13===e.currentChar;g(e),t&&e.index<e.end&&10===e.currentChar&&(e.currentChar=n.charCodeAt(++e.index));break}if((8232^e.currentChar)<=1){g(e);break}c(e),e.tokenIndex=e.index,e.tokenLine=e.line,e.tokenColumn=e.column}if(e.onComment){const t={start:{line:a,column:i},end:{line:e.tokenLine,column:e.tokenColumn}};e.onComment(T[255&o],n.slice(s,e.tokenIndex),r,e.tokenIndex,t)}return 1|t}function v(e,n,t){const{index:r}=e;for(;e.index<e.end;)if(e.currentChar<43){let o=!1;for(;42===e.currentChar;)if(o||(t&=-5,o=!0),47===c(e)){if(c(e),e.onComment){const t={start:{line:e.tokenLine,column:e.tokenColumn},end:{line:e.line,column:e.column}};e.onComment(T[1],n.slice(r,e.index-2),r-2,e.index,t)}return e.tokenIndex=e.index,e.tokenLine=e.line,e.tokenColumn=e.column,t}if(o)continue;8&f[e.currentChar]?13===e.currentChar?(t|=5,g(e)):(d(e,t),t=-5&t|1):c(e)}else(8232^e.currentChar)<=1?(t=-5&t|1,g(e)):(t&=-5,c(e));o(e,18)}var w,L;function I(e,n){const t=e.index;let r=w.Empty;e:for(;;){const n=e.currentChar;if(c(e),r&w.Escape)r&=~w.Escape;else switch(n){case 47:if(r)break;break e;case 92:r|=w.Escape;break;case 91:r|=w.Class;break;case 93:r&=w.Escape}if(13!==n&&10!==n&&8232!==n&&8233!==n||o(e,34),e.index>=e.source.length)return o(e,34)}const a=e.index-1;let i=L.Empty,s=e.currentChar;const{index:l}=e;for(;x(s);){switch(s){case 103:i&L.Global&&o(e,36,"g"),i|=L.Global;break;case 105:i&L.IgnoreCase&&o(e,36,"i"),i|=L.IgnoreCase;break;case 109:i&L.Multiline&&o(e,36,"m"),i|=L.Multiline;break;case 117:i&L.Unicode&&o(e,36,"u"),i&L.UnicodeSets&&o(e,36,"vu"),i|=L.Unicode;break;case 118:i&L.Unicode&&o(e,36,"uv"),i&L.UnicodeSets&&o(e,36,"v"),i|=L.UnicodeSets;break;case 121:i&L.Sticky&&o(e,36,"y"),i|=L.Sticky;break;case 115:i&L.DotAll&&o(e,36,"s"),i|=L.DotAll;break;case 100:i&L.Indices&&o(e,36,"d"),i|=L.Indices;break;default:o(e,35)}s=c(e)}const u=e.source.slice(l,e.index),d=e.source.slice(t,a);return e.tokenRegExp={pattern:d,flags:u},128&n&&(e.tokenRaw=e.source.slice(e.tokenIndex,e.index)),e.tokenValue=function(e,n,t){try{return new RegExp(n,t)}catch{try{return new RegExp(n,t),null}catch{o(e,34)}}}(e,d,u),65540}function q(e,n,t){const{index:r}=e;let a="",i=c(e),s=e.index;for(;!(8&f[i]);){if(i===t)return a+=e.source.slice(s,e.index),c(e),128&n&&(e.tokenRaw=e.source.slice(r,e.index)),e.tokenValue=a,134283267;if(!(8&~i)&&92===i){if(a+=e.source.slice(s,e.index),i=c(e),i<127||8232===i||8233===i){const t=E(e,n,i);t>=0?a+=String.fromCodePoint(t):S(e,t,0)}else a+=String.fromCodePoint(i);s=e.index+1}e.index>=e.end&&o(e,16),i=c(e)}o(e,16)}function E(e,n,t,o=0){switch(t){case 98:return 8;case 102:return 12;case 114:return 13;case 110:return 10;case 116:return 9;case 118:return 11;case 13:if(e.index<e.end){const n=e.source.charCodeAt(e.index+1);10===n&&(e.index=e.index+1,e.currentChar=n)}case 10:case 8232:case 8233:return e.column=-1,e.line++,-1;case 48:case 49:case 50:case 51:{let r=t-48,a=e.index+1,i=e.column+1;if(a<e.end){const t=e.source.charCodeAt(a);if(32&f[t]){if(256&n||o)return-2;if(e.currentChar=t,r=r<<3|t-48,a++,i++,a<e.end){const n=e.source.charCodeAt(a);32&f[n]&&(e.currentChar=n,r=r<<3|n-48,a++,i++)}e.flags|=64}else if(0!==r||512&f[t]){if(256&n||o)return-2;e.flags|=64}e.index=a-1,e.column=i-1}return r}case 52:case 53:case 54:case 55:{if(o||256&n)return-2;let r=t-48;const a=e.index+1,i=e.column+1;if(a<e.end){const n=e.source.charCodeAt(a);32&f[n]&&(r=r<<3|n-48,e.currentChar=n,e.index=a,e.column=i)}return e.flags|=64,r}case 120:{const n=c(e);if(!(64&f[n]))return-4;const t=k(n),o=c(e);if(!(64&f[o]))return-4;return t<<4|k(o)}case 117:{const n=c(e);if(123===e.currentChar){let n=0;for(;64&f[c(e)];)if(n=n<<4|k(e.currentChar),n>1114111)return-5;return e.currentChar<1||125!==e.currentChar?-4:n}{if(!(64&f[n]))return-4;const t=e.source.charCodeAt(e.index+1);if(!(64&f[t]))return-4;const o=e.source.charCodeAt(e.index+2);if(!(64&f[o]))return-4;const r=e.source.charCodeAt(e.index+3);return 64&f[r]?(e.index+=3,e.column+=3,e.currentChar=e.source.charCodeAt(e.index),k(n)<<12|k(t)<<8|k(o)<<4|k(r)):-4}}case 56:case 57:if(o||!(64&n)||256&n)return-3;e.flags|=4096;default:return t}}function S(e,n,t){switch(n){case-1:return;case-2:o(e,t?2:1);case-3:o(e,t?3:14);case-4:o(e,7);case-5:o(e,104)}}function A(e,n){const{index:t}=e;let r=67174409,a="",i=c(e);for(;96!==i;){if(36===i&&123===e.source.charCodeAt(e.index+1)){c(e),r=67174408;break}if(92===i)if(i=c(e),i>126)a+=String.fromCodePoint(i);else{const{index:t,line:o,column:s}=e,l=E(e,256|n,i,1);if(l>=0)a+=String.fromCodePoint(l);else{if(-1!==l&&16384&n){e.index=t,e.line=o,e.column=s,a=null,i=D(e,i),i<0&&(r=67174408);break}S(e,l,1)}}else e.index<e.end&&(13===i&&10===e.source.charCodeAt(e.index)&&(a+=String.fromCodePoint(i),e.currentChar=e.source.charCodeAt(++e.index)),((83&i)<3&&10===i||(8232^i)<=1)&&(e.column=-1,e.line++),a+=String.fromCodePoint(i));e.index>=e.end&&o(e,17),i=c(e)}return c(e),e.tokenValue=a,e.tokenRaw=e.source.slice(t+1,e.index-(67174409===r?1:2)),r}function D(e,n){for(;96!==n;){switch(n){case 36:{const t=e.index+1;if(t<e.end&&123===e.source.charCodeAt(t))return e.index=t,e.column++,-n;break}case 10:case 8232:case 8233:e.column=-1,e.line++}e.index>=e.end&&o(e,17),n=c(e)}return n}function V(e,n){return e.index>=e.end&&o(e,0),e.index--,e.column--,A(e,n)}function R(e,n,t){let r=e.currentChar,a=0,s=9,l=64&t?0:1,u=0,d=0;if(64&t)a="."+N(e,r),r=e.currentChar,110===r&&o(e,12);else{if(48===r)if(r=c(e),120==(32|r)){for(t=136,r=c(e);4160&f[r];)95!==r?(d=1,a=16*a+k(r),u++,r=c(e)):(d||o(e,152),d=0,r=c(e));0!==u&&d||o(e,0===u?21:153)}else if(111==(32|r)){for(t=132,r=c(e);4128&f[r];)95!==r?(d=1,a=8*a+(r-48),u++,r=c(e)):(d||o(e,152),d=0,r=c(e));0!==u&&d||o(e,0===u?0:153)}else if(98==(32|r)){for(t=130,r=c(e);4224&f[r];)95!==r?(d=1,a=2*a+(r-48),u++,r=c(e)):(d||o(e,152),d=0,r=c(e));0!==u&&d||o(e,0===u?0:153)}else if(32&f[r])for(256&n&&o(e,1),t=1;16&f[r];){if(512&f[r]){t=32,l=0;break}a=8*a+(r-48),r=c(e)}else 512&f[r]?(256&n&&o(e,1),e.flags|=64,t=32):95===r&&o(e,0);if(48&t){if(l){for(;s>=0&&4112&f[r];)95!==r?(d=0,a=10*a+(r-48),r=c(e),--s):(r=c(e),(95===r||32&t)&&i(e.index,e.line,e.column,e.index+1,e.line,e.column,152),d=1);if(d&&i(e.index,e.line,e.column,e.index+1,e.line,e.column,153),s>=0&&!h(r)&&46!==r)return e.tokenValue=a,128&n&&(e.tokenRaw=e.source.slice(e.tokenIndex,e.index)),134283266}a+=N(e,r),r=e.currentChar,46===r&&(95===c(e)&&o(e,0),t=64,a+="."+N(e,e.currentChar),r=e.currentChar)}}const g=e.index;let p=0;if(110===r&&128&t)p=1,r=c(e);else if(101==(32|r)){r=c(e),256&f[r]&&(r=c(e));const{index:n}=e;16&f[r]||o(e,11),a+=e.source.substring(g,n)+N(e,r),r=e.currentChar}return(e.index<e.end&&16&f[r]||h(r))&&o(e,13),p?(e.tokenRaw=e.source.slice(e.tokenIndex,e.index),e.tokenValue=BigInt(e.tokenRaw.slice(0,-1).replaceAll("_","")),134283388):(e.tokenValue=15&t?a:32&t?parseFloat(e.source.substring(e.tokenIndex,e.index)):+a,128&n&&(e.tokenRaw=e.source.slice(e.tokenIndex,e.index)),134283266)}function N(e,n){let t=0,o=e.index,r="";for(;4112&f[n];)if(95!==n)t=0,n=c(e);else{const{index:a}=e;95===(n=c(e))&&i(e.index,e.line,e.column,e.index+1,e.line,e.column,152),t=1,r+=e.source.substring(o,a),o=e.index}return t&&i(e.index,e.line,e.column,e.index+1,e.line,e.column,153),r+e.source.substring(o,e.index)}!function(e){e[e.Empty=0]="Empty",e[e.Escape=1]="Escape",e[e.Class=2]="Class"}(w||(w={})),function(e){e[e.Empty=0]="Empty",e[e.IgnoreCase=1]="IgnoreCase",e[e.Global=2]="Global",e[e.Multiline=4]="Multiline",e[e.Unicode=16]="Unicode",e[e.Sticky=8]="Sticky",e[e.DotAll=32]="DotAll",e[e.Indices=64]="Indices",e[e.UnicodeSets=128]="UnicodeSets"}(L||(L={}));const U=["end of source","identifier","number","string","regular expression","false","true","null","template continuation","template tail","=>","(","{",".","...","}",")",";",",","[","]",":","?","'",'"',"++","--","=","<<=",">>=",">>>=","**=","+=","-=","*=","/=","%=","^=","|=","&=","||=","&&=","??=","typeof","delete","void","!","~","+","-","in","instanceof","*","%","/","**","&&","||","===","!==","==","!=","<=",">=","<",">","<<",">>",">>>","&","|","^","var","let","const","break","case","catch","class","continue","debugger","default","do","else","export","extends","finally","for","function","if","import","new","return","super","switch","this","throw","try","while","with","implements","interface","package","private","protected","public","static","yield","as","async","await","constructor","get","set","accessor","from","of","enum","eval","arguments","escaped keyword","escaped future reserved keyword","reserved if strict","#","BigIntLiteral","??","?.","WhiteSpace","Illegal","LineTerminator","PrivateField","Template","@","target","meta","LineFeed","Escaped","JSXText"],P=Object.create(null,{this:{value:86111},function:{value:86104},if:{value:20569},return:{value:20572},var:{value:86088},else:{value:20563},for:{value:20567},new:{value:86107},in:{value:8673330},typeof:{value:16863275},while:{value:20578},case:{value:20556},break:{value:20555},try:{value:20577},catch:{value:20557},delete:{value:16863276},throw:{value:86112},switch:{value:86110},continue:{value:20559},default:{value:20561},instanceof:{value:8411187},do:{value:20562},void:{value:16863277},finally:{value:20566},async:{value:209005},await:{value:209006},class:{value:86094},const:{value:86090},constructor:{value:12399},debugger:{value:20560},export:{value:20564},extends:{value:20565},false:{value:86021},from:{value:12403},get:{value:12400},implements:{value:36964},import:{value:86106},interface:{value:36965},let:{value:241737},null:{value:86023},of:{value:274548},package:{value:36966},private:{value:36967},protected:{value:36968},public:{value:36969},set:{value:12401},static:{value:36970},super:{value:86109},true:{value:86022},with:{value:20579},yield:{value:241771},enum:{value:86133},eval:{value:537079926},as:{value:77932},arguments:{value:537079927},target:{value:209029},meta:{value:209030},accessor:{value:12402}});function B(e,n,t){for(;b[c(e)];);return e.tokenValue=e.source.slice(e.tokenIndex,e.index),92!==e.currentChar&&e.currentChar<=126?P[e.tokenValue]||208897:G(e,n,0,t)}function O(e,n){const t=j(e);return h(t)||o(e,5),e.tokenValue=String.fromCodePoint(t),G(e,n,1,4&f[t])}function G(e,n,t,r){let a=e.index;for(;e.index<e.end;)if(92===e.currentChar){e.tokenValue+=e.source.slice(a,e.index),t=1;const n=j(e);x(n)||o(e,5),r=r&&4&f[n],e.tokenValue+=String.fromCodePoint(n),a=e.index}else{const n=u(e);if(n>0)x(n)||o(e,20,String.fromCodePoint(n)),e.currentChar=n,e.index++,e.column++;else if(!x(e.currentChar))break;c(e)}e.index<=e.end&&(e.tokenValue+=e.source.slice(a,e.index));const{length:i}=e.tokenValue;if(r&&i>=2&&i<=11){const o=P[e.tokenValue];return void 0===o?208897|(t?-2147483648:0):t?209006===o?524800&n?-2147483528:-2147483648|o:256&n?36970===o?-2147483527:36864&~o?20480&~o?-2147274630:67108864&n&&!(2048&n)?-2147483648|o:-2147483528:-2147483527:!(67108864&n)||2048&n||20480&~o?241771===o?67108864&n?-2147274630:262144&n?-2147483528:-2147483648|o:209005===o?-2147274630:36864&~o?-2147483528:12288|o|-2147483648:-2147483648|o:o}return 208897|(t?-2147483648:0)}function F(e){let n=c(e);if(92===n)return 130;const t=u(e);return t&&(n=t),h(n)||o(e,96),130}function j(e){return 117!==e.source.charCodeAt(e.index+1)&&o(e,5),e.currentChar=e.source.charCodeAt(e.index+=2),function(e){let n=0;const t=e.currentChar;if(123===t){const t=e.index-2;for(;64&f[c(e)];)n=n<<4|k(e.currentChar),n>1114111&&i(t,e.line,e.column,e.index,e.line,e.column,104);return 125!==e.currentChar&&i(t,e.line,e.column,e.index,e.line,e.column,7),c(e),n}64&f[t]||o(e,7);const r=e.source.charCodeAt(e.index+1);64&f[r]||o(e,7);const a=e.source.charCodeAt(e.index+2);64&f[a]||o(e,7);const s=e.source.charCodeAt(e.index+3);64&f[s]||o(e,7);return n=k(t)<<12|k(r)<<8|k(a)<<4|k(s),e.currentChar=e.source.charCodeAt(e.index+=4),n}(e)}const J=[128,128,128,128,128,128,128,128,128,127,135,127,127,129,128,128,128,128,128,128,128,128,128,128,128,128,128,128,128,128,128,128,127,16842798,134283267,130,208897,8391477,8390213,134283267,67174411,16,8391476,25233968,18,25233969,67108877,8457014,134283266,134283266,134283266,134283266,134283266,134283266,134283266,134283266,134283266,134283266,21,1074790417,8456256,1077936155,8390721,22,132,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,69271571,136,20,8389959,208897,131,4096,4096,4096,4096,4096,4096,4096,208897,4096,208897,208897,4096,208897,4096,208897,4096,208897,4096,4096,4096,208897,4096,4096,208897,4096,4096,2162700,8389702,1074790415,16842799,128];function H(e,n){e.flags=1^(1|e.flags),e.startIndex=e.index,e.startColumn=e.column,e.startLine=e.line,e.setToken(M(e,n,0))}function M(e,n,t){const r=0===e.index,{source:a}=e;let i=e.index,l=e.line,k=e.column;for(;e.index<e.end;){e.tokenIndex=e.index,e.tokenColumn=e.column,e.tokenLine=e.line;let f=e.currentChar;if(f<=126){const s=J[f];switch(s){case 67174411:case 16:case 2162700:case 1074790415:case 69271571:case 20:case 21:case 1074790417:case 18:case 16842799:case 132:case 128:return c(e),s;case 208897:return B(e,n,0);case 4096:return B(e,n,1);case 134283266:return R(e,n,144);case 134283267:return q(e,n,f);case 131:return A(e,n);case 136:return O(e,n);case 130:return F(e);case 127:c(e);break;case 129:t|=5,g(e);break;case 135:d(e,t),t=-5&t|1;break;case 8456256:{const o=c(e);if(e.index<e.end){if(60===o)return e.index<e.end&&61===c(e)?(c(e),4194332):8390978;if(61===o)return c(e),8390718;if(33===o){const o=e.index+1;if(o+1<e.end&&45===a.charCodeAt(o)&&45==a.charCodeAt(o+1)){e.column+=3,e.currentChar=a.charCodeAt(e.index+=3),t=y(e,a,t,n,2,e.tokenIndex,e.tokenLine,e.tokenColumn),i=e.tokenIndex,l=e.tokenLine,k=e.tokenColumn;continue}return 8456256}}return 8456256}case 1077936155:{c(e);const n=e.currentChar;return 61===n?61===c(e)?(c(e),8390458):8390460:62===n?(c(e),10):1077936155}case 16842798:return 61!==c(e)?16842798:61!==c(e)?8390461:(c(e),8390459);case 8391477:return 61!==c(e)?8391477:(c(e),4194340);case 8391476:{if(c(e),e.index>=e.end)return 8391476;const n=e.currentChar;return 61===n?(c(e),4194338):42!==n?8391476:61!==c(e)?8391735:(c(e),4194335)}case 8389959:return 61!==c(e)?8389959:(c(e),4194341);case 25233968:{c(e);const n=e.currentChar;return 43===n?(c(e),33619993):61===n?(c(e),4194336):25233968}case 25233969:{c(e);const s=e.currentChar;if(45===s){if(c(e),(1&t||r)&&62===e.currentChar){64&n||o(e,112),c(e),t=y(e,a,t,n,3,i,l,k),i=e.tokenIndex,l=e.tokenLine,k=e.tokenColumn;continue}return 33619994}return 61===s?(c(e),4194337):25233969}case 8457014:if(c(e),e.index<e.end){const o=e.currentChar;if(47===o){c(e),t=C(e,a,t,0,e.tokenIndex,e.tokenLine,e.tokenColumn),i=e.tokenIndex,l=e.tokenLine,k=e.tokenColumn;continue}if(42===o){c(e),t=v(e,a,t),i=e.tokenIndex,l=e.tokenLine,k=e.tokenColumn;continue}if(8192&n)return I(e,n);if(61===o)return c(e),4259875}return 8457014;case 67108877:{const t=c(e);if(t>=48&&t<=57)return R(e,n,80);if(46===t){const n=e.index+1;if(n<e.end&&46===a.charCodeAt(n))return e.column+=2,e.currentChar=a.charCodeAt(e.index+=2),14}return 67108877}case 8389702:{c(e);const n=e.currentChar;return 124===n?(c(e),61===e.currentChar?(c(e),4194344):8913465):61===n?(c(e),4194342):8389702}case 8390721:{c(e);const n=e.currentChar;if(61===n)return c(e),8390719;if(62!==n)return 8390721;if(c(e),e.index<e.end){const n=e.currentChar;if(62===n)return 61===c(e)?(c(e),4194334):8390980;if(61===n)return c(e),4194333}return 8390979}case 8390213:{c(e);const n=e.currentChar;return 38===n?(c(e),61===e.currentChar?(c(e),4194345):8913720):61===n?(c(e),4194343):8390213}case 22:{let n=c(e);if(63===n)return c(e),61===e.currentChar?(c(e),4194346):276824445;if(46===n){const t=e.index+1;if(t<e.end&&(n=a.charCodeAt(t),!(n>=48&&n<=57)))return c(e),67108990}return 22}}}else{if((8232^f)<=1){t=-5&t|1,g(e);continue}const r=u(e);if(r>0&&(f=r),s(f))return e.tokenValue="",G(e,n,0,0);if(160===(p=f)||65279===p||133===p||5760===p||p>=8192&&p<=8203||8239===p||8287===p||12288===p||8201===p||65519===p){c(e);continue}o(e,20,String.fromCodePoint(f))}}var p;return 1048576}const z={AElig:"Æ",AMP:"&",Aacute:"Á",Abreve:"Ă",Acirc:"Â",Acy:"А",Afr:"𝔄",Agrave:"À",Alpha:"Α",Amacr:"Ā",And:"⩓",Aogon:"Ą",Aopf:"𝔸",ApplyFunction:"⁡",Aring:"Å",Ascr:"𝒜",Assign:"≔",Atilde:"Ã",Auml:"Ä",Backslash:"∖",Barv:"⫧",Barwed:"⌆",Bcy:"Б",Because:"∵",Bernoullis:"ℬ",Beta:"Β",Bfr:"𝔅",Bopf:"𝔹",Breve:"˘",Bscr:"ℬ",Bumpeq:"≎",CHcy:"Ч",COPY:"©",Cacute:"Ć",Cap:"⋒",CapitalDifferentialD:"ⅅ",Cayleys:"ℭ",Ccaron:"Č",Ccedil:"Ç",Ccirc:"Ĉ",Cconint:"∰",Cdot:"Ċ",Cedilla:"¸",CenterDot:"·",Cfr:"ℭ",Chi:"Χ",CircleDot:"⊙",CircleMinus:"⊖",CirclePlus:"⊕",CircleTimes:"⊗",ClockwiseContourIntegral:"∲",CloseCurlyDoubleQuote:"”",CloseCurlyQuote:"’",Colon:"∷",Colone:"⩴",Congruent:"≡",Conint:"∯",ContourIntegral:"∮",Copf:"ℂ",Coproduct:"∐",CounterClockwiseContourIntegral:"∳",Cross:"⨯",Cscr:"𝒞",Cup:"⋓",CupCap:"≍",DD:"ⅅ",DDotrahd:"⤑",DJcy:"Ђ",DScy:"Ѕ",DZcy:"Џ",Dagger:"‡",Darr:"↡",Dashv:"⫤",Dcaron:"Ď",Dcy:"Д",Del:"∇",Delta:"Δ",Dfr:"𝔇",DiacriticalAcute:"´",DiacriticalDot:"˙",DiacriticalDoubleAcute:"˝",DiacriticalGrave:"`",DiacriticalTilde:"˜",Diamond:"⋄",DifferentialD:"ⅆ",Dopf:"𝔻",Dot:"¨",DotDot:"⃜",DotEqual:"≐",DoubleContourIntegral:"∯",DoubleDot:"¨",DoubleDownArrow:"⇓",DoubleLeftArrow:"⇐",DoubleLeftRightArrow:"⇔",DoubleLeftTee:"⫤",DoubleLongLeftArrow:"⟸",DoubleLongLeftRightArrow:"⟺",DoubleLongRightArrow:"⟹",DoubleRightArrow:"⇒",DoubleRightTee:"⊨",DoubleUpArrow:"⇑",DoubleUpDownArrow:"⇕",DoubleVerticalBar:"∥",DownArrow:"↓",DownArrowBar:"⤓",DownArrowUpArrow:"⇵",DownBreve:"̑",DownLeftRightVector:"⥐",DownLeftTeeVector:"⥞",DownLeftVector:"↽",DownLeftVectorBar:"⥖",DownRightTeeVector:"⥟",DownRightVector:"⇁",DownRightVectorBar:"⥗",DownTee:"⊤",DownTeeArrow:"↧",Downarrow:"⇓",Dscr:"𝒟",Dstrok:"Đ",ENG:"Ŋ",ETH:"Ð",Eacute:"É",Ecaron:"Ě",Ecirc:"Ê",Ecy:"Э",Edot:"Ė",Efr:"𝔈",Egrave:"È",Element:"∈",Emacr:"Ē",EmptySmallSquare:"◻",EmptyVerySmallSquare:"▫",Eogon:"Ę",Eopf:"𝔼",Epsilon:"Ε",Equal:"⩵",EqualTilde:"≂",Equilibrium:"⇌",Escr:"ℰ",Esim:"⩳",Eta:"Η",Euml:"Ë",Exists:"∃",ExponentialE:"ⅇ",Fcy:"Ф",Ffr:"𝔉",FilledSmallSquare:"◼",FilledVerySmallSquare:"▪",Fopf:"𝔽",ForAll:"∀",Fouriertrf:"ℱ",Fscr:"ℱ",GJcy:"Ѓ",GT:">",Gamma:"Γ",Gammad:"Ϝ",Gbreve:"Ğ",Gcedil:"Ģ",Gcirc:"Ĝ",Gcy:"Г",Gdot:"Ġ",Gfr:"𝔊",Gg:"⋙",Gopf:"𝔾",GreaterEqual:"≥",GreaterEqualLess:"⋛",GreaterFullEqual:"≧",GreaterGreater:"⪢",GreaterLess:"≷",GreaterSlantEqual:"⩾",GreaterTilde:"≳",Gscr:"𝒢",Gt:"≫",HARDcy:"Ъ",Hacek:"ˇ",Hat:"^",Hcirc:"Ĥ",Hfr:"ℌ",HilbertSpace:"ℋ",Hopf:"ℍ",HorizontalLine:"─",Hscr:"ℋ",Hstrok:"Ħ",HumpDownHump:"≎",HumpEqual:"≏",IEcy:"Е",IJlig:"Ĳ",IOcy:"Ё",Iacute:"Í",Icirc:"Î",Icy:"И",Idot:"İ",Ifr:"ℑ",Igrave:"Ì",Im:"ℑ",Imacr:"Ī",ImaginaryI:"ⅈ",Implies:"⇒",Int:"∬",Integral:"∫",Intersection:"⋂",InvisibleComma:"⁣",InvisibleTimes:"⁢",Iogon:"Į",Iopf:"𝕀",Iota:"Ι",Iscr:"ℐ",Itilde:"Ĩ",Iukcy:"І",Iuml:"Ï",Jcirc:"Ĵ",Jcy:"Й",Jfr:"𝔍",Jopf:"𝕁",Jscr:"𝒥",Jsercy:"Ј",Jukcy:"Є",KHcy:"Х",KJcy:"Ќ",Kappa:"Κ",Kcedil:"Ķ",Kcy:"К",Kfr:"𝔎",Kopf:"𝕂",Kscr:"𝒦",LJcy:"Љ",LT:"<",Lacute:"Ĺ",Lambda:"Λ",Lang:"⟪",Laplacetrf:"ℒ",Larr:"↞",Lcaron:"Ľ",Lcedil:"Ļ",Lcy:"Л",LeftAngleBracket:"⟨",LeftArrow:"←",LeftArrowBar:"⇤",LeftArrowRightArrow:"⇆",LeftCeiling:"⌈",LeftDoubleBracket:"⟦",LeftDownTeeVector:"⥡",LeftDownVector:"⇃",LeftDownVectorBar:"⥙",LeftFloor:"⌊",LeftRightArrow:"↔",LeftRightVector:"⥎",LeftTee:"⊣",LeftTeeArrow:"↤",LeftTeeVector:"⥚",LeftTriangle:"⊲",LeftTriangleBar:"⧏",LeftTriangleEqual:"⊴",LeftUpDownVector:"⥑",LeftUpTeeVector:"⥠",LeftUpVector:"↿",LeftUpVectorBar:"⥘",LeftVector:"↼",LeftVectorBar:"⥒",Leftarrow:"⇐",Leftrightarrow:"⇔",LessEqualGreater:"⋚",LessFullEqual:"≦",LessGreater:"≶",LessLess:"⪡",LessSlantEqual:"⩽",LessTilde:"≲",Lfr:"𝔏",Ll:"⋘",Lleftarrow:"⇚",Lmidot:"Ŀ",LongLeftArrow:"⟵",LongLeftRightArrow:"⟷",LongRightArrow:"⟶",Longleftarrow:"⟸",Longleftrightarrow:"⟺",Longrightarrow:"⟹",Lopf:"𝕃",LowerLeftArrow:"↙",LowerRightArrow:"↘",Lscr:"ℒ",Lsh:"↰",Lstrok:"Ł",Lt:"≪",Map:"⤅",Mcy:"М",MediumSpace:" ",Mellintrf:"ℳ",Mfr:"𝔐",MinusPlus:"∓",Mopf:"𝕄",Mscr:"ℳ",Mu:"Μ",NJcy:"Њ",Nacute:"Ń",Ncaron:"Ň",Ncedil:"Ņ",Ncy:"Н",NegativeMediumSpace:"​",NegativeThickSpace:"​",NegativeThinSpace:"​",NegativeVeryThinSpace:"​",NestedGreaterGreater:"≫",NestedLessLess:"≪",NewLine:"\n",Nfr:"𝔑",NoBreak:"⁠",NonBreakingSpace:" ",Nopf:"ℕ",Not:"⫬",NotCongruent:"≢",NotCupCap:"≭",NotDoubleVerticalBar:"∦",NotElement:"∉",NotEqual:"≠",NotEqualTilde:"≂̸",NotExists:"∄",NotGreater:"≯",NotGreaterEqual:"≱",NotGreaterFullEqual:"≧̸",NotGreaterGreater:"≫̸",NotGreaterLess:"≹",NotGreaterSlantEqual:"⩾̸",NotGreaterTilde:"≵",NotHumpDownHump:"≎̸",NotHumpEqual:"≏̸",NotLeftTriangle:"⋪",NotLeftTriangleBar:"⧏̸",NotLeftTriangleEqual:"⋬",NotLess:"≮",NotLessEqual:"≰",NotLessGreater:"≸",NotLessLess:"≪̸",NotLessSlantEqual:"⩽̸",NotLessTilde:"≴",NotNestedGreaterGreater:"⪢̸",NotNestedLessLess:"⪡̸",NotPrecedes:"⊀",NotPrecedesEqual:"⪯̸",NotPrecedesSlantEqual:"⋠",NotReverseElement:"∌",NotRightTriangle:"⋫",NotRightTriangleBar:"⧐̸",NotRightTriangleEqual:"⋭",NotSquareSubset:"⊏̸",NotSquareSubsetEqual:"⋢",NotSquareSuperset:"⊐̸",NotSquareSupersetEqual:"⋣",NotSubset:"⊂⃒",NotSubsetEqual:"⊈",NotSucceeds:"⊁",NotSucceedsEqual:"⪰̸",NotSucceedsSlantEqual:"⋡",NotSucceedsTilde:"≿̸",NotSuperset:"⊃⃒",NotSupersetEqual:"⊉",NotTilde:"≁",NotTildeEqual:"≄",NotTildeFullEqual:"≇",NotTildeTilde:"≉",NotVerticalBar:"∤",Nscr:"𝒩",Ntilde:"Ñ",Nu:"Ν",OElig:"Œ",Oacute:"Ó",Ocirc:"Ô",Ocy:"О",Odblac:"Ő",Ofr:"𝔒",Ograve:"Ò",Omacr:"Ō",Omega:"Ω",Omicron:"Ο",Oopf:"𝕆",OpenCurlyDoubleQuote:"“",OpenCurlyQuote:"‘",Or:"⩔",Oscr:"𝒪",Oslash:"Ø",Otilde:"Õ",Otimes:"⨷",Ouml:"Ö",OverBar:"‾",OverBrace:"⏞",OverBracket:"⎴",OverParenthesis:"⏜",PartialD:"∂",Pcy:"П",Pfr:"𝔓",Phi:"Φ",Pi:"Π",PlusMinus:"±",Poincareplane:"ℌ",Popf:"ℙ",Pr:"⪻",Precedes:"≺",PrecedesEqual:"⪯",PrecedesSlantEqual:"≼",PrecedesTilde:"≾",Prime:"″",Product:"∏",Proportion:"∷",Proportional:"∝",Pscr:"𝒫",Psi:"Ψ",QUOT:'"',Qfr:"𝔔",Qopf:"ℚ",Qscr:"𝒬",RBarr:"⤐",REG:"®",Racute:"Ŕ",Rang:"⟫",Rarr:"↠",Rarrtl:"⤖",Rcaron:"Ř",Rcedil:"Ŗ",Rcy:"Р",Re:"ℜ",ReverseElement:"∋",ReverseEquilibrium:"⇋",ReverseUpEquilibrium:"⥯",Rfr:"ℜ",Rho:"Ρ",RightAngleBracket:"⟩",RightArrow:"→",RightArrowBar:"⇥",RightArrowLeftArrow:"⇄",RightCeiling:"⌉",RightDoubleBracket:"⟧",RightDownTeeVector:"⥝",RightDownVector:"⇂",RightDownVectorBar:"⥕",RightFloor:"⌋",RightTee:"⊢",RightTeeArrow:"↦",RightTeeVector:"⥛",RightTriangle:"⊳",RightTriangleBar:"⧐",RightTriangleEqual:"⊵",RightUpDownVector:"⥏",RightUpTeeVector:"⥜",RightUpVector:"↾",RightUpVectorBar:"⥔",RightVector:"⇀",RightVectorBar:"⥓",Rightarrow:"⇒",Ropf:"ℝ",RoundImplies:"⥰",Rrightarrow:"⇛",Rscr:"ℛ",Rsh:"↱",RuleDelayed:"⧴",SHCHcy:"Щ",SHcy:"Ш",SOFTcy:"Ь",Sacute:"Ś",Sc:"⪼",Scaron:"Š",Scedil:"Ş",Scirc:"Ŝ",Scy:"С",Sfr:"𝔖",ShortDownArrow:"↓",ShortLeftArrow:"←",ShortRightArrow:"→",ShortUpArrow:"↑",Sigma:"Σ",SmallCircle:"∘",Sopf:"𝕊",Sqrt:"√",Square:"□",SquareIntersection:"⊓",SquareSubset:"⊏",SquareSubsetEqual:"⊑",SquareSuperset:"⊐",SquareSupersetEqual:"⊒",SquareUnion:"⊔",Sscr:"𝒮",Star:"⋆",Sub:"⋐",Subset:"⋐",SubsetEqual:"⊆",Succeeds:"≻",SucceedsEqual:"⪰",SucceedsSlantEqual:"≽",SucceedsTilde:"≿",SuchThat:"∋",Sum:"∑",Sup:"⋑",Superset:"⊃",SupersetEqual:"⊇",Supset:"⋑",THORN:"Þ",TRADE:"™",TSHcy:"Ћ",TScy:"Ц",Tab:"\t",Tau:"Τ",Tcaron:"Ť",Tcedil:"Ţ",Tcy:"Т",Tfr:"𝔗",Therefore:"∴",Theta:"Θ",ThickSpace:"  ",ThinSpace:" ",Tilde:"∼",TildeEqual:"≃",TildeFullEqual:"≅",TildeTilde:"≈",Topf:"𝕋",TripleDot:"⃛",Tscr:"𝒯",Tstrok:"Ŧ",Uacute:"Ú",Uarr:"↟",Uarrocir:"⥉",Ubrcy:"Ў",Ubreve:"Ŭ",Ucirc:"Û",Ucy:"У",Udblac:"Ű",Ufr:"𝔘",Ugrave:"Ù",Umacr:"Ū",UnderBar:"_",UnderBrace:"⏟",UnderBracket:"⎵",UnderParenthesis:"⏝",Union:"⋃",UnionPlus:"⊎",Uogon:"Ų",Uopf:"𝕌",UpArrow:"↑",UpArrowBar:"⤒",UpArrowDownArrow:"⇅",UpDownArrow:"↕",UpEquilibrium:"⥮",UpTee:"⊥",UpTeeArrow:"↥",Uparrow:"⇑",Updownarrow:"⇕",UpperLeftArrow:"↖",UpperRightArrow:"↗",Upsi:"ϒ",Upsilon:"Υ",Uring:"Ů",Uscr:"𝒰",Utilde:"Ũ",Uuml:"Ü",VDash:"⊫",Vbar:"⫫",Vcy:"В",Vdash:"⊩",Vdashl:"⫦",Vee:"⋁",Verbar:"‖",Vert:"‖",VerticalBar:"∣",VerticalLine:"|",VerticalSeparator:"❘",VerticalTilde:"≀",VeryThinSpace:" ",Vfr:"𝔙",Vopf:"𝕍",Vscr:"𝒱",Vvdash:"⊪",Wcirc:"Ŵ",Wedge:"⋀",Wfr:"𝔚",Wopf:"𝕎",Wscr:"𝒲",Xfr:"𝔛",Xi:"Ξ",Xopf:"𝕏",Xscr:"𝒳",YAcy:"Я",YIcy:"Ї",YUcy:"Ю",Yacute:"Ý",Ycirc:"Ŷ",Ycy:"Ы",Yfr:"𝔜",Yopf:"𝕐",Yscr:"𝒴",Yuml:"Ÿ",ZHcy:"Ж",Zacute:"Ź",Zcaron:"Ž",Zcy:"З",Zdot:"Ż",ZeroWidthSpace:"​",Zeta:"Ζ",Zfr:"ℨ",Zopf:"ℤ",Zscr:"𝒵",aacute:"á",abreve:"ă",ac:"∾",acE:"∾̳",acd:"∿",acirc:"â",acute:"´",acy:"а",aelig:"æ",af:"⁡",afr:"𝔞",agrave:"à",alefsym:"ℵ",aleph:"ℵ",alpha:"α",amacr:"ā",amalg:"⨿",amp:"&",and:"∧",andand:"⩕",andd:"⩜",andslope:"⩘",andv:"⩚",ang:"∠",ange:"⦤",angle:"∠",angmsd:"∡",angmsdaa:"⦨",angmsdab:"⦩",angmsdac:"⦪",angmsdad:"⦫",angmsdae:"⦬",angmsdaf:"⦭",angmsdag:"⦮",angmsdah:"⦯",angrt:"∟",angrtvb:"⊾",angrtvbd:"⦝",angsph:"∢",angst:"Å",angzarr:"⍼",aogon:"ą",aopf:"𝕒",ap:"≈",apE:"⩰",apacir:"⩯",ape:"≊",apid:"≋",apos:"'",approx:"≈",approxeq:"≊",aring:"å",ascr:"𝒶",ast:"*",asymp:"≈",asympeq:"≍",atilde:"ã",auml:"ä",awconint:"∳",awint:"⨑",bNot:"⫭",backcong:"≌",backepsilon:"϶",backprime:"‵",backsim:"∽",backsimeq:"⋍",barvee:"⊽",barwed:"⌅",barwedge:"⌅",bbrk:"⎵",bbrktbrk:"⎶",bcong:"≌",bcy:"б",bdquo:"„",becaus:"∵",because:"∵",bemptyv:"⦰",bepsi:"϶",bernou:"ℬ",beta:"β",beth:"ℶ",between:"≬",bfr:"𝔟",bigcap:"⋂",bigcirc:"◯",bigcup:"⋃",bigodot:"⨀",bigoplus:"⨁",bigotimes:"⨂",bigsqcup:"⨆",bigstar:"★",bigtriangledown:"▽",bigtriangleup:"△",biguplus:"⨄",bigvee:"⋁",bigwedge:"⋀",bkarow:"⤍",blacklozenge:"⧫",blacksquare:"▪",blacktriangle:"▴",blacktriangledown:"▾",blacktriangleleft:"◂",blacktriangleright:"▸",blank:"␣",blk12:"▒",blk14:"░",blk34:"▓",block:"█",bne:"=⃥",bnequiv:"≡⃥",bnot:"⌐",bopf:"𝕓",bot:"⊥",bottom:"⊥",bowtie:"⋈",boxDL:"╗",boxDR:"╔",boxDl:"╖",boxDr:"╓",boxH:"═",boxHD:"╦",boxHU:"╩",boxHd:"╤",boxHu:"╧",boxUL:"╝",boxUR:"╚",boxUl:"╜",boxUr:"╙",boxV:"║",boxVH:"╬",boxVL:"╣",boxVR:"╠",boxVh:"╫",boxVl:"╢",boxVr:"╟",boxbox:"⧉",boxdL:"╕",boxdR:"╒",boxdl:"┐",boxdr:"┌",boxh:"─",boxhD:"╥",boxhU:"╨",boxhd:"┬",boxhu:"┴",boxminus:"⊟",boxplus:"⊞",boxtimes:"⊠",boxuL:"╛",boxuR:"╘",boxul:"┘",boxur:"└",boxv:"│",boxvH:"╪",boxvL:"╡",boxvR:"╞",boxvh:"┼",boxvl:"┤",boxvr:"├",bprime:"‵",breve:"˘",brvbar:"¦",bscr:"𝒷",bsemi:"⁏",bsim:"∽",bsime:"⋍",bsol:"\\",bsolb:"⧅",bsolhsub:"⟈",bull:"•",bullet:"•",bump:"≎",bumpE:"⪮",bumpe:"≏",bumpeq:"≏",cacute:"ć",cap:"∩",capand:"⩄",capbrcup:"⩉",capcap:"⩋",capcup:"⩇",capdot:"⩀",caps:"∩︀",caret:"⁁",caron:"ˇ",ccaps:"⩍",ccaron:"č",ccedil:"ç",ccirc:"ĉ",ccups:"⩌",ccupssm:"⩐",cdot:"ċ",cedil:"¸",cemptyv:"⦲",cent:"¢",centerdot:"·",cfr:"𝔠",chcy:"ч",check:"✓",checkmark:"✓",chi:"χ",cir:"○",cirE:"⧃",circ:"ˆ",circeq:"≗",circlearrowleft:"↺",circlearrowright:"↻",circledR:"®",circledS:"Ⓢ",circledast:"⊛",circledcirc:"⊚",circleddash:"⊝",cire:"≗",cirfnint:"⨐",cirmid:"⫯",cirscir:"⧂",clubs:"♣",clubsuit:"♣",colon:":",colone:"≔",coloneq:"≔",comma:",",commat:"@",comp:"∁",compfn:"∘",complement:"∁",complexes:"ℂ",cong:"≅",congdot:"⩭",conint:"∮",copf:"𝕔",coprod:"∐",copy:"©",copysr:"℗",crarr:"↵",cross:"✗",cscr:"𝒸",csub:"⫏",csube:"⫑",csup:"⫐",csupe:"⫒",ctdot:"⋯",cudarrl:"⤸",cudarrr:"⤵",cuepr:"⋞",cuesc:"⋟",cularr:"↶",cularrp:"⤽",cup:"∪",cupbrcap:"⩈",cupcap:"⩆",cupcup:"⩊",cupdot:"⊍",cupor:"⩅",cups:"∪︀",curarr:"↷",curarrm:"⤼",curlyeqprec:"⋞",curlyeqsucc:"⋟",curlyvee:"⋎",curlywedge:"⋏",curren:"¤",curvearrowleft:"↶",curvearrowright:"↷",cuvee:"⋎",cuwed:"⋏",cwconint:"∲",cwint:"∱",cylcty:"⌭",dArr:"⇓",dHar:"⥥",dagger:"†",daleth:"ℸ",darr:"↓",dash:"‐",dashv:"⊣",dbkarow:"⤏",dblac:"˝",dcaron:"ď",dcy:"д",dd:"ⅆ",ddagger:"‡",ddarr:"⇊",ddotseq:"⩷",deg:"°",delta:"δ",demptyv:"⦱",dfisht:"⥿",dfr:"𝔡",dharl:"⇃",dharr:"⇂",diam:"⋄",diamond:"⋄",diamondsuit:"♦",diams:"♦",die:"¨",digamma:"ϝ",disin:"⋲",div:"÷",divide:"÷",divideontimes:"⋇",divonx:"⋇",djcy:"ђ",dlcorn:"⌞",dlcrop:"⌍",dollar:"$",dopf:"𝕕",dot:"˙",doteq:"≐",doteqdot:"≑",dotminus:"∸",dotplus:"∔",dotsquare:"⊡",doublebarwedge:"⌆",downarrow:"↓",downdownarrows:"⇊",downharpoonleft:"⇃",downharpoonright:"⇂",drbkarow:"⤐",drcorn:"⌟",drcrop:"⌌",dscr:"𝒹",dscy:"ѕ",dsol:"⧶",dstrok:"đ",dtdot:"⋱",dtri:"▿",dtrif:"▾",duarr:"⇵",duhar:"⥯",dwangle:"⦦",dzcy:"џ",dzigrarr:"⟿",eDDot:"⩷",eDot:"≑",eacute:"é",easter:"⩮",ecaron:"ě",ecir:"≖",ecirc:"ê",ecolon:"≕",ecy:"э",edot:"ė",ee:"ⅇ",efDot:"≒",efr:"𝔢",eg:"⪚",egrave:"è",egs:"⪖",egsdot:"⪘",el:"⪙",elinters:"⏧",ell:"ℓ",els:"⪕",elsdot:"⪗",emacr:"ē",empty:"∅",emptyset:"∅",emptyv:"∅",emsp13:" ",emsp14:" ",emsp:" ",eng:"ŋ",ensp:" ",eogon:"ę",eopf:"𝕖",epar:"⋕",eparsl:"⧣",eplus:"⩱",epsi:"ε",epsilon:"ε",epsiv:"ϵ",eqcirc:"≖",eqcolon:"≕",eqsim:"≂",eqslantgtr:"⪖",eqslantless:"⪕",equals:"=",equest:"≟",equiv:"≡",equivDD:"⩸",eqvparsl:"⧥",erDot:"≓",erarr:"⥱",escr:"ℯ",esdot:"≐",esim:"≂",eta:"η",eth:"ð",euml:"ë",euro:"€",excl:"!",exist:"∃",expectation:"ℰ",exponentiale:"ⅇ",fallingdotseq:"≒",fcy:"ф",female:"♀",ffilig:"ﬃ",fflig:"ﬀ",ffllig:"ﬄ",ffr:"𝔣",filig:"ﬁ",fjlig:"fj",flat:"♭",fllig:"ﬂ",fltns:"▱",fnof:"ƒ",fopf:"𝕗",forall:"∀",fork:"⋔",forkv:"⫙",fpartint:"⨍",frac12:"½",frac13:"⅓",frac14:"¼",frac15:"⅕",frac16:"⅙",frac18:"⅛",frac23:"⅔",frac25:"⅖",frac34:"¾",frac35:"⅗",frac38:"⅜",frac45:"⅘",frac56:"⅚",frac58:"⅝",frac78:"⅞",frasl:"⁄",frown:"⌢",fscr:"𝒻",gE:"≧",gEl:"⪌",gacute:"ǵ",gamma:"γ",gammad:"ϝ",gap:"⪆",gbreve:"ğ",gcirc:"ĝ",gcy:"г",gdot:"ġ",ge:"≥",gel:"⋛",geq:"≥",geqq:"≧",geqslant:"⩾",ges:"⩾",gescc:"⪩",gesdot:"⪀",gesdoto:"⪂",gesdotol:"⪄",gesl:"⋛︀",gesles:"⪔",gfr:"𝔤",gg:"≫",ggg:"⋙",gimel:"ℷ",gjcy:"ѓ",gl:"≷",glE:"⪒",gla:"⪥",glj:"⪤",gnE:"≩",gnap:"⪊",gnapprox:"⪊",gne:"⪈",gneq:"⪈",gneqq:"≩",gnsim:"⋧",gopf:"𝕘",grave:"`",gscr:"ℊ",gsim:"≳",gsime:"⪎",gsiml:"⪐",gt:">",gtcc:"⪧",gtcir:"⩺",gtdot:"⋗",gtlPar:"⦕",gtquest:"⩼",gtrapprox:"⪆",gtrarr:"⥸",gtrdot:"⋗",gtreqless:"⋛",gtreqqless:"⪌",gtrless:"≷",gtrsim:"≳",gvertneqq:"≩︀",gvnE:"≩︀",hArr:"⇔",hairsp:" ",half:"½",hamilt:"ℋ",hardcy:"ъ",harr:"↔",harrcir:"⥈",harrw:"↭",hbar:"ℏ",hcirc:"ĥ",hearts:"♥",heartsuit:"♥",hellip:"…",hercon:"⊹",hfr:"𝔥",hksearow:"⤥",hkswarow:"⤦",hoarr:"⇿",homtht:"∻",hookleftarrow:"↩",hookrightarrow:"↪",hopf:"𝕙",horbar:"―",hscr:"𝒽",hslash:"ℏ",hstrok:"ħ",hybull:"⁃",hyphen:"‐",iacute:"í",ic:"⁣",icirc:"î",icy:"и",iecy:"е",iexcl:"¡",iff:"⇔",ifr:"𝔦",igrave:"ì",ii:"ⅈ",iiiint:"⨌",iiint:"∭",iinfin:"⧜",iiota:"℩",ijlig:"ĳ",imacr:"ī",image:"ℑ",imagline:"ℐ",imagpart:"ℑ",imath:"ı",imof:"⊷",imped:"Ƶ",in:"∈",incare:"℅",infin:"∞",infintie:"⧝",inodot:"ı",int:"∫",intcal:"⊺",integers:"ℤ",intercal:"⊺",intlarhk:"⨗",intprod:"⨼",iocy:"ё",iogon:"į",iopf:"𝕚",iota:"ι",iprod:"⨼",iquest:"¿",iscr:"𝒾",isin:"∈",isinE:"⋹",isindot:"⋵",isins:"⋴",isinsv:"⋳",isinv:"∈",it:"⁢",itilde:"ĩ",iukcy:"і",iuml:"ï",jcirc:"ĵ",jcy:"й",jfr:"𝔧",jmath:"ȷ",jopf:"𝕛",jscr:"𝒿",jsercy:"ј",jukcy:"є",kappa:"κ",kappav:"ϰ",kcedil:"ķ",kcy:"к",kfr:"𝔨",kgreen:"ĸ",khcy:"х",kjcy:"ќ",kopf:"𝕜",kscr:"𝓀",lAarr:"⇚",lArr:"⇐",lAtail:"⤛",lBarr:"⤎",lE:"≦",lEg:"⪋",lHar:"⥢",lacute:"ĺ",laemptyv:"⦴",lagran:"ℒ",lambda:"λ",lang:"⟨",langd:"⦑",langle:"⟨",lap:"⪅",laquo:"«",larr:"←",larrb:"⇤",larrbfs:"⤟",larrfs:"⤝",larrhk:"↩",larrlp:"↫",larrpl:"⤹",larrsim:"⥳",larrtl:"↢",lat:"⪫",latail:"⤙",late:"⪭",lates:"⪭︀",lbarr:"⤌",lbbrk:"❲",lbrace:"{",lbrack:"[",lbrke:"⦋",lbrksld:"⦏",lbrkslu:"⦍",lcaron:"ľ",lcedil:"ļ",lceil:"⌈",lcub:"{",lcy:"л",ldca:"⤶",ldquo:"“",ldquor:"„",ldrdhar:"⥧",ldrushar:"⥋",ldsh:"↲",le:"≤",leftarrow:"←",leftarrowtail:"↢",leftharpoondown:"↽",leftharpoonup:"↼",leftleftarrows:"⇇",leftrightarrow:"↔",leftrightarrows:"⇆",leftrightharpoons:"⇋",leftrightsquigarrow:"↭",leftthreetimes:"⋋",leg:"⋚",leq:"≤",leqq:"≦",leqslant:"⩽",les:"⩽",lescc:"⪨",lesdot:"⩿",lesdoto:"⪁",lesdotor:"⪃",lesg:"⋚︀",lesges:"⪓",lessapprox:"⪅",lessdot:"⋖",lesseqgtr:"⋚",lesseqqgtr:"⪋",lessgtr:"≶",lesssim:"≲",lfisht:"⥼",lfloor:"⌊",lfr:"𝔩",lg:"≶",lgE:"⪑",lhard:"↽",lharu:"↼",lharul:"⥪",lhblk:"▄",ljcy:"љ",ll:"≪",llarr:"⇇",llcorner:"⌞",llhard:"⥫",lltri:"◺",lmidot:"ŀ",lmoust:"⎰",lmoustache:"⎰",lnE:"≨",lnap:"⪉",lnapprox:"⪉",lne:"⪇",lneq:"⪇",lneqq:"≨",lnsim:"⋦",loang:"⟬",loarr:"⇽",lobrk:"⟦",longleftarrow:"⟵",longleftrightarrow:"⟷",longmapsto:"⟼",longrightarrow:"⟶",looparrowleft:"↫",looparrowright:"↬",lopar:"⦅",lopf:"𝕝",loplus:"⨭",lotimes:"⨴",lowast:"∗",lowbar:"_",loz:"◊",lozenge:"◊",lozf:"⧫",lpar:"(",lparlt:"⦓",lrarr:"⇆",lrcorner:"⌟",lrhar:"⇋",lrhard:"⥭",lrm:"‎",lrtri:"⊿",lsaquo:"‹",lscr:"𝓁",lsh:"↰",lsim:"≲",lsime:"⪍",lsimg:"⪏",lsqb:"[",lsquo:"‘",lsquor:"‚",lstrok:"ł",lt:"<",ltcc:"⪦",ltcir:"⩹",ltdot:"⋖",lthree:"⋋",ltimes:"⋉",ltlarr:"⥶",ltquest:"⩻",ltrPar:"⦖",ltri:"◃",ltrie:"⊴",ltrif:"◂",lurdshar:"⥊",luruhar:"⥦",lvertneqq:"≨︀",lvnE:"≨︀",mDDot:"∺",macr:"¯",male:"♂",malt:"✠",maltese:"✠",map:"↦",mapsto:"↦",mapstodown:"↧",mapstoleft:"↤",mapstoup:"↥",marker:"▮",mcomma:"⨩",mcy:"м",mdash:"—",measuredangle:"∡",mfr:"𝔪",mho:"℧",micro:"µ",mid:"∣",midast:"*",midcir:"⫰",middot:"·",minus:"−",minusb:"⊟",minusd:"∸",minusdu:"⨪",mlcp:"⫛",mldr:"…",mnplus:"∓",models:"⊧",mopf:"𝕞",mp:"∓",mscr:"𝓂",mstpos:"∾",mu:"μ",multimap:"⊸",mumap:"⊸",nGg:"⋙̸",nGt:"≫⃒",nGtv:"≫̸",nLeftarrow:"⇍",nLeftrightarrow:"⇎",nLl:"⋘̸",nLt:"≪⃒",nLtv:"≪̸",nRightarrow:"⇏",nVDash:"⊯",nVdash:"⊮",nabla:"∇",nacute:"ń",nang:"∠⃒",nap:"≉",napE:"⩰̸",napid:"≋̸",napos:"ŉ",napprox:"≉",natur:"♮",natural:"♮",naturals:"ℕ",nbsp:" ",nbump:"≎̸",nbumpe:"≏̸",ncap:"⩃",ncaron:"ň",ncedil:"ņ",ncong:"≇",ncongdot:"⩭̸",ncup:"⩂",ncy:"н",ndash:"–",ne:"≠",neArr:"⇗",nearhk:"⤤",nearr:"↗",nearrow:"↗",nedot:"≐̸",nequiv:"≢",nesear:"⤨",nesim:"≂̸",nexist:"∄",nexists:"∄",nfr:"𝔫",ngE:"≧̸",nge:"≱",ngeq:"≱",ngeqq:"≧̸",ngeqslant:"⩾̸",nges:"⩾̸",ngsim:"≵",ngt:"≯",ngtr:"≯",nhArr:"⇎",nharr:"↮",nhpar:"⫲",ni:"∋",nis:"⋼",nisd:"⋺",niv:"∋",njcy:"њ",nlArr:"⇍",nlE:"≦̸",nlarr:"↚",nldr:"‥",nle:"≰",nleftarrow:"↚",nleftrightarrow:"↮",nleq:"≰",nleqq:"≦̸",nleqslant:"⩽̸",nles:"⩽̸",nless:"≮",nlsim:"≴",nlt:"≮",nltri:"⋪",nltrie:"⋬",nmid:"∤",nopf:"𝕟",not:"¬",notin:"∉",notinE:"⋹̸",notindot:"⋵̸",notinva:"∉",notinvb:"⋷",notinvc:"⋶",notni:"∌",notniva:"∌",notnivb:"⋾",notnivc:"⋽",npar:"∦",nparallel:"∦",nparsl:"⫽⃥",npart:"∂̸",npolint:"⨔",npr:"⊀",nprcue:"⋠",npre:"⪯̸",nprec:"⊀",npreceq:"⪯̸",nrArr:"⇏",nrarr:"↛",nrarrc:"⤳̸",nrarrw:"↝̸",nrightarrow:"↛",nrtri:"⋫",nrtrie:"⋭",nsc:"⊁",nsccue:"⋡",nsce:"⪰̸",nscr:"𝓃",nshortmid:"∤",nshortparallel:"∦",nsim:"≁",nsime:"≄",nsimeq:"≄",nsmid:"∤",nspar:"∦",nsqsube:"⋢",nsqsupe:"⋣",nsub:"⊄",nsubE:"⫅̸",nsube:"⊈",nsubset:"⊂⃒",nsubseteq:"⊈",nsubseteqq:"⫅̸",nsucc:"⊁",nsucceq:"⪰̸",nsup:"⊅",nsupE:"⫆̸",nsupe:"⊉",nsupset:"⊃⃒",nsupseteq:"⊉",nsupseteqq:"⫆̸",ntgl:"≹",ntilde:"ñ",ntlg:"≸",ntriangleleft:"⋪",ntrianglelefteq:"⋬",ntriangleright:"⋫",ntrianglerighteq:"⋭",nu:"ν",num:"#",numero:"№",numsp:" ",nvDash:"⊭",nvHarr:"⤄",nvap:"≍⃒",nvdash:"⊬",nvge:"≥⃒",nvgt:">⃒",nvinfin:"⧞",nvlArr:"⤂",nvle:"≤⃒",nvlt:"<⃒",nvltrie:"⊴⃒",nvrArr:"⤃",nvrtrie:"⊵⃒",nvsim:"∼⃒",nwArr:"⇖",nwarhk:"⤣",nwarr:"↖",nwarrow:"↖",nwnear:"⤧",oS:"Ⓢ",oacute:"ó",oast:"⊛",ocir:"⊚",ocirc:"ô",ocy:"о",odash:"⊝",odblac:"ő",odiv:"⨸",odot:"⊙",odsold:"⦼",oelig:"œ",ofcir:"⦿",ofr:"𝔬",ogon:"˛",ograve:"ò",ogt:"⧁",ohbar:"⦵",ohm:"Ω",oint:"∮",olarr:"↺",olcir:"⦾",olcross:"⦻",oline:"‾",olt:"⧀",omacr:"ō",omega:"ω",omicron:"ο",omid:"⦶",ominus:"⊖",oopf:"𝕠",opar:"⦷",operp:"⦹",oplus:"⊕",or:"∨",orarr:"↻",ord:"⩝",order:"ℴ",orderof:"ℴ",ordf:"ª",ordm:"º",origof:"⊶",oror:"⩖",orslope:"⩗",orv:"⩛",oscr:"ℴ",oslash:"ø",osol:"⊘",otilde:"õ",otimes:"⊗",otimesas:"⨶",ouml:"ö",ovbar:"⌽",par:"∥",para:"¶",parallel:"∥",parsim:"⫳",parsl:"⫽",part:"∂",pcy:"п",percnt:"%",period:".",permil:"‰",perp:"⊥",pertenk:"‱",pfr:"𝔭",phi:"φ",phiv:"ϕ",phmmat:"ℳ",phone:"☎",pi:"π",pitchfork:"⋔",piv:"ϖ",planck:"ℏ",planckh:"ℎ",plankv:"ℏ",plus:"+",plusacir:"⨣",plusb:"⊞",pluscir:"⨢",plusdo:"∔",plusdu:"⨥",pluse:"⩲",plusmn:"±",plussim:"⨦",plustwo:"⨧",pm:"±",pointint:"⨕",popf:"𝕡",pound:"£",pr:"≺",prE:"⪳",prap:"⪷",prcue:"≼",pre:"⪯",prec:"≺",precapprox:"⪷",preccurlyeq:"≼",preceq:"⪯",precnapprox:"⪹",precneqq:"⪵",precnsim:"⋨",precsim:"≾",prime:"′",primes:"ℙ",prnE:"⪵",prnap:"⪹",prnsim:"⋨",prod:"∏",profalar:"⌮",profline:"⌒",profsurf:"⌓",prop:"∝",propto:"∝",prsim:"≾",prurel:"⊰",pscr:"𝓅",psi:"ψ",puncsp:" ",qfr:"𝔮",qint:"⨌",qopf:"𝕢",qprime:"⁗",qscr:"𝓆",quaternions:"ℍ",quatint:"⨖",quest:"?",questeq:"≟",quot:'"',rAarr:"⇛",rArr:"⇒",rAtail:"⤜",rBarr:"⤏",rHar:"⥤",race:"∽̱",racute:"ŕ",radic:"√",raemptyv:"⦳",rang:"⟩",rangd:"⦒",range:"⦥",rangle:"⟩",raquo:"»",rarr:"→",rarrap:"⥵",rarrb:"⇥",rarrbfs:"⤠",rarrc:"⤳",rarrfs:"⤞",rarrhk:"↪",rarrlp:"↬",rarrpl:"⥅",rarrsim:"⥴",rarrtl:"↣",rarrw:"↝",ratail:"⤚",ratio:"∶",rationals:"ℚ",rbarr:"⤍",rbbrk:"❳",rbrace:"}",rbrack:"]",rbrke:"⦌",rbrksld:"⦎",rbrkslu:"⦐",rcaron:"ř",rcedil:"ŗ",rceil:"⌉",rcub:"}",rcy:"р",rdca:"⤷",rdldhar:"⥩",rdquo:"”",rdquor:"”",rdsh:"↳",real:"ℜ",realine:"ℛ",realpart:"ℜ",reals:"ℝ",rect:"▭",reg:"®",rfisht:"⥽",rfloor:"⌋",rfr:"𝔯",rhard:"⇁",rharu:"⇀",rharul:"⥬",rho:"ρ",rhov:"ϱ",rightarrow:"→",rightarrowtail:"↣",rightharpoondown:"⇁",rightharpoonup:"⇀",rightleftarrows:"⇄",rightleftharpoons:"⇌",rightrightarrows:"⇉",rightsquigarrow:"↝",rightthreetimes:"⋌",ring:"˚",risingdotseq:"≓",rlarr:"⇄",rlhar:"⇌",rlm:"‏",rmoust:"⎱",rmoustache:"⎱",rnmid:"⫮",roang:"⟭",roarr:"⇾",robrk:"⟧",ropar:"⦆",ropf:"𝕣",roplus:"⨮",rotimes:"⨵",rpar:")",rpargt:"⦔",rppolint:"⨒",rrarr:"⇉",rsaquo:"›",rscr:"𝓇",rsh:"↱",rsqb:"]",rsquo:"’",rsquor:"’",rthree:"⋌",rtimes:"⋊",rtri:"▹",rtrie:"⊵",rtrif:"▸",rtriltri:"⧎",ruluhar:"⥨",rx:"℞",sacute:"ś",sbquo:"‚",sc:"≻",scE:"⪴",scap:"⪸",scaron:"š",sccue:"≽",sce:"⪰",scedil:"ş",scirc:"ŝ",scnE:"⪶",scnap:"⪺",scnsim:"⋩",scpolint:"⨓",scsim:"≿",scy:"с",sdot:"⋅",sdotb:"⊡",sdote:"⩦",seArr:"⇘",searhk:"⤥",searr:"↘",searrow:"↘",sect:"§",semi:";",seswar:"⤩",setminus:"∖",setmn:"∖",sext:"✶",sfr:"𝔰",sfrown:"⌢",sharp:"♯",shchcy:"щ",shcy:"ш",shortmid:"∣",shortparallel:"∥",shy:"­",sigma:"σ",sigmaf:"ς",sigmav:"ς",sim:"∼",simdot:"⩪",sime:"≃",simeq:"≃",simg:"⪞",simgE:"⪠",siml:"⪝",simlE:"⪟",simne:"≆",simplus:"⨤",simrarr:"⥲",slarr:"←",smallsetminus:"∖",smashp:"⨳",smeparsl:"⧤",smid:"∣",smile:"⌣",smt:"⪪",smte:"⪬",smtes:"⪬︀",softcy:"ь",sol:"/",solb:"⧄",solbar:"⌿",sopf:"𝕤",spades:"♠",spadesuit:"♠",spar:"∥",sqcap:"⊓",sqcaps:"⊓︀",sqcup:"⊔",sqcups:"⊔︀",sqsub:"⊏",sqsube:"⊑",sqsubset:"⊏",sqsubseteq:"⊑",sqsup:"⊐",sqsupe:"⊒",sqsupset:"⊐",sqsupseteq:"⊒",squ:"□",square:"□",squarf:"▪",squf:"▪",srarr:"→",sscr:"𝓈",ssetmn:"∖",ssmile:"⌣",sstarf:"⋆",star:"☆",starf:"★",straightepsilon:"ϵ",straightphi:"ϕ",strns:"¯",sub:"⊂",subE:"⫅",subdot:"⪽",sube:"⊆",subedot:"⫃",submult:"⫁",subnE:"⫋",subne:"⊊",subplus:"⪿",subrarr:"⥹",subset:"⊂",subseteq:"⊆",subseteqq:"⫅",subsetneq:"⊊",subsetneqq:"⫋",subsim:"⫇",subsub:"⫕",subsup:"⫓",succ:"≻",succapprox:"⪸",succcurlyeq:"≽",succeq:"⪰",succnapprox:"⪺",succneqq:"⪶",succnsim:"⋩",succsim:"≿",sum:"∑",sung:"♪",sup1:"¹",sup2:"²",sup3:"³",sup:"⊃",supE:"⫆",supdot:"⪾",supdsub:"⫘",supe:"⊇",supedot:"⫄",suphsol:"⟉",suphsub:"⫗",suplarr:"⥻",supmult:"⫂",supnE:"⫌",supne:"⊋",supplus:"⫀",supset:"⊃",supseteq:"⊇",supseteqq:"⫆",supsetneq:"⊋",supsetneqq:"⫌",supsim:"⫈",supsub:"⫔",supsup:"⫖",swArr:"⇙",swarhk:"⤦",swarr:"↙",swarrow:"↙",swnwar:"⤪",szlig:"ß",target:"⌖",tau:"τ",tbrk:"⎴",tcaron:"ť",tcedil:"ţ",tcy:"т",tdot:"⃛",telrec:"⌕",tfr:"𝔱",there4:"∴",therefore:"∴",theta:"θ",thetasym:"ϑ",thetav:"ϑ",thickapprox:"≈",thicksim:"∼",thinsp:" ",thkap:"≈",thksim:"∼",thorn:"þ",tilde:"˜",times:"×",timesb:"⊠",timesbar:"⨱",timesd:"⨰",tint:"∭",toea:"⤨",top:"⊤",topbot:"⌶",topcir:"⫱",topf:"𝕥",topfork:"⫚",tosa:"⤩",tprime:"‴",trade:"™",triangle:"▵",triangledown:"▿",triangleleft:"◃",trianglelefteq:"⊴",triangleq:"≜",triangleright:"▹",trianglerighteq:"⊵",tridot:"◬",trie:"≜",triminus:"⨺",triplus:"⨹",trisb:"⧍",tritime:"⨻",trpezium:"⏢",tscr:"𝓉",tscy:"ц",tshcy:"ћ",tstrok:"ŧ",twixt:"≬",twoheadleftarrow:"↞",twoheadrightarrow:"↠",uArr:"⇑",uHar:"⥣",uacute:"ú",uarr:"↑",ubrcy:"ў",ubreve:"ŭ",ucirc:"û",ucy:"у",udarr:"⇅",udblac:"ű",udhar:"⥮",ufisht:"⥾",ufr:"𝔲",ugrave:"ù",uharl:"↿",uharr:"↾",uhblk:"▀",ulcorn:"⌜",ulcorner:"⌜",ulcrop:"⌏",ultri:"◸",umacr:"ū",uml:"¨",uogon:"ų",uopf:"𝕦",uparrow:"↑",updownarrow:"↕",upharpoonleft:"↿",upharpoonright:"↾",uplus:"⊎",upsi:"υ",upsih:"ϒ",upsilon:"υ",upuparrows:"⇈",urcorn:"⌝",urcorner:"⌝",urcrop:"⌎",uring:"ů",urtri:"◹",uscr:"𝓊",utdot:"⋰",utilde:"ũ",utri:"▵",utrif:"▴",uuarr:"⇈",uuml:"ü",uwangle:"⦧",vArr:"⇕",vBar:"⫨",vBarv:"⫩",vDash:"⊨",vangrt:"⦜",varepsilon:"ϵ",varkappa:"ϰ",varnothing:"∅",varphi:"ϕ",varpi:"ϖ",varpropto:"∝",varr:"↕",varrho:"ϱ",varsigma:"ς",varsubsetneq:"⊊︀",varsubsetneqq:"⫋︀",varsupsetneq:"⊋︀",varsupsetneqq:"⫌︀",vartheta:"ϑ",vartriangleleft:"⊲",vartriangleright:"⊳",vcy:"в",vdash:"⊢",vee:"∨",veebar:"⊻",veeeq:"≚",vellip:"⋮",verbar:"|",vert:"|",vfr:"𝔳",vltri:"⊲",vnsub:"⊂⃒",vnsup:"⊃⃒",vopf:"𝕧",vprop:"∝",vrtri:"⊳",vscr:"𝓋",vsubnE:"⫋︀",vsubne:"⊊︀",vsupnE:"⫌︀",vsupne:"⊋︀",vzigzag:"⦚",wcirc:"ŵ",wedbar:"⩟",wedge:"∧",wedgeq:"≙",weierp:"℘",wfr:"𝔴",wopf:"𝕨",wp:"℘",wr:"≀",wreath:"≀",wscr:"𝓌",xcap:"⋂",xcirc:"◯",xcup:"⋃",xdtri:"▽",xfr:"𝔵",xhArr:"⟺",xharr:"⟷",xi:"ξ",xlArr:"⟸",xlarr:"⟵",xmap:"⟼",xnis:"⋻",xodot:"⨀",xopf:"𝕩",xoplus:"⨁",xotime:"⨂",xrArr:"⟹",xrarr:"⟶",xscr:"𝓍",xsqcup:"⨆",xuplus:"⨄",xutri:"△",xvee:"⋁",xwedge:"⋀",yacute:"ý",yacy:"я",ycirc:"ŷ",ycy:"ы",yen:"¥",yfr:"𝔶",yicy:"ї",yopf:"𝕪",yscr:"𝓎",yucy:"ю",yuml:"ÿ",zacute:"ź",zcaron:"ž",zcy:"з",zdot:"ż",zeetrf:"ℨ",zeta:"ζ",zfr:"𝔷",zhcy:"ж",zigrarr:"⇝",zopf:"𝕫",zscr:"𝓏",zwj:"‍",zwnj:"‌"},X={0:65533,128:8364,130:8218,131:402,132:8222,133:8230,134:8224,135:8225,136:710,137:8240,138:352,139:8249,140:338,142:381,145:8216,146:8217,147:8220,148:8221,149:8226,150:8211,151:8212,152:732,153:8482,154:353,155:8250,156:339,158:382,159:376};function _(e){return e.replace(/&(?:[a-zA-Z]+|#[xX][\da-fA-F]+|#\d+);/g,(e=>{if("#"===e.charAt(1)){const n=e.charAt(2);return function(e){if(e>=55296&&e<=57343||e>1114111)return"�";e in X&&(e=X[e]);return String.fromCodePoint(e)}("X"===n||"x"===n?parseInt(e.slice(3),16):parseInt(e.slice(2),10))}return z[e.slice(1,-1)]||e}))}function $(e,n){return e.startIndex=e.tokenIndex=e.index,e.startColumn=e.tokenColumn=e.column,e.startLine=e.tokenLine=e.line,e.setToken(8192&f[e.currentChar]?function(e,n){const t=e.currentChar;let r=c(e);const a=e.index;for(;r!==t;)e.index>=e.end&&o(e,16),r=c(e);r!==t&&o(e,16);e.tokenValue=e.source.slice(a,e.index),c(e),128&n&&(e.tokenRaw=e.source.slice(e.tokenIndex,e.index));return 134283267}(e,n):M(e,n,0)),e.getToken()}function Y(e,n){if(e.startIndex=e.tokenIndex=e.index,e.startColumn=e.tokenColumn=e.column,e.startLine=e.tokenLine=e.line,e.index>=e.end)return void e.setToken(1048576);if(60===e.currentChar)return c(e),void e.setToken(8456256);if(123===e.currentChar)return c(e),void e.setToken(2162700);let t=0;for(;e.index<e.end;){const n=f[e.source.charCodeAt(e.index)];if(1024&n?(t|=5,g(e)):2048&n?(d(e,t),t=-5&t|1):c(e),16384&f[e.currentChar])break}e.tokenIndex===e.index&&o(e,0);const r=e.source.slice(e.tokenIndex,e.index);128&n&&(e.tokenRaw=r),e.tokenValue=_(r),e.setToken(137)}function Z(e){if(!(143360&~e.getToken())){const{index:n}=e;let t=e.currentChar;for(;32770&f[t];)t=c(e);e.tokenValue+=e.source.slice(n,e.index)}return e.setToken(208897,!0),e.getToken()}function W(e,n){!(1&e.flags)&&1048576&~e.getToken()&&o(e,30,U[255&e.getToken()]),ee(e,n,1074790417)||e.onInsertedSemicolon?.(e.startIndex)}function K(e,n,t,o){return n-t<13&&"use strict"===o&&(!(1048576&~e.getToken())||1&e.flags)?1:0}function Q(e,n,t){return e.getToken()!==t?0:(H(e,n),1)}function ee(e,n,t){return e.getToken()===t&&(H(e,n),!0)}function ne(e,n,t){e.getToken()!==t&&o(e,25,U[255&t]),H(e,n)}function te(e,n){switch(n.type){case"ArrayExpression":{n.type="ArrayPattern";const{elements:t}=n;for(let n=0,o=t.length;n<o;++n){const o=t[n];o&&te(e,o)}return}case"ObjectExpression":{n.type="ObjectPattern";const{properties:t}=n;for(let n=0,o=t.length;n<o;++n)te(e,t[n]);return}case"AssignmentExpression":return n.type="AssignmentPattern","="!==n.operator&&o(e,71),delete n.operator,void te(e,n.left);case"Property":return void te(e,n.value);case"SpreadElement":n.type="RestElement",te(e,n.argument)}}function oe(e,n,t,r,a){256&n&&(36864&~r||o(e,118),a||537079808&~r||o(e,119)),20480&~r&&-2147483528!==r||o(e,102),24&t&&73==(255&r)&&o(e,100),524800&n&&209006===r&&o(e,110),262400&n&&241771===r&&o(e,97,"yield")}function re(e,n,t){256&n&&(36864&~t||o(e,118),537079808&~t||o(e,119),-2147483527===t&&o(e,95),-2147483528===t&&o(e,95)),20480&~t||o(e,102),524800&n&&209006===t&&o(e,110),262400&n&&241771===t&&o(e,97,"yield")}function ae(e,n,t){return 209006===t&&(524800&n&&o(e,110),e.destructible|=128),241771===t&&262144&n&&o(e,97,"yield"),!(20480&~t&&36864&~t&&-2147483527!=t)}function ie(e,n,t,r){for(;n;){if(n["$"+t])return r&&o(e,137),1;r&&n.loop&&(r=0),n=n.$}return 0}function se(e,n,t,o,r,a){return 2&n&&(a.start=t,a.end=e.startIndex,a.range=[t,e.startIndex]),4&n&&(a.loc={start:{line:o,column:r},end:{line:e.startLine,column:e.startColumn}},e.sourceFile&&(a.loc.source=e.sourceFile)),a}function le(e){switch(e.type){case"JSXIdentifier":return e.name;case"JSXNamespacedName":return e.namespace+":"+e.name;case"JSXMemberExpression":return le(e.object)+"."+le(e.property)}}function ce(e,n,t){const o=de({parent:void 0,type:2},1024);return ke(e,n,o,t,1,0),o}function ue(e,n,...t){const{index:o,line:r,column:a,tokenIndex:i,tokenLine:s,tokenColumn:l}=e;return{type:n,params:t,index:o,line:r,column:a,tokenIndex:i,tokenLine:s,tokenColumn:l}}function de(e,n){return{parent:e,type:n,scopeError:void 0}}function ge(e,n,t,o,r,a){4&r?pe(e,n,t,o,r):ke(e,n,t,o,r,a),64&a&&me(e,o)}function ke(e,n,t,r,a,i){const s=t["#"+r];!s||2&s||(1&a?t.scopeError=ue(e,145,r):64&n&&!(256&n)&&2&i&&64===s&&64===a||o(e,145,r)),128&t.type&&t.parent["#"+r]&&!(2&t.parent["#"+r])&&o(e,145,r),1024&t.type&&s&&!(2&s)&&1&a&&(t.scopeError=ue(e,145,r)),64&t.type&&768&t.parent["#"+r]&&o(e,159,r),t["#"+r]=a}function pe(e,n,t,r,a){let i=t;for(;i&&!(256&i.type);){const s=i["#"+r];248&s&&(64&n&&!(256&n)&&(128&a&&68&s||128&s&&68&a)||o(e,145,r)),i===t&&1&s&&1&a&&(i.scopeError=ue(e,145,r)),(256&s||512&s&&!(64&n))&&o(e,145,r),i["#"+r]=a,i=i.parent}}function fe(e,n){return n["#"+e]?1:n.parent?fe(e,n.parent):0}function me(e,n){void 0!==e.exportedNames&&""!==n&&(e.exportedNames["#"+n]&&o(e,147,n),e.exportedNames["#"+n]=1)}function be(e,n){return 262400&e?!(512&e&&209006===n)&&(!(262144&e&&241771===n)&&!(12288&~n)):!(12288&~n&&36864&~n)}function he(e,n,t){537079808&~t||(256&n&&o(e,119),e.flags|=512),be(n,t)||o(e,0)}function xe(e,n,t){let r,i,s,l="";null!=n&&(n.module&&(t|=768),n.next&&(t|=1),n.loc&&(t|=4),n.ranges&&(t|=2),n.uniqueKeyInPattern&&(t|=134217728),n.lexical&&(t|=16),n.webcompat&&(t|=64),n.globalReturn&&(t|=1048576),n.raw&&(t|=128),n.preserveParens&&(t|=32),n.impliedStrict&&(t|=256),n.jsx&&(t|=8),n.source&&(l=n.source),null!=n.onComment&&(r=Array.isArray(n.onComment)?function(e,n){return function(t,o,r,a,i){const s={type:t,value:o};2&e&&(s.start=r,s.end=a,s.range=[r,a]),4&e&&(s.loc=i),n.push(s)}}(t,n.onComment):n.onComment),null!=n.onInsertedSemicolon&&(i=n.onInsertedSemicolon),null!=n.onToken&&(s=Array.isArray(n.onToken)?function(e,n){return function(t,o,r,a){const i={token:t};2&e&&(i.start=o,i.end=r,i.range=[o,r]),4&e&&(i.loc=a),n.push(i)}}(t,n.onToken):n.onToken));const u=function(e,n,t,o,r){let a=1048576,i=null;return{source:e,flags:0,index:0,line:1,column:0,startIndex:0,end:e.length,tokenIndex:0,startColumn:0,tokenColumn:0,tokenLine:1,startLine:1,sourceFile:n,tokenValue:"",getToken:()=>a,setToken(e,n=!1){if(o)if(1048576!==e){const t={start:{line:this.tokenLine,column:this.tokenColumn},end:{line:this.line,column:this.column}};!n&&i&&o(...i),i=[p(e),this.tokenIndex,this.index,t]}else i&&(o(...i),i=null);return a=e},tokenRaw:"",tokenRegExp:void 0,currentChar:e.charCodeAt(0),exportedNames:[],exportedBindings:[],assignable:1,destructible:0,onComment:t,onToken:o,onInsertedSemicolon:r,leadingDecorators:[]}}(e,l,r,s,i);!function(e){const{source:n}=e;35===e.currentChar&&33===n.charCodeAt(e.index+1)&&(c(e),c(e),C(e,n,0,4,e.tokenIndex,e.tokenLine,e.tokenColumn))}(u);const d=16&t?{parent:void 0,type:2}:void 0;let g=[],k="script";if(512&t){if(k="module",g=function(e,n,t){H(e,8192|n);const o=[];for(;134283267===e.getToken();){const{tokenIndex:t,tokenLine:r,tokenColumn:a}=e,i=e.getToken();o.push(qe(e,n,dn(e,n),i,t,r,a))}for(;1048576!==e.getToken();)o.push(Te(e,n,t));return o}(u,2048|t,d),d)for(const e in u.exportedBindings)"#"!==e[0]||d[e]||o(u,148,e.slice(1))}else g=function(e,n,t){H(e,67117056|n);const o=[];for(;134283267===e.getToken();){const{index:t,tokenIndex:r,tokenValue:i,tokenLine:s,tokenColumn:l}=e,c=e.getToken(),u=dn(e,n);K(e,t,r,i)&&(n|=256,64&e.flags&&a(e.tokenIndex,e.tokenLine,e.tokenColumn,e.index,e.line,e.column,9),4096&e.flags&&a(e.tokenIndex,e.tokenLine,e.tokenColumn,e.index,e.line,e.column,15)),o.push(qe(e,n,u,c,r,s,l))}for(;1048576!==e.getToken();)o.push(ye(e,n,t,void 0,4,{}));return o}(u,2048|t,d);const f={type:"Program",sourceType:k,body:g};return 2&t&&(f.start=0,f.end=e.length,f.range=[0,e.length]),4&t&&(f.loc={start:{line:1,column:0},end:{line:u.line,column:u.column}},u.sourceFile&&(f.loc.source=l)),f}function Te(e,n,t){let r;switch(e.leadingDecorators=Sn(e,n,void 0),e.getToken()){case 20564:r=function(e,n,t){const r=e.tokenIndex,a=e.tokenLine,i=e.tokenColumn;H(e,8192|n);const s=[];let l,c=null,u=null,d=null;if(ee(e,8192|n,20561)){switch(e.getToken()){case 86104:c=gn(e,n,t,void 0,4,1,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn);break;case 132:case 86094:c=En(e,n,t,void 0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);break;case 209005:{const{tokenIndex:o,tokenLine:r,tokenColumn:a}=e;c=un(e,n);const{flags:i}=e;1&i||(86104===e.getToken()?c=gn(e,n,t,void 0,4,1,1,1,o,r,a):67174411===e.getToken()?(c=qn(e,n,void 0,c,1,1,0,i,o,r,a),c=$e(e,n,void 0,c,0,0,o,r,a),c=Je(e,n,void 0,0,0,o,r,a,c)):143360&e.getToken()&&(t&&(t=ce(e,n,e.tokenValue)),c=un(e,n),c=vn(e,n,t,void 0,[c],1,o,r,a)));break}default:c=Ge(e,n,void 0,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn),W(e,8192|n)}return t&&me(e,"default"),se(e,n,r,a,i,{type:"ExportDefaultDeclaration",declaration:c})}switch(e.getToken()){case 8391476:{H(e,n);let s=null;ee(e,n,77932)&&(t&&me(e,e.tokenValue),s=tn(e,n)),ne(e,n,12403),134283267!==e.getToken()&&o(e,105,"Export"),u=dn(e,n);const l={type:"ExportAllDeclaration",source:u,exported:s};return 1&n&&(l.attributes=Qe(e,n)),W(e,8192|n),se(e,n,r,a,i,l)}case 2162700:{H(e,n);const r=[],a=[];let i=0;for(;143360&e.getToken()||134283267===e.getToken();){const{tokenIndex:l,tokenValue:c,tokenLine:u,tokenColumn:d}=e,g=tn(e,n);let k;"Literal"===g.type&&(i=1),77932===e.getToken()?(H(e,n),143360&e.getToken()||134283267===e.getToken()||o(e,106),t&&(r.push(e.tokenValue),a.push(c)),k=tn(e,n)):(t&&(r.push(e.tokenValue),a.push(e.tokenValue)),k=g),s.push(se(e,n,l,u,d,{type:"ExportSpecifier",local:g,exported:k})),1074790415!==e.getToken()&&ne(e,n,18)}ne(e,n,1074790415),ee(e,n,12403)?(134283267!==e.getToken()&&o(e,105,"Export"),u=dn(e,n),1&n&&(d=Qe(e,n,s)),t&&r.forEach((n=>me(e,n)))):(i&&o(e,172),t&&(r.forEach((n=>me(e,n))),a.forEach((n=>function(e,n){void 0!==e.exportedBindings&&""!==n&&(e.exportedBindings["#"+n]=1)}(e,n))))),W(e,8192|n);break}case 86094:c=En(e,n,t,void 0,2,e.tokenIndex,e.tokenLine,e.tokenColumn);break;case 86104:c=gn(e,n,t,void 0,4,1,2,0,e.tokenIndex,e.tokenLine,e.tokenColumn);break;case 241737:c=Ae(e,n,t,void 0,8,64,e.tokenIndex,e.tokenLine,e.tokenColumn);break;case 86090:c=Ae(e,n,t,void 0,16,64,e.tokenIndex,e.tokenLine,e.tokenColumn);break;case 86088:c=De(e,n,t,void 0,64,e.tokenIndex,e.tokenLine,e.tokenColumn);break;case 209005:{const{tokenIndex:o,tokenLine:r,tokenColumn:a}=e;if(H(e,n),!(1&e.flags)&&86104===e.getToken()){c=gn(e,n,t,void 0,4,1,2,1,o,r,a),t&&(l=c.id?c.id.name:"",me(e,l));break}}default:o(e,30,U[255&e.getToken()])}const g={type:"ExportNamedDeclaration",declaration:c,specifiers:s,source:u};d&&(g.attributes=d);return se(e,n,r,a,i,g)}(e,n,t);break;case 86106:r=function(e,n,t){const r=e.tokenIndex,a=e.tokenLine,i=e.tokenColumn;H(e,n);let s=null;const{tokenIndex:l,tokenLine:c,tokenColumn:u}=e;let d=[];if(134283267===e.getToken())s=dn(e,n);else{if(143360&e.getToken()){if(d=[se(e,n,l,c,u,{type:"ImportDefaultSpecifier",local:Ne(e,n,t)})],ee(e,n,18))switch(e.getToken()){case 8391476:d.push(Ue(e,n,t));break;case 2162700:Pe(e,n,t,d);break;default:o(e,107)}}else switch(e.getToken()){case 8391476:d=[Ue(e,n,t)];break;case 2162700:Pe(e,n,t,d);break;case 67174411:return Oe(e,n,void 0,r,a,i);case 67108877:return Be(e,n,r,a,i);default:o(e,30,U[255&e.getToken()])}s=function(e,n){ne(e,n,12403),134283267!==e.getToken()&&o(e,105,"Import");return dn(e,n)}(e,n)}const g={type:"ImportDeclaration",specifiers:d,source:s};1&n&&(g.attributes=Qe(e,n,d));return W(e,8192|n),se(e,n,r,a,i,g)}(e,n,t);break;default:r=ye(e,n,t,void 0,4,{})}return e.leadingDecorators.length&&o(e,170),r}function ye(e,n,t,r,a,i){const s=e.tokenIndex,l=e.tokenLine,c=e.tokenColumn;switch(e.getToken()){case 86104:return gn(e,n,t,r,a,1,0,0,s,l,c);case 132:case 86094:return En(e,n,t,r,0,s,l,c);case 86090:return Ae(e,n,t,r,16,0,s,l,c);case 241737:return function(e,n,t,r,a,i,s,l){const{tokenValue:c}=e,u=e.getToken();let d=un(e,n);if(2240512&e.getToken()){const o=Ve(e,n,t,r,8,0);return W(e,8192|n),se(e,n,i,s,l,{type:"VariableDeclaration",kind:"let",declarations:o})}e.assignable=1,256&n&&o(e,85);if(21===e.getToken())return Le(e,n,t,r,a,{},c,d,u,0,i,s,l);if(10===e.getToken()){let t;16&n&&(t=ce(e,n,c)),e.flags=128^(128|e.flags),d=vn(e,n,t,r,[d],0,i,s,l)}else d=$e(e,n,r,d,0,0,i,s,l),d=Je(e,n,r,0,0,i,s,l,d);18===e.getToken()&&(d=Fe(e,n,r,0,i,s,l,d));return we(e,n,d,i,s,l)}(e,n,t,r,a,s,l,c);case 20564:o(e,103,"export");case 86106:switch(H(e,n),e.getToken()){case 67174411:return Oe(e,n,r,s,l,c);case 67108877:return Be(e,n,s,l,c);default:o(e,103,"import")}case 209005:return Ie(e,n,t,r,a,i,1,s,l,c);default:return Ce(e,n,t,r,a,i,1,s,l,c)}}function Ce(e,n,t,r,a,i,s,l,c,u){switch(e.getToken()){case 86088:return De(e,n,t,r,0,l,c,u);case 20572:return function(e,n,t,r,a,i){1048576&n||o(e,92);H(e,8192|n);const s=1&e.flags||1048576&e.getToken()?null:je(e,n,t,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);return W(e,8192|n),se(e,n,r,a,i,{type:"ReturnStatement",argument:s})}(e,n,r,l,c,u);case 20569:return function(e,n,t,o,r,a,i,s){H(e,n),ne(e,8192|n,67174411),e.assignable=1;const l=je(e,n,o,0,1,e.tokenIndex,e.line,e.tokenColumn);ne(e,8192|n,16);const c=Ee(e,n,t,o,r,e.tokenIndex,e.tokenLine,e.tokenColumn);let u=null;20563===e.getToken()&&(H(e,8192|n),u=Ee(e,n,t,o,r,e.tokenIndex,e.tokenLine,e.tokenColumn));return se(e,n,a,i,s,{type:"IfStatement",test:l,consequent:c,alternate:u})}(e,n,t,r,i,l,c,u);case 20567:return function(e,n,t,r,a,i,s,l){H(e,n);const c=((524288&n)>0||(512&n)>0&&(2048&n)>0)&&ee(e,n,209006);ne(e,8192|n,67174411),t&&(t=de(t,1));let u,d=null,g=null,k=0,p=null,f=86088===e.getToken()||241737===e.getToken()||86090===e.getToken();const{tokenIndex:m,tokenLine:b,tokenColumn:h}=e,x=e.getToken();f?241737===x?(p=un(e,n),2240512&e.getToken()?(8673330===e.getToken()?256&n&&o(e,67):p=se(e,n,m,b,h,{type:"VariableDeclaration",kind:"let",declarations:Ve(e,33554432|n,t,r,8,32)}),e.assignable=1):256&n?o(e,67):(f=!1,e.assignable=1,p=$e(e,n,r,p,0,0,m,b,h),274548===e.getToken()&&o(e,115))):(H(e,n),p=se(e,n,m,b,h,86088===x?{type:"VariableDeclaration",kind:"var",declarations:Ve(e,33554432|n,t,r,4,32)}:{type:"VariableDeclaration",kind:"const",declarations:Ve(e,33554432|n,t,r,16,32)}),e.assignable=1):1074790417===x?c&&o(e,82):2097152&~x?p=_e(e,33554432|n,r,1,0,1,m,b,h):(p=2162700===x?hn(e,n,void 0,r,1,0,0,2,32,m,b,h):pn(e,n,void 0,r,1,0,0,2,32,m,b,h),k=e.destructible,64&k&&o(e,63),e.assignable=16&k?2:1,p=$e(e,33554432|n,r,p,0,0,e.tokenIndex,e.tokenLine,e.tokenColumn));if(!(262144&~e.getToken())){if(274548===e.getToken()){2&e.assignable&&o(e,80,c?"await":"of"),te(e,p),H(e,8192|n),u=Ge(e,n,r,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn),ne(e,8192|n,16);return se(e,n,i,s,l,{type:"ForOfStatement",left:p,right:u,body:Se(e,n,t,r,a),await:c})}2&e.assignable&&o(e,80,"in"),te(e,p),H(e,8192|n),c&&o(e,82),u=je(e,n,r,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn),ne(e,8192|n,16);return se(e,n,i,s,l,{type:"ForInStatement",body:Se(e,n,t,r,a),left:p,right:u})}c&&o(e,82);f||(8&k&&1077936155!==e.getToken()&&o(e,80,"loop"),p=Je(e,33554432|n,r,0,0,m,b,h,p));18===e.getToken()&&(p=Fe(e,n,r,0,e.tokenIndex,e.tokenLine,e.tokenColumn,p));ne(e,8192|n,1074790417),1074790417!==e.getToken()&&(d=je(e,n,r,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn));ne(e,8192|n,1074790417),16!==e.getToken()&&(g=je(e,n,r,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn));ne(e,8192|n,16);const T=Se(e,n,t,r,a);return se(e,n,i,s,l,{type:"ForStatement",init:p,test:d,update:g,body:T})}(e,n,t,r,i,l,c,u);case 20562:return function(e,n,t,o,r,a,i,s){H(e,8192|n);const l=Se(e,n,t,o,r);ne(e,n,20578),ne(e,8192|n,67174411);const c=je(e,n,o,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);return ne(e,8192|n,16),ee(e,8192|n,1074790417),se(e,n,a,i,s,{type:"DoWhileStatement",body:l,test:c})}(e,n,t,r,i,l,c,u);case 20578:return function(e,n,t,o,r,a,i,s){H(e,n),ne(e,8192|n,67174411);const l=je(e,n,o,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);ne(e,8192|n,16);const c=Se(e,n,t,o,r);return se(e,n,a,i,s,{type:"WhileStatement",test:l,body:c})}(e,n,t,r,i,l,c,u);case 86110:return function(e,n,t,r,a,i,s,l){H(e,n),ne(e,8192|n,67174411);const c=je(e,n,r,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);ne(e,n,16),ne(e,n,2162700);const u=[];let d=0;t&&(t=de(t,8));for(;1074790415!==e.getToken();){const{tokenIndex:i,tokenLine:s,tokenColumn:l}=e;let c=null;const g=[];for(ee(e,8192|n,20556)?c=je(e,n,r,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn):(ne(e,8192|n,20561),d&&o(e,89),d=1),ne(e,8192|n,21);20556!==e.getToken()&&1074790415!==e.getToken()&&20561!==e.getToken();)g.push(ye(e,1024|n,t,r,2,{$:a}));u.push(se(e,n,i,s,l,{type:"SwitchCase",test:c,consequent:g}))}return ne(e,8192|n,1074790415),se(e,n,i,s,l,{type:"SwitchStatement",discriminant:c,cases:u})}(e,n,t,r,i,l,c,u);case 1074790417:return function(e,n,t,o,r){return H(e,8192|n),se(e,n,t,o,r,{type:"EmptyStatement"})}(e,n,l,c,u);case 2162700:return ve(e,n,t?de(t,2):t,r,i,l,c,u);case 86112:return function(e,n,t,r,a,i){H(e,8192|n),1&e.flags&&o(e,90);const s=je(e,n,t,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);return W(e,8192|n),se(e,n,r,a,i,{type:"ThrowStatement",argument:s})}(e,n,r,l,c,u);case 20555:return function(e,n,t,r,a,i){H(e,8192|n);let s=null;if(!(1&e.flags)&&143360&e.getToken()){const{tokenValue:r}=e;s=un(e,8192|n),ie(e,t,r,0)||o(e,138,r)}else 33792&n||o(e,69);return W(e,8192|n),se(e,n,r,a,i,{type:"BreakStatement",label:s})}(e,n,i,l,c,u);case 20559:return function(e,n,t,r,a,i){32768&n||o(e,68);H(e,n);let s=null;if(!(1&e.flags)&&143360&e.getToken()){const{tokenValue:r}=e;s=un(e,8192|n),ie(e,t,r,1)||o(e,138,r)}return W(e,8192|n),se(e,n,r,a,i,{type:"ContinueStatement",label:s})}(e,n,i,l,c,u);case 20577:return function(e,n,t,r,a,i,s,l){H(e,8192|n);const c=t?de(t,32):void 0,u=ve(e,n,c,r,{$:a},e.tokenIndex,e.tokenLine,e.tokenColumn),{tokenIndex:d,tokenLine:g,tokenColumn:k}=e,p=ee(e,8192|n,20557)?function(e,n,t,r,a,i,s,l){let c=null,u=t;ee(e,n,67174411)&&(t&&(t=de(t,4)),c=Un(e,n,t,r,2097152&~e.getToken()?512:256,0,e.tokenIndex,e.tokenLine,e.tokenColumn),18===e.getToken()?o(e,86):1077936155===e.getToken()&&o(e,87),ne(e,8192|n,16));t&&(u=de(t,64));const d=ve(e,n,u,r,{$:a},e.tokenIndex,e.tokenLine,e.tokenColumn);return se(e,n,i,s,l,{type:"CatchClause",param:c,body:d})}(e,n,t,r,a,d,g,k):null;let f=null;if(20566===e.getToken()){H(e,8192|n);f=ve(e,n,c?de(t,4):void 0,r,{$:a},e.tokenIndex,e.tokenLine,e.tokenColumn)}p||f||o(e,88);return se(e,n,i,s,l,{type:"TryStatement",block:u,handler:p,finalizer:f})}(e,n,t,r,i,l,c,u);case 20579:return function(e,n,t,r,a,i,s,l){H(e,n),256&n&&o(e,91);ne(e,8192|n,67174411);const c=je(e,n,r,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);ne(e,8192|n,16);const u=Ce(e,n,t,r,2,a,0,e.tokenIndex,e.tokenLine,e.tokenColumn);return se(e,n,i,s,l,{type:"WithStatement",object:c,body:u})}(e,n,t,r,i,l,c,u);case 20560:return function(e,n,t,o,r){return H(e,8192|n),W(e,8192|n),se(e,n,t,o,r,{type:"DebuggerStatement"})}(e,n,l,c,u);case 209005:return Ie(e,n,t,r,a,i,0,l,c,u);case 20557:o(e,162);case 20566:o(e,163);case 86104:o(e,256&n?76:64&n?77:78);case 86094:o(e,79);default:return function(e,n,t,r,a,i,s,l,c,u){const{tokenValue:d}=e,g=e.getToken();let k;if(241737===g)k=un(e,n),256&n&&o(e,85),69271571===e.getToken()&&o(e,84);else k=Ze(e,n,r,2,0,1,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);if(143360&g&&21===e.getToken())return Le(e,n,t,r,a,i,d,k,g,s,l,c,u);k=$e(e,n,r,k,0,0,l,c,u),k=Je(e,n,r,0,0,l,c,u,k),18===e.getToken()&&(k=Fe(e,n,r,0,l,c,u,k));return we(e,n,k,l,c,u)}(e,n,t,r,a,i,s,l,c,u)}}function ve(e,n,t,o,r,a,i,s){const l=[];for(ne(e,8192|n,2162700);1074790415!==e.getToken();)l.push(ye(e,n,t,o,2,{$:r}));return ne(e,8192|n,1074790415),se(e,n,a,i,s,{type:"BlockStatement",body:l})}function we(e,n,t,o,r,a){return W(e,8192|n),se(e,n,o,r,a,{type:"ExpressionStatement",expression:t})}function Le(e,n,t,r,a,i,s,l,c,u,d,g,k){oe(e,n,0,c,1),function(e,n,t){let r=n;for(;r;)r["$"+t]&&o(e,136,t),r=r.$;n["$"+t]=1}(e,i,s),H(e,8192|n);const p=u&&!(256&n)&&64&n&&86104===e.getToken()?gn(e,n,de(t,2),r,a,0,0,0,e.tokenIndex,e.tokenLine,e.tokenColumn):Ce(e,n,t,r,a,i,u,e.tokenIndex,e.tokenLine,e.tokenColumn);return se(e,n,d,g,k,{type:"LabeledStatement",label:l,body:p})}function Ie(e,n,t,r,a,i,s,l,c,u){const{tokenValue:d}=e,g=e.getToken();let k=un(e,n);if(21===e.getToken())return Le(e,n,t,r,a,i,d,k,g,1,l,c,u);const p=1&e.flags;if(!p){if(86104===e.getToken())return s||o(e,123),gn(e,n,t,r,a,1,0,1,l,c,u);if(be(n,e.getToken()))return k=In(e,n,r,1,l,c,u),18===e.getToken()&&(k=Fe(e,n,r,0,l,c,u,k)),we(e,n,k,l,c,u)}return 67174411===e.getToken()?k=qn(e,n,r,k,1,1,0,p,l,c,u):(10===e.getToken()&&(he(e,n,g),36864&~g||(e.flags|=256),k=yn(e,524288|n,r,e.tokenValue,k,0,1,0,l,c,u)),e.assignable=1),k=$e(e,n,r,k,0,0,l,c,u),k=Je(e,n,r,0,0,l,c,u,k),e.assignable=1,18===e.getToken()&&(k=Fe(e,n,r,0,l,c,u,k)),we(e,n,k,l,c,u)}function qe(e,n,t,o,r,a,i){const s=e.startIndex;return 1074790417!==o&&(e.assignable=2,t=$e(e,n,void 0,t,0,0,r,a,i),1074790417!==e.getToken()&&(t=Je(e,n,void 0,0,0,r,a,i,t),18===e.getToken()&&(t=Fe(e,n,void 0,0,r,a,i,t))),W(e,8192|n)),"Literal"===t.type&&"string"==typeof t.value?se(e,n,r,a,i,{type:"ExpressionStatement",expression:t,directive:e.source.slice(r+1,s-1)}):se(e,n,r,a,i,{type:"ExpressionStatement",expression:t})}function Ee(e,n,t,o,r,a,i,s){return 256&n||!(64&n)||86104!==e.getToken()?Ce(e,n,t,o,0,{$:r},0,e.tokenIndex,e.tokenLine,e.tokenColumn):gn(e,n,de(t,2),o,0,0,0,0,a,i,s)}function Se(e,n,t,o,r){return Ce(e,33554432^(33554432|n)|32768,t,o,0,{loop:1,$:r},0,e.tokenIndex,e.tokenLine,e.tokenColumn)}function Ae(e,n,t,o,r,a,i,s,l){H(e,n);const c=Ve(e,n,t,o,r,a);return W(e,8192|n),se(e,n,i,s,l,{type:"VariableDeclaration",kind:8&r?"let":"const",declarations:c})}function De(e,n,t,o,r,a,i,s){H(e,n);const l=Ve(e,n,t,o,4,r);return W(e,8192|n),se(e,n,a,i,s,{type:"VariableDeclaration",kind:"var",declarations:l})}function Ve(e,n,t,r,a,i){let s=1;const l=[Re(e,n,t,r,a,i)];for(;ee(e,n,18);)s++,l.push(Re(e,n,t,r,a,i));return s>1&&32&i&&262144&e.getToken()&&o(e,61,U[255&e.getToken()]),l}function Re(e,n,t,r,i,s){const{tokenIndex:l,tokenLine:c,tokenColumn:u}=e,d=e.getToken();let g=null;const k=Un(e,n,t,r,i,s,l,c,u);return 1077936155===e.getToken()?(H(e,8192|n),g=Ge(e,n,r,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn),!(32&s)&&2097152&d||(274548===e.getToken()||8673330===e.getToken()&&(2097152&d||!(4&i)||256&n))&&a(l,c,u,e.index,e.line,e.column,60,274548===e.getToken()?"of":"in")):(16&i||(2097152&d)>0)&&262144&~e.getToken()&&o(e,59,16&i?"const":"destructuring"),se(e,n,l,c,u,{type:"VariableDeclarator",id:k,init:g})}function Ne(e,n,t){return be(n,e.getToken())||o(e,118),537079808&~e.getToken()||o(e,119),t&&ke(e,n,t,e.tokenValue,8,0),un(e,n)}function Ue(e,n,t){const{tokenIndex:o,tokenLine:r,tokenColumn:i}=e;return H(e,n),ne(e,n,77932),134217728&~e.getToken()||a(o,r,i,e.index,e.line,e.column,30,U[255&e.getToken()]),se(e,n,o,r,i,{type:"ImportNamespaceSpecifier",local:Ne(e,n,t)})}function Pe(e,n,t,r){for(H(e,n);143360&e.getToken()||134283267===e.getToken();){let{tokenValue:a,tokenIndex:i,tokenLine:s,tokenColumn:l}=e;const c=e.getToken(),u=tn(e,n);let d;ee(e,n,77932)?(134217728&~e.getToken()&&18!==e.getToken()?oe(e,n,16,e.getToken(),0):o(e,106),a=e.tokenValue,d=un(e,n)):"Identifier"===u.type?(oe(e,n,16,c,0),d=u):o(e,25,U[108]),t&&ke(e,n,t,a,8,0),r.push(se(e,n,i,s,l,{type:"ImportSpecifier",local:d,imported:u})),1074790415!==e.getToken()&&ne(e,n,18)}return ne(e,n,1074790415),r}function Be(e,n,t,o,r){let a=We(e,n,se(e,n,t,o,r,{type:"Identifier",name:"import"}),t,o,r);return a=$e(e,n,void 0,a,0,0,t,o,r),a=Je(e,n,void 0,0,0,t,o,r,a),18===e.getToken()&&(a=Fe(e,n,void 0,0,t,o,r,a)),we(e,n,a,t,o,r)}function Oe(e,n,t,o,r,a){let i=Ke(e,n,t,0,o,r,a);return i=$e(e,n,t,i,0,0,o,r,a),18===e.getToken()&&(i=Fe(e,n,t,0,o,r,a,i)),we(e,n,i,o,r,a)}function Ge(e,n,t,o,r,a,i,s){let l=Ze(e,n,t,2,0,o,r,1,a,i,s);return l=$e(e,n,t,l,r,0,a,i,s),Je(e,n,t,r,0,a,i,s,l)}function Fe(e,n,t,o,r,a,i,s){const l=[s];for(;ee(e,8192|n,18);)l.push(Ge(e,n,t,1,o,e.tokenIndex,e.tokenLine,e.tokenColumn));return se(e,n,r,a,i,{type:"SequenceExpression",expressions:l})}function je(e,n,t,o,r,a,i,s){const l=Ge(e,n,t,r,o,a,i,s);return 18===e.getToken()?Fe(e,n,t,o,a,i,s,l):l}function Je(e,n,t,r,a,i,s,l,c){const u=e.getToken();if(!(4194304&~u)){2&e.assignable&&o(e,26),(!a&&1077936155===u&&"ArrayExpression"===c.type||"ObjectExpression"===c.type)&&te(e,c),H(e,8192|n);const d=Ge(e,n,t,1,r,e.tokenIndex,e.tokenLine,e.tokenColumn);return e.assignable=2,se(e,n,i,s,l,a?{type:"AssignmentPattern",left:c,right:d}:{type:"AssignmentExpression",left:c,operator:U[255&u],right:d})}return 8388608&~u||(c=ze(e,n,t,r,i,s,l,4,u,c)),ee(e,8192|n,22)&&(c=Me(e,n,t,c,i,s,l)),c}function He(e,n,t,o,r,a,i,s,l){const c=e.getToken();H(e,8192|n);const u=Ge(e,n,t,1,o,e.tokenIndex,e.tokenLine,e.tokenColumn);return l=se(e,n,a,i,s,r?{type:"AssignmentPattern",left:l,right:u}:{type:"AssignmentExpression",left:l,operator:U[255&c],right:u}),e.assignable=2,l}function Me(e,n,t,o,r,a,i){const s=Ge(e,33554432^(33554432|n),t,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn);ne(e,8192|n,21),e.assignable=1;const l=Ge(e,n,t,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn);return e.assignable=2,se(e,n,r,a,i,{type:"ConditionalExpression",test:o,consequent:s,alternate:l})}function ze(e,n,t,r,a,i,s,l,c,u){const d=8673330&-((33554432&n)>0);let g,k;for(e.assignable=2;8388608&e.getToken()&&(g=e.getToken(),k=3840&g,(524288&g&&268435456&c||524288&c&&268435456&g)&&o(e,165),!(k+((8391735===g)<<8)-((d===g)<<12)<=l));)H(e,8192|n),u=se(e,n,a,i,s,{type:524288&g||268435456&g?"LogicalExpression":"BinaryExpression",left:u,right:ze(e,n,t,r,e.tokenIndex,e.tokenLine,e.tokenColumn,k,g,_e(e,n,t,0,r,1,e.tokenIndex,e.tokenLine,e.tokenColumn)),operator:U[255&g]});return 1077936155===e.getToken()&&o(e,26),u}function Xe(e,n,t,i,s,l,c){const{tokenIndex:u,tokenLine:d,tokenColumn:g}=e;ne(e,8192|n,2162700);const k=[];if(1074790415!==e.getToken()){for(;134283267===e.getToken();){const{index:t,tokenIndex:o,tokenValue:i}=e,s=e.getToken(),l=dn(e,n);K(e,t,o,i)&&(n|=256,128&e.flags&&a(o,d,g,e.index,e.line,e.column,66),64&e.flags&&a(o,d,g,e.index,e.line,e.column,9),4096&e.flags&&a(o,d,g,e.index,e.line,e.column,15),c&&r(c)),k.push(qe(e,n,l,s,o,e.tokenLine,e.tokenColumn))}256&n&&(l&&(537079808&~l||o(e,119),36864&~l||o(e,40)),512&e.flags&&o(e,119),256&e.flags&&o(e,118))}for(e.flags=4928^(4928|e.flags),e.destructible=256^(256|e.destructible);1074790415!==e.getToken();)k.push(ye(e,n,t,i,4,{}));return ne(e,24&s?8192|n:n,1074790415),e.flags&=-4289,1077936155===e.getToken()&&o(e,26),se(e,n,u,d,g,{type:"BlockStatement",body:k})}function _e(e,n,t,o,r,a,i,s,l){return $e(e,n,t,Ze(e,n,t,2,0,o,r,a,i,s,l),r,0,i,s,l)}function $e(e,n,t,r,a,i,s,l,c){if(33619968&~e.getToken()||1&e.flags){if(!(67108864&~e.getToken())){switch(n=33554432^(33554432|n),e.getToken()){case 67108877:H(e,2048^(67110912|n)),4096&n&&130===e.getToken()&&"super"===e.tokenValue&&o(e,173),e.assignable=1;r=se(e,n,s,l,c,{type:"MemberExpression",object:r,computed:!1,property:Ye(e,16384|n,t)});break;case 69271571:{let o=!1;2048&~e.flags||(o=!0,e.flags=2048^(2048|e.flags)),H(e,8192|n);const{tokenIndex:i,tokenLine:u,tokenColumn:d}=e,g=je(e,n,t,a,1,i,u,d);ne(e,n,20),e.assignable=1,r=se(e,n,s,l,c,{type:"MemberExpression",object:r,computed:!0,property:g}),o&&(e.flags|=2048);break}case 67174411:{if(!(1024&~e.flags))return e.flags=1024^(1024|e.flags),r;let o=!1;2048&~e.flags||(o=!0,e.flags=2048^(2048|e.flags));const i=cn(e,n,t,a);e.assignable=2,r=se(e,n,s,l,c,{type:"CallExpression",callee:r,arguments:i}),o&&(e.flags|=2048);break}case 67108990:H(e,2048^(67110912|n)),e.flags|=2048,e.assignable=2,r=function(e,n,t,o,r,a,i){let s,l=!1;69271571!==e.getToken()&&67174411!==e.getToken()||2048&~e.flags||(l=!0,e.flags=2048^(2048|e.flags));if(69271571===e.getToken()){H(e,8192|n);const{tokenIndex:l,tokenLine:c,tokenColumn:u}=e,d=je(e,n,t,0,1,l,c,u);ne(e,n,20),e.assignable=2,s=se(e,n,r,a,i,{type:"MemberExpression",object:o,computed:!0,optional:!0,property:d})}else if(67174411===e.getToken()){const l=cn(e,n,t,0);e.assignable=2,s=se(e,n,r,a,i,{type:"CallExpression",callee:o,arguments:l,optional:!0})}else{const l=Ye(e,n,t);e.assignable=2,s=se(e,n,r,a,i,{type:"MemberExpression",object:o,computed:!1,optional:!0,property:l})}l&&(e.flags|=2048);return s}(e,n,t,r,s,l,c);break;default:2048&~e.flags||o(e,166),e.assignable=2,r=se(e,n,s,l,c,{type:"TaggedTemplateExpression",tag:r,quasi:67174408===e.getToken()?an(e,16384|n,t):rn(e,n,e.tokenIndex,e.tokenLine,e.tokenColumn)})}r=$e(e,n,t,r,0,1,s,l,c)}}else r=function(e,n,t,r,a,i){2&e.assignable&&o(e,55);const s=e.getToken();return H(e,n),e.assignable=2,se(e,n,r,a,i,{type:"UpdateExpression",argument:t,operator:U[255&s],prefix:!1})}(e,n,r,s,l,c);return 0!==i||2048&~e.flags||(e.flags=2048^(2048|e.flags),r=se(e,n,s,l,c,{type:"ChainExpression",expression:r})),r}function Ye(e,n,t){return 143360&e.getToken()||-2147483528===e.getToken()||-2147483527===e.getToken()||130===e.getToken()||o(e,160),130===e.getToken()?Rn(e,n,t,0,e.tokenIndex,e.tokenLine,e.tokenColumn):un(e,n)}function Ze(e,n,t,r,i,s,l,c,u,d,g){if(!(143360&~e.getToken())){switch(e.getToken()){case 209006:return function(e,n,t,r,i,s,l,c){i&&(e.destructible|=128),268435456&n&&o(e,177);const u=Tn(e,n,t,s,l,c);if("ArrowFunctionExpression"===u.type||!(65536&e.getToken()))return 524288&n&&a(s,l,c,e.startIndex,e.startLine,e.startColumn,176),512&n&&a(s,l,c,e.startIndex,e.startLine,e.startColumn,110),2097152&n&&524288&n&&a(s,l,c,e.startIndex,e.startLine,e.startColumn,110),u;if(2097152&n&&a(s,l,c,e.startIndex,e.startLine,e.startColumn,31),524288&n||512&n&&2048&n){r&&a(s,l,c,e.startIndex,e.startLine,e.startColumn,0);const i=_e(e,n,t,0,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);return 8391735===e.getToken()&&o(e,33),e.assignable=2,se(e,n,s,l,c,{type:"AwaitExpression",argument:i})}return 512&n&&a(s,l,c,e.startIndex,e.startLine,e.startColumn,98),u}(e,n,t,i,l,u,d,g);case 241771:return function(e,n,t,r,a,i,s,l){if(r&&(e.destructible|=256),262144&n){H(e,8192|n),2097152&n&&o(e,32),a||o(e,26),22===e.getToken()&&o(e,124);let r=null,c=!1;return 1&e.flags?8391476===e.getToken()&&o(e,30,U[255&e.getToken()]):(c=ee(e,8192|n,8391476),(77824&e.getToken()||c)&&(r=Ge(e,n,t,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn))),e.assignable=2,se(e,n,i,s,l,{type:"YieldExpression",argument:r,delegate:c})}return 256&n&&o(e,97,"yield"),Tn(e,n,t,i,s,l)}(e,n,t,l,s,u,d,g);case 209005:return function(e,n,t,r,a,i,s,l,c,u){const d=e.getToken(),g=un(e,n),{flags:k}=e;if(!(1&k)){if(86104===e.getToken())return kn(e,n,t,1,r,l,c,u);if(be(n,e.getToken()))return a||o(e,0),36864&~e.getToken()||(e.flags|=256),In(e,n,t,i,l,c,u)}return s||67174411!==e.getToken()?10===e.getToken()?(he(e,n,d),s&&o(e,51),36864&~d||(e.flags|=256),yn(e,n,t,e.tokenValue,g,s,i,0,l,c,u)):(e.assignable=1,g):qn(e,n,t,g,i,1,0,k,l,c,u)}(e,n,t,l,c,s,i,u,d,g)}const{tokenValue:k}=e,p=e.getToken(),f=un(e,16384|n);return 10===e.getToken()?(c||o(e,0),he(e,n,p),36864&~p||(e.flags|=256),yn(e,n,t,k,f,i,s,0,u,d,g)):(!(4096&n)||8388608&n||2097152&n||"arguments"!==e.tokenValue||o(e,130),73==(255&p)&&(256&n&&o(e,113),24&r&&o(e,100)),e.assignable=256&n&&!(537079808&~p)?2:1,f)}if(!(134217728&~e.getToken()))return dn(e,n);switch(e.getToken()){case 33619993:case 33619994:return function(e,n,t,r,a,i,s,l){r&&o(e,56),a||o(e,0);const c=e.getToken();H(e,8192|n);const u=_e(e,n,t,0,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn);return 2&e.assignable&&o(e,55),e.assignable=2,se(e,n,i,s,l,{type:"UpdateExpression",argument:u,operator:U[255&c],prefix:!0})}(e,n,t,i,c,u,d,g);case 16863276:case 16842798:case 16842799:case 25233968:case 25233969:case 16863275:case 16863277:return function(e,n,t,r,a,i,s,l){r||o(e,0);const c=e.getToken();H(e,8192|n);const u=_e(e,n,t,0,l,1,e.tokenIndex,e.tokenLine,e.tokenColumn);var d;return 8391735===e.getToken()&&o(e,33),256&n&&16863276===c&&("Identifier"===u.type?o(e,121):(d=u).property&&"PrivateIdentifier"===d.property.type&&o(e,127)),e.assignable=2,se(e,n,a,i,s,{type:"UnaryExpression",operator:U[255&c],argument:u,prefix:!0})}(e,n,t,c,u,d,g,l);case 86104:return kn(e,n,t,0,l,u,d,g);case 2162700:return function(e,n,t,r,a,i,s,l){const c=hn(e,n,void 0,t,r,a,0,2,0,i,s,l);64&e.destructible&&o(e,63);8&e.destructible&&o(e,62);return c}(e,n,t,s?0:1,l,u,d,g);case 69271571:return function(e,n,t,r,a,i,s,l){const c=pn(e,n,void 0,t,r,a,0,2,0,i,s,l);64&e.destructible&&o(e,63);8&e.destructible&&o(e,62);return c}(e,n,t,s?0:1,l,u,d,g);case 67174411:return function(e,n,t,r,a,i,s,l,c){e.flags=128^(128|e.flags);const{tokenIndex:u,tokenLine:d,tokenColumn:g}=e;H(e,67117056|n);const k=16&n?de({parent:void 0,type:2},1024):void 0;if(n=33554432^(33554432|n),ee(e,n,16))return Cn(e,n,k,t,[],r,0,s,l,c);let p,f=0;e.destructible&=-385;let m=[],b=0,h=0,x=0;const{tokenIndex:T,tokenLine:y,tokenColumn:C}=e;e.assignable=1;for(;16!==e.getToken();){const{tokenIndex:r,tokenLine:s,tokenColumn:l}=e,c=e.getToken();if(143360&c)k&&ke(e,n,k,e.tokenValue,1,0),537079808&~c?36864&~c||(x=1):h=1,p=Ze(e,n,t,a,0,1,1,1,r,s,l),16===e.getToken()||18===e.getToken()?2&e.assignable&&(f|=16,h=1):(1077936155===e.getToken()?h=1:f|=16,p=$e(e,n,t,p,1,0,r,s,l),16!==e.getToken()&&18!==e.getToken()&&(p=Je(e,n,t,1,0,r,s,l,p)));else{if(2097152&~c){if(14===c){p=mn(e,n,k,t,16,a,i,0,1,0,r,s,l),16&e.destructible&&o(e,74),h=1,!b||16!==e.getToken()&&18!==e.getToken()||m.push(p),f|=8;break}if(f|=16,p=Ge(e,n,t,1,1,r,s,l),!b||16!==e.getToken()&&18!==e.getToken()||m.push(p),18===e.getToken()&&(b||(b=1,m=[p])),b){for(;ee(e,8192|n,18);)m.push(Ge(e,n,t,1,1,e.tokenIndex,e.tokenLine,e.tokenColumn));e.assignable=2,p=se(e,n,T,y,C,{type:"SequenceExpression",expressions:m})}return ne(e,n,16),e.destructible=f,p}p=2162700===c?hn(e,67108864|n,k,t,0,1,0,a,i,r,s,l):pn(e,67108864|n,k,t,0,1,0,a,i,r,s,l),f|=e.destructible,h=1,e.assignable=2,16!==e.getToken()&&18!==e.getToken()&&(8&f&&o(e,122),p=$e(e,n,t,p,0,0,r,s,l),f|=16,16!==e.getToken()&&18!==e.getToken()&&(p=Je(e,n,t,0,0,r,s,l,p)))}if(!b||16!==e.getToken()&&18!==e.getToken()||m.push(p),!ee(e,8192|n,18))break;if(b||(b=1,m=[p]),16===e.getToken()){f|=8;break}}b&&(e.assignable=2,p=se(e,n,T,y,C,{type:"SequenceExpression",expressions:m}));ne(e,n,16),16&f&&8&f&&o(e,151);if(f|=256&e.destructible?256:128&e.destructible?128:0,10===e.getToken())return 48&f&&o(e,49),524800&n&&128&f&&o(e,31),262400&n&&256&f&&o(e,32),h&&(e.flags|=128),x&&(e.flags|=256),Cn(e,n,k,t,b?m:[p],r,0,s,l,c);64&f&&o(e,63);8&f&&o(e,144);return e.destructible=256^(256|e.destructible)|f,32&n?se(e,n,u,d,g,{type:"ParenthesizedExpression",expression:p}):p}(e,16384|n,t,s,1,0,u,d,g);case 86021:case 86022:case 86023:return function(e,n,t,o,r){const a=U[255&e.getToken()],i=86023===e.getToken()?null:"true"===a;return H(e,n),e.assignable=2,se(e,n,t,o,r,128&n?{type:"Literal",value:i,raw:a}:{type:"Literal",value:i})}(e,n,u,d,g);case 86111:return function(e,n){const{tokenIndex:t,tokenLine:o,tokenColumn:r}=e;return H(e,n),e.assignable=2,se(e,n,t,o,r,{type:"ThisExpression"})}(e,n);case 65540:return function(e,n,t,o,r){const{tokenRaw:a,tokenRegExp:i,tokenValue:s}=e;return H(e,n),e.assignable=2,se(e,n,t,o,r,128&n?{type:"Literal",value:s,regex:i,raw:a}:{type:"Literal",value:s,regex:i})}(e,n,u,d,g);case 132:case 86094:return function(e,n,t,r,a,i,s){let l=null,c=null;const u=Sn(e,n,t);u.length&&(a=e.tokenIndex,i=e.tokenLine,s=e.tokenColumn);n=4194304^(4194560|n),H(e,n),4096&e.getToken()&&20565!==e.getToken()&&(ae(e,n,e.getToken())&&o(e,118),537079808&~e.getToken()||o(e,119),l=un(e,n));let d=n;ee(e,8192|n,20565)?(c=_e(e,n,t,0,r,0,e.tokenIndex,e.tokenLine,e.tokenColumn),d|=131072):d=131072^(131072|d);const g=Dn(e,d,n,void 0,t,2,0,r);return e.assignable=2,se(e,n,a,i,s,{type:"ClassExpression",id:l,superClass:c,body:g,...1&n?{decorators:u}:null})}(e,n,t,l,u,d,g);case 86109:return function(e,n,t,r,a){switch(H(e,n),e.getToken()){case 67108990:o(e,167);case 67174411:131072&n||o(e,28),e.assignable=2;break;case 69271571:case 67108877:65536&n||o(e,29),e.assignable=1;break;default:o(e,30,"super")}return se(e,n,t,r,a,{type:"Super"})}(e,n,u,d,g);case 67174409:return rn(e,n,u,d,g);case 67174408:return an(e,n,t);case 86107:return function(e,n,t,r,a,i,s){const l=un(e,8192|n),{tokenIndex:c,tokenLine:u,tokenColumn:d}=e;if(ee(e,n,67108877)){if(16777216&n&&209029===e.getToken())return e.assignable=2,function(e,n,t,o,r,a){const i=un(e,n);return se(e,n,o,r,a,{type:"MetaProperty",meta:t,property:i})}(e,n,l,a,i,s);o(e,94)}e.assignable=2,16842752&~e.getToken()||o(e,65,U[255&e.getToken()]);const g=Ze(e,n,t,2,1,0,r,1,c,u,d);n=33554432^(33554432|n),67108990===e.getToken()&&o(e,168);const k=Ln(e,n,t,g,r,c,u,d);return e.assignable=2,se(e,n,a,i,s,{type:"NewExpression",callee:k,arguments:67174411===e.getToken()?cn(e,n,t,r):[]})}(e,n,t,l,u,d,g);case 134283388:return on(e,n,u,d,g);case 130:return Rn(e,n,t,0,u,d,g);case 86106:return function(e,n,t,r,a,i,s,l){let c=un(e,n);if(67108877===e.getToken())return We(e,n,c,i,s,l);r&&o(e,142);return c=Ke(e,n,t,a,i,s,l),e.assignable=2,$e(e,n,t,c,a,0,i,s,l)}(e,n,t,i,l,u,d,g);case 8456256:if(8&n)return Bn(e,n,t,0,u,d,g);default:if(be(n,e.getToken()))return Tn(e,n,t,u,d,g);o(e,30,U[255&e.getToken()])}}function We(e,n,t,r,a,i){512&n||o(e,169),H(e,n);const s=e.getToken();return 209030!==s&&"meta"!==e.tokenValue?o(e,174):-2147483648&s&&o(e,175),e.assignable=2,se(e,n,r,a,i,{type:"MetaProperty",meta:t,property:un(e,n)})}function Ke(e,n,t,r,a,i,s){ne(e,8192|n,67174411),14===e.getToken()&&o(e,143);const l={type:"ImportExpression",source:Ge(e,n,t,1,r,e.tokenIndex,e.tokenLine,e.tokenColumn)};if(1&n){let o=null;if(18===e.getToken()&&(ne(e,n,18),16!==e.getToken())){o=Ge(e,33554432^(33554432|n),t,1,r,e.tokenIndex,e.tokenLine,e.tokenColumn)}l.options=o,ee(e,n,18)}return ne(e,n,16),se(e,n,a,i,s,l)}function Qe(e,n,t=null){if(!ee(e,n,20579))return[];ne(e,n,2162700);const r=[],a=new Set;for(;1074790415!==e.getToken();){const i=e.tokenIndex,s=e.tokenLine,l=e.tokenColumn,c=nn(e,n);ne(e,n,21);const u=en(e,n),d="Literal"===c.type?c.value:c.name;if("type"===d&&"json"===u.value){null===t||1===t.length&&("ImportDefaultSpecifier"===t[0].type||"ImportNamespaceSpecifier"===t[0].type||"ImportSpecifier"===t[0].type&&"Identifier"===t[0].imported.type&&"default"===t[0].imported.name||"ExportSpecifier"===t[0].type&&"Identifier"===t[0].local.type&&"default"===t[0].local.name)||o(e,140)}a.has(d)&&o(e,145,`${d}`),a.add(d),r.push(se(e,n,i,s,l,{type:"ImportAttribute",key:c,value:u})),1074790415!==e.getToken()&&ne(e,n,18)}return ne(e,n,1074790415),r}function en(e,n){if(134283267===e.getToken())return dn(e,n);o(e,30,U[255&e.getToken()])}function nn(e,n){return 134283267===e.getToken()?dn(e,n):143360&e.getToken()?un(e,n):void o(e,30,U[255&e.getToken()])}function tn(e,n){return 134283267===e.getToken()?(function(e,n){const t=n.length;for(let r=0;r<t;r++){const a=n.charCodeAt(r);55296==(64512&a)&&(a>56319||++r>=t||56320!=(64512&n.charCodeAt(r)))&&o(e,171,JSON.stringify(n.charAt(r--)))}}(e,e.tokenValue),dn(e,n)):143360&e.getToken()?un(e,n):void o(e,30,U[255&e.getToken()])}function on(e,n,t,o,r){const{tokenRaw:a,tokenValue:i}=e;return H(e,n),e.assignable=2,se(e,n,t,o,r,128&n?{type:"Literal",value:i,bigint:a.slice(0,-1),raw:a}:{type:"Literal",value:i,bigint:a.slice(0,-1)})}function rn(e,n,t,o,r){e.assignable=2;const{tokenValue:a,tokenRaw:i,tokenIndex:s,tokenLine:l,tokenColumn:c}=e;ne(e,n,67174409);return se(e,n,t,o,r,{type:"TemplateLiteral",expressions:[],quasis:[sn(e,n,a,i,s,l,c,!0)]})}function an(e,n,t){n=33554432^(33554432|n);const{tokenValue:r,tokenRaw:a,tokenIndex:i,tokenLine:s,tokenColumn:l}=e;ne(e,-16385&n|8192,67174408);const c=[sn(e,n,r,a,i,s,l,!1)],u=[je(e,-16385&n,t,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn)];for(1074790415!==e.getToken()&&o(e,83);67174409!==e.setToken(V(e,n),!0);){const{tokenValue:r,tokenRaw:a,tokenIndex:i,tokenLine:s,tokenColumn:l}=e;ne(e,-16385&n|8192,67174408),c.push(sn(e,n,r,a,i,s,l,!1)),u.push(je(e,n,t,0,1,e.tokenIndex,e.tokenLine,e.tokenColumn)),1074790415!==e.getToken()&&o(e,83)}{const{tokenValue:t,tokenRaw:o,tokenIndex:r,tokenLine:a,tokenColumn:i}=e;ne(e,n,67174409),c.push(sn(e,n,t,o,r,a,i,!0))}return se(e,n,i,s,l,{type:"TemplateLiteral",expressions:u,quasis:c})}function sn(e,n,t,o,r,a,i,s){const l=se(e,n,r,a,i,{type:"TemplateElement",value:{cooked:t,raw:o},tail:s}),c=s?1:2;return 2&n&&(l.start+=1,l.range[0]+=1,l.end-=c,l.range[1]-=c),4&n&&(l.loc.start.column+=1,l.loc.end.column-=c),l}function ln(e,n,t,o,r,a){ne(e,8192|(n=33554432^(33554432|n)),14);const i=Ge(e,n,t,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn);return e.assignable=1,se(e,n,o,r,a,{type:"SpreadElement",argument:i})}function cn(e,n,t,o){H(e,8192|n);const r=[];if(16===e.getToken())return H(e,16384|n),r;for(;16!==e.getToken()&&(14===e.getToken()?r.push(ln(e,n,t,e.tokenIndex,e.tokenLine,e.tokenColumn)):r.push(Ge(e,n,t,1,o,e.tokenIndex,e.tokenLine,e.tokenColumn)),18===e.getToken())&&(H(e,8192|n),16!==e.getToken()););return ne(e,16384|n,16),r}function un(e,n){const{tokenValue:t,tokenIndex:o,tokenLine:r,tokenColumn:a}=e,i="await"===t&&!(-2147483648&e.getToken());return H(e,n|(i?8192:0)),se(e,n,o,r,a,{type:"Identifier",name:t})}function dn(e,n){const{tokenValue:t,tokenRaw:o,tokenIndex:r,tokenLine:a,tokenColumn:i}=e;return 134283388===e.getToken()?on(e,n,r,a,i):(H(e,n),e.assignable=2,se(e,n,r,a,i,128&n?{type:"Literal",value:t,raw:o}:{type:"Literal",value:t}))}function gn(e,n,t,r,a,i,s,l,c,u,d){H(e,8192|n);const g=i?Q(e,n,8391476):0;let k,p=null,f=t?{parent:void 0,type:2}:void 0;if(67174411===e.getToken())1&s||o(e,39,"Function");else{const r=!(4&a)||2048&n&&512&n?64|(l?1024:0)|(g?1024:0):4;re(e,n,e.getToken()),t&&(4&r?pe(e,n,t,e.tokenValue,r):ke(e,n,t,e.tokenValue,r,a),f=de(f,256),s&&2&s&&me(e,e.tokenValue)),k=e.getToken(),143360&e.getToken()?p=un(e,n):o(e,30,U[255&e.getToken()])}const m=7274496;n=(n|m)^m|16777216|(l?524288:0)|(g?262144:0)|(g?0:67108864),t&&(f=de(f,512));const b=268471296;return se(e,n,c,u,d,{type:"FunctionDeclaration",id:p,params:wn(e,-268435457&n|2097152,f,r,0,1),body:Xe(e,9437184|(n|b)^b,t?de(f,128):f,r,8,k,f?.scopeError),async:1===l,generator:1===g})}function kn(e,n,t,o,r,a,i,s){H(e,8192|n);const l=Q(e,n,8391476),c=(o?524288:0)|(l?262144:0);let u,d=null,g=16&n?{parent:void 0,type:2}:void 0;const k=275709952;143360&e.getToken()&&(re(e,(n|k)^k|c,e.getToken()),g&&(g=de(g,256)),u=e.getToken(),d=un(e,n)),n=(n|k)^k|16777216|c|(l?0:67108864),g&&(g=de(g,512));const p=wn(e,-268435457&n|2097152,g,t,r,1),f=Xe(e,9437184|-33594369&n,g?de(g,128):g,t,0,u,g?.scopeError);return e.assignable=2,se(e,n,a,i,s,{type:"FunctionExpression",id:d,params:p,body:f,async:1===o,generator:1===l})}function pn(e,n,t,r,a,i,s,l,c,u,d,g){H(e,8192|n);const k=[];let p=0;for(n=33554432^(33554432|n);20!==e.getToken();)if(ee(e,8192|n,18))k.push(null);else{let a;const{tokenIndex:u,tokenLine:d,tokenColumn:g,tokenValue:f}=e,m=e.getToken();if(143360&m)if(a=Ze(e,n,r,l,0,1,i,1,u,d,g),1077936155===e.getToken()){2&e.assignable&&o(e,26),H(e,8192|n),t&&ge(e,n,t,f,l,c);const k=Ge(e,n,r,1,i,e.tokenIndex,e.tokenLine,e.tokenColumn);a=se(e,n,u,d,g,s?{type:"AssignmentPattern",left:a,right:k}:{type:"AssignmentExpression",operator:"=",left:a,right:k}),p|=256&e.destructible?256:128&e.destructible?128:0}else 18===e.getToken()||20===e.getToken()?(2&e.assignable?p|=16:t&&ge(e,n,t,f,l,c),p|=256&e.destructible?256:128&e.destructible?128:0):(p|=1&l?32:2&l?0:16,a=$e(e,n,r,a,i,0,u,d,g),18!==e.getToken()&&20!==e.getToken()?(1077936155!==e.getToken()&&(p|=16),a=Je(e,n,r,i,s,u,d,g,a)):1077936155!==e.getToken()&&(p|=2&e.assignable?16:32));else 2097152&m?(a=2162700===e.getToken()?hn(e,n,t,r,0,i,s,l,c,u,d,g):pn(e,n,t,r,0,i,s,l,c,u,d,g),p|=e.destructible,e.assignable=16&e.destructible?2:1,18===e.getToken()||20===e.getToken()?2&e.assignable&&(p|=16):8&e.destructible?o(e,71):(a=$e(e,n,r,a,i,0,u,d,g),p=2&e.assignable?16:0,18!==e.getToken()&&20!==e.getToken()?a=Je(e,n,r,i,s,u,d,g,a):1077936155!==e.getToken()&&(p|=2&e.assignable?16:32))):14===m?(a=mn(e,n,t,r,20,l,c,0,i,s,u,d,g),p|=e.destructible,18!==e.getToken()&&20!==e.getToken()&&o(e,30,U[255&e.getToken()])):(a=_e(e,n,r,1,0,1,u,d,g),18!==e.getToken()&&20!==e.getToken()?(a=Je(e,n,r,i,s,u,d,g,a),3&l||67174411!==m||(p|=16)):2&e.assignable?p|=16:67174411===m&&(p|=1&e.assignable&&3&l?32:16));if(k.push(a),!ee(e,8192|n,18))break;if(20===e.getToken())break}ne(e,n,20);const f=se(e,n,u,d,g,{type:s?"ArrayPattern":"ArrayExpression",elements:k});return!a&&4194304&e.getToken()?fn(e,n,r,p,i,s,u,d,g,f):(e.destructible=p,f)}function fn(e,n,t,r,a,i,s,l,c,u){1077936155!==e.getToken()&&o(e,26),H(e,8192|n),16&r&&o(e,26),i||te(e,u);const{tokenIndex:d,tokenLine:g,tokenColumn:k}=e,p=Ge(e,n,t,1,a,d,g,k);return e.destructible=72^(72|r)|(128&e.destructible?128:0)|(256&e.destructible?256:0),se(e,n,s,l,c,i?{type:"AssignmentPattern",left:u,right:p}:{type:"AssignmentExpression",left:u,operator:"=",right:p})}function mn(e,n,t,r,a,i,s,l,c,u,d,g,k){H(e,8192|n);let p=null,f=0;const{tokenValue:m,tokenIndex:b,tokenLine:h,tokenColumn:x}=e;let T=e.getToken();if(143360&T)e.assignable=1,p=Ze(e,n,r,i,0,1,c,1,b,h,x),T=e.getToken(),p=$e(e,n,r,p,c,0,b,h,x),18!==e.getToken()&&e.getToken()!==a&&(2&e.assignable&&1077936155===e.getToken()&&o(e,71),f|=16,p=Je(e,n,r,c,u,b,h,x,p)),2&e.assignable?f|=16:T===a||18===T?t&&ge(e,n,t,m,i,s):f|=32,f|=128&e.destructible?128:0;else if(T===a)o(e,41);else{if(!(2097152&T)){f|=32,p=_e(e,n,r,1,c,1,e.tokenIndex,e.tokenLine,e.tokenColumn);const{tokenIndex:t,tokenLine:i,tokenColumn:s}=e,l=e.getToken();return 1077936155===l?(2&e.assignable&&o(e,26),p=Je(e,n,r,c,u,t,i,s,p),f|=16):(18===l?f|=16:l!==a&&(p=Je(e,n,r,c,u,t,i,s,p)),f|=1&e.assignable?32:16),e.destructible=f,e.getToken()!==a&&18!==e.getToken()&&o(e,161),se(e,n,d,g,k,{type:u?"RestElement":"SpreadElement",argument:p})}p=2162700===e.getToken()?hn(e,n,t,r,1,c,u,i,s,b,h,x):pn(e,n,t,r,1,c,u,i,s,b,h,x),T=e.getToken(),1077936155!==T&&T!==a&&18!==T?(8&e.destructible&&o(e,71),p=$e(e,n,r,p,c,0,b,h,x),f|=2&e.assignable?16:0,4194304&~e.getToken()?(8388608&~e.getToken()||(p=ze(e,n,r,1,b,h,x,4,T,p)),ee(e,8192|n,22)&&(p=Me(e,n,r,p,b,h,x)),f|=2&e.assignable?16:32):(1077936155!==e.getToken()&&(f|=16),p=Je(e,n,r,c,u,b,h,x,p))):f|=1074790415===a&&1077936155!==T?16:e.destructible}if(e.getToken()!==a)if(1&i&&(f|=l?16:32),ee(e,8192|n,1077936155)){16&f&&o(e,26),te(e,p);const t=Ge(e,n,r,1,c,e.tokenIndex,e.tokenLine,e.tokenColumn);p=se(e,n,b,h,x,u?{type:"AssignmentPattern",left:p,right:t}:{type:"AssignmentExpression",left:p,operator:"=",right:t}),f=16}else f|=16;return e.destructible=f,se(e,n,d,g,k,{type:u?"RestElement":"SpreadElement",argument:p})}function bn(e,n,t,a,i,s,l,c){const u=2883584|(64&a?0:4325376);let d=16&(n=25231360|((n|u)^u|(8&a?262144:0)|(16&a?524288:0)|(64&a?4194304:0)))?de({parent:void 0,type:2},512):void 0;const g=function(e,n,t,a,i,s,l){ne(e,n,67174411);const c=[];if(e.flags=128^(128|e.flags),16===e.getToken())return 512&i&&o(e,37,"Setter","one",""),H(e,n),c;256&i&&o(e,37,"Getter","no","s");512&i&&14===e.getToken()&&o(e,38);n=33554432^(33554432|n);let u=0,d=0;for(;18!==e.getToken();){let r=null;const{tokenIndex:g,tokenLine:k,tokenColumn:p}=e;if(143360&e.getToken()?(256&n||(36864&~e.getToken()||(e.flags|=256),537079808&~e.getToken()||(e.flags|=512)),r=Pn(e,n,t,1|i,0,g,k,p)):(2162700===e.getToken()?r=hn(e,n,t,a,1,l,1,s,0,g,k,p):69271571===e.getToken()?r=pn(e,n,t,a,1,l,1,s,0,g,k,p):14===e.getToken()&&(r=mn(e,n,t,a,16,s,0,0,l,1,g,k,p)),d=1,48&e.destructible&&o(e,50)),1077936155===e.getToken()){H(e,8192|n),d=1;r=se(e,n,g,k,p,{type:"AssignmentPattern",left:r,right:Ge(e,n,a,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn)})}if(u++,c.push(r),!ee(e,n,18))break;if(16===e.getToken())break}512&i&&1!==u&&o(e,37,"Setter","one","");t&&t.scopeError&&r(t.scopeError);d&&(e.flags|=128);return ne(e,n,16),c}(e,-268435457&n|2097152,d,t,a,1,i);d&&(d=de(d,128));return se(e,n,s,l,c,{type:"FunctionExpression",params:g,body:Xe(e,9437184|-301992961&n,d,t,0,void 0,d?.parent?.scopeError),async:(16&a)>0,generator:(8&a)>0,id:null})}function hn(e,n,t,r,i,s,l,c,u,d,g,k){H(e,n);const p=[];let f=0,m=0;for(n=33554432^(33554432|n);1074790415!==e.getToken();){const{tokenValue:i,tokenLine:d,tokenColumn:g,tokenIndex:k}=e,b=e.getToken();if(14===b)p.push(mn(e,n,t,r,1074790415,c,u,0,s,l,k,d,g));else{let h,x=0,T=null;if(143360&e.getToken()||-2147483528===e.getToken()||-2147483527===e.getToken())if(-2147483527===e.getToken()&&(f|=16),T=un(e,n),18===e.getToken()||1074790415===e.getToken()||1077936155===e.getToken())if(x|=4,256&n&&!(537079808&~b)?f|=16:oe(e,n,c,b,0),t&&ge(e,n,t,i,c,u),ee(e,8192|n,1077936155)){f|=8;const t=Ge(e,n,r,1,s,e.tokenIndex,e.tokenLine,e.tokenColumn);f|=256&e.destructible?256:128&e.destructible?128:0,h=se(e,n,k,d,g,{type:"AssignmentPattern",left:134217728&n?Object.assign({},T):T,right:t})}else f|=(209006===b?128:0)|(-2147483528===b?16:0),h=134217728&n?Object.assign({},T):T;else if(ee(e,8192|n,21)){const{tokenIndex:a,tokenLine:d,tokenColumn:g}=e;if("__proto__"===i&&m++,143360&e.getToken()){const o=e.getToken(),i=e.tokenValue;h=Ze(e,n,r,c,0,1,s,1,a,d,g);const k=e.getToken();h=$e(e,n,r,h,s,0,a,d,g),18===e.getToken()||1074790415===e.getToken()?1077936155===k||1074790415===k||18===k?(f|=128&e.destructible?128:0,2&e.assignable?f|=16:!t||143360&~o||ge(e,n,t,i,c,u)):f|=1&e.assignable?32:16:4194304&~e.getToken()?(f|=16,8388608&~e.getToken()||(h=ze(e,n,r,1,a,d,g,4,k,h)),ee(e,8192|n,22)&&(h=Me(e,n,r,h,a,d,g))):(2&e.assignable?f|=16:1077936155!==k?f|=32:t&&ge(e,n,t,i,c,u),h=Je(e,n,r,s,l,a,d,g,h))}else 2097152&~e.getToken()?(h=_e(e,n,r,1,s,1,a,d,g),f|=1&e.assignable?32:16,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(f|=16):(h=$e(e,n,r,h,s,0,a,d,g),f=2&e.assignable?16:0,18!==e.getToken()&&1074790415!==b&&(1077936155!==e.getToken()&&(f|=16),h=Je(e,n,r,s,l,a,d,g,h)))):(h=69271571===e.getToken()?pn(e,n,t,r,0,s,l,c,u,a,d,g):hn(e,n,t,r,0,s,l,c,u,a,d,g),f=e.destructible,e.assignable=16&f?2:1,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(f|=16):8&e.destructible?o(e,71):(h=$e(e,n,r,h,s,0,a,d,g),f=2&e.assignable?16:0,4194304&~e.getToken()?(8388608&~e.getToken()||(h=ze(e,n,r,1,a,d,g,4,b,h)),ee(e,8192|n,22)&&(h=Me(e,n,r,h,a,d,g)),f|=2&e.assignable?16:32):h=He(e,n,r,s,l,a,d,g,h)))}else 69271571===e.getToken()?(f|=16,209005===b&&(x|=16),x|=2|(12400===b?256:12401===b?512:1),T=xn(e,n,r,s),f|=e.assignable,h=bn(e,n,r,x,s,e.tokenIndex,e.tokenLine,e.tokenColumn)):143360&e.getToken()?(f|=16,-2147483528===b&&o(e,95),209005===b?(1&e.flags&&o(e,132),x|=17):12400===b?x|=256:12401===b?x|=512:o(e,0),T=un(e,n),h=bn(e,n,r,x,s,e.tokenIndex,e.tokenLine,e.tokenColumn)):67174411===e.getToken()?(f|=16,x|=1,h=bn(e,n,r,x,s,e.tokenIndex,e.tokenLine,e.tokenColumn)):8391476===e.getToken()?(f|=16,12400===b?o(e,42):12401===b?o(e,43):209005!==b&&o(e,30,U[52]),H(e,n),x|=9|(209005===b?16:0),143360&e.getToken()?T=un(e,n):134217728&~e.getToken()?69271571===e.getToken()?(x|=2,T=xn(e,n,r,s),f|=e.assignable):o(e,30,U[255&e.getToken()]):T=dn(e,n),h=bn(e,n,r,x,s,e.tokenIndex,e.tokenLine,e.tokenColumn)):134217728&~e.getToken()?o(e,133):(209005===b&&(x|=16),x|=12400===b?256:12401===b?512:1,f|=16,T=dn(e,n),h=bn(e,n,r,x,s,e.tokenIndex,e.tokenLine,e.tokenColumn));else if(134217728&~e.getToken())if(69271571===e.getToken())if(T=xn(e,n,r,s),f|=256&e.destructible?256:0,x|=2,21===e.getToken()){H(e,8192|n);const{tokenIndex:a,tokenLine:i,tokenColumn:d,tokenValue:g}=e,k=e.getToken();if(143360&e.getToken()){h=Ze(e,n,r,c,0,1,s,1,a,i,d);const o=e.getToken();h=$e(e,n,r,h,s,0,a,i,d),4194304&~e.getToken()?18===e.getToken()||1074790415===e.getToken()?1077936155===o||1074790415===o||18===o?2&e.assignable?f|=16:!t||143360&~k||ge(e,n,t,g,c,u):f|=1&e.assignable?32:16:(f|=16,h=Je(e,n,r,s,l,a,i,d,h)):(f|=2&e.assignable?16:1077936155===o?0:32,h=He(e,n,r,s,l,a,i,d,h))}else 2097152&~e.getToken()?(h=_e(e,n,r,1,0,1,a,i,d),f|=1&e.assignable?32:16,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(f|=16):(h=$e(e,n,r,h,s,0,a,i,d),f=1&e.assignable?0:16,18!==e.getToken()&&1074790415!==e.getToken()&&(1077936155!==e.getToken()&&(f|=16),h=Je(e,n,r,s,l,a,i,d,h)))):(h=69271571===e.getToken()?pn(e,n,t,r,0,s,l,c,u,a,i,d):hn(e,n,t,r,0,s,l,c,u,a,i,d),f=e.destructible,e.assignable=16&f?2:1,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(f|=16):8&f?o(e,62):(h=$e(e,n,r,h,s,0,a,i,d),f=2&e.assignable?16|f:0,4194304&~e.getToken()?(8388608&~e.getToken()||(h=ze(e,n,r,1,a,i,d,4,b,h)),ee(e,8192|n,22)&&(h=Me(e,n,r,h,a,i,d)),f|=2&e.assignable?16:32):(1077936155!==e.getToken()&&(f|=16),h=He(e,n,r,s,l,a,i,d,h))))}else 67174411===e.getToken()?(x|=1,h=bn(e,n,r,x,s,e.tokenIndex,d,g),f=16):o(e,44);else if(8391476===b)if(ne(e,8192|n,8391476),x|=8,143360&e.getToken()){const t=e.getToken();T=un(e,n),x|=1,67174411===e.getToken()?(f|=16,h=bn(e,n,r,x,s,e.tokenIndex,e.tokenLine,e.tokenColumn)):a(e.tokenIndex,e.tokenLine,e.tokenColumn,e.index,e.line,e.column,209005===t?46:12400===t||12401===e.getToken()?45:47,U[255&t])}else 134217728&~e.getToken()?69271571===e.getToken()?(f|=16,x|=3,T=xn(e,n,r,s),h=bn(e,n,r,x,s,e.tokenIndex,e.tokenLine,e.tokenColumn)):o(e,126):(f|=16,T=dn(e,n),x|=1,h=bn(e,n,r,x,s,k,d,g));else o(e,30,U[255&b]);else if(T=dn(e,n),21===e.getToken()){ne(e,8192|n,21);const{tokenIndex:o,tokenLine:a,tokenColumn:d}=e;if("__proto__"===i&&m++,143360&e.getToken()){h=Ze(e,n,r,c,0,1,s,1,o,a,d);const{tokenValue:i}=e,g=e.getToken();h=$e(e,n,r,h,s,0,o,a,d),18===e.getToken()||1074790415===e.getToken()?1077936155===g||1074790415===g||18===g?2&e.assignable?f|=16:t&&ge(e,n,t,i,c,u):f|=1&e.assignable?32:16:1077936155===e.getToken()?(2&e.assignable&&(f|=16),h=Je(e,n,r,s,l,o,a,d,h)):(f|=16,h=Je(e,n,r,s,l,o,a,d,h))}else 2097152&~e.getToken()?(h=_e(e,n,r,1,0,1,o,a,d),f|=1&e.assignable?32:16,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(f|=16):(h=$e(e,n,r,h,s,0,o,a,d),f=1&e.assignable?0:16,18!==e.getToken()&&1074790415!==e.getToken()&&(1077936155!==e.getToken()&&(f|=16),h=Je(e,n,r,s,l,o,a,d,h)))):(h=69271571===e.getToken()?pn(e,n,t,r,0,s,l,c,u,o,a,d):hn(e,n,t,r,0,s,l,c,u,o,a,d),f=e.destructible,e.assignable=16&f?2:1,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(f|=16):8&~e.destructible&&(h=$e(e,n,r,h,s,0,o,a,d),f=2&e.assignable?16:0,4194304&~e.getToken()?(8388608&~e.getToken()||(h=ze(e,n,r,1,o,a,d,4,b,h)),ee(e,8192|n,22)&&(h=Me(e,n,r,h,o,a,d)),f|=2&e.assignable?16:32):h=He(e,n,r,s,l,o,a,d,h)))}else 67174411===e.getToken()?(x|=1,h=bn(e,n,r,x,s,e.tokenIndex,e.tokenLine,e.tokenColumn),f=16|e.assignable):o(e,134);f|=128&e.destructible?128:0,e.destructible=f,p.push(se(e,n,k,d,g,{type:"Property",key:T,value:h,kind:768&x?512&x?"set":"get":"init",computed:(2&x)>0,method:(1&x)>0,shorthand:(4&x)>0}))}if(f|=e.destructible,18!==e.getToken())break;H(e,n)}ne(e,n,1074790415),m>1&&(f|=64);const b=se(e,n,d,g,k,{type:l?"ObjectPattern":"ObjectExpression",properties:p});return!i&&4194304&e.getToken()?fn(e,n,r,f,s,l,d,g,k,b):(e.destructible=f,b)}function xn(e,n,t,o){H(e,8192|n);const r=Ge(e,33554432^(33554432|n),t,1,o,e.tokenIndex,e.tokenLine,e.tokenColumn);return ne(e,n,20),r}function Tn(e,n,t,o,r,a){const{tokenValue:i}=e;let s=0,l=0;537079808&~e.getToken()?36864&~e.getToken()||(l=1):s=1;const c=un(e,n);if(e.assignable=1,10===e.getToken()){let u;return 16&n&&(u=ce(e,n,i)),s&&(e.flags|=128),l&&(e.flags|=256),vn(e,n,u,t,[c],0,o,r,a)}return c}function yn(e,n,t,r,a,i,s,l,c,u,d){s||o(e,57),i&&o(e,51),e.flags&=-129;return vn(e,n,16&n?ce(e,n,r):void 0,t,[a],l,c,u,d)}function Cn(e,n,t,r,a,i,s,l,c,u){i||o(e,57);for(let n=0;n<a.length;++n)te(e,a[n]);return vn(e,n,t,r,a,s,l,c,u)}function vn(e,n,t,a,i,s,l,c,u){1&e.flags&&o(e,48),ne(e,8192|n,10);const d=271319040;n=(n|d)^d|(s?524288:0);const g=2162700!==e.getToken();let k;if(t&&t.scopeError&&r(t.scopeError),g)e.flags=4928^(4928|e.flags),k=Ge(e,n,a,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn);else{t&&(t=de(t,128));const r=33557504;switch(k=Xe(e,(n|r)^r|1048576,t,a,16,void 0,void 0),e.getToken()){case 69271571:1&e.flags||o(e,116);break;case 67108877:case 67174409:case 22:o(e,117);case 67174411:1&e.flags||o(e,116),e.flags|=1024}8388608&~e.getToken()||1&e.flags||o(e,30,U[255&e.getToken()]),33619968&~e.getToken()||o(e,125)}return e.assignable=2,se(e,n,l,c,u,{type:"ArrowFunctionExpression",params:i,body:k,async:1===s,expression:g})}function wn(e,n,t,a,i,s){ne(e,n,67174411),e.flags=128^(128|e.flags);const l=[];if(ee(e,n,16))return l;n=33554432^(33554432|n);let c=0;for(;18!==e.getToken();){let r;const{tokenIndex:u,tokenLine:d,tokenColumn:g}=e,k=e.getToken();if(143360&k?(256&n||(36864&~k||(e.flags|=256),537079808&~k||(e.flags|=512)),r=Pn(e,n,t,1|s,0,u,d,g)):(2162700===k?r=hn(e,n,t,a,1,i,1,s,0,u,d,g):69271571===k?r=pn(e,n,t,a,1,i,1,s,0,u,d,g):14===k?r=mn(e,n,t,a,16,s,0,0,i,1,u,d,g):o(e,30,U[255&k]),c=1,48&e.destructible&&o(e,50)),1077936155===e.getToken()){H(e,8192|n),c=1;r=se(e,n,u,d,g,{type:"AssignmentPattern",left:r,right:Ge(e,n,a,1,i,e.tokenIndex,e.tokenLine,e.tokenColumn)})}if(l.push(r),!ee(e,n,18))break;if(16===e.getToken())break}return c&&(e.flags|=128),t&&(c||256&n)&&t.scopeError&&r(t.scopeError),ne(e,n,16),l}function Ln(e,n,t,o,r,a,i,s){const l=e.getToken();if(67108864&l){if(67108877===l){H(e,67108864|n),e.assignable=1;return Ln(e,n,t,se(e,n,a,i,s,{type:"MemberExpression",object:o,computed:!1,property:Ye(e,n,t)}),0,a,i,s)}if(69271571===l){H(e,8192|n);const{tokenIndex:l,tokenLine:c,tokenColumn:u}=e,d=je(e,n,t,r,1,l,c,u);return ne(e,n,20),e.assignable=1,Ln(e,n,t,se(e,n,a,i,s,{type:"MemberExpression",object:o,computed:!0,property:d}),0,a,i,s)}if(67174408===l||67174409===l)return e.assignable=2,Ln(e,n,t,se(e,n,a,i,s,{type:"TaggedTemplateExpression",tag:o,quasi:67174408===e.getToken()?an(e,16384|n,t):rn(e,16384|n,e.tokenIndex,e.tokenLine,e.tokenColumn)}),0,a,i,s)}return o}function In(e,n,t,r,a,i,s){return 209006===e.getToken()&&o(e,31),262400&n&&241771===e.getToken()&&o(e,32),he(e,n,e.getToken()),36864&~e.getToken()||(e.flags|=256),yn(e,-268435457&n|524288,t,e.tokenValue,un(e,n),0,r,1,a,i,s)}function qn(e,n,t,r,a,i,s,l,c,u,d){H(e,8192|n);const g=16&n?de({parent:void 0,type:2},1024):void 0;if(ee(e,n=33554432^(33554432|n),16))return 10===e.getToken()?(1&l&&o(e,48),Cn(e,n,g,t,[],a,1,c,u,d)):se(e,n,c,u,d,{type:"CallExpression",callee:r,arguments:[]});let k=0,p=null,f=0;e.destructible=384^(384|e.destructible);const m=[];for(;16!==e.getToken();){const{tokenIndex:a,tokenLine:l,tokenColumn:b}=e,h=e.getToken();if(143360&h)g&&ke(e,n,g,e.tokenValue,i,0),537079808&~h?36864&~h||(e.flags|=256):e.flags|=512,p=Ze(e,n,t,i,0,1,1,1,a,l,b),16===e.getToken()||18===e.getToken()?2&e.assignable&&(k|=16,f=1):(1077936155===e.getToken()?f=1:k|=16,p=$e(e,n,t,p,1,0,a,l,b),16!==e.getToken()&&18!==e.getToken()&&(p=Je(e,n,t,1,0,a,l,b,p)));else if(2097152&h)p=2162700===h?hn(e,n,g,t,0,1,0,i,s,a,l,b):pn(e,n,g,t,0,1,0,i,s,a,l,b),k|=e.destructible,f=1,16!==e.getToken()&&18!==e.getToken()&&(8&k&&o(e,122),p=$e(e,n,t,p,0,0,a,l,b),k|=16,8388608&~e.getToken()||(p=ze(e,n,t,1,c,u,d,4,h,p)),ee(e,8192|n,22)&&(p=Me(e,n,t,p,c,u,d)));else{if(14!==h){for(p=Ge(e,n,t,1,0,a,l,b),k=e.assignable,m.push(p);ee(e,8192|n,18);)m.push(Ge(e,n,t,1,0,a,l,b));return k|=e.assignable,ne(e,n,16),e.destructible=16|k,e.assignable=2,se(e,n,c,u,d,{type:"CallExpression",callee:r,arguments:m})}p=mn(e,n,g,t,16,i,s,1,1,0,a,l,b),k|=(16===e.getToken()?0:16)|e.destructible,f=1}if(m.push(p),!ee(e,8192|n,18))break}return ne(e,n,16),k|=256&e.destructible?256:128&e.destructible?128:0,10===e.getToken()?(48&k&&o(e,27),(1&e.flags||1&l)&&o(e,48),128&k&&o(e,31),262400&n&&256&k&&o(e,32),f&&(e.flags|=128),Cn(e,524288|n,g,t,m,a,1,c,u,d)):(64&k&&o(e,63),8&k&&o(e,62),e.assignable=2,se(e,n,c,u,d,{type:"CallExpression",callee:r,arguments:m}))}function En(e,n,t,r,a,i,s,l){let c=Sn(e,n,r);c.length&&(i=e.tokenIndex,s=e.tokenLine,l=e.tokenColumn),e.leadingDecorators.length&&(e.leadingDecorators.push(...c),c=e.leadingDecorators,e.leadingDecorators=[]),H(e,n=4194304^(4194560|n));let u=null,d=null;const{tokenValue:g}=e;4096&e.getToken()&&20565!==e.getToken()?(ae(e,n,e.getToken())&&o(e,118),537079808&~e.getToken()||o(e,119),t&&(ke(e,n,t,g,32,0),a&&2&a&&me(e,g)),u=un(e,n)):1&a||o(e,39,"Class");let k=n;ee(e,8192|n,20565)?(d=_e(e,n,r,0,0,0,e.tokenIndex,e.tokenLine,e.tokenColumn),k|=131072):k=131072^(131072|k);return se(e,n,i,s,l,{type:"ClassDeclaration",id:u,superClass:d,body:Dn(e,k,n,t,r,2,8,0),...1&n?{decorators:c}:null})}function Sn(e,n,t){const o=[];if(1&n)for(;132===e.getToken();)o.push(An(e,n,t,e.tokenIndex,e.tokenLine,e.tokenColumn));return o}function An(e,n,t,o,r,a){H(e,8192|n);let i=Ze(e,n,t,2,0,1,0,1,o,r,a);return i=$e(e,n,t,i,0,0,o,r,a),se(e,n,o,r,a,{type:"Decorator",expression:i})}function Dn(e,n,r,a,i,s,l,c){const{tokenIndex:u,tokenLine:d,tokenColumn:g}=e,k=16&n?{parent:i,refs:Object.create(null)}:void 0;ne(e,8192|n,2162700);const p=301989888;n=(n|p)^p;const f=32&e.flags;e.flags=32^(32|e.flags);const m=[];let b;for(;1074790415!==e.getToken();){let t=0;b=Sn(e,n,k),t=b.length,t>0&&"constructor"===e.tokenValue&&o(e,109),1074790415===e.getToken()&&o(e,108),ee(e,n,1074790417)?t>0&&o(e,120):m.push(Vn(e,n,a,k,r,s,b,0,c,e.tokenIndex,e.tokenLine,e.tokenColumn))}return ne(e,8&l?8192|n:n,1074790415),k&&function(e){for(const n in e.refs)if(!fe(n,e)){const{index:o,line:r,column:a}=e.refs[n][0];throw new t(o,r,a,o+n.length,r,a+n.length,4,n)}}(k),e.flags=-33&e.flags|f,se(e,n,u,d,g,{type:"ClassBody",body:m})}function Vn(e,n,t,r,a,i,s,l,c,u,d,g){let k=l?32:0,p=null;const{tokenIndex:f,tokenLine:m,tokenColumn:b}=e,h=e.getToken();if(176128&h||-2147483528===h)switch(p=un(e,n),h){case 36970:if(!l&&67174411!==e.getToken()&&1048576&~e.getToken()&&1077936155!==e.getToken())return Vn(e,n,t,r,a,i,s,1,c,u,d,g);break;case 209005:if(67174411!==e.getToken()&&!(1&e.flags)){if(!(1073741824&~e.getToken()))return Nn(e,n,r,p,k,s,f,m,b);k|=16|(Q(e,n,8391476)?8:0)}break;case 12400:if(67174411!==e.getToken()){if(!(1073741824&~e.getToken()))return Nn(e,n,r,p,k,s,f,m,b);k|=256}break;case 12401:if(67174411!==e.getToken()){if(!(1073741824&~e.getToken()))return Nn(e,n,r,p,k,s,f,m,b);k|=512}break;case 12402:if(67174411!==e.getToken()&&!(1&e.flags)){if(!(1073741824&~e.getToken()))return Nn(e,n,r,p,k,s,f,m,b);1&n&&(k|=1024)}}else if(69271571===h)k|=2,p=xn(e,a,r,c);else if(134217728&~h)if(8391476===h)k|=8,H(e,n);else if(130===e.getToken())k|=8192,p=Rn(e,4096|n,r,768,f,m,b);else if(1073741824&~e.getToken()){if(l&&2162700===h)return function(e,n,t,o,r,a,i){t&&(t=de(t,2));const s=1475584;n=285802496|(n|s)^s;const{body:l}=ve(e,n,t,o,{},r,a,i);return se(e,n,r,a,i,{type:"StaticBlock",body:l})}(e,4096|n,t,r,f,m,b);-2147483527===h?(p=un(e,n),67174411!==e.getToken()&&o(e,30,U[255&e.getToken()])):o(e,30,U[255&e.getToken()])}else k|=128;else p=dn(e,n);if(1816&k&&(143360&e.getToken()||-2147483528===e.getToken()||-2147483527===e.getToken()?p=un(e,n):134217728&~e.getToken()?69271571===e.getToken()?(k|=2,p=xn(e,n,r,0)):130===e.getToken()?(k|=8192,p=Rn(e,n,r,k,f,m,b)):o(e,135):p=dn(e,n)),2&k||("constructor"===e.tokenValue?(1073741824&~e.getToken()?32&k||67174411!==e.getToken()||(920&k?o(e,53,"accessor"):131072&n||(32&e.flags?o(e,54):e.flags|=32)):o(e,129),k|=64):!(8192&k)&&32&k&&"prototype"===e.tokenValue&&o(e,52)),1024&k||67174411!==e.getToken()&&!(768&k))return Nn(e,n,r,p,k,s,f,m,b);return se(e,n,u,d,g,{type:"MethodDefinition",kind:!(32&k)&&64&k?"constructor":256&k?"get":512&k?"set":"method",static:(32&k)>0,computed:(2&k)>0,key:p,value:bn(e,4096|n,r,k,c,e.tokenIndex,e.tokenLine,e.tokenColumn),...1&n?{decorators:s}:null})}function Rn(e,n,t,r,a,i,s){H(e,n);const{tokenValue:l}=e;return"constructor"===l&&o(e,128),16&n&&(t||o(e,4,l),r?function(e,n,t,r){let a=800&r;768&a||(a|=768);const i=n["#"+t];void 0!==i&&((32&i)!=(32&a)||i&a&768)&&o(e,146,t),n["#"+t]=i?i|a:a}(e,t,l,r):function(e,n,t){n.refs[t]??=[],n.refs[t].push({index:e.tokenIndex,line:e.tokenLine,column:e.tokenColumn})}(e,t,l)),H(e,n),se(e,n,a,i,s,{type:"PrivateIdentifier",name:l})}function Nn(e,n,t,r,a,i,s,l,c){let u=null;if(8&a&&o(e,0),1077936155===e.getToken()){H(e,8192|n);const{tokenIndex:r,tokenLine:i,tokenColumn:s}=e;537079927===e.getToken()&&o(e,119);const l=2883584|(64&a?0:4325376);u=Ze(e,4096|(n=16842752|((n|l)^l|(8&a?262144:0)|(16&a?524288:0)|(64&a?4194304:0))),t,2,0,1,0,1,r,i,s),!(1073741824&~e.getToken())&&4194304&~e.getToken()||(u=$e(e,4096|n,t,u,0,0,r,i,s),u=Je(e,4096|n,t,0,0,r,i,s,u))}return W(e,n),se(e,n,s,l,c,{type:1024&a?"AccessorProperty":"PropertyDefinition",key:r,value:u,static:(32&a)>0,computed:(2&a)>0,...1&n?{decorators:i}:null})}function Un(e,n,t,r,a,i,s,l,c){if(143360&e.getToken()||!(256&n)&&-2147483527===e.getToken())return Pn(e,n,t,a,i,s,l,c);2097152&~e.getToken()&&o(e,30,U[255&e.getToken()]);const u=69271571===e.getToken()?pn(e,n,t,r,1,0,1,a,i,s,l,c):hn(e,n,t,r,1,0,1,a,i,s,l,c);return 16&e.destructible&&o(e,50),32&e.destructible&&o(e,50),u}function Pn(e,n,t,r,a,i,s,l){const{tokenValue:c}=e,u=e.getToken();return 256&n&&(537079808&~u?36864&~u&&-2147483527!==u||o(e,118):o(e,119)),20480&~u||o(e,102),241771===u&&(262144&n&&o(e,32),512&n&&o(e,111)),73==(255&u)&&24&r&&o(e,100),209006===u&&(524288&n&&o(e,176),512&n&&o(e,110)),H(e,n),t&&ge(e,n,t,c,r,a),se(e,n,i,s,l,{type:"Identifier",name:c})}function Bn(e,n,t,r,a,i,s){if(r||ne(e,n,8456256),8390721===e.getToken()){const o=function(e,n,t,o,r){return Y(e,n),se(e,n,t,o,r,{type:"JSXOpeningFragment"})}(e,n,a,i,s),[l,c]=function(e,n,t,o){const r=[];for(;;){const a=Gn(e,n,t,o,e.tokenIndex,e.tokenLine,e.tokenColumn);if("JSXClosingFragment"===a.type)return[r,a];r.push(a)}}(e,n,t,r);return se(e,n,a,i,s,{type:"JSXFragment",openingFragment:o,children:l,closingFragment:c})}8457014===e.getToken()&&o(e,30,U[255&e.getToken()]);let l=null,c=[];const u=function(e,n,t,r,a,i,s){143360&~e.getToken()&&4096&~e.getToken()&&o(e,0);const l=jn(e,n,e.tokenIndex,e.tokenLine,e.tokenColumn),c=function(e,n,t){const o=[];for(;8457014!==e.getToken()&&8390721!==e.getToken()&&1048576!==e.getToken();)o.push(Hn(e,n,t,e.tokenIndex,e.tokenLine,e.tokenColumn));return o}(e,n,t),u=8457014===e.getToken();u&&ne(e,n,8457014);8390721!==e.getToken()&&o(e,25,U[65]);r||!u?Y(e,n):H(e,n);return se(e,n,a,i,s,{type:"JSXOpeningElement",name:l,attributes:c,selfClosing:u})}(e,n,t,r,a,i,s);if(!u.selfClosing){[c,l]=function(e,n,t,o){const r=[];for(;;){const a=On(e,n,t,o,e.tokenIndex,e.tokenLine,e.tokenColumn);if("JSXClosingElement"===a.type)return[r,a];r.push(a)}}(e,n,t,r);const a=le(l.name);le(u.name)!==a&&o(e,155,a)}return se(e,n,a,i,s,{type:"JSXElement",children:c,openingElement:u,closingElement:l})}function On(e,n,t,r,a,i,s){return 137===e.getToken()?Fn(e,n,a,i,s):2162700===e.getToken()?zn(e,n,t,1,0,a,i,s):8456256===e.getToken()?(H(e,n),8457014===e.getToken()?function(e,n,t,r,a,i){ne(e,n,8457014);const s=jn(e,n,e.tokenIndex,e.tokenLine,e.tokenColumn);return 8390721!==e.getToken()&&o(e,25,U[65]),t?Y(e,n):H(e,n),se(e,n,r,a,i,{type:"JSXClosingElement",name:s})}(e,n,r,a,i,s):Bn(e,n,t,1,a,i,s)):void o(e,0)}function Gn(e,n,t,r,a,i,s){return 137===e.getToken()?Fn(e,n,a,i,s):2162700===e.getToken()?zn(e,n,t,1,0,a,i,s):8456256===e.getToken()?(H(e,n),8457014===e.getToken()?function(e,n,t,r,a,i){return ne(e,n,8457014),8390721!==e.getToken()&&o(e,25,U[65]),t?Y(e,n):H(e,n),se(e,n,r,a,i,{type:"JSXClosingFragment"})}(e,n,r,a,i,s):Bn(e,n,t,1,a,i,s)):void o(e,0)}function Fn(e,n,t,o,r){H(e,n);const a={type:"JSXText",value:e.tokenValue};return 128&n&&(a.raw=e.tokenRaw),se(e,n,t,o,r,a)}function jn(e,n,t,o,r){Z(e);let a=Xn(e,n,t,o,r);if(21===e.getToken())return Mn(e,n,a,t,o,r);for(;ee(e,n,67108877);)Z(e),a=Jn(e,n,a,t,o,r);return a}function Jn(e,n,t,o,r,a){return se(e,n,o,r,a,{type:"JSXMemberExpression",object:t,property:Xn(e,n,e.tokenIndex,e.tokenLine,e.tokenColumn)})}function Hn(e,n,t,r,a,i){if(2162700===e.getToken())return function(e,n,t,o,r,a){H(e,n),ne(e,n,14);const i=Ge(e,n,t,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn);return ne(e,n,1074790415),se(e,n,o,r,a,{type:"JSXSpreadAttribute",argument:i})}(e,n,t,r,a,i);Z(e);let s=null,l=Xn(e,n,r,a,i);if(21===e.getToken()&&(l=Mn(e,n,l,r,a,i)),1077936155===e.getToken()){const r=$(e,n),{tokenIndex:a,tokenLine:i,tokenColumn:l}=e;switch(r){case 134283267:s=dn(e,n);break;case 8456256:s=Bn(e,n,t,0,a,i,l);break;case 2162700:s=zn(e,n,t,0,1,a,i,l);break;default:o(e,154)}}return se(e,n,r,a,i,{type:"JSXAttribute",value:s,name:l})}function Mn(e,n,t,o,r,a){ne(e,n,21);return se(e,n,o,r,a,{type:"JSXNamespacedName",namespace:t,name:Xn(e,n,e.tokenIndex,e.tokenLine,e.tokenColumn)})}function zn(e,n,t,r,a,i,s,l){H(e,8192|n);const{tokenIndex:c,tokenLine:u,tokenColumn:d}=e;if(14===e.getToken())return function(e,n,t,o,r,a){ne(e,n,14);const i=Ge(e,n,t,1,0,e.tokenIndex,e.tokenLine,e.tokenColumn);return ne(e,n,1074790415),se(e,n,o,r,a,{type:"JSXSpreadChild",expression:i})}(e,n,t,i,s,l);let g=null;return 1074790415===e.getToken()?(a&&o(e,157),g=function(e,n,t,o,r){return e.startIndex=e.tokenIndex,e.startLine=e.tokenLine,e.startColumn=e.tokenColumn,se(e,n,t,o,r,{type:"JSXEmptyExpression"})}(e,n,e.startIndex,e.startLine,e.startColumn)):g=Ge(e,n,t,1,0,c,u,d),1074790415!==e.getToken()&&o(e,25,U[15]),r?Y(e,n):H(e,n),se(e,n,i,s,l,{type:"JSXExpressionContainer",expression:g})}function Xn(e,n,t,o,r){const{tokenValue:a}=e;return H(e,n),se(e,n,t,o,r,{type:"JSXIdentifier",name:a})}var _n=Object.freeze({__proto__:null});e.ESTree=_n,e.parse=function(e,n){return xe(e,n,0)},e.parseModule=function(e,n){return xe(e,n,768)},e.parseScript=function(e,n){return xe(e,n,0)},e.version="6.0.3"}));

},{}],9:[function(require,module,exports){
module.exports={
  "advisories": {
    "retire-example": {
      "licenses": [
        "Apache-2.0 >=0"
      ],
      "vulnerabilities": [
        {
          "below": "0.0.2",
          "severity": "low",
          "cwe": [
            "CWE-477"
          ],
          "identifiers": {
            "summary": "bug summary",
            "CVE": [
              "CVE-XXXX-XXXX"
            ],
            "bug": "1234"
          },
          "info": [
            "http://github.com/eoftedal/retire.js/"
          ]
        }
      ],
      "extractors": {
        "func": [
          "retire.VERSION"
        ],
        "filename": [
          "retire-example-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "/\\*!? Retire-example v(§§version§§)"
        ],
        "hashes": {
          "07f8b94c8d601a24a1914a1a92bec0e4fafda964": "0.0.1"
        }
      }
    },
    "jquery": {
      "bowername": [
        "jQuery"
      ],
      "npmname": "jquery",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.6.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS with location.hash",
            "CVE": [
              "CVE-2011-4969"
            ],
            "githubID": "GHSA-579v-mp3v-rrw5"
          },
          "info": [
            "http://research.insecurelabs.org/jquery/test/",
            "https://bugs.jquery.com/ticket/9521",
            "https://nvd.nist.gov/vuln/detail/CVE-2011-4969"
          ]
        },
        {
          "below": "1.9.0b1",
          "cwe": [
            "CWE-64",
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Selector interpreted as HTML",
            "CVE": [
              "CVE-2012-6708"
            ],
            "bug": "11290",
            "githubID": "GHSA-2pqj-h3vj-pqgw"
          },
          "info": [
            "http://bugs.jquery.com/ticket/11290",
            "http://research.insecurelabs.org/jquery/test/",
            "https://nvd.nist.gov/vuln/detail/CVE-2012-6708"
          ]
        },
        {
          "atOrAbove": "1.2.1",
          "below": "1.9.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Versions of jquery prior to 1.9.0 are vulnerable to Cross-Site Scripting. The load method fails to recognize and remove \"<script>\" HTML tags that contain a whitespace character, i.e: \"</script >\", which results in the enclosed script logic to be executed. This allows attackers to execute arbitrary JavaScript in a victim's browser.\n\n\n## Recommendation\n\nUpgrade to version 1.9.0 or later.",
            "CVE": [
              "CVE-2020-7656"
            ],
            "githubID": "GHSA-q4m3-2j7h-f7xw"
          },
          "info": [
            "https://github.com/advisories/GHSA-q4m3-2j7h-f7xw",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7656",
            "https://research.insecurelabs.org/jquery/test/"
          ]
        },
        {
          "atOrAbove": "1.4.0",
          "below": "1.12.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "3rd party CORS request may execute",
            "issue": "2432",
            "CVE": [
              "CVE-2015-9251"
            ],
            "githubID": "GHSA-rmxg-73gg-4p98"
          },
          "info": [
            "http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/",
            "http://research.insecurelabs.org/jquery/test/",
            "https://bugs.jquery.com/ticket/11974",
            "https://github.com/advisories/GHSA-rmxg-73gg-4p98",
            "https://github.com/jquery/jquery/issues/2432",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-9251"
          ]
        },
        {
          "below": "2.999.999",
          "cwe": [
            "CWE-1104"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "jQuery 1.x and 2.x are End-of-Life and no longer receiving security updates",
            "retid": "73",
            "issue": "162"
          },
          "info": [
            "https://github.com/jquery/jquery.com/issues/162"
          ]
        },
        {
          "atOrAbove": "1.12.3",
          "below": "3.0.0-beta1",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "3rd party CORS request may execute",
            "issue": "2432",
            "CVE": [
              "CVE-2015-9251"
            ],
            "githubID": "GHSA-rmxg-73gg-4p98"
          },
          "info": [
            "http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/",
            "http://research.insecurelabs.org/jquery/test/",
            "https://bugs.jquery.com/ticket/11974",
            "https://github.com/advisories/GHSA-rmxg-73gg-4p98",
            "https://github.com/jquery/jquery/issues/2432",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-9251"
          ]
        },
        {
          "atOrAbove": "3.0.0-rc.1",
          "below": "3.0.0",
          "cwe": [
            "CWE-400",
            "CWE-674"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Denial of Service in jquery",
            "CVE": [
              "CVE-2016-10707"
            ],
            "githubID": "GHSA-mhpp-875w-9cpv"
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2016-10707"
          ]
        },
        {
          "atOrAbove": "1.1.4",
          "below": "3.4.0",
          "cwe": [
            "CWE-1321",
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution",
            "CVE": [
              "CVE-2019-11358"
            ],
            "PR": "4333",
            "githubID": "GHSA-6c3j-c64m-qhgq"
          },
          "info": [
            "https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/",
            "https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-11358"
          ]
        },
        {
          "atOrAbove": "1.0.3",
          "below": "3.5.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "passing HTML containing <option> elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code.",
            "CVE": [
              "CVE-2020-11023"
            ],
            "issue": "4647",
            "githubID": "GHSA-jpcq-cgw6-v4j6"
          },
          "info": [
            "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"
          ]
        },
        {
          "atOrAbove": "1.2.0",
          "below": "3.5.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Regex in its jQuery.htmlPrefilter sometimes may introduce XSS",
            "CVE": [
              "CVE-2020-11022"
            ],
            "issue": "4642",
            "githubID": "GHSA-gxr4-xjj5-5px2"
          },
          "info": [
            "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"
          ]
        }
      ],
      "extractors": {
        "func": [
          "(window.jQuery || window.$ || window.$jq || window.$j).fn.jquery",
          "require('jquery').fn.jquery"
        ],
        "uri": [
          "/(§§version§§)/jquery(\\.min)?\\.js"
        ],
        "filename": [
          "jquery-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "/\\*!? jQuery v(§§version§§)",
          "\\* jQuery JavaScript Library v(§§version§§)",
          "\\* jQuery (§§version§§) - New Wave Javascript",
          "/\\*![\\s]+\\* jQuery JavaScript Library v(§§version§§)",
          "// \\$Id: jquery.js,v (§§version§§)",
          "/\\*! jQuery v(§§version§§)",
          "[^a-z]f=\"(§§version§§)\",.*[^a-z]jquery:f,",
          "[^a-z]m=\"(§§version§§)\",.*[^a-z]jquery:m,",
          "[^a-z.]jquery:[ ]?\"(§§version§§)\"",
          "\\$\\.documentElement,Q=e.jQuery,Z=e\\.\\$,ee=\\{\\},te=\\[\\],ne=\"(§§version§§)\"",
          "=\"(§§version§§)\",.{50,300}(.)\\.fn=(\\2)\\.prototype=\\{jquery:"
        ],
        "filecontentreplace": [
          "/var [a-z]=[a-z]\\.document,([a-z])=\"(§§version§§)\",([a-z])=.{130,160};\\3\\.fn=\\3\\.prototype=\\{jquery:\\1/$2/"
        ],
        "hashes": {},
        "ast": [
          "//AssignmentExpression[/:left/:property/:name == 'fn']       /AssignmentExpression[/:left/:property/:name=='prototype' && /:left/$:object == ../:left/$:object]       /ObjectExpression/:properties[/:key/:name == 'jquery']/$$:value/:value     "
        ]
      }
    },
    "jquery-migrate": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.2.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "cross-site-scripting",
            "issue": "36",
            "release": "jQuery Migrate 1.2.0 Released"
          },
          "info": [
            "http://blog.jquery.com/2013/05/01/jquery-migrate-1-2-0-released/",
            "https://github.com/jquery/jquery-migrate/issues/36"
          ]
        },
        {
          "below": "1.2.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Selector interpreted as HTML",
            "bug": "11290"
          },
          "info": [
            "http://bugs.jquery.com/ticket/11290",
            "http://research.insecurelabs.org/jquery/test/"
          ]
        }
      ],
      "extractors": {
        "filename": [
          "jquery-migrate-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "/\\*!?(?:\n \\*)? jQuery Migrate(?: -)? v(§§version§§)",
          "\\.migrateVersion ?= ?\"(§§version§§)\"[\\s\\S]{10,150}(migrateDisablePatches|migrateWarnings|JQMIGRATE)",
          "jQuery\\.migrateVersion ?= ?\"(§§version§§)\""
        ],
        "hashes": {},
        "ast": [
          "//FunctionExpression[       /:params ==       //AssignmentExpression/MemberExpression[         /:property/:name == \"migrateVersion\"       ]/$:object     ]//AssignmentExpression[       /MemberExpression/:property/:name == \"migrateVersion\"     ]/$$:right/:value"
        ]
      }
    },
    "jquery-validation": {
      "bowername": [
        "jquery-validation"
      ],
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.19.3",
          "severity": "high",
          "cwe": [
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Regular Expression Denial of Service vulnerability",
            "CVE": [
              "CVE-2021-21252"
            ],
            "githubID": "GHSA-jxwx-85vp-gvwm"
          },
          "info": [
            "https://github.com/jquery-validation/jquery-validation/blob/master/changelog.md#1193--2021-01-09"
          ]
        },
        {
          "below": "1.19.4",
          "severity": "low",
          "cwe": [
            "CWE-1333"
          ],
          "identifiers": {
            "summary": "ReDoS vulnerability in URL2 validation",
            "CVE": [
              "CVE-2021-43306"
            ],
            "issue": "2428",
            "githubID": "GHSA-j9m2-h2pv-wvph"
          },
          "info": [
            "https://github.com/jquery-validation/jquery-validation/blob/master/changelog.md#1194--2022-05-19"
          ]
        },
        {
          "below": "1.19.5",
          "severity": "high",
          "cwe": [
            "CWE-1333"
          ],
          "identifiers": {
            "summary": "ReDoS vulnerability in url and URL2 validation",
            "CVE": [
              "CVE-2022-31147"
            ],
            "githubID": "GHSA-ffmh-x56j-9rc3"
          },
          "info": [
            "https://github.com/advisories/GHSA-ffmh-x56j-9rc3",
            "https://github.com/jquery-validation/jquery-validation/commit/5bbd80d27fc6b607d2f7f106c89522051a9fb0dd"
          ]
        },
        {
          "below": "1.20.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Potential XSS via showLabel",
            "PR": "2462"
          },
          "info": [
            "https://github.com/jquery-validation/jquery-validation/blob/master/changelog.md#1200--2023-10-10"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "1.20.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "jquery-validation vulnerable to Cross-site Scripting",
            "CVE": [
              "CVE-2025-3573"
            ],
            "githubID": "GHSA-rrj2-ph5q-jxw2"
          },
          "info": [
            "https://github.com/advisories/GHSA-rrj2-ph5q-jxw2",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-3573",
            "https://github.com/jquery-validation/jquery-validation/pull/2462",
            "https://github.com/jquery-validation/jquery-validation/commit/7a490d8f39bd988027568ddcf51755e1f4688902",
            "https://github.com/jquery-validation/jquery-validation",
            "https://security.snyk.io/vuln/SNYK-JS-JQUERYVALIDATION-5952285"
          ]
        }
      ],
      "extractors": {
        "func": [
          "jQuery.validation.version"
        ],
        "filename": [
          "jquery.validat(?:ion|e)-(§§version§§)(.min)?\\.js"
        ],
        "uri": [
          "/(§§version§§)/jquery.validat(ion|e)(\\.min)?\\.js",
          "/jquery-validation@(§§version§§)/dist/.*\\.js"
        ],
        "filecontent": [
          "/\\*!?(?:\n \\*)?[\\s]*jQuery Validation Plugin -? ?v(§§version§§)",
          "Original file: /npm/jquery-validation@(§§version§§)/dist/jquery.validate.js"
        ],
        "hashes": {}
      }
    },
    "jquery-mobile": {
      "bowername": [
        "jquery-mobile",
        "jquery-mobile-min",
        "jquery-mobile-build",
        "jquery-mobile-dist",
        "jquery-mobile-bower"
      ],
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.0.1",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "osvdb": [
              "94317"
            ]
          },
          "info": [
            "http://osvdb.org/show/osvdb/94317"
          ]
        },
        {
          "below": "1.0RC2",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "osvdb": [
              "94563",
              "93562",
              "94316",
              "94561",
              "94560"
            ]
          },
          "info": [
            "http://osvdb.org/show/osvdb/94316",
            "http://osvdb.org/show/osvdb/94560",
            "http://osvdb.org/show/osvdb/94561",
            "http://osvdb.org/show/osvdb/94562",
            "http://osvdb.org/show/osvdb/94563"
          ]
        },
        {
          "below": "1.1.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "location.href cross-site scripting",
            "issue": "4787"
          },
          "info": [
            "http://jquerymobile.com/changelog/1.1.2/",
            "http://jquerymobile.com/changelog/1.2.0/",
            "https://github.com/jquery/jquery-mobile/issues/4787"
          ]
        },
        {
          "below": "1.2.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "location.href cross-site scripting",
            "issue": "4787"
          },
          "info": [
            "http://jquerymobile.com/changelog/1.2.0/",
            "https://github.com/jquery/jquery-mobile/issues/4787"
          ]
        },
        {
          "below": "1.3.0",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Endpoint that reflect user input leads to cross site scripting",
            "gist": "jupenur/e5d0c6f9b58aa81860bf74e010cf1685"
          },
          "info": [
            "https://gist.github.com/jupenur/e5d0c6f9b58aa81860bf74e010cf1685"
          ]
        },
        {
          "below": "100.0.0",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "open redirect leads to cross site scripting",
            "blog": "sirdarckcat/unpatched-0day-jquery-mobile-xss",
            "githubID": "GHSA-fj93-7wm4-8x2g"
          },
          "info": [
            "http://sirdarckcat.blogspot.no/2017/02/unpatched-0day-jquery-mobile-xss.html",
            "https://github.com/jquery/jquery-mobile/issues/8640",
            "https://snyk.io/vuln/SNYK-JS-JQUERYMOBILE-174599"
          ]
        }
      ],
      "extractors": {
        "func": [
          "jQuery.mobile.version"
        ],
        "filename": [
          "jquery.mobile-(§§version§§)(.min)?\\.js"
        ],
        "uri": [
          "/(§§version§§)/jquery.mobile(\\.min)?\\.js"
        ],
        "filecontent": [
          "/\\*!?[\\s*]*jQuery Mobile(?: -)? v?(§§version§§)",
          "// Version of the jQuery Mobile Framework[\\s]+version: *[\"'](§§version§§)[\"'],"
        ],
        "hashes": {}
      }
    },
    "jquery-ui": {
      "bowername": [
        "jquery-ui",
        "jquery.ui"
      ],
      "npmname": "jquery-ui",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.13.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS in the `altField` option of the Datepicker widget",
            "CVE": [
              "CVE-2021-41182"
            ],
            "githubID": "GHSA-9gj3-hwp5-pmwc"
          },
          "info": [
            "https://github.com/jquery/jquery-ui/security/advisories/GHSA-9gj3-hwp5-pmwc",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41182"
          ]
        },
        {
          "below": "1.13.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS in the `of` option of the `.position()` util",
            "CVE": [
              "CVE-2021-41184"
            ],
            "githubID": "GHSA-gpqq-952q-5327"
          },
          "info": [
            "https://github.com/jquery/jquery-ui/security/advisories/GHSA-gpqq-952q-5327",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41184"
          ]
        },
        {
          "below": "1.13.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS Vulnerability on text options of jQuery UI datepicker",
            "CVE": [
              "CVE-2021-41183"
            ],
            "bug": "15284",
            "githubID": "GHSA-j7qv-pgf6-hvh4"
          },
          "info": [
            "https://bugs.jqueryui.com/ticket/15284",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41183"
          ]
        },
        {
          "below": "1.13.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS when refreshing a checkboxradio with an HTML-like initial text label ",
            "CVE": [
              "CVE-2022-31160"
            ],
            "issue": "2101",
            "githubID": "GHSA-h6gj-6jjq-h8g9"
          },
          "info": [
            "https://github.com/advisories/GHSA-h6gj-6jjq-h8g9",
            "https://github.com/jquery/jquery-ui/commit/8cc5bae1caa1fcf96bf5862c5646c787020ba3f9",
            "https://github.com/jquery/jquery-ui/issues/2101",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-31160"
          ]
        }
      ],
      "extractors": {
        "func": [
          "jQuery.ui.version"
        ],
        "uri": [
          "/(§§version§§)/jquery-ui(\\.min)?\\.js"
        ],
        "filecontent": [
          "/\\*!? jQuery UI - v(§§version§§)",
          "/\\*!?[\n *]+jQuery UI (§§version§§)"
        ],
        "hashes": {},
        "ast": [
          "//AssignmentExpression[         /MemberExpression[           /MemberExpression[             /$:object == ../../../../../../:params ||             /$:object == ../../../../../:params           ]/:property/:name == \"ui\"         ]/:property/:name == \"version\"       ]/:right/:value",
          "//CallExpression[         /:callee/:property/:name == \"extend\" &&          /:arguments/:property/:name == \"ui\"       ]/:arguments/Property[         /:key/:name == \"version\"       ]/:value/:value",
          "       //AssignmentExpression[          /:left/:property/:name == \"ui\" &&         /:left/$:object == ../../../:params       ]/:right/Property[         /:key/:name == \"version\"       ]/:value/:value       "
        ]
      }
    },
    "jquery-ui-dialog": {
      "bowername": [
        "jquery-ui",
        "jquery.ui"
      ],
      "npmname": "jquery-ui",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "1.7.0",
          "below": "1.10.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Title cross-site scripting vulnerability",
            "CVE": [
              "CVE-2010-5312"
            ],
            "bug": "6016",
            "githubID": "GHSA-wcm2-9c89-wmfm"
          },
          "info": [
            "http://bugs.jqueryui.com/ticket/6016",
            "https://nvd.nist.gov/vuln/detail/CVE-2010-5312"
          ]
        },
        {
          "below": "1.12.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS Vulnerability on closeText option",
            "CVE": [
              "CVE-2016-7103"
            ],
            "bug": "281",
            "githubID": "GHSA-hpcf-8vf9-q4gj"
          },
          "info": [
            "https://github.com/jquery/api.jqueryui.com/issues/281",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-7103",
            "https://snyk.io/vuln/npm:jquery-ui:20160721"
          ]
        }
      ],
      "extractors": {
        "func": [
          "jQuery.ui.dialog.version"
        ],
        "filecontent": [
          "/\\*!? jQuery UI - v(§§version§§)(.*\n){1,3}.*jquery\\.ui\\.dialog\\.js",
          "/\\*!?[\n *]+jQuery UI (§§version§§)(.*\n)*.*\\.ui\\.dialog",
          "/\\*!?[\n *]+jQuery UI Dialog (§§version§§)",
          "/\\*!? jQuery UI - v(§§version§§)(.*\n){1,3}\\* Includes: .* dialog\\.js"
        ],
        "hashes": {}
      }
    },
    "jquery-ui-autocomplete": {
      "bowername": [
        "jquery-ui",
        "jquery.ui"
      ],
      "npmname": "jquery-ui",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [],
      "extractors": {
        "func": [
          "jQuery.ui.autocomplete.version"
        ],
        "filecontent": [
          "/\\*!? jQuery UI - v(§§version§§)(.*\n){1,3}.*jquery\\.ui\\.autocomplete\\.js",
          "/\\*!?[\n *]+jQuery UI (§§version§§)(.*\n)*.*\\.ui\\.autocomplete",
          "/\\*!?[\n *]+jQuery UI Autocomplete (§§version§§)",
          "/\\*!? jQuery UI - v(§§version§§)(.*\n){1,3}\\* Includes: .* autocomplete\\.js"
        ],
        "hashes": {}
      }
    },
    "jquery-ui-tooltip": {
      "bowername": [
        "jquery-ui",
        "jquery.ui"
      ],
      "npmname": "jquery-ui",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "1.9.2",
          "below": "1.10.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-site scripting (XSS) vulnerability in the default content option in jquery.ui.tooltip",
            "CVE": [
              "CVE-2012-6662"
            ],
            "bug": "8859",
            "githubID": "GHSA-qqxp-xp9v-vvx6"
          },
          "info": [
            "http://bugs.jqueryui.com/ticket/8859",
            "https://nvd.nist.gov/vuln/detail/CVE-2012-6662"
          ]
        }
      ],
      "extractors": {
        "func": [
          "jQuery.ui.tooltip.version"
        ],
        "filecontent": [
          "/\\*!? jQuery UI - v(§§version§§)(.*\n){1,3}.*jquery\\.ui\\.tooltip\\.js",
          "/\\*!?[\n *]+jQuery UI (§§version§§)(.*\n)*.*\\.ui\\.tooltip",
          "/\\*!?[\n *]+jQuery UI Tooltip (§§version§§)"
        ],
        "hashes": {}
      }
    },
    "jquery.prettyPhoto": {
      "bowername": [
        "jquery-prettyPhoto"
      ],
      "basePurl": "pkg:github/scaron/prettyphoto",
      "licenses": [
        "(CC-BY-2.5 OR GPL-2.0) >=0"
      ],
      "vulnerabilities": [
        {
          "below": "3.1.5",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-6837"
            ]
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2013-6837"
          ]
        },
        {
          "below": "3.1.6",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "issue": "149"
          },
          "info": [
            "https://blog.anantshri.info/forgotten_disclosure_dom_xss_prettyphoto",
            "https://github.com/scaron/prettyphoto/issues/149"
          ]
        }
      ],
      "extractors": {
        "func": [
          "jQuery.prettyPhoto.version"
        ],
        "uri": [
          "/prettyPhoto/(§§version§§)/js/jquery\\.prettyPhoto(\\.min?)\\.js",
          "/prettyphoto@(§§version§§)/js/jquery\\.prettyPhoto\\.js"
        ],
        "filecontent": [
          "/\\*[\r\n -]+Class: prettyPhoto(?:.*\n){1,3}[ ]*Version: (§§version§§)",
          "\\.prettyPhoto[ ]?=[ ]?\\{version:[ ]?(?:'|\")(§§version§§)(?:'|\")\\}"
        ],
        "hashes": {},
        "ast": [
          "//AssignmentExpression[       /:left/:property/:name == \"prettyPhoto\"     ]/:right/:properties[       /:key/:name == \"version\"     ]/:value/:value"
        ]
      }
    },
    "jquery.terminal": {
      "licenses": [
        "MIT >=0.10.0",
        "LGPL-3.0 >=0.9.1 <0.10.0"
      ],
      "vulnerabilities": [
        {
          "below": "1.21.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Reflected Cross-Site Scripting in jquery.terminal",
            "githubID": "GHSA-2hwp-g4g7-mwwj"
          },
          "info": [
            "https://github.com/jcubic/jquery.terminal/commit/c8b7727d21960031b62a4ef1ed52f3c634046211",
            "https://www.npmjs.com/advisories/769"
          ]
        },
        {
          "below": "2.31.1",
          "severity": "low",
          "cwe": [
            "CWE-79",
            "CWE-80"
          ],
          "identifiers": {
            "summary": "jquery.terminal self XSS on user input",
            "githubID": "GHSA-x9r5-jxvq-4387",
            "CVE": [
              "CVE-2021-43862"
            ]
          },
          "info": [
            "https://github.com/jcubic/jquery.terminal/security/advisories/GHSA-x9r5-jxvq-4387",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-43862"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/jquery.terminal[@/](§§version§§)/"
        ],
        "filecontent": [
          "version (§§version§§)[\\s]+\\*[\\s]+\\* This file is part of jQuery Terminal.",
          "\\$\\.terminal=\\{version:\"(§§version§§)\""
        ]
      }
    },
    "jquery-deparam": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "0.5.4",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "githubID": "GHSA-xg68-chx2-253g",
            "CVE": [
              "CVE-2021-20087"
            ]
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-20087"
          ]
        }
      ],
      "extractors": {
        "hashes": {
          "61c9d49ae64331402c3bde766c9dc504ed2ca509": "0.5.3",
          "10a68e5048995351a01b0ad7f322bb755a576a02": "0.5.2",
          "b8f063c860fa3aab266df06b290e7da648f9328d": "0.4.2",
          "851bc74dc664aa55130ecc74dd6b1243becc3242": "0.4.1",
          "2aae12841f4d00143ffc1effa59fbd058218c29f": "0.4.0",
          "967942805137f9eb0ae26005d94e8285e2e288a0": "0.3.0",
          "fbf2e115feae7ade26788e38ebf338af11a98bb2": "0.1.0"
        }
      }
    },
    "tableexport.jquery.plugin": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.25.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "There is a cross-site scripting vulnerability with default `onCellHtmlData`",
            "githubID": "GHSA-j636-crp3-m584",
            "CVE": [
              "CVE-2022-1291"
            ]
          },
          "info": [
            "https://github.com/hhurz/tableexport.jquery.plugin/commit/dcbaee23cf98328397a153e71556f75202988ec9"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/tableexport.jquery.plugin@(§§version§§)/tableExport.min.js",
          "/TableExport/(§§version§§)/js/tableexport.min.js"
        ],
        "filecontent": [
          "/\\*[\\s]+tableExport.jquery.plugin[\\s]+Version (§§version§§)",
          "/\\*![\\s]+\\* TableExport.js v(§§version§§)"
        ]
      }
    },
    "jPlayer": {
      "bowername": [
        "jPlayer"
      ],
      "npmname": "jplayer",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "2.2.20",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS vulnerabilities in actionscript/Jplayer.as in the Flash SWF component",
            "CVE": [
              "CVE-2013-1942"
            ],
            "release": "2.2.20"
          },
          "info": [
            "http://jplayer.org/latest/release-notes/",
            "https://nvd.nist.gov/vuln/detail/CVE-2013-1942"
          ]
        },
        {
          "below": "2.3.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS vulnerabilities in actionscript/Jplayer.as in the Flash SWF component",
            "CVE": [
              "CVE-2013-2022"
            ],
            "githubID": "GHSA-3jcq-cwr7-6332"
          },
          "info": [
            "http://jplayer.org/latest/release-notes/",
            "https://nvd.nist.gov/vuln/detail/CVE-2013-2022"
          ]
        },
        {
          "below": "2.3.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS vulnerability in actionscript/Jplayer.as in the Flash SWF component",
            "CVE": [
              "CVE-2013-2023"
            ],
            "release": "2.3.1"
          },
          "info": [
            "http://jplayer.org/latest/release-notes/",
            "https://nvd.nist.gov/vuln/detail/CVE-2013-2023"
          ]
        }
      ],
      "extractors": {
        "func": [
          "new jQuery.jPlayer().version.script"
        ],
        "filecontent": [
          "/\\*!?[\n *]+jPlayer Plugin for jQuery (?:.*\n){1,10}[ *]+Version: (§§version§§)",
          "/\\*!? jPlayer (§§version§§) for jQuery"
        ],
        "hashes": {}
      }
    },
    "knockout": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "3.5.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS injection point in attr name binding for browser IE7 and older",
            "issue": "1244",
            "CVE": [
              "CVE-2019-14862"
            ],
            "githubID": "GHSA-vcjj-xf2r-mwvc"
          },
          "info": [
            "https://github.com/knockout/knockout/issues/1244"
          ]
        }
      ],
      "extractors": {
        "func": [
          "ko.version"
        ],
        "filename": [
          "knockout-(§§version§§)(.min)?\\.js"
        ],
        "uri": [
          "/knockout/(§§version§§)/knockout(-[a-z.]+)?\\.js"
        ],
        "filecontent": [
          "(?:\\*|//) Knockout JavaScript library v(§§version§§)",
          ".version=\"(§§version§§)\",_.b\\(.version.,_.version\\),_.options=\\{deferUpdates:!1,useOnlyNativeEvents:!1,foreachHidesDestroyed:!1\\}"
        ],
        "hashes": {},
        "ast": [
          "//ExpressionStatement/SequenceExpression[           /AssignmentExpression[/:left/:property/:name == \"options\" && /ObjectExpression/:properties/:key/:name == \"foreachHidesDestroyed\" ]         ]/AssignmentExpression[/:left/:property/:name == \"version\"]/:right/:value",
          "//BlockStatement[           /ExpressionStatement/AssignmentExpression[             /:left/:property/:name == \"options\"  &&             /ObjectExpression/:properties/:key[                 /:name == \"foreachHidesDestroyed\" ||                 /:value == \"foreachHidesDestroyed\"             ]           ]         ]/ExpressionStatement/AssignmentExpression[/:left/:property/:name == \"version\"]/:right/:value",
          "//BlockStatement[           /ExpressionStatement/CallExpression/:arguments/:value == \"isWriteableObservable\"         ]/ExpressionStatement/AssignmentExpression[/:left/:property/:name == \"version\"]/:right/:value"
        ]
      }
    },
    "sessvars": {
      "licenses": [],
      "vulnerabilities": [
        {
          "below": "1.01",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Unsanitized data passed to eval()",
            "tenable": "98645"
          },
          "info": [
            "http://www.thomasfrank.se/sessionvars.html"
          ]
        }
      ],
      "extractors": {
        "filename": [
          "sessvars-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "sessvars ver (§§version§§)"
        ],
        "hashes": {}
      }
    },
    "swfobject": {
      "bowername": [
        "swfobject",
        "swfobject-bower"
      ],
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "2.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "DOM-based XSS",
            "retid": "1"
          },
          "info": [
            "https://github.com/swfobject/swfobject/wiki/SWFObject-Release-Notes#swfobject-v21-beta7-june-6th-2008"
          ]
        }
      ],
      "extractors": {
        "filename": [
          "swfobject_(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "SWFObject v(§§version§§) "
        ],
        "hashes": {}
      }
    },
    "tinyMCE": {
      "bowername": [
        "tinymce",
        "tinymce-dist"
      ],
      "npmname": "tinymce",
      "licenses": [
        "MIT >=6.0.0 <7.0.0",
        "GPL-2.0 >=7.0.0",
        "LGPL-2.1 >=4.0.25 <6.0.0"
      ],
      "vulnerabilities": [
        {
          "below": "1.4.2",
          "severity": "high",
          "cwe": [
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Static code injection vulnerability in inc/function.base.php",
            "CVE": [
              "CVE-2011-4825"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2011-4825/"
          ]
        },
        {
          "below": "4.2.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "FIXED so script elements gets removed by default to prevent possible XSS issues in default config implementations",
            "retid": "62"
          },
          "info": [
            "https://www.tinymce.com/docs/changelog/"
          ]
        },
        {
          "below": "4.2.4",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "xss issues with media plugin not properly filtering out some script attributes.",
            "retid": "61"
          },
          "info": [
            "https://www.tinymce.com/docs/changelog/"
          ]
        },
        {
          "below": "4.7.12",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "FIXED so links with xlink:href attributes are filtered correctly to prevent XSS.",
            "retid": "63"
          },
          "info": [
            "https://www.tinymce.com/docs/changelog/"
          ]
        },
        {
          "below": "4.9.7",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "The vulnerability allowed arbitrary JavaScript execution when inserting a specially crafted piece of content into the editor via the clipboard or APIs",
            "githubID": "GHSA-27gm-ghr9-4v95",
            "CVE": [
              "CVE-2020-17480"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-27gm-ghr9-4v95",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-27gm-ghr9-4v95"
          ]
        },
        {
          "below": "4.9.7",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "TinyMCE before 4.9.7 and 5.x before 5.1.4 allows XSS in the core parser, the paste plugin, and the visualchars plugin by using the clipboard or APIs to insert content into the editor.",
            "githubID": "GHSA-p7j5-4mwm-hv86"
          },
          "info": [
            "https://github.com/advisories/GHSA-p7j5-4mwm-hv86",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-p7j5-4mwm-hv86"
          ]
        },
        {
          "below": "4.9.10",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "cross-site scripting (XSS) vulnerability was discovered in: the core parser and `media` plugin. ",
            "githubID": "GHSA-c78w-2gw7-gjv3",
            "CVE": [
              "CVE-2019-1010091"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-c78w-2gw7-gjv3",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-vrv8-v4w8-f95h"
          ]
        },
        {
          "below": "4.9.11",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-site scripting vulnerability in TinyMCE",
            "githubID": "GHSA-vrv8-v4w8-f95h",
            "CVE": [
              "CVE-2020-12648"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-vrv8-v4w8-f95h",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-vrv8-v4w8-f95h"
          ]
        },
        {
          "atOrAbove": "5.0.0",
          "below": "5.1.4",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "The vulnerability allowed arbitrary JavaScript execution when inserting a specially crafted piece of content into the editor via the clipboard or APIs",
            "githubID": "GHSA-27gm-ghr9-4v95",
            "CVE": [
              "CVE-2020-17480"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-27gm-ghr9-4v95",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-27gm-ghr9-4v95"
          ]
        },
        {
          "atOrAbove": "5.0.0",
          "below": "5.1.4",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "TinyMCE before 4.9.7 and 5.x before 5.1.4 allows XSS in the core parser, the paste plugin, and the visualchars plugin by using the clipboard or APIs to insert content into the editor.",
            "githubID": "GHSA-p7j5-4mwm-hv86"
          },
          "info": [
            "https://github.com/advisories/GHSA-p7j5-4mwm-hv86",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-p7j5-4mwm-hv86"
          ]
        },
        {
          "below": "5.1.6",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "CDATA parsing and sanitization has been improved to address a cross-site scripting (XSS) vulnerability.",
            "retid": "64"
          },
          "info": [
            "https://www.tiny.cloud/docs/release-notes/release-notes516/"
          ]
        },
        {
          "below": "5.2.2",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "media embed content not processing safely in some cases.",
            "retid": "65"
          },
          "info": [
            "https://www.tiny.cloud/docs/release-notes/release-notes522/"
          ]
        },
        {
          "atOrAbove": "5.0.0",
          "below": "5.2.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "cross-site scripting (XSS) vulnerability was discovered in: the core parser and `media` plugin. ",
            "githubID": "GHSA-c78w-2gw7-gjv3",
            "CVE": [
              "CVE-2019-1010091"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-c78w-2gw7-gjv3",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-vrv8-v4w8-f95h"
          ]
        },
        {
          "below": "5.4.0",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "content in an iframe element parsing as DOM elements instead of text content.",
            "retid": "66"
          },
          "info": [
            "https://www.tiny.cloud/docs/release-notes/release-notes54/"
          ]
        },
        {
          "atOrAbove": "5.0.0",
          "below": "5.4.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-site scripting vulnerability in TinyMCE",
            "githubID": "GHSA-vrv8-v4w8-f95h",
            "CVE": [
              "CVE-2020-12648"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-vrv8-v4w8-f95h",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-vrv8-v4w8-f95h"
          ]
        },
        {
          "below": "5.6.0",
          "severity": "low",
          "cwe": [
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Regex denial of service vulnerability in codesample plugin",
            "githubID": "GHSA-h96f-fc7c-9r55"
          },
          "info": [
            "https://www.tiny.cloud/docs/release-notes/release-notes56/#securityfixes"
          ]
        },
        {
          "below": "5.6.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "security issue where URLs in attributes weren’t correctly sanitized. security issue in the codesample plugin",
            "retid": "67",
            "githubID": "GHSA-w7jx-j77m-wp65",
            "CVE": [
              "CVE-2024-21911"
            ]
          },
          "info": [
            "https://www.tiny.cloud/docs/release-notes/release-notes56/#securityfixes"
          ]
        },
        {
          "below": "5.7.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "URLs are not correctly filtered in some cases.",
            "retid": "68",
            "githubID": "GHSA-5vm8-hhgr-jcjp"
          },
          "info": [
            "https://www.tiny.cloud/docs/release-notes/release-notes571/#securityfixes"
          ]
        },
        {
          "below": "5.9.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Inserting certain HTML content into the editor could result in invalid HTML once parsed. This caused a medium severity Cross Site Scripting (XSS) vulnerability",
            "retid": "69",
            "githubID": "GHSA-5h9g-x5rv-25wg",
            "CVE": [
              "CVE-2024-21908"
            ]
          },
          "info": [
            "https://www.tiny.cloud/docs/release-notes/release-notes59/#securityfixes"
          ]
        },
        {
          "below": "5.10.0",
          "severity": "medium",
          "cwe": [
            "CWE-64",
            "CWE-79"
          ],
          "identifiers": {
            "summary": "URLs not cleaned correctly in some cases in the link and image plugins",
            "retid": "70",
            "githubID": "GHSA-r8hm-w5f7-wj39",
            "CVE": [
              "CVE-2024-21910"
            ]
          },
          "info": [
            "https://www.tiny.cloud/docs/release-notes/release-notes510/#securityfixes"
          ]
        },
        {
          "below": "5.10.7",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "A cross-site scripting (XSS) vulnerability in TinyMCE alerts which allowed arbitrary JavaScript execution was found and fixed.",
            "CVE": [
              "CVE-2022-23494"
            ],
            "githubID": "GHSA-gg8r-xjwq-4w92"
          },
          "info": [
            "https://github.com/advisories/GHSA-gg8r-xjwq-4w92",
            "https://www.cve.org/CVERecord?id=CVE-2022-23494",
            "https://www.tiny.cloud/docs/changelog/#5107-2022-12-06"
          ]
        },
        {
          "below": "5.10.8",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "TinyMCE XSS vulnerability in notificationManager.open API",
            "CVE": [
              "CVE-2023-45819"
            ],
            "githubID": "GHSA-hgqx-r2hp-jr38"
          },
          "info": [
            "https://github.com/advisories/GHSA-hgqx-r2hp-jr38",
            "https://www.cve.org/CVERecord?id=CVE-2022-23494",
            "https://www.tiny.cloud/docs/changelog/#5107-2022-12-06"
          ]
        },
        {
          "below": "5.10.8",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "TinyMCE mXSS vulnerability in undo/redo, getContent API, resetContent API, and Autosave plugin",
            "CVE": [
              "CVE-2023-45818"
            ],
            "githubID": "GHSA-v65r-p3vv-jjfv"
          },
          "info": [
            "https://github.com/advisories/GHSA-v65r-p3vv-jjfv"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "5.10.9",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE vulnerable to mutation Cross-site Scripting via special characters in unescaped text nodes",
            "CVE": [
              "CVE-2023-48219"
            ],
            "githubID": "GHSA-v626-r774-j7f8"
          },
          "info": [
            "https://github.com/advisories/GHSA-v626-r774-j7f8",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-v626-r774-j7f8",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-48219",
            "https://github.com/tinymce/tinymce",
            "https://github.com/tinymce/tinymce/releases/tag/5.10.9",
            "https://github.com/tinymce/tinymce/releases/tag/6.7.3",
            "https://tiny.cloud/docs/release-notes/release-notes5109/",
            "https://tiny.cloud/docs/tinymce/6/6.7.3-release-notes/"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "5.11.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE Cross-Site Scripting (XSS) vulnerability using noneditable_regexp option",
            "CVE": [
              "CVE-2024-38356"
            ],
            "githubID": "GHSA-9hcv-j9pv-qmph"
          },
          "info": [
            "https://github.com/advisories/GHSA-9hcv-j9pv-qmph",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-9hcv-j9pv-qmph",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-38356",
            "https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d",
            "https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0",
            "https://github.com/tinymce/tinymce",
            "https://owasp.org/www-community/attacks/xss",
            "https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview",
            "https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview",
            "https://www.tiny.cloud/docs/tinymce/latest/7.2-release-notes/#overview"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "5.11.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE Cross-Site Scripting (XSS) vulnerability using noscript elements",
            "CVE": [
              "CVE-2024-38357"
            ],
            "githubID": "GHSA-w9jx-4g6g-rp7x"
          },
          "info": [
            "https://github.com/advisories/GHSA-w9jx-4g6g-rp7x",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-w9jx-4g6g-rp7x",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-38357",
            "https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d",
            "https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0",
            "https://github.com/tinymce/tinymce",
            "https://owasp.org/www-community/attacks/xss",
            "https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview",
            "https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview"
          ]
        },
        {
          "atOrAbove": "6.0.0",
          "below": "6.3.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "A cross-site scripting (XSS) vulnerability in TinyMCE alerts which allowed arbitrary JavaScript execution was found and fixed.",
            "CVE": [
              "CVE-2022-23494"
            ],
            "githubID": "GHSA-gg8r-xjwq-4w92"
          },
          "info": [
            "https://github.com/advisories/GHSA-gg8r-xjwq-4w92",
            "https://www.cve.org/CVERecord?id=CVE-2022-23494",
            "https://www.tiny.cloud/docs/changelog/#5107-2022-12-06"
          ]
        },
        {
          "atOrAbove": "6.0.0",
          "below": "6.7.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "TinyMCE XSS vulnerability in notificationManager.open API",
            "CVE": [
              "CVE-2023-45819"
            ],
            "githubID": "GHSA-hgqx-r2hp-jr38"
          },
          "info": [
            "https://github.com/advisories/GHSA-hgqx-r2hp-jr38",
            "https://www.cve.org/CVERecord?id=CVE-2022-23494",
            "https://www.tiny.cloud/docs/changelog/#5107-2022-12-06"
          ]
        },
        {
          "atOrAbove": "6.0.0",
          "below": "6.7.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "TinyMCE mXSS vulnerability in undo/redo, getContent API, resetContent API, and Autosave plugin",
            "CVE": [
              "CVE-2023-45818"
            ],
            "githubID": "GHSA-v65r-p3vv-jjfv"
          },
          "info": [
            "https://github.com/advisories/GHSA-v65r-p3vv-jjfv"
          ]
        },
        {
          "atOrAbove": "6.0.0",
          "below": "6.7.3",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE vulnerable to mutation Cross-site Scripting via special characters in unescaped text nodes",
            "CVE": [
              "CVE-2023-48219"
            ],
            "githubID": "GHSA-v626-r774-j7f8"
          },
          "info": [
            "https://github.com/advisories/GHSA-v626-r774-j7f8",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-v626-r774-j7f8",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-48219",
            "https://github.com/tinymce/tinymce",
            "https://github.com/tinymce/tinymce/releases/tag/5.10.9",
            "https://github.com/tinymce/tinymce/releases/tag/6.7.3",
            "https://tiny.cloud/docs/release-notes/release-notes5109/",
            "https://tiny.cloud/docs/tinymce/6/6.7.3-release-notes/"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "6.8.1",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE Cross-Site Scripting (XSS) vulnerability in handling iframes",
            "CVE": [
              "CVE-2024-29203"
            ],
            "githubID": "GHSA-438c-3975-5x3f"
          },
          "info": [
            "https://github.com/advisories/GHSA-438c-3975-5x3f",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-438c-3975-5x3f",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-29203",
            "https://github.com/tinymce/tinymce/commit/bcdea2ad14e3c2cea40743fb48c63bba067ae6d1",
            "https://github.com/tinymce/tinymce",
            "https://www.tiny.cloud/docs/tinymce/6/6.8.1-release-notes/#new-convert_unsafe_embeds-option-that-controls-whether-object-and-embed-elements-will-be-converted-to-more-restrictive-alternatives-namely-img-for-image-mime-types-video-for-video-mime-types-audio-audio-mime-types-or-iframe-for-other-or-unspecified-mime-types",
            "https://www.tiny.cloud/docs/tinymce/7/7.0-release-notes/#sandbox_iframes-editor-option-is-now-defaulted-to-true"
          ]
        },
        {
          "atOrAbove": "6.0.0",
          "below": "6.8.4",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE Cross-Site Scripting (XSS) vulnerability using noneditable_regexp option",
            "CVE": [
              "CVE-2024-38356"
            ],
            "githubID": "GHSA-9hcv-j9pv-qmph"
          },
          "info": [
            "https://github.com/advisories/GHSA-9hcv-j9pv-qmph",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-9hcv-j9pv-qmph",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-38356",
            "https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d",
            "https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0",
            "https://github.com/tinymce/tinymce",
            "https://owasp.org/www-community/attacks/xss",
            "https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview",
            "https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview",
            "https://www.tiny.cloud/docs/tinymce/latest/7.2-release-notes/#overview"
          ]
        },
        {
          "atOrAbove": "6.0.0",
          "below": "6.8.4",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE Cross-Site Scripting (XSS) vulnerability using noscript elements",
            "CVE": [
              "CVE-2024-38357"
            ],
            "githubID": "GHSA-w9jx-4g6g-rp7x"
          },
          "info": [
            "https://github.com/advisories/GHSA-w9jx-4g6g-rp7x",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-w9jx-4g6g-rp7x",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-38357",
            "https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d",
            "https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0",
            "https://github.com/tinymce/tinymce",
            "https://owasp.org/www-community/attacks/xss",
            "https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview",
            "https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "7.0.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE Cross-Site Scripting (XSS) vulnerability in handling external SVG files through Object or Embed elements",
            "CVE": [
              "CVE-2024-29881"
            ],
            "githubID": "GHSA-5359-pvf2-pw78"
          },
          "info": [
            "https://github.com/advisories/GHSA-5359-pvf2-pw78",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-5359-pvf2-pw78",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-29881",
            "https://github.com/tinymce/tinymce/commit/bcdea2ad14e3c2cea40743fb48c63bba067ae6d1",
            "https://github.com/tinymce/tinymce",
            "https://www.tiny.cloud/docs/tinymce/6/6.8.1-release-notes/#new-convert_unsafe_embeds-option-that-controls-whether-object-and-embed-elements-will-be-converted-to-more-restrictive-alternatives-namely-img-for-image-mime-types-video-for-video-mime-types-audio-audio-mime-types-or-iframe-for-other-or-unspecified-mime-types",
            "https://www.tiny.cloud/docs/tinymce/7/7.0-release-notes/#convert_unsafe_embeds-editor-option-is-now-defaulted-to-true"
          ]
        },
        {
          "atOrAbove": "7.0.0",
          "below": "7.2.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE Cross-Site Scripting (XSS) vulnerability using noneditable_regexp option",
            "CVE": [
              "CVE-2024-38356"
            ],
            "githubID": "GHSA-9hcv-j9pv-qmph"
          },
          "info": [
            "https://github.com/advisories/GHSA-9hcv-j9pv-qmph",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-9hcv-j9pv-qmph",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-38356",
            "https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d",
            "https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0",
            "https://github.com/tinymce/tinymce",
            "https://owasp.org/www-community/attacks/xss",
            "https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview",
            "https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview",
            "https://www.tiny.cloud/docs/tinymce/latest/7.2-release-notes/#overview"
          ]
        },
        {
          "atOrAbove": "7.0.0",
          "below": "7.2.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "TinyMCE Cross-Site Scripting (XSS) vulnerability using noscript elements",
            "CVE": [
              "CVE-2024-38357"
            ],
            "githubID": "GHSA-w9jx-4g6g-rp7x"
          },
          "info": [
            "https://github.com/advisories/GHSA-w9jx-4g6g-rp7x",
            "https://github.com/tinymce/tinymce/security/advisories/GHSA-w9jx-4g6g-rp7x",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-38357",
            "https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d",
            "https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0",
            "https://github.com/tinymce/tinymce",
            "https://owasp.org/www-community/attacks/xss",
            "https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview",
            "https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/tinymce/(§§version§§)/tinymce(\\.min)?\\.js"
        ],
        "filecontent": [
          "// (§§version§§) \\([0-9\\-]+\\)[\n\r]+.{0,1200}l=.tinymce/geom/Rect.",
          "/\\*\\*[\\s]*\\* TinyMCE version (§§version§§)"
        ],
        "filecontentreplace": [
          "/tinyMCEPreInit.*majorVersion:.([0-9]+).,minorVersion:.([0-9.]+)./$1.$2/",
          "/majorVersion:.([0-9]+).,minorVersion:.([0-9.]+).,.*tinyMCEPreInit/$1.$2/"
        ],
        "func": [
          "tinyMCE.majorVersion + '.'+ tinyMCE.minorVersion"
        ]
      }
    },
    "YUI": {
      "bowername": [
        "yui",
        "yui3"
      ],
      "npmname": "yui",
      "licenses": [
        "BSD-2-Clause >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "2.4.0",
          "below": "2.8.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2010-4207"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2010-4207/"
          ]
        },
        {
          "atOrAbove": "2.5.0",
          "below": "2.8.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2010-4208"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2010-4208/"
          ]
        },
        {
          "atOrAbove": "2.8.0",
          "below": "2.8.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2010-4209"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2010-4209/"
          ]
        },
        {
          "below": "2.9.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2010-4710"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2010-4710/"
          ]
        },
        {
          "atOrAbove": "2.4.0",
          "below": "2.9.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2012-5881"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2012-5881/"
          ]
        },
        {
          "atOrAbove": "2.5.0",
          "below": "2.9.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2012-5882"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2012-5882/"
          ]
        },
        {
          "atOrAbove": "2.8.0",
          "below": "2.9.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2012-5883"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2012-5883/"
          ]
        },
        {
          "atOrAbove": "3.2.0",
          "below": "3.9.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4941"
            ],
            "githubID": "GHSA-64r3-582j-frqm"
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2013-4941/"
          ]
        },
        {
          "atOrAbove": "3.2.0",
          "below": "3.9.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4942"
            ],
            "githubID": "GHSA-9ww8-j8j2-3788"
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2013-4942/"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.10.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4939"
            ],
            "githubID": "GHSA-mj87-8xf8-fp4w"
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2013-4939/",
            "https://clarle.github.io/yui3/support/20130515-vulnerability/"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.10.11",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4940"
            ],
            "githubID": "GHSA-x5hj-47vv-53p8"
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2013-4940/"
          ]
        },
        {
          "atOrAbove": "3.10.12",
          "below": "3.10.13",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4940"
            ],
            "githubID": "GHSA-x5hj-47vv-53p8"
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2013-4940/"
          ]
        }
      ],
      "extractors": {
        "func": [
          "YUI.Version",
          "YAHOO.VERSION"
        ],
        "filename": [
          "yui-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "/*\nYUI (§§version§§)",
          "/yui/license.(?:html|txt)\nversion: (§§version§§)"
        ],
        "hashes": {}
      }
    },
    "prototypejs": {
      "bowername": [
        "prototypejs",
        "prototype.js",
        "prototypejs-bower"
      ],
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.5.1.2",
          "severity": "high",
          "cwe": [
            "CWE-942"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2008-7220"
            ]
          },
          "info": [
            "http://prototypejs.org/2008/01/25/prototype-1-6-0-2-bug-fixes-performance-improvements-and-security/",
            "http://www.cvedetails.com/cve/CVE-2008-7220/"
          ]
        },
        {
          "atOrAbove": "1.6.0",
          "below": "1.6.0.2",
          "severity": "high",
          "cwe": [
            "CWE-942"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2008-7220"
            ]
          },
          "info": [
            "http://prototypejs.org/2008/01/25/prototype-1-6-0-2-bug-fixes-performance-improvements-and-security/",
            "http://www.cvedetails.com/cve/CVE-2008-7220/"
          ]
        }
      ],
      "extractors": {
        "func": [
          "Prototype.Version"
        ],
        "uri": [
          "/(§§version§§)/prototype(\\.min)?\\.js"
        ],
        "filename": [
          "prototype-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "Prototype JavaScript framework, version (§§version§§)",
          "Prototype[ ]?=[ ]?\\{[ \r\n\t]*Version:[ ]?(?:'|\")(§§version§§)(?:'|\")"
        ],
        "hashes": {}
      }
    },
    "ember": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "0.9.7",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Bound attributes aren't escaped properly",
            "bug": "699"
          },
          "info": [
            "https://github.com/emberjs/ember.js/issues/699"
          ]
        },
        {
          "below": "0.9.7.1",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "More rigorous XSS escaping from bindAttr",
            "retid": "60"
          },
          "info": [
            "https://github.com/emberjs/ember.js/blob/master/CHANGELOG.md"
          ]
        },
        {
          "atOrAbove": "1.0.0-rc.1",
          "below": "1.0.0-rc.1.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4170"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"
          ]
        },
        {
          "atOrAbove": "1.0.0-rc.2",
          "below": "1.0.0-rc.2.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4170"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"
          ]
        },
        {
          "atOrAbove": "1.0.0-rc.3",
          "below": "1.0.0-rc.3.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4170"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"
          ]
        },
        {
          "atOrAbove": "1.0.0-rc.4",
          "below": "1.0.0-rc.4.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4170"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"
          ]
        },
        {
          "atOrAbove": "1.0.0-rc.5",
          "below": "1.0.0-rc.5.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4170"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"
          ]
        },
        {
          "atOrAbove": "1.0.0-rc.6",
          "below": "1.0.0-rc.6.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4170"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/dokLVwwxAdM"
          ]
        },
        {
          "atOrAbove": "1.0.0",
          "below": "1.0.1",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2014-0013",
              "CVE-2014-0014"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4",
            "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"
          ]
        },
        {
          "atOrAbove": "1.1.0",
          "below": "1.1.3",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2014-0013",
              "CVE-2014-0014"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4",
            "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"
          ]
        },
        {
          "atOrAbove": "1.2.0",
          "below": "1.2.1",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2014-0013",
              "CVE-2014-0014"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4",
            "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"
          ]
        },
        {
          "atOrAbove": "1.2.0",
          "below": "1.2.2",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "ember-routing-auto-location can be forced to redirect to another domain",
            "CVE": [
              "CVE-2014-0046"
            ]
          },
          "info": [
            "https://github.com/emberjs/ember.js/blob/v1.5.0/CHANGELOG.md",
            "https://groups.google.com/forum/#!topic/ember-security/1h6FRgr8lXQ"
          ]
        },
        {
          "atOrAbove": "1.3.0",
          "below": "1.3.1",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2014-0013",
              "CVE-2014-0014"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4",
            "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"
          ]
        },
        {
          "atOrAbove": "1.3.0",
          "below": "1.3.2",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "ember-routing-auto-location can be forced to redirect to another domain",
            "CVE": [
              "CVE-2014-0046"
            ]
          },
          "info": [
            "https://github.com/emberjs/ember.js/blob/v1.5.0/CHANGELOG.md",
            "https://groups.google.com/forum/#!topic/ember-security/1h6FRgr8lXQ"
          ]
        },
        {
          "atOrAbove": "1.4.0",
          "below": "1.4.0-beta.2",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2014-0013",
              "CVE-2014-0014"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/2kpXXCxISS4",
            "https://groups.google.com/forum/#!topic/ember-security/PSE4RzTi6l4"
          ]
        },
        {
          "below": "1.5.0",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "ember-routing-auto-location can be forced to redirect to another domain",
            "CVE": [
              "CVE-2014-0046"
            ]
          },
          "info": [
            "https://github.com/emberjs/ember.js/blob/v1.5.0/CHANGELOG.md",
            "https://groups.google.com/forum/#!topic/ember-security/1h6FRgr8lXQ"
          ]
        },
        {
          "atOrAbove": "1.8.0",
          "below": "1.11.4",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2015-7565"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY"
          ]
        },
        {
          "atOrAbove": "1.12.0",
          "below": "1.12.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2015-7565"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY"
          ]
        },
        {
          "atOrAbove": "1.13.0",
          "below": "1.13.12",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2015-7565"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY"
          ]
        },
        {
          "atOrAbove": "2.0.0",
          "below": "2.0.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2015-7565"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY"
          ]
        },
        {
          "atOrAbove": "2.1.0",
          "below": "2.1.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2015-7565"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY"
          ]
        },
        {
          "atOrAbove": "2.2.0",
          "below": "2.2.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2015-7565"
            ]
          },
          "info": [
            "https://groups.google.com/forum/#!topic/ember-security/OfyQkoSuppY"
          ]
        },
        {
          "below": "3.24.7",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype pollution",
            "retid": "59"
          },
          "info": [
            "https://blog.emberjs.com/ember-4-8-1-released/"
          ]
        },
        {
          "atOrAbove": "3.25.0",
          "below": "3.28.10",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype pollution",
            "retid": "58"
          },
          "info": [
            "https://blog.emberjs.com/ember-4-8-1-released/"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.4.4",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype pollution",
            "retid": "57"
          },
          "info": [
            "https://blog.emberjs.com/ember-4-8-1-released/"
          ]
        },
        {
          "atOrAbove": "4.5.0",
          "below": "4.8.1",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype pollution",
            "retid": "56"
          },
          "info": [
            "https://blog.emberjs.com/ember-4-8-1-released/"
          ]
        },
        {
          "atOrAbove": "4.9.0-alpha.1",
          "below": "4.9.0-beta.3",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype pollution",
            "retid": "55"
          },
          "info": [
            "https://blog.emberjs.com/ember-4-8-1-released/"
          ]
        }
      ],
      "extractors": {
        "func": [
          "Ember.VERSION"
        ],
        "uri": [
          "/(?:v)?(§§version§§)/ember(\\.min)?\\.js",
          "/ember\\.?js/(§§version§§)/ember((\\.|-)[a-z\\-.]+)?\\.js"
        ],
        "filename": [
          "ember-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "Project:   Ember -(?:.*\n){9,11}// Version: v(§§version§§)",
          "// Version: v(§§version§§)(.*\n){10,15}(Ember Debug|@module ember|@class ember)",
          "Ember.VERSION[ ]?=[ ]?(?:'|\")(§§version§§)(?:'|\")",
          "meta\\.revision=\"Ember@(§§version§§)\"",
          "e\\(\"ember/version\",\\[\"exports\"\\],function\\(e\\)\\{\"use strict\";?[\\s]*e(?:\\.|\\[\")default(?:\"\\])?=\"(§§version§§)\"",
          "\\(\"ember/version\",\\[\"exports\"\\],function\\(e\\)\\{\"use strict\";.{1,70}\\.default=\"(§§version§§)\"",
          "/\\*![\\s]+\\* @overview  Ember - JavaScript Application Framework[\\s\\S]{0,400}\\* @version   (§§version§§)",
          "// Version: (§§version§§)[\\s]+\\(function\\(\\) *\\{[\\s]*/\\*\\*[\\s]+@module ember[\\s]"
        ],
        "hashes": {},
        "ast": [
          "//AssignmentExpression[       /:left/:object/:name == \"Ember\" &&       /:left/:property/:name == \"VERSION\"     ]/:right/:value",
          "//CallExpression[       /Literal/:value == \"ember/version\"     ]/FunctionExpression/BlockStatement/ExpressionStatement/AssignmentExpression[       /:left/:property/:name == \"default\" || /:left/:property/:value == \"default\"     ]/:right/:value",
          "//SequenceExpression[       /AssignmentExpression[         /:left/:property/:name == \"toString\" &&         /:right//ReturnStatement/:argument/:value == \"Ember\"       ]     ]/AssignmentExpression[       /MemberExpression/:property/:name == \"VERSION\"     ]/:right/:value"
        ]
      }
    },
    "dojo": {
      "licenses": [
        "BSD-3-Clause >=2.0.0-alpha.5 <2.0.0-alpha1",
        "(AFL-2.1 OR BSD-2-Clause) >=1.6.4 <1.7.11; >=1.9.1 <1.9.8; >=1.10.0 <1.10.5",
        "(BSD-3-Clause OR AFL-2.1) >=1.7.11 <1.9.1; >=1.9.8 <1.10.0; >=1.10.5 <2.0.0-alpha.5"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "0.4",
          "below": "0.4.4",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "atOrAbove": "1.0",
          "below": "1.0.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "below": "1.1.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Affected versions of dojo are susceptible to a cross-site scripting vulnerability in the dijit.Editor and textarea components, which execute their contents as Javascript, even when sanitized.",
            "CVE": [
              "CVE-2008-6681"
            ],
            "githubID": "GHSA-39cx-xcwj-3rc4"
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2008-6681/"
          ]
        },
        {
          "atOrAbove": "1.1",
          "below": "1.1.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "below": "1.2.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.2.0 are vulnerable to Cross-Site Scripting (XSS). The package fails to sanitize HTML code in user-controlled input, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "CVE": [
              "CVE-2015-5654"
            ],
            "githubID": "GHSA-p82g-2xpp-m5r3"
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2015-5654"
          ]
        },
        {
          "atOrAbove": "1.2",
          "below": "1.2.4",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "atOrAbove": "1.3",
          "below": "1.3.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "below": "1.4.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-site scripting (XSS) vulnerability in dijit/tests/_testCommon.js in Dojo Toolkit SDK before 1.4.2 allows remote attackers to inject arbitrary web script or HTML via the theme parameter, as demonstrated by an attack against dijit/tests/form/test_Button.html",
            "CVE": [
              "CVE-2010-2275"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2010-2275/"
          ]
        },
        {
          "atOrAbove": "1.4",
          "below": "1.4.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "atOrAbove": "1.10.0",
          "below": "1.10.10",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "atOrAbove": "1.11.0",
          "below": "1.11.6",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "below": "1.11.10",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-74",
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Prototype pollution in dojo",
            "CVE": [
              "CVE-2020-5258"
            ],
            "githubID": "GHSA-jxfh-8wgv-vfr2"
          },
          "info": [
            "https://github.com/advisories/GHSA-jxfh-8wgv-vfr2",
            "https://github.com/dojo/dojo/security/advisories/GHSA-jxfh-8wgv-vfr2"
          ]
        },
        {
          "atOrAbove": "1.12.0",
          "below": "1.12.4",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "atOrAbove": "1.12.0",
          "below": "1.12.8",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-74",
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Prototype pollution in dojo",
            "CVE": [
              "CVE-2020-5258"
            ],
            "githubID": "GHSA-jxfh-8wgv-vfr2"
          },
          "info": [
            "https://github.com/advisories/GHSA-jxfh-8wgv-vfr2",
            "https://github.com/dojo/dojo/security/advisories/GHSA-jxfh-8wgv-vfr2"
          ]
        },
        {
          "atOrAbove": "1.13.0",
          "below": "1.13.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of dojo prior to 1.4.2 are vulnerable to DOM-based Cross-Site Scripting (XSS). The package does not sanitize URL parameters in the _testCommon.js and runner.html test files, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
            "PR": "307",
            "CVE": [
              "CVE-2010-2273"
            ],
            "githubID": "GHSA-536q-8gxx-m782"
          },
          "info": [
            "http://dojotoolkit.org/blog/dojo-security-advisory",
            "http://www.cvedetails.com/cve/CVE-2010-2272/",
            "http://www.cvedetails.com/cve/CVE-2010-2273/",
            "http://www.cvedetails.com/cve/CVE-2010-2274/",
            "http://www.cvedetails.com/cve/CVE-2010-2276/",
            "https://dojotoolkit.org/blog/dojo-1-14-released",
            "https://github.com/advisories/GHSA-536q-8gxx-m782",
            "https://github.com/dojo/dojo/pull/307"
          ]
        },
        {
          "atOrAbove": "1.13.0",
          "below": "1.13.7",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-74",
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Prototype pollution in dojo",
            "CVE": [
              "CVE-2020-5258"
            ],
            "githubID": "GHSA-jxfh-8wgv-vfr2"
          },
          "info": [
            "https://github.com/advisories/GHSA-jxfh-8wgv-vfr2",
            "https://github.com/dojo/dojo/security/advisories/GHSA-jxfh-8wgv-vfr2"
          ]
        },
        {
          "below": "1.14",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "In Dojo Toolkit before 1.14.0, there is unescaped string injection in dojox/Grid/DataGrid.",
            "CVE": [
              "CVE-2018-15494"
            ],
            "githubID": "GHSA-84cm-x2q5-8225"
          },
          "info": [
            "https://dojotoolkit.org/blog/dojo-1-14-released"
          ]
        },
        {
          "atOrAbove": "1.14.0",
          "below": "1.14.6",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-74",
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Prototype pollution in dojo",
            "CVE": [
              "CVE-2020-5258"
            ],
            "githubID": "GHSA-jxfh-8wgv-vfr2"
          },
          "info": [
            "https://github.com/advisories/GHSA-jxfh-8wgv-vfr2",
            "https://github.com/dojo/dojo/security/advisories/GHSA-jxfh-8wgv-vfr2"
          ]
        },
        {
          "atOrAbove": "1.15.0",
          "below": "1.15.3",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-74",
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Prototype pollution in dojo",
            "CVE": [
              "CVE-2020-5258"
            ],
            "githubID": "GHSA-jxfh-8wgv-vfr2"
          },
          "info": [
            "https://github.com/advisories/GHSA-jxfh-8wgv-vfr2",
            "https://github.com/dojo/dojo/security/advisories/GHSA-jxfh-8wgv-vfr2"
          ]
        },
        {
          "atOrAbove": "1.16.0",
          "below": "1.16.2",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-74",
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Prototype pollution in dojo",
            "CVE": [
              "CVE-2020-5258"
            ],
            "githubID": "GHSA-jxfh-8wgv-vfr2"
          },
          "info": [
            "https://github.com/advisories/GHSA-jxfh-8wgv-vfr2",
            "https://github.com/dojo/dojo/security/advisories/GHSA-jxfh-8wgv-vfr2"
          ]
        },
        {
          "below": "1.17.0",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype pollution",
            "CVE": [
              "CVE-2021-23450"
            ],
            "githubID": "GHSA-m8gw-hjpr-rjv7"
          },
          "info": [
            "https://github.com/dojo/dojo/pull/418"
          ]
        }
      ],
      "extractors": {
        "func": [
          "dojo.version.toString()"
        ],
        "uri": [
          "/(?:dojo-)?(§§version§§)(?:/dojo)?/dojo(\\.min)?\\.js"
        ],
        "filename": [
          "dojo-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontentreplace": [
          "/dojo.version=\\{major:([0-9]+),minor:([0-9]+),patch:([0-9]+)/$1.$2.$3/",
          "/\"dojox\"[\\s\\S]{1,350}\\.version=\\{major:([0-9]+),minor:([0-9]+),patch:([0-9]+)/$1.$2.$3/"
        ],
        "hashes": {
          "73cdd262799aab850abbe694cd3bfb709ea23627": "1.4.1",
          "c8c84eddc732c3cbf370764836a7712f3f873326": "1.4.0",
          "d569ce9efb7edaedaec8ca9491aab0c656f7c8f0": "1.0.0",
          "ad44e1770895b7fa84aff5a56a0f99b855a83769": "1.3.2",
          "8fc10142a06966a8709cd9b8732f7b6db88d0c34": "1.3.1",
          "a09b5851a0a3e9d81353745a4663741238ee1b84": "1.3.0",
          "2ab48d45abe2f54cdda6ca32193b5ceb2b1bc25d": "1.2.3",
          "12208a1e649402e362f528f6aae2c614fc697f8f": "1.2.0",
          "72a6a9fbef9fa5a73cd47e49942199147f905206": "1.1.1"
        },
        "ast": [
          "//BlockStatement/ExpressionStatement/AssignmentExpression[       /:left/:property/:name == \"version\" &&        /:left[         /:object/:name == \"dojo\" ||         /:$object/:init/:properties/:key/:name == \"dojox\"       ]     ]/ObjectExpression[       /Property/:key/:name == \"major\" ||       /Property/:key/:name == \"minor\" ||       /Property/:key/:name == \"patch\"     ]/fn:concat(       /Property[/:key/:name == \"major\"]/:value/:value, \".\",       /Property[/:key/:name == \"minor\"]/:value/:value, \".\",       /Property[/:key/:name == \"patch\"]/:value/:value     )"
        ]
      }
    },
    "angularjs": {
      "bowername": [
        "angularjs",
        "angular.js"
      ],
      "npmname": "angular",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "1.0.0",
          "below": "1.2.30",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "The attribute usemap can be used as a security exploit",
            "retid": "50"
          },
          "info": [
            "https://github.com/angular/angular.js/blob/master/CHANGELOG.md#1230-patronal-resurrection-2016-07-21"
          ]
        },
        {
          "below": "1.5.0-beta.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS through xlink:href attributes",
            "CVE": [
              "CVE-2019-14863"
            ],
            "githubID": "GHSA-r5fx-8r73-v86c"
          },
          "info": [
            "https://github.com/advisories/GHSA-r5fx-8r73-v86c",
            "https://github.com/angular/angular.js/blob/master/CHANGELOG.md#150-beta1-dense-dispersion-2015-09-29"
          ]
        },
        {
          "atOrAbove": "1.3.0",
          "below": "1.5.0-rc2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "The attribute usemap can be used as a security exploit",
            "retid": "49"
          },
          "info": [
            "https://github.com/angular/angular.js/blob/master/CHANGELOG.md#1230-patronal-resurrection-2016-07-21"
          ]
        },
        {
          "below": "1.6.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-Site Scripting via JSONP",
            "githubID": "GHSA-28hp-fgcr-2r4h"
          },
          "info": [
            "https://github.com/advisories/GHSA-28hp-fgcr-2r4h"
          ]
        },
        {
          "below": "1.6.3",
          "severity": "medium",
          "cwe": [
            "CWE-400"
          ],
          "identifiers": {
            "summary": "DOS in $sanitize",
            "retid": "52"
          },
          "info": [
            "https://github.com/angular/angular.js/blob/master/CHANGELOG.md",
            "https://github.com/angular/angular.js/pull/15699"
          ]
        },
        {
          "below": "1.6.3",
          "severity": "medium",
          "cwe": [
            "CWE-942"
          ],
          "identifiers": {
            "summary": "Universal CSP bypass via add-on in Firefox",
            "retid": "51"
          },
          "info": [
            "http://pastebin.com/raw/kGrdaypP",
            "https://github.com/mozilla/addons-linter/issues/1000#issuecomment-282083435"
          ]
        },
        {
          "below": "1.6.5",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS in $sanitize in Safari/Firefox",
            "retid": "53"
          },
          "info": [
            "https://github.com/angular/angular.js/commit/8f31f1ff43b673a24f84422d5c13d6312b2c4d94"
          ]
        },
        {
          "atOrAbove": "1.5.0",
          "below": "1.6.9",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS through SVG if enableSvg is set",
            "retid": "48"
          },
          "info": [
            "https://github.com/angular/angular.js/blob/master/CHANGELOG.md#169-fiery-basilisk-2018-02-02",
            "https://vulnerabledoma.in/ngSanitize1.6.8_bypass.html"
          ]
        },
        {
          "below": "1.7.9",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-20",
            "CWE-915"
          ],
          "identifiers": {
            "summary": "Prototype pollution",
            "retid": "47",
            "githubID": "GHSA-89mq-4x47-5v83",
            "CVE": [
              "CVE-2019-10768"
            ]
          },
          "info": [
            "https://github.com/angular/angular.js/blob/master/CHANGELOG.md#179-pollution-eradication-2019-11-19",
            "https://github.com/angular/angular.js/commit/726f49dcf6c23106ddaf5cfd5e2e592841db743a"
          ]
        },
        {
          "below": "1.8.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS via JQLite DOM manipulation functions in AngularJS",
            "githubID": "GHSA-5cp4-xmrw-59wf"
          },
          "info": [
            "https://github.com/advisories/GHSA-5cp4-xmrw-59wf"
          ]
        },
        {
          "below": "1.8.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS may be triggered in AngularJS applications that sanitize user-controlled HTML snippets before passing them to JQLite methods like JQLite.prepend, JQLite.after, JQLite.append, JQLite.replaceWith, JQLite.append, new JQLite and angular.element.",
            "CVE": [
              "CVE-2020-7676"
            ],
            "githubID": "GHSA-mhp6-pxh8-r675"
          },
          "info": [
            "https://github.com/advisories/GHSA-5cp4-xmrw-59wf",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7676"
          ]
        },
        {
          "below": "1.8.4",
          "severity": "medium",
          "cwe": [
            "CWE-1333"
          ],
          "identifiers": {
            "summary": "angular vulnerable to regular expression denial of service via the $resource service",
            "CVE": [
              "CVE-2023-26117"
            ],
            "githubID": "GHSA-2qqx-w9hr-q5gx"
          },
          "info": [
            "https://github.com/advisories/GHSA-2qqx-w9hr-q5gx"
          ]
        },
        {
          "below": "1.8.4",
          "severity": "medium",
          "cwe": [
            "CWE-1333"
          ],
          "identifiers": {
            "summary": "angular vulnerable to regular expression denial of service via the angular.copy() utility",
            "CVE": [
              "CVE-2023-26116"
            ],
            "githubID": "GHSA-2vrf-hf26-jrp5"
          },
          "info": [
            "https://github.com/advisories/GHSA-2vrf-hf26-jrp5"
          ]
        },
        {
          "below": "1.8.4",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Angular (deprecated package) Cross-site Scripting",
            "CVE": [
              "CVE-2022-25869"
            ],
            "githubID": "GHSA-prc3-vjfx-vhm9"
          },
          "info": [
            "https://github.com/advisories/GHSA-prc3-vjfx-vhm9"
          ]
        },
        {
          "below": "1.8.4",
          "severity": "medium",
          "cwe": [
            "CWE-1333"
          ],
          "identifiers": {
            "summary": "angular vulnerable to regular expression denial of service via the <input type=\"url\"> element",
            "githubID": "GHSA-qwqh-hm9m-p5hr",
            "CVE": [
              "CVE-2023-26118"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-qwqh-hm9m-p5hr"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "1.8.4",
          "cwe": [
            "CWE-791"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "AngularJS improperly sanitizes SVG elements",
            "CVE": [
              "CVE-2025-0716"
            ],
            "githubID": "GHSA-j58c-ww9w-pwp5"
          },
          "info": [
            "https://github.com/advisories/GHSA-j58c-ww9w-pwp5",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-0716",
            "https://codepen.io/herodevs/pen/qEWQmpd/a86a0d29310e12c7a3756768e6c7b915",
            "https://github.com/angular/angular.js",
            "https://www.herodevs.com/vulnerability-directory/cve-2025-0716"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "1.8.4",
          "cwe": [
            "CWE-791"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "AngularJS allows attackers to bypass common image source restrictions",
            "CVE": [
              "CVE-2024-8373"
            ],
            "githubID": "GHSA-mqm9-c95h-x2p6"
          },
          "info": [
            "https://github.com/advisories/GHSA-mqm9-c95h-x2p6",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-8373",
            "https://codepen.io/herodevs/full/bGPQgMp/8da9ce87e99403ee13a295c305ebfa0b",
            "https://github.com/angular/angular.js",
            "https://www.herodevs.com/vulnerability-directory/cve-2024-8373"
          ]
        },
        {
          "atOrAbove": "1.3.0",
          "below": "1.8.4",
          "cwe": [
            "CWE-1333"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "angular vulnerable to super-linear runtime due to backtracking",
            "CVE": [
              "CVE-2024-21490"
            ],
            "githubID": "GHSA-4w4v-5hc9-xrr2"
          },
          "info": [
            "https://github.com/advisories/GHSA-4w4v-5hc9-xrr2",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-21490",
            "https://github.com/angular/angular.js",
            "https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-6241746",
            "https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-6241747",
            "https://security.snyk.io/vuln/SNYK-JS-ANGULAR-6091113",
            "https://stackblitz.com/edit/angularjs-vulnerability-ng-srcset-redos"
          ]
        },
        {
          "atOrAbove": "1.3.0-rc.4",
          "below": "1.8.4",
          "cwe": [
            "CWE-1289"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "AngularJS allows attackers to bypass common image source restrictions",
            "CVE": [
              "CVE-2024-8372"
            ],
            "githubID": "GHSA-m9gf-397r-hwpg"
          },
          "info": [
            "https://github.com/advisories/GHSA-m9gf-397r-hwpg",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-8372",
            "https://codepen.io/herodevs/full/xxoQRNL/0072e627abe03e9cda373bc75b4c1017",
            "https://github.com/angular/angular.js",
            "https://www.herodevs.com/vulnerability-directory/cve-2024-8372"
          ]
        },
        {
          "below": "1.999",
          "severity": "low",
          "cwe": [
            "CWE-1104"
          ],
          "identifiers": {
            "summary": "End-of-Life: Long term support for AngularJS has been discontinued as of December 31, 2021",
            "retid": "54"
          },
          "info": [
            "https://docs.angularjs.org/misc/version-support-status"
          ]
        },
        {
          "atOrAbove": "1.7.0",
          "below": "999",
          "severity": "medium",
          "cwe": [
            "CWE-1333",
            "CWE-770"
          ],
          "identifiers": {
            "summary": "angular vulnerable to regular expression denial of service (ReDoS)",
            "CVE": [
              "CVE-2022-25844"
            ],
            "githubID": "GHSA-m2h2-264f-f486"
          },
          "info": [
            "https://github.com/advisories/GHSA-m2h2-264f-f486"
          ]
        }
      ],
      "extractors": {
        "func": [
          "angular.version.full"
        ],
        "uri": [
          "/(§§version§§)/angular(\\.min)?\\.js"
        ],
        "filename": [
          "angular(?:js)?-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "/\\*[\\*\\s]+(?:@license )?AngularJS v(§§version§§)",
          "http://errors\\.angularjs\\.org/(§§version§§)/"
        ],
        "hashes": {},
        "ast": [
          "//ObjectExpression[       /Property/:key/:name == \"angularVersion\"     ]/:properties/$$:value/:value",
          "//ObjectExpression[       /Property/:key[/:name == \"version\" || /:value == \"version\"] &&        /Property/:key[/:name == \"bind\" || /:value == \"bind\"] &&       /Property/:key[/:name == \"injector\" || /:value == \"injector\"]     ]/Property[/:key/:name == \"version\" || /:key/:value == \"version\"]/$:value/ObjectExpression/Property[       /:key/:name == \"full\"     ]/:value/:value",
          "//ObjectExpression[       /Property/:key[/:name == \"version\" || /:value == \"version\"] &&       /Property/:key[/:name == \"bind\" || /:value == \"bind\"] &&       /Property/:key[/:name == \"injector\" || /:value == \"injector\"]     ]/Property[/:key/:name == \"version\" || /:key/:value == \"version\"]/:value/Property[       /:key/:name == \"full\"     ]/:value/:value"
        ]
      }
    },
    "@angular/core": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "0",
          "below": "10.2.5",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Cross site scripting in Angular",
            "CVE": [
              "CVE-2021-4231"
            ],
            "githubID": "GHSA-c75v-2vq8-878f"
          },
          "info": [
            "https://github.com/advisories/GHSA-c75v-2vq8-878f",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-4231",
            "https://github.com/angular/angular/issues/40136",
            "https://github.com/angular/angular/commit/0aa220bc0000fc4d1651ec388975bbf5baa1da36",
            "https://github.com/angular/angular/commit/47d9b6d72dab9d60c96bc1c3604219f6385649ea",
            "https://github.com/angular/angular/commit/ba8da742e3b243e8f43d4c63aa842b44e14f2b09",
            "https://github.com/angular/angular",
            "https://security.snyk.io/vuln/SNYK-JS-ANGULARCORE-1070902",
            "https://vuldb.com/?id.181356"
          ]
        },
        {
          "atOrAbove": "11.0.0",
          "below": "11.0.5",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Cross site scripting in Angular",
            "CVE": [
              "CVE-2021-4231"
            ],
            "githubID": "GHSA-c75v-2vq8-878f"
          },
          "info": [
            "https://github.com/advisories/GHSA-c75v-2vq8-878f",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-4231",
            "https://github.com/angular/angular/issues/40136",
            "https://github.com/angular/angular/commit/0aa220bc0000fc4d1651ec388975bbf5baa1da36",
            "https://github.com/angular/angular/commit/47d9b6d72dab9d60c96bc1c3604219f6385649ea",
            "https://github.com/angular/angular/commit/ba8da742e3b243e8f43d4c63aa842b44e14f2b09",
            "https://github.com/angular/angular",
            "https://security.snyk.io/vuln/SNYK-JS-ANGULARCORE-1070902",
            "https://vuldb.com/?id.181356"
          ]
        },
        {
          "atOrAbove": "11.1.0-next.0",
          "below": "11.1.0-next.3",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Cross site scripting in Angular",
            "CVE": [
              "CVE-2021-4231"
            ],
            "githubID": "GHSA-c75v-2vq8-878f"
          },
          "info": [
            "https://github.com/advisories/GHSA-c75v-2vq8-878f",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-4231",
            "https://github.com/angular/angular/issues/40136",
            "https://github.com/angular/angular/commit/0aa220bc0000fc4d1651ec388975bbf5baa1da36",
            "https://github.com/angular/angular/commit/47d9b6d72dab9d60c96bc1c3604219f6385649ea",
            "https://github.com/angular/angular/commit/ba8da742e3b243e8f43d4c63aa842b44e14f2b09",
            "https://github.com/angular/angular",
            "https://security.snyk.io/vuln/SNYK-JS-ANGULARCORE-1070902",
            "https://vuldb.com/?id.181356"
          ]
        }
      ],
      "extractors": {
        "func": [
          "document.querySelector('[ng-version]').getAttribute('ng-version')",
          "window.getAllAngularRootElements()[0].getAttribute(['ng-version'])"
        ],
        "ast": [
          "//ExportNamedDeclaration[       /ExportSpecifier/:exported[         /:name == \"NgModuleFactory\" ||          /:name == \"ɵBrowserDomAdapter\"       ]     ]/ExportSpecifier[       /:exported/:name == \"VERSION\"     ]/:$local/:init/:arguments/:value",
          "//CallExpression/ArrayExpression[/Literal/:value == \"ng-version\"]/MemberExpression[       /:property/:name == \"full\"     ]/:$object/:init/:arguments/:value",
          "//CallExpression/ArrayExpression[/Literal/:value == \"ng-version\"]/:1/:value"
        ]
      }
    },
    "backbone.js": {
      "bowername": [
        "backbonejs",
        "backbone"
      ],
      "npmname": "backbone",
      "basePurl": "pkg:npm/backbone",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "0.5.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "cross-site scripting vulnerability",
            "release": "0.5.0",
            "retid": "46",
            "githubID": "GHSA-j6p2-cx3w-6jcp",
            "CVE": [
              "CVE-2016-10537"
            ]
          },
          "info": [
            "http://backbonejs.org/#changelog"
          ]
        }
      ],
      "extractors": {
        "func": [
          "Backbone.VERSION"
        ],
        "uri": [
          "/(§§version§§)/backbone(\\.min)?\\.js"
        ],
        "filename": [
          "backbone(?:js)?-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "//[ ]+Backbone.js (§§version§§)",
          "a=t.Backbone=\\{\\}\\}a.VERSION=\"(§§version§§)\"",
          "Backbone\\.VERSION *= *[\"'](§§version§§)[\"']"
        ],
        "hashes": {}
      }
    },
    "mustache.js": {
      "bowername": [
        "mustache.js",
        "mustache"
      ],
      "npmname": "mustache",
      "basePurl": "pkg:npm/mustache",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "0.3.1",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "execution of arbitrary javascript",
            "bug": "112"
          },
          "info": [
            "https://github.com/janl/mustache.js/issues/112"
          ]
        },
        {
          "below": "2.2.1",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "weakness in HTML escaping",
            "PR": "530",
            "githubID": "GHSA-w3w8-37jv-2c58",
            "CVE": [
              "CVE-2015-8862"
            ]
          },
          "info": [
            "https://github.com/janl/mustache.js/pull/530",
            "https://github.com/janl/mustache.js/releases/tag/v2.2.1"
          ]
        }
      ],
      "extractors": {
        "func": [
          "Mustache.version"
        ],
        "uri": [
          "/(§§version§§)/mustache(\\.min)?\\.js"
        ],
        "filename": [
          "mustache(?:js)?-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "name:\"mustache.js\",version:\"(§§version§§)\"",
          "name=\"mustache.js\"[;,].\\.version=\"(§§version§§)\"",
          "[^a-z]mustache.version[ ]?=[ ]?(?:'|\")(§§version§§)(?:'|\")",
          "exports.name[ ]?=[ ]?\"mustache.js\";[\n ]*exports.version[ ]?=[ ]?(?:'|\")(§§version§§)(?:'|\");"
        ],
        "hashes": {}
      }
    },
    "handlebars": {
      "bowername": [
        "handlebars",
        "handlebars.js"
      ],
      "licenses": [
        "MIT >=0",
        "BSD-2-Clause >=1.0.2-beta <1.2.0"
      ],
      "vulnerabilities": [
        {
          "below": "1.0.0.beta.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "poorly sanitized input passed to eval()",
            "issue": "68"
          },
          "info": [
            "https://github.com/wycats/handlebars.js/pull/68"
          ]
        },
        {
          "below": "3.0.7",
          "severity": "high",
          "cwe": [
            "CWE-471"
          ],
          "identifiers": {
            "summary": "A prototype pollution vulnerability in handlebars is exploitable if an attacker can control the template",
            "issue": "1495",
            "githubID": "GHSA-q42p-pg8m-cqh6"
          },
          "info": [
            "https://github.com/advisories/GHSA-q42p-pg8m-cqh6",
            "https://github.com/wycats/handlebars.js/commit/cd38583216dce3252831916323202749431c773e",
            "https://github.com/wycats/handlebars.js/issues/1495",
            "https://snyk.io/vuln/SNYK-JS-HANDLEBARS-174183"
          ]
        },
        {
          "below": "3.0.8",
          "severity": "high",
          "cwe": [
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Versions of `handlebars` prior to 3.0.8 or 4.5.2 are vulnerable to Arbitrary Code Execution. The package's lookup helper fails to properly validate templates, allowing attackers to submit templates that execute arbitrary JavaScript in the system. It can be used to run arbitrary code in a server processing Handlebars templates or on a victim's browser (effectively serving as Cross-Site Scripting).\n\nThe following template can be used to demonstrate the vulnerability:  \n```{{#with \"constructor\"}}\n\t{{#with split as |a|}}\n\t\t{{pop (push \"alert('Vulnerable Handlebars JS');\")}}\n\t\t{{#with (concat (lookup join (slice 0 1)))}}\n\t\t\t{{#each (slice 2 3)}}\n\t\t\t\t{{#with (apply 0 a)}}\n\t\t\t\t\t{{.}}\n\t\t\t\t{{/with}}\n\t\t\t{{/each}}\n\t\t{{/with}}\n\t{{/with}}\n{{/with}}```\n\n\n## Recommendation\n\nUpgrade to version 3.0.8, 4.5.2 or later.",
            "githubID": "GHSA-2cf5-4w76-r9qv"
          },
          "info": [
            "https://github.com/advisories/GHSA-2cf5-4w76-r9qv",
            "https://www.npmjs.com/advisories/1316"
          ]
        },
        {
          "below": "3.0.8",
          "severity": "high",
          "cwe": [
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Handlebars before 3.0.8 and 4.x before 4.5.3 is vulnerable to Arbitrary Code Execution. The lookup helper fails to properly validate templates, allowing attackers to submit templates that execute arbitrary JavaScript. This can be used to run arbitrary code on a server processing Handlebars templates or in a victim's browser (effectively serving as XSS).",
            "githubID": "GHSA-3cqr-58rm-57f8",
            "CVE": [
              "CVE-2019-20920"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-3cqr-58rm-57f8",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-20920"
          ]
        },
        {
          "below": "3.0.8",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype pollution",
            "retid": "45",
            "githubID": "GHSA-g9r4-xpmj-mj65"
          },
          "info": [
            "https://github.com/advisories/GHSA-g9r4-xpmj-mj65",
            "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v453---november-18th-2019"
          ]
        },
        {
          "below": "3.0.8",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of `handlebars` prior to 3.0.8 or 4.5.3 are vulnerable to Arbitrary Code Execution. The package's lookup helper fails to properly validate templates, allowing attackers to submit templates that execute arbitrary JavaScript in the system. It is due to an incomplete fix for a [previous issue](https://www.npmjs.com/advisories/1316). This vulnerability can be used to run arbitrary code in a server processing Handlebars templates or on a victim's browser (effectively serving as Cross-Site Scripting)",
            "githubID": "GHSA-q2c6-c6pm-g3gh"
          },
          "info": [
            "https://github.com/advisories/GHSA-q2c6-c6pm-g3gh",
            "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v453---november-18th-2019"
          ]
        },
        {
          "below": "3.0.8",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-74"
          ],
          "identifiers": {
            "summary": "Disallow calling helperMissing and blockHelperMissing directly",
            "retid": "44",
            "CVE": [
              "CVE-2019-19919"
            ],
            "githubID": "GHSA-w457-6q6x-cgp9"
          },
          "info": [
            "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v430---september-24th-2019"
          ]
        },
        {
          "below": "4.0.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Quoteless attributes in templates can lead to XSS",
            "issue": "1083",
            "CVE": [
              "CVE-2015-8861"
            ],
            "githubID": "GHSA-9prh-257w-9277"
          },
          "info": [
            "https://github.com/wycats/handlebars.js/pull/1083"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.0.13",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "A prototype pollution vulnerability in handlebars is exploitable if an attacker can control the template",
            "retid": "43"
          },
          "info": [
            "https://github.com/wycats/handlebars.js/commit/7372d4e9dffc9d70c09671aa28b9392a1577fd86",
            "https://snyk.io/vuln/SNYK-JS-HANDLEBARS-173692"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.0.14",
          "severity": "high",
          "cwe": [
            "CWE-471"
          ],
          "identifiers": {
            "summary": "A prototype pollution vulnerability in handlebars is exploitable if an attacker can control the template",
            "issue": "1495",
            "githubID": "GHSA-q42p-pg8m-cqh6"
          },
          "info": [
            "https://github.com/advisories/GHSA-q42p-pg8m-cqh6",
            "https://github.com/wycats/handlebars.js/commit/cd38583216dce3252831916323202749431c773e",
            "https://github.com/wycats/handlebars.js/issues/1495",
            "https://snyk.io/vuln/SNYK-JS-HANDLEBARS-174183"
          ]
        },
        {
          "atOrAbove": "4.1.0",
          "below": "4.1.2",
          "severity": "high",
          "cwe": [
            "CWE-471"
          ],
          "identifiers": {
            "summary": "A prototype pollution vulnerability in handlebars is exploitable if an attacker can control the template",
            "issue": "1495",
            "githubID": "GHSA-q42p-pg8m-cqh6"
          },
          "info": [
            "https://github.com/advisories/GHSA-q42p-pg8m-cqh6",
            "https://github.com/wycats/handlebars.js/commit/cd38583216dce3252831916323202749431c773e",
            "https://github.com/wycats/handlebars.js/issues/1495",
            "https://snyk.io/vuln/SNYK-JS-HANDLEBARS-174183"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.3.0",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-74"
          ],
          "identifiers": {
            "summary": "Disallow calling helperMissing and blockHelperMissing directly",
            "retid": "44",
            "CVE": [
              "CVE-2019-19919"
            ],
            "githubID": "GHSA-w457-6q6x-cgp9"
          },
          "info": [
            "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v430---september-24th-2019"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.4.5",
          "severity": "high",
          "cwe": [
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Regular Expression Denial of Service in Handlebars",
            "githubID": "GHSA-62gr-4qp9-h98f",
            "CVE": [
              "CVE-2019-20922"
            ]
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-20922"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.4.5",
          "severity": "medium",
          "cwe": [
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Affected versions of `handlebars` are vulnerable to Denial of Service. The package's parser may be forced into an endless loop while processing specially-crafted templates. This may allow attackers to exhaust system resources leading to Denial of Service.\n\n\n## Recommendation\n\nUpgrade to version 4.4.5 or later.",
            "retid": "75",
            "githubID": "GHSA-f52g-6jhx-586p"
          },
          "info": [
            "https://github.com/handlebars-lang/handlebars.js/commit/f0589701698268578199be25285b2ebea1c1e427"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.5.2",
          "severity": "high",
          "cwe": [
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Versions of `handlebars` prior to 3.0.8 or 4.5.2 are vulnerable to Arbitrary Code Execution. The package's lookup helper fails to properly validate templates, allowing attackers to submit templates that execute arbitrary JavaScript in the system. It can be used to run arbitrary code in a server processing Handlebars templates or on a victim's browser (effectively serving as Cross-Site Scripting).\n\nThe following template can be used to demonstrate the vulnerability:  \n```{{#with \"constructor\"}}\n\t{{#with split as |a|}}\n\t\t{{pop (push \"alert('Vulnerable Handlebars JS');\")}}\n\t\t{{#with (concat (lookup join (slice 0 1)))}}\n\t\t\t{{#each (slice 2 3)}}\n\t\t\t\t{{#with (apply 0 a)}}\n\t\t\t\t\t{{.}}\n\t\t\t\t{{/with}}\n\t\t\t{{/each}}\n\t\t{{/with}}\n\t{{/with}}\n{{/with}}```\n\n\n## Recommendation\n\nUpgrade to version 3.0.8, 4.5.2 or later.",
            "githubID": "GHSA-2cf5-4w76-r9qv"
          },
          "info": [
            "https://github.com/advisories/GHSA-2cf5-4w76-r9qv",
            "https://www.npmjs.com/advisories/1316"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.5.3",
          "severity": "high",
          "cwe": [
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Handlebars before 3.0.8 and 4.x before 4.5.3 is vulnerable to Arbitrary Code Execution. The lookup helper fails to properly validate templates, allowing attackers to submit templates that execute arbitrary JavaScript. This can be used to run arbitrary code on a server processing Handlebars templates or in a victim's browser (effectively serving as XSS).",
            "githubID": "GHSA-3cqr-58rm-57f8",
            "CVE": [
              "CVE-2019-20920"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-3cqr-58rm-57f8",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-20920"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.5.3",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype pollution",
            "retid": "45",
            "githubID": "GHSA-g9r4-xpmj-mj65"
          },
          "info": [
            "https://github.com/advisories/GHSA-g9r4-xpmj-mj65",
            "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v453---november-18th-2019"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.5.3",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of `handlebars` prior to 3.0.8 or 4.5.3 are vulnerable to Arbitrary Code Execution. The package's lookup helper fails to properly validate templates, allowing attackers to submit templates that execute arbitrary JavaScript in the system. It is due to an incomplete fix for a [previous issue](https://www.npmjs.com/advisories/1316). This vulnerability can be used to run arbitrary code in a server processing Handlebars templates or on a victim's browser (effectively serving as Cross-Site Scripting)",
            "githubID": "GHSA-q2c6-c6pm-g3gh"
          },
          "info": [
            "https://github.com/advisories/GHSA-q2c6-c6pm-g3gh",
            "https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v453---november-18th-2019"
          ]
        },
        {
          "below": "4.6.0",
          "severity": "medium",
          "cwe": [
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Denial of service",
            "issue": "1633"
          },
          "info": [
            "https://github.com/handlebars-lang/handlebars.js/pull/1633"
          ]
        },
        {
          "below": "4.7.7",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype Pollution in handlebars",
            "retid": "71",
            "CVE": [
              "CVE-2021-23383"
            ],
            "githubID": "GHSA-765h-qjxv-5f44"
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-23383"
          ]
        },
        {
          "below": "4.7.7",
          "severity": "high",
          "cwe": [
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Remote code execution in handlebars when compiling templates",
            "CVE": [
              "CVE-2021-23369"
            ],
            "githubID": "GHSA-f2jv-r9rf-7988"
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-23369"
          ]
        }
      ],
      "extractors": {
        "func": [
          "Handlebars.VERSION"
        ],
        "uri": [
          "/(§§version§§)/handlebars(\\.min)?\\.js"
        ],
        "filename": [
          "handlebars(?:js)?-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "Handlebars.VERSION = \"(§§version§§)\";",
          "Handlebars=\\{VERSION:(?:'|\")(§§version§§)(?:'|\")",
          "this.Handlebars=\\{\\};[\n\r \t]+\\(function\\([a-z]\\)\\{[a-z].VERSION=(?:'|\")(§§version§§)(?:'|\")",
          "exports.HandlebarsEnvironment=[\\s\\S]{70,120}exports.VERSION=(?:'|\")(§§version§§)(?:'|\")",
          "/\\*+![\\s]+(?:@license)?[\\s]+handlebars v+(§§version§§)",
          "window\\.Handlebars=.,.\\.VERSION=\"(§§version§§)\"",
          ".\\.HandlebarsEnvironment=.;var .=.\\(.\\),.=.\\(.\\),.=\"(§§version§§)\";.\\.VERSION="
        ],
        "hashes": {},
        "ast": [
          "//FunctionExpression/BlockStatement[       /ExpressionStatement//AssignmentExpression[         /:left/:property/:name == 'HandlebarsEnvironment'       ]/:left/$:object ==       /ExpressionStatement/AssignmentExpression[         /:left/:property/:name == 'VERSION'       ]/:left/$:object     ]     /ExpressionStatement/AssignmentExpression[       /:left/:property/:name == 'VERSION'     ]/$$:right/:value",
          "       //SequenceExpression[         /AssignmentExpression[           /:left/:property/:name == 'Handlebars' &&            /:left/:object/:name == 'window'         ]       ]/AssignmentExpression[/:left/:property/:name == 'VERSION']/:right/:value     "
        ]
      }
    },
    "easyXDM": {
      "npmname": "easyxdm",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "2.4.18",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-5212"
            ]
          },
          "info": [
            "http://blog.kotowicz.net/2013/09/exploiting-easyxdm-part-1-not-usual.html",
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-5212"
          ]
        },
        {
          "below": "2.4.19",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2014-1403"
            ]
          },
          "info": [
            "http://blog.kotowicz.net/2014/01/xssing-with-shakespeare-name-calling.html",
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1403"
          ]
        },
        {
          "below": "2.4.20",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "This release fixes a potential XSS for IE running in compatibility mode.",
            "retid": "39"
          },
          "info": [
            "https://github.com/oyvindkinsey/easyXDM/releases/tag/2.4.20"
          ]
        },
        {
          "below": "2.5.0",
          "severity": "medium",
          "cwe": [
            "CWE-942"
          ],
          "identifiers": {
            "summary": "This tightens down the default origin whitelist in the CORS example.",
            "retid": "40"
          },
          "info": [
            "https://github.com/oyvindkinsey/easyXDM/releases/tag/2.5.0"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/(?:easyXDM-)?(§§version§§)/easyXDM(\\.min)?\\.js"
        ],
        "filename": [
          "easyXDM-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          " \\* easyXDM\n \\* http://easyxdm.net/(?:\r|\n|.)+version:\"(§§version§§)\"",
          "@class easyXDM(?:.|\r|\n)+@version (§§version§§)(\r|\n)"
        ],
        "hashes": {
          "cf266e3bc2da372c4f0d6b2bd87bcbaa24d5a643": "2.4.6"
        }
      }
    },
    "plupload": {
      "bowername": [
        "Plupload",
        "plupload"
      ],
      "licenses": [
        "AGPL-3.0 >=2.2.1",
        "GPL-2.0 >=2.2.0 <2.2.1"
      ],
      "vulnerabilities": [
        {
          "below": "1.5.4",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2012-2401"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2012-2401/"
          ]
        },
        {
          "below": "1.5.5",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-0237"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2013-0237/"
          ]
        },
        {
          "below": "2.1.9",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2016-4566"
            ]
          },
          "info": [
            "https://github.com/moxiecode/plupload/releases"
          ]
        },
        {
          "below": "2.3.7",
          "severity": "medium",
          "cwe": [
            "CWE-434"
          ],
          "identifiers": {
            "summary": "Fixed security vulnerability by adding die calls to all php files to prevent them from being executed unless modified.",
            "retid": "35"
          },
          "info": [
            "https://github.com/moxiecode/plupload/releases/tag/v2.3.7"
          ]
        },
        {
          "below": "2.3.8",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fixed a potential security issue with not entity encoding the file names in the html in the queue/ui widgets.",
            "retid": "38"
          },
          "info": [
            "https://github.com/moxiecode/plupload/releases/tag/v2.3.8"
          ]
        },
        {
          "below": "2.3.9",
          "severity": "medium",
          "cwe": [
            "CWE-434",
            "CWE-75"
          ],
          "identifiers": {
            "summary": "Fixed another case of html entities not being encoded that could be exploded by uploading a file name with html in it.",
            "retid": "42",
            "CVE": [
              "CVE-2021-23562"
            ],
            "githubID": "GHSA-rp2c-jrgp-cvr8"
          },
          "info": [
            "https://github.com/moxiecode/plupload/releases/tag/v2.3.9"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.1.3",
          "severity": "medium",
          "cwe": [
            "CWE-434"
          ],
          "identifiers": {
            "summary": "Fixed security vulnerability by adding die calls to all php files to prevent them from being executed unless modified.",
            "retid": "36"
          },
          "info": [
            "https://github.com/moxiecode/plupload/releases/tag/v3.1.3"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.1.4",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fixed a potential security issue with not entity encoding the file names in the html in the queue/ui widgets.",
            "retid": "37"
          },
          "info": [
            "https://github.com/moxiecode/plupload/releases/tag/v3.1.4"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.1.5",
          "severity": "medium",
          "cwe": [
            "CWE-434"
          ],
          "identifiers": {
            "summary": "Fixed another case of html entities not being encoded that could be exploded by uploading a file name with html in it.",
            "retid": "41"
          },
          "info": [
            "https://github.com/moxiecode/plupload/releases/tag/v3.1.5"
          ]
        }
      ],
      "extractors": {
        "func": [
          "plupload.VERSION"
        ],
        "uri": [
          "/(§§version§§)/plupload(\\.min)?\\.js"
        ],
        "filename": [
          "plupload-(§§version§§)(.min)?\\.js"
        ],
        "filecontent": [
          "\\* Plupload - multi-runtime File Uploader(?:\r|\n)+ \\* v(§§version§§)",
          "var g=\\{VERSION:\"(§§version§§)\",.*;window.plupload=g\\}"
        ],
        "hashes": {}
      }
    },
    "DOMPurify": {
      "bowername": [
        "dompurify",
        "DOMPurify"
      ],
      "npmname": "dompurify",
      "licenses": [
        "MPL-2.0 >=0.4.0 <0.6.6",
        "(MPL-2.0 OR Apache-2.0) >=0.6.6"
      ],
      "vulnerabilities": [
        {
          "below": "0.6.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "retid": "24"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases/tag/0.6.1"
          ]
        },
        {
          "below": "0.8.6",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "retid": "25"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases/tag/0.8.6"
          ]
        },
        {
          "below": "0.8.9",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "safari UXSS",
            "retid": "26"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases/tag/0.8.9",
            "https://lists.ruhr-uni-bochum.de/pipermail/dompurify-security/2017-May/000006.html"
          ]
        },
        {
          "below": "0.9.0",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "safari UXSS",
            "retid": "27"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases/tag/0.9.0"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "1.0.11",
          "cwe": [
            "CWE-601"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "DOMPurify Open Redirect vulnerability",
            "CVE": [
              "CVE-2019-25155"
            ],
            "githubID": "GHSA-8hgg-xxm5-3873"
          },
          "info": [
            "https://github.com/advisories/GHSA-8hgg-xxm5-3873",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-25155",
            "https://github.com/cure53/DOMPurify/pull/337",
            "https://github.com/cure53/DOMPurify/commit/7601c33a57e029cce51d910eda5179a3f1b51c83",
            "https://github.com/cure53/DOMPurify",
            "https://github.com/cure53/DOMPurify/compare/1.0.10...1.0.11"
          ]
        },
        {
          "below": "2.0.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fixed an mXSS-based bypass caused by nested forms inside MathML",
            "githubID": "GHSA-chqj-j4fh-rw7m",
            "CVE": [
              "CVE-2019-16728"
            ]
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases"
          ]
        },
        {
          "below": "2.0.7",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "possible to bypass the package sanitization through Mutation XSS",
            "githubID": "GHSA-mjjq-c88q-qhr6"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases"
          ]
        },
        {
          "below": "2.0.16",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fixed an mXSS-based bypass caused by nested forms inside MathML",
            "retid": "28"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases"
          ]
        },
        {
          "below": "2.0.17",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fixed another bypass causing mXSS by using MathML",
            "retid": "29",
            "githubID": "GHSA-63q7-h895-m982",
            "CVE": [
              "CVE-2020-26870"
            ]
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases"
          ]
        },
        {
          "below": "2.1.1",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fixed several possible mXSS patterns, thanks @hackvertor",
            "retid": "30"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases"
          ]
        },
        {
          "below": "2.2.0",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fix a possible XSS in Chrome that is hidden behind #enable-experimental-web-platform-features",
            "retid": "31"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases"
          ]
        },
        {
          "below": "2.2.2",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fixed an mXSS bypass dropped on us publicly via",
            "retid": "32"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases"
          ]
        },
        {
          "below": "2.2.3",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fixed an mXSS issue reported",
            "retid": "33"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases"
          ]
        },
        {
          "below": "2.2.4",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Fixed a new MathML-based bypass submitted by PewGrand. Fixed a new SVG-related bypass submitted by SecurityMB",
            "retid": "34"
          },
          "info": [
            "https://github.com/cure53/DOMPurify/releases"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "2.4.2",
          "cwe": [
            "CWE-1321"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "DOMPurify vulnerable to tampering by prototype polution",
            "CVE": [
              "CVE-2024-48910"
            ],
            "githubID": "GHSA-p3vf-v8qc-cwcr"
          },
          "info": [
            "https://github.com/advisories/GHSA-p3vf-v8qc-cwcr",
            "https://github.com/cure53/DOMPurify/security/advisories/GHSA-p3vf-v8qc-cwcr",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-48910",
            "https://github.com/cure53/DOMPurify/commit/d1dd0374caef2b4c56c3bd09fe1988c3479166dc",
            "https://github.com/cure53/DOMPurify"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "2.5.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "DOMpurify has a nesting-based mXSS",
            "CVE": [
              "CVE-2024-47875"
            ],
            "githubID": "GHSA-gx9m-whjm-85jf"
          },
          "info": [
            "https://github.com/advisories/GHSA-gx9m-whjm-85jf",
            "https://github.com/cure53/DOMPurify/security/advisories/GHSA-gx9m-whjm-85jf",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-47875",
            "https://github.com/cure53/DOMPurify/commit/0ef5e537a514f904b6aa1d7ad9e749e365d7185f",
            "https://github.com/cure53/DOMPurify/commit/6ea80cd8b47640c20f2f230c7920b1f4ce4fdf7a",
            "https://github.com/cure53/DOMPurify",
            "https://github.com/cure53/DOMPurify/blob/0ef5e537a514f904b6aa1d7ad9e749e365d7185f/test/test-suite.js#L2098"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "2.5.4",
          "cwe": [
            "CWE-1321",
            "CWE-1333"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "DOMPurify allows tampering by prototype pollution",
            "CVE": [
              "CVE-2024-45801"
            ],
            "githubID": "GHSA-mmhx-hmjr-r674"
          },
          "info": [
            "https://github.com/advisories/GHSA-mmhx-hmjr-r674",
            "https://github.com/cure53/DOMPurify/security/advisories/GHSA-mmhx-hmjr-r674",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-45801",
            "https://github.com/cure53/DOMPurify/commit/1e520262bf4c66b5efda49e2316d6d1246ca7b21",
            "https://github.com/cure53/DOMPurify/commit/26e1d69ca7f769f5c558619d644d90dd8bf26ebc",
            "https://github.com/cure53/DOMPurify"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.1.3",
          "cwe": [
            "CWE-79"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "DOMpurify has a nesting-based mXSS",
            "CVE": [
              "CVE-2024-47875"
            ],
            "githubID": "GHSA-gx9m-whjm-85jf"
          },
          "info": [
            "https://github.com/advisories/GHSA-gx9m-whjm-85jf",
            "https://github.com/cure53/DOMPurify/security/advisories/GHSA-gx9m-whjm-85jf",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-47875",
            "https://github.com/cure53/DOMPurify/commit/0ef5e537a514f904b6aa1d7ad9e749e365d7185f",
            "https://github.com/cure53/DOMPurify/commit/6ea80cd8b47640c20f2f230c7920b1f4ce4fdf7a",
            "https://github.com/cure53/DOMPurify",
            "https://github.com/cure53/DOMPurify/blob/0ef5e537a514f904b6aa1d7ad9e749e365d7185f/test/test-suite.js#L2098"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.1.3",
          "cwe": [
            "CWE-1321",
            "CWE-1333"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "DOMPurify allows tampering by prototype pollution",
            "CVE": [
              "CVE-2024-45801"
            ],
            "githubID": "GHSA-mmhx-hmjr-r674"
          },
          "info": [
            "https://github.com/advisories/GHSA-mmhx-hmjr-r674",
            "https://github.com/cure53/DOMPurify/security/advisories/GHSA-mmhx-hmjr-r674",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-45801",
            "https://github.com/cure53/DOMPurify/commit/1e520262bf4c66b5efda49e2316d6d1246ca7b21",
            "https://github.com/cure53/DOMPurify/commit/26e1d69ca7f769f5c558619d644d90dd8bf26ebc",
            "https://github.com/cure53/DOMPurify"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "3.2.4",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "DOMPurify allows Cross-site Scripting (XSS)",
            "CVE": [
              "CVE-2025-26791"
            ],
            "githubID": "GHSA-vhxf-7vqr-mrjg"
          },
          "info": [
            "https://github.com/advisories/GHSA-vhxf-7vqr-mrjg",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-26791",
            "https://github.com/cure53/DOMPurify/commit/d18ffcb554e0001748865da03ac75dd7829f0f02",
            "https://ensy.zip/posts/dompurify-323-bypass",
            "https://github.com/cure53/DOMPurify",
            "https://github.com/cure53/DOMPurify/releases/tag/3.2.4",
            "https://nsysean.github.io/posts/dompurify-323-bypass"
          ]
        }
      ],
      "extractors": {
        "func": [
          "DOMPurify.version"
        ],
        "filecontent": [
          "DOMPurify.version = '(§§version§§)';",
          "DOMPurify.version=\"(§§version§§)\"",
          "DOMPurify=.[^\\r\\n]{10,850}?\\.version=\"(§§version§§)\"",
          "/\\*! @license DOMPurify (§§version§§)",
          "var .=\"dompurify\"+.{10,550}?\\.version=\"(§§version§§)\""
        ],
        "hashes": {},
        "ast": [
          "//CallExpression[       /:callee//:left/:property/:name == \"DOMPurify\"     ]/:arguments//AssignmentExpression[       /:left/:property/:name == \"version\" &&       /:left/$:object/:init/:type == \"FunctionExpression\"     ]/:right/:value"
        ]
      }
    },
    "react": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "0.4.0",
          "below": "0.4.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "potential XSS vulnerability can arise when using user data as a key",
            "CVE": [
              "CVE-2013-7035"
            ],
            "githubID": "GHSA-g53w-52xc-2j85"
          },
          "info": [
            "https://facebook.github.io/react/blog/2013/12/18/react-v0.5.2-v0.4.2.html",
            "https://github.com/advisories/GHSA-g53w-52xc-2j85"
          ]
        },
        {
          "atOrAbove": "0.5.0",
          "below": "0.5.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "potential XSS vulnerability can arise when using user data as a key",
            "CVE": [
              "CVE-2013-7035"
            ],
            "githubID": "GHSA-g53w-52xc-2j85"
          },
          "info": [
            "https://facebook.github.io/react/blog/2013/12/18/react-v0.5.2-v0.4.2.html",
            "https://github.com/advisories/GHSA-g53w-52xc-2j85"
          ]
        },
        {
          "atOrAbove": "0.0.1",
          "below": "0.14.0",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": " including untrusted objects as React children can result in an XSS security vulnerability",
            "retid": "23",
            "githubID": "GHSA-hg79-j56m-fxgv"
          },
          "info": [
            "http://danlec.com/blog/xss-via-a-spoofed-react-element",
            "https://facebook.github.io/react/blog/2015/10/07/react-v0.14.html"
          ]
        },
        {
          "atOrAbove": "16.0.0",
          "below": "16.0.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "potential XSS vulnerability when the attacker controls an attribute name",
            "CVE": [
              "CVE-2018-6341"
            ]
          },
          "info": [
            "https://github.com/facebook/react/blob/master/CHANGELOG.md",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        },
        {
          "atOrAbove": "16.1.0",
          "below": "16.1.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "potential XSS vulnerability when the attacker controls an attribute name",
            "CVE": [
              "CVE-2018-6341"
            ]
          },
          "info": [
            "https://github.com/facebook/react/blob/master/CHANGELOG.md",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        },
        {
          "atOrAbove": "16.2.0",
          "below": "16.2.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "potential XSS vulnerability when the attacker controls an attribute name",
            "CVE": [
              "CVE-2018-6341"
            ]
          },
          "info": [
            "https://github.com/facebook/react/blob/master/CHANGELOG.md",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        },
        {
          "atOrAbove": "16.3.0",
          "below": "16.3.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "potential XSS vulnerability when the attacker controls an attribute name",
            "CVE": [
              "CVE-2018-6341"
            ]
          },
          "info": [
            "https://github.com/facebook/react/blob/master/CHANGELOG.md",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        },
        {
          "atOrAbove": "16.4.0",
          "below": "16.4.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "potential XSS vulnerability when the attacker controls an attribute name",
            "CVE": [
              "CVE-2018-6341"
            ]
          },
          "info": [
            "https://github.com/facebook/react/blob/master/CHANGELOG.md",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        }
      ],
      "extractors": {
        "func": [
          "react.version",
          "require('react').version"
        ],
        "filecontent": [
          "/\\*\\*\n +\\* React \\(with addons\\) ?v(§§version§§)",
          "/\\*\\*\n +\\* React v(§§version§§)",
          "/\\*\\* @license React v(§§version§§)[\\s]*\\* react(-jsx-runtime)?\\.",
          "\"\\./ReactReconciler\":[0-9]+,\"\\./Transaction\":[0-9]+,\"fbjs/lib/invariant\":[0-9]+\\}\\],[0-9]+:\\[function\\(require,module,exports\\)\\{\"use strict\";module\\.exports=\"(§§version§§)\"\\}",
          "ReactVersion\\.js[\\*! \\\\/\n\r]{0,100}function\\(e,t\\)\\{\"use strict\";e\\.exports=\"(§§version§§)\"",
          "expected a ReactNode.[\\s\\S]{0,1800}?function\\(e,t\\)\\{\"use strict\";e\\.exports=\"(§§version§§)\""
        ],
        "ast": [
          "//CallExpression[       /FunctionExpression//MemberExpression/:property/:name == \"React\"     ]/FunctionExpression/BlockStatement/ExpressionStatement/AssignmentExpression[       /:left/:property/:name == \"version\"     ]/$$:right/:value",
          "//BlockStatement[       /ExpressionStatement/AssignmentExpression/MemberExpression[/:property/:name == \"__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED\"]/$:object ==       /ExpressionStatement/AssignmentExpression/MemberExpression[/:property/:name == \"version\"]/$:object     ]/ExpressionStatement/AssignmentExpression[/MemberExpression/:property/:name == \"version\"]/$$:right/:value",
          "/ExpressionStatement/AssignmentExpression[         /MemberExpression/:property/:name == \"version\" &&         /MemberExpression/:$object ==          ../../ExpressionStatement/AssignmentExpression/MemberExpression[           /:property/:name == \"__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED\"         ]/$:object     ]/$$:right/:value"
        ]
      }
    },
    "react-dom": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "16.0.0",
          "below": "16.0.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Affected versions of `react-dom` are vulnerable to Cross-Site Scripting (XSS). The package fails to validate attribute names in HTML tags which may lead to Cross-Site Scripting in specific scenarios",
            "CVE": [
              "CVE-2018-6341"
            ],
            "githubID": "GHSA-mvjj-gqq2-p4hw"
          },
          "info": [
            "https://github.com/advisories/GHSA-mvjj-gqq2-p4hw",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-6341",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        },
        {
          "atOrAbove": "16.1.0",
          "below": "16.1.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Affected versions of `react-dom` are vulnerable to Cross-Site Scripting (XSS). The package fails to validate attribute names in HTML tags which may lead to Cross-Site Scripting in specific scenarios",
            "CVE": [
              "CVE-2018-6341"
            ],
            "githubID": "GHSA-mvjj-gqq2-p4hw"
          },
          "info": [
            "https://github.com/advisories/GHSA-mvjj-gqq2-p4hw",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-6341",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        },
        {
          "atOrAbove": "16.2.0",
          "below": "16.2.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Affected versions of `react-dom` are vulnerable to Cross-Site Scripting (XSS). The package fails to validate attribute names in HTML tags which may lead to Cross-Site Scripting in specific scenarios",
            "CVE": [
              "CVE-2018-6341"
            ],
            "githubID": "GHSA-mvjj-gqq2-p4hw"
          },
          "info": [
            "https://github.com/advisories/GHSA-mvjj-gqq2-p4hw",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-6341",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        },
        {
          "atOrAbove": "16.3.0",
          "below": "16.3.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Affected versions of `react-dom` are vulnerable to Cross-Site Scripting (XSS). The package fails to validate attribute names in HTML tags which may lead to Cross-Site Scripting in specific scenarios",
            "CVE": [
              "CVE-2018-6341"
            ],
            "githubID": "GHSA-mvjj-gqq2-p4hw"
          },
          "info": [
            "https://github.com/advisories/GHSA-mvjj-gqq2-p4hw",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-6341",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        },
        {
          "atOrAbove": "16.4.0",
          "below": "16.4.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Affected versions of `react-dom` are vulnerable to Cross-Site Scripting (XSS). The package fails to validate attribute names in HTML tags which may lead to Cross-Site Scripting in specific scenarios",
            "CVE": [
              "CVE-2018-6341"
            ],
            "githubID": "GHSA-mvjj-gqq2-p4hw"
          },
          "info": [
            "https://github.com/advisories/GHSA-mvjj-gqq2-p4hw",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-6341",
            "https://reactjs.org/blog/2018/08/01/react-v-16-4-2.html"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/react-dom@(§§version§§)/",
          "/react-dom/(§§version§§)/"
        ],
        "filecontent": [
          "version:\"(§§version§§)[a-z0-9\\-]*\"[\\s,]*rendererPackageName:\"react-dom\"",
          "/\\*\\* @license React v(§§version§§)[\\s]*\\* react-dom\\.",
          "return ReactSharedInternals.[a-zA-Z].useHostTransitionStatus\\(\\)\\},exports.version=\"(§§version§§)\""
        ],
        "ast": [
          "//ObjectExpression/Property[/:key/:name == \"reconcilerVersion\"]/$$:value/:value",
          "//ObjectExpression[       /Property[/:key/:name == \"rendererPackageName\" && /:value/:value == \"react-dom\"]     ]/Property[/:key/:name == \"version\"]/:value/:value",
          "//SequenceExpression[             /AssignmentExpression/:left[/:object/:name == \"exports\" && /:property/:name == \"__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE\"]          ]/AssignmentExpression[             /:left/:object/:name == \"exports\" && /:left/:property/:name == \"version\"         ]/:right/:value"
        ]
      }
    },
    "react-is": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [],
      "extractors": {
        "filecontent": [
          "/\\*\\* @license React v(§§version§§)[\\s]*\\* react-is\\."
        ]
      }
    },
    "scheduler": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [],
      "extractors": {
        "filecontent": [
          "/\\*\\* @license React v(§§version§§)[\\s]*\\* scheduler\\."
        ]
      }
    },
    "flowplayer": {
      "licenses": [
        "GPL-3.0 >=0"
      ],
      "vulnerabilities": [
        {
          "below": "5.4.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS vulnerability in Flash fallback",
            "issue": "381"
          },
          "info": [
            "https://github.com/flowplayer/flowplayer/issues/381"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "flowplayer-(§§version§§)(\\.min)?\\.js"
        ],
        "filename": [
          "flowplayer-(§§version§§)(\\.min)?\\.js"
        ]
      }
    },
    "DWR": {
      "npmname": "dwr",
      "licenses": [
        "Apache-2.0 >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.1.4",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2007-01-09"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2014-5326/",
            "http://www.cvedetails.com/cve/CVE-2014-5326/"
          ]
        },
        {
          "below": "2.0.11",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2014-5326",
              "CVE-2014-5325"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2014-5326/"
          ]
        },
        {
          "atOrAbove": "3",
          "below": "3.0.RC3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2014-5326",
              "CVE-2014-5325"
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2014-5326/"
          ]
        }
      ],
      "extractors": {
        "func": [
          "dwr.version"
        ],
        "filecontent": [
          " dwr-(§§version§§).jar"
        ]
      }
    },
    "moment.js": {
      "bowername": [
        "moment",
        "momentjs"
      ],
      "npmname": "moment",
      "basePurl": "pkg:npm/moment",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "2.11.2",
          "severity": "medium",
          "cwe": [
            "CWE-400"
          ],
          "identifiers": {
            "summary": "reDOS - regular expression denial of service",
            "issue": "2936",
            "githubID": "GHSA-87vv-r9j6-g5qv",
            "CVE": [
              "CVE-2016-4055"
            ]
          },
          "info": [
            "https://github.com/moment/moment/issues/2936"
          ]
        },
        {
          "below": "2.15.2",
          "severity": "medium",
          "cwe": [
            "CWE-1333"
          ],
          "identifiers": {
            "summary": "Regular Expression Denial of Service (ReDoS)",
            "retid": "22"
          },
          "info": [
            "https://security.snyk.io/vuln/npm:moment:20161019"
          ]
        },
        {
          "below": "2.19.3",
          "severity": "high",
          "cwe": [
            "CWE-1333",
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Regular Expression Denial of Service (ReDoS)",
            "CVE": [
              "CVE-2017-18214"
            ],
            "githubID": "GHSA-446m-mv8f-q348"
          },
          "info": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18214",
            "https://github.com/moment/moment/issues/4163",
            "https://security.snyk.io/vuln/npm:moment:20170905"
          ]
        },
        {
          "below": "2.29.2",
          "severity": "high",
          "cwe": [
            "CWE-22",
            "CWE-27"
          ],
          "identifiers": {
            "summary": "This vulnerability impacts npm (server) users of moment.js, especially if user provided locale string, eg fr is directly used to switch moment locale.",
            "CVE": [
              "CVE-2022-24785"
            ],
            "githubID": "GHSA-8hfj-j24r-96c4"
          },
          "info": [
            "https://github.com/moment/moment/security/advisories/GHSA-8hfj-j24r-96c4"
          ]
        },
        {
          "atOrAbove": "2.18.0",
          "below": "2.29.4",
          "severity": "high",
          "cwe": [
            "CWE-1333",
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Regular Expression Denial of Service (ReDoS), Affecting moment package, versions >=2.18.0 <2.29.4",
            "CVE": [
              "CVE-2022-31129"
            ],
            "githubID": "GHSA-wc69-rhjr-hc9g"
          },
          "info": [
            "https://github.com/moment/moment/security/advisories/GHSA-wc69-rhjr-hc9g",
            "https://security.snyk.io/vuln/SNYK-JS-MOMENT-2944238"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/moment\\.js/(§§version§§)/moment(.min)?\\.js"
        ],
        "filename": [
          "moment(?:-|\\.)(§§version§§)(?:-min)?\\.js"
        ],
        "func": [
          "moment.version"
        ],
        "filecontent": [
          "//!? moment.js(?:[\n\r]+)//!? version : (§§version§§)",
          "/\\* Moment.js +\\| +version : (§§version§§) \\|",
          "\\.version=\"(§§version§§)\".{20,60}\"isBefore\".{20,60}\"isAfter\".{200,500}\\.isMoment=",
          "\\.version=\"(§§version§§)\".{20,300}duration.{2,100}\\.isMoment=",
          "\\.isMoment\\(.{50,400}_isUTC.{50,400}=\"(§§version§§)\"",
          "=\"(§§version§§)\".{300,1000}Years:31536e6.{60,80}\\.isMoment",
          "// Moment.js is freely distributable under the terms of the MIT license.[\\s]+//[\\s]+// Version (§§version§§)"
        ],
        "ast": [
          "//SequenceExpression[       /AssignmentExpression[         /:left/:property/:name == \"isMoment\"       ]/:left/$:object ==        /AssignmentExpression[         /:left/:property/:name == \"version\"       ]/:left/$:object     ]/AssignmentExpression[       /:left/:property/:name == \"version\"     ]/$$:right/:value",
          "//BlockStatement[         //AssignmentExpression[/:left/:property/:name == \"moment\"]/:$right ==         /*/SequenceExpression/AssignmentExpression[/:left/:property/:name == \"version\"]/:left/$:object       ]/*/SequenceExpression/AssignmentExpression[/:left/:property/:name == \"version\"]/:$right/:init/:value"
        ]
      }
    },
    "underscore.js": {
      "bowername": [
        "Underscore",
        "underscore"
      ],
      "npmname": "underscore",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "1.3.2",
          "below": "1.12.1",
          "severity": "high",
          "cwe": [
            "CWE-94"
          ],
          "identifiers": {
            "summary": " vulnerable to Arbitrary Code Injection via the template function",
            "CVE": [
              "CVE-2021-23358"
            ],
            "githubID": "GHSA-cf4h-3jhx-xvhq"
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-23358"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/underscore\\.js/(§§version§§)/underscore(-min)?\\.js"
        ],
        "func": [
          "underscore.version"
        ],
        "filecontent": [
          "//[\\s]*Underscore.js (§§version§§)",
          "// *Underscore\\.js[\\s\\S]{1,2500}_\\.VERSION *= *['\"](§§version§§)['\"]"
        ]
      }
    },
    "bootstrap": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "2.1.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "cross-site scripting vulnerability",
            "issue": "3421"
          },
          "info": [
            "https://github.com/twbs/bootstrap/pull/3421"
          ]
        },
        {
          "below": "3.4.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "In Bootstrap before 3.4.0, XSS is possible in the tooltip data-viewport attribute.",
            "issue": "27044",
            "CVE": [
              "CVE-2018-20676"
            ],
            "githubID": "GHSA-3mgp-fx93-9xv5"
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-20676"
          ]
        },
        {
          "below": "3.4.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS in data-container property of tooltip",
            "issue": "20184",
            "CVE": [
              "CVE-2018-14042"
            ],
            "githubID": "GHSA-7mvr-5x2g-wfc8"
          },
          "info": [
            "https://github.com/twbs/bootstrap/issues/20184"
          ]
        },
        {
          "below": "3.4.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "In Bootstrap before 3.4.0, XSS is possible in the affix configuration target property.",
            "CVE": [
              "CVE-2018-20677"
            ],
            "githubID": "GHSA-ph58-4vrj-w6hr"
          },
          "info": [
            "https://github.com/advisories/GHSA-ph58-4vrj-w6hr"
          ]
        },
        {
          "below": "3.4.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS in data-target property of scrollspy",
            "issue": "20184",
            "CVE": [
              "CVE-2018-14041"
            ],
            "githubID": "GHSA-pj7m-g53m-7638"
          },
          "info": [
            "https://github.com/advisories/GHSA-pj7m-g53m-7638",
            "https://github.com/twbs/bootstrap/issues/20184"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.4.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS is possible in the data-target attribute.",
            "CVE": [
              "CVE-2016-10735"
            ],
            "githubID": "GHSA-4p24-vmcr-4gqj"
          },
          "info": [
            "https://github.com/advisories/GHSA-4p24-vmcr-4gqj"
          ]
        },
        {
          "atOrAbove": "1.4.0",
          "below": "3.4.1",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Bootstrap Cross-Site Scripting (XSS) vulnerability for data-* attributes",
            "CVE": [
              "CVE-2024-6485"
            ],
            "githubID": "GHSA-vxmc-5x29-h64v"
          },
          "info": [
            "https://github.com/advisories/GHSA-vxmc-5x29-h64v",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6485",
            "https://github.com/twbs/bootstrap",
            "https://www.herodevs.com/vulnerability-directory/cve-2024-6485"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.4.1",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS in data-template, data-content and data-title properties of tooltip/popover",
            "issue": "28236",
            "CVE": [
              "CVE-2019-8331"
            ],
            "githubID": "GHSA-9v3m-8fp8-mj99"
          },
          "info": [
            "https://github.com/advisories/GHSA-9v3m-8fp8-mj99",
            "https://github.com/twbs/bootstrap/issues/28236"
          ]
        },
        {
          "atOrAbove": "2.0.0",
          "below": "3.4.2",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Bootstrap Cross-Site Scripting (XSS) vulnerability",
            "CVE": [
              "CVE-2024-6484"
            ],
            "githubID": "GHSA-9mvj-f7w8-pvh2"
          },
          "info": [
            "https://github.com/advisories/GHSA-9mvj-f7w8-pvh2",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6484",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/bootstrap-sass/CVE-2024-6484.yml",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/bootstrap/CVE-2024-6484.yml",
            "https://github.com/twbs/bootstrap",
            "https://www.herodevs.com/vulnerability-directory/cve-2024-6484"
          ]
        },
        {
          "below": "3.999.999",
          "severity": "low",
          "cwe": [
            "CWE-1104"
          ],
          "identifiers": {
            "summary": "Bootstrap before 4.0.0 is end-of-life and no longer maintained.",
            "retid": "72"
          },
          "info": [
            "https://github.com/twbs/bootstrap/issues/20631"
          ]
        },
        {
          "atOrAbove": "4.0.0-beta",
          "below": "4.0.0-beta.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS is possible in the data-target attribute.",
            "CVE": [
              "CVE-2016-10735"
            ],
            "githubID": "GHSA-4p24-vmcr-4gqj"
          },
          "info": [
            "https://github.com/advisories/GHSA-4p24-vmcr-4gqj"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.1.2",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS in collapse data-parent attribute",
            "issue": "20184",
            "CVE": [
              "CVE-2018-14040"
            ],
            "githubID": "GHSA-3wqf-4x89-9g79"
          },
          "info": [
            "https://github.com/twbs/bootstrap/issues/20184"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.1.2",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS in data-container property of tooltip",
            "issue": "20184",
            "CVE": [
              "CVE-2018-14042"
            ],
            "githubID": "GHSA-7mvr-5x2g-wfc8"
          },
          "info": [
            "https://github.com/twbs/bootstrap/issues/20184"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.1.2",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS in data-target property of scrollspy",
            "issue": "20184",
            "CVE": [
              "CVE-2018-14041"
            ],
            "githubID": "GHSA-pj7m-g53m-7638"
          },
          "info": [
            "https://github.com/advisories/GHSA-pj7m-g53m-7638",
            "https://github.com/twbs/bootstrap/issues/20184"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.3.1",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS in data-template, data-content and data-title properties of tooltip/popover",
            "issue": "28236",
            "CVE": [
              "CVE-2019-8331"
            ],
            "githubID": "GHSA-9v3m-8fp8-mj99"
          },
          "info": [
            "https://github.com/advisories/GHSA-9v3m-8fp8-mj99",
            "https://github.com/twbs/bootstrap/issues/28236"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "5.0.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Bootstrap Cross-Site Scripting (XSS) vulnerability",
            "CVE": [
              "CVE-2024-6531"
            ],
            "githubID": "GHSA-vc8w-jr9v-vj7f"
          },
          "info": [
            "https://github.com/advisories/GHSA-vc8w-jr9v-vj7f",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6531",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/bootstrap/CVE-2024-6531.yml",
            "https://github.com/twbs/bootstrap",
            "https://www.herodevs.com/vulnerability-directory/cve-2024-6531"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/(§§version§§)/bootstrap(\\.min)?\\.js",
          "/(§§version§§)/js/bootstrap(\\.min)?\\.js"
        ],
        "filename": [
          "bootstrap-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "/\\*!? Bootstrap v(§§version§§)",
          "\\* Bootstrap v(§§version§§)",
          "/\\*! Bootstrap v(§§version§§)",
          "this\\.close\\)\\};.\\.VERSION=\"(§§version§§)\"(?:,.\\.TRANSITION_DURATION=150)?,.\\.prototype\\.close"
        ],
        "hashes": {}
      }
    },
    "bootstrap-select": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.13.6",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-site Scripting (XSS) via title and data-content",
            "CVE": [
              "CVE-2019-20921"
            ],
            "githubID": "GHSA-7c82-mp33-r854"
          },
          "info": [
            "https://github.com/snapappointments/bootstrap-select/issues/2199#issuecomment-701806876"
          ]
        },
        {
          "below": "1.13.6",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-Site Scripting in bootstrap-select",
            "githubID": "GHSA-9r7h-6639-v5mw",
            "CVE": [
              "CVE-2019-20921"
            ]
          },
          "info": [
            "https://github.com/snapappointments/bootstrap-select/issues/2199"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/bootstrap-select/(§§version§§)/"
        ],
        "filecontent": [
          "/\\*![\\s]+\\*[\\s]+Bootstrap-select[\\s]+v(§§version§§)",
          ".\\.data\\(\"selectpicker\",.=new .\\(this,.\\)\\)\\}\"string\"==typeof .&&\\(.=.\\[.\\]instanceof Function\\?.\\[.\\]\\.apply\\(.,.\\):.\\.options\\[.\\]\\)\\}\\}\\);return void 0!==.\\?.:.\\}.\\.VERSION=\"(§§version§§)\","
        ]
      }
    },
    "ckeditor": {
      "licenses": [
        "(GPL-2.0 OR LGPL-2.1 OR MPL-1.1) >=0"
      ],
      "vulnerabilities": [
        {
          "below": "4.4.3",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS",
            "retid": "13"
          },
          "info": [
            "https://github.com/ckeditor/ckeditor-dev/blob/master/CHANGES.md#ckeditor-443"
          ]
        },
        {
          "below": "4.4.6",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS",
            "retid": "14"
          },
          "info": [
            "https://github.com/ckeditor/ckeditor-dev/blob/master/CHANGES.md#ckeditor-446"
          ]
        },
        {
          "below": "4.4.8",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS",
            "retid": "15"
          },
          "info": [
            "https://github.com/ckeditor/ckeditor-dev/blob/master/CHANGES.md#ckeditor-448"
          ]
        },
        {
          "below": "4.5.11",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS",
            "retid": "16"
          },
          "info": [
            "https://github.com/ckeditor/ckeditor-dev/blob/master/CHANGES.md#ckeditor-4511"
          ]
        },
        {
          "atOrAbove": "4.5.11",
          "below": "4.9.2",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS if the enhanced image plugin is installed",
            "retid": "17"
          },
          "info": [
            "https://ckeditor.com/blog/CKEditor-4.9.2-with-a-security-patch-released/",
            "https://ckeditor.com/cke4/release-notes"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.11.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS vulnerability in the HTML parser",
            "retid": "18",
            "CVE": [
              "CVE-2018-17960"
            ],
            "githubID": "GHSA-g68x-vvqq-pvw3"
          },
          "info": [
            "https://ckeditor.com/blog/CKEditor-4.11-with-emoji-dropdown-and-auto-link-on-typing-released/",
            "https://snyk.io/vuln/SNYK-JS-CKEDITOR-72618"
          ]
        },
        {
          "below": "4.14.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "XSS",
            "retid": "20"
          },
          "info": [
            "https://github.com/ckeditor/ckeditor4/blob/major/CHANGES.md#ckeditor-414"
          ]
        },
        {
          "below": "4.15.1",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS-type attack inside CKEditor 4 by persuading a victim to paste a specially crafted HTML code into the Color Button dialog",
            "retid": "19"
          },
          "info": [
            "https://github.com/ckeditor/ckeditor4/blob/major/CHANGES.md#ckeditor-4151"
          ]
        },
        {
          "below": "4.16.0",
          "cwe": [
            "CWE-1333"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "ReDoS vulnerability in Autolink plugin and Advanced Tab for Dialogs plugin",
            "retid": "21"
          },
          "info": [
            "https://ckeditor.com/cke4/release/CKEditor-4.16.0"
          ]
        },
        {
          "below": "4.16.2",
          "cwe": [
            "CWE-79"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "XSS vulnerability in the Widget plugin",
            "CVE": [
              "CVE-2021-32808"
            ]
          },
          "info": [
            "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-6226-h7ff-ch6c"
          ]
        },
        {
          "below": "4.16.2",
          "cwe": [
            "CWE-79"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "XSS vulnerability in the Clipboard plugin",
            "CVE": [
              "CVE-2021-32809"
            ]
          },
          "info": [
            "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-7889-rm5j-hpgg"
          ]
        },
        {
          "below": "4.16.2",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS vulnerability in the Fake Objects plugin",
            "CVE": [
              "CVE-2021-37695"
            ]
          },
          "info": [
            "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-m94c-37g6-cjhc"
          ]
        },
        {
          "below": "4.17.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "XSS vulnerabilities in the core module",
            "CVE": [
              "CVE-2021-41164",
              "CVE-2021-41165"
            ]
          },
          "info": [
            "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-7h26-63m7-qhf2",
            "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-pvmx-g8h5-cprj"
          ]
        },
        {
          "below": "4.18.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Inject malformed URL to bypass content sanitization for XSS",
            "CVE": [
              "CVE-2022-24728"
            ]
          },
          "info": [
            "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-f6rf-9m92-x2hh"
          ]
        },
        {
          "below": "4.21.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "cross-site scripting vulnerability has been discovered affecting Iframe Dialog and Media Embed packages. The vulnerability may trigger a JavaScript code",
            "CVE": [
              "CVE-2023-28439"
            ]
          },
          "info": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28439",
            "https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-vh5c-xwqv-cv9g",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-28439"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/(§§version§§)/ckeditor(\\.min)?\\.js"
        ],
        "filename": [
          "ckeditor-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "ckeditor..js.{4,30}=\\{timestamp:\"[^\"]+\",version:\"(§§version§§)",
          "window\\.CKEDITOR=function\\(\\)\\{var [a-z]=\\{timestamp:\"[^\"]+\",version:\"(§§version§§)"
        ],
        "hashes": {},
        "func": [
          "CKEDITOR.version"
        ]
      }
    },
    "ckeditor5": {
      "licenses": [
        "GPL-2.0 >=0.0.0-nightly-20230629.0 <0.0.1-security; >=10.0.0-rc.1",
        "ISC >=0.0.1-security <10.0.0-rc.1"
      ],
      "vulnerabilities": [
        {
          "below": "10.0.1",
          "cwe": [
            "CWE-79"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "XSS in the link package",
            "CVE": [
              "CVE-2018-11093"
            ]
          },
          "info": [
            "https://ckeditor.com/blog/CKEditor-5-v10.0.1-released/"
          ]
        },
        {
          "below": "25.0.0",
          "cwe": [
            "CWE-1333"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "ReDos in several packages",
            "CVE": [
              "CVE-2021-21254"
            ]
          },
          "info": [
            "https://github.com/ckeditor/ckeditor5/security/advisories/GHSA-hgmg-hhc8-g5wr"
          ]
        },
        {
          "below": "27.0.0",
          "cwe": [
            "CWE-1333"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "ReDos in several packages",
            "CVE": [
              "CVE-2021-21391"
            ]
          },
          "info": [
            "https://github.com/ckeditor/ckeditor5/security/advisories/GHSA-3rh3-wfr4-76mj"
          ]
        },
        {
          "below": "35.0.0",
          "cwe": [
            "CWE-79"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "security fix for the Markdown GFM, HTML support and HTML embed packages",
            "CVE": [
              "CVE-2022-31175"
            ]
          },
          "info": [
            "https://github.com/ckeditor/ckeditor5/compare/v34.2.0...v35.0.0",
            "https://github.com/ckeditor/ckeditor5/security/advisories/GHSA-42wq-rch8-6f6j"
          ]
        },
        {
          "atOrAbove": "40.0.0",
          "below": "43.1.1",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Cross-site scripting (XSS) in the clipboard package",
            "CVE": [
              "CVE-2024-45613"
            ],
            "githubID": "GHSA-rgg8-g5x8-wr9v"
          },
          "info": [
            "https://github.com/advisories/GHSA-rgg8-g5x8-wr9v",
            "https://github.com/ckeditor/ckeditor5/security/advisories/GHSA-rgg8-g5x8-wr9v",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-45613",
            "https://github.com/ckeditor/ckeditor5",
            "https://github.com/ckeditor/ckeditor5/releases/tag/v43.1.1"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/(§§version§§)/ckeditor5(\\.min)?\\.js"
        ],
        "filename": [
          "ckeditor5-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "const .=\"(§§version§§)\";.{0,140}?\\.CKEDITOR_VERSION=.;",
          "CKEDITOR_VERSION=\"(§§version§§)\""
        ],
        "hashes": {},
        "func": [
          "CKEDITOR_VERSION"
        ]
      }
    },
    "vue": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "2.4.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "possible xss vector",
            "retid": "12"
          },
          "info": [
            "https://github.com/vuejs/vue/releases/tag/v2.4.3"
          ]
        },
        {
          "below": "2.5.17",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "potential xss in ssr when using v-bind",
            "retid": "11"
          },
          "info": [
            "https://github.com/vuejs/vue/releases/tag/v2.5.17"
          ]
        },
        {
          "below": "2.6.11",
          "severity": "medium",
          "cwe": [
            "CWE-94"
          ],
          "identifiers": {
            "summary": "Bump vue-server-renderer's dependency of serialize-javascript to 2.1.2",
            "retid": "10"
          },
          "info": [
            "https://github.com/vuejs/vue/releases/tag/v2.6.11"
          ]
        },
        {
          "atOrAbove": "2.0.0-alpha.1",
          "below": "3.0.0-alpha.0",
          "cwe": [
            "CWE-1333"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "ReDoS vulnerability in vue package that is exploitable through inefficient regex evaluation in the parseHTML function",
            "CVE": [
              "CVE-2024-9506"
            ],
            "githubID": "GHSA-5j4c-8p2g-v4jx"
          },
          "info": [
            "https://github.com/advisories/GHSA-5j4c-8p2g-v4jx",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-9506",
            "https://github.com/vuejs/core",
            "https://www.herodevs.com/vulnerability-directory/cve-2024-9506"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/vue@(§§version§§)/dist/vue\\.js",
          "/vue/(§§version§§)/vue\\..*\\.js",
          "/npm/vue@(§§version§§)"
        ],
        "filename": [
          "vue-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "/\\*!\\n \\* Vue.js v(§§version§§)",
          "/\\*\\*?!?\\n ?\\* vue v(§§version§§)",
          "Vue.version = '(§§version§§)';",
          "'(§§version§§)'[^\\n]{0,8000}Vue compiler",
          "\\* Original file: /npm/vue@(§§version§§)/dist/vue.(global|common).js",
          "const version[ ]*=[ ]*\"(§§version§§)\";[\\s]*/\\*\\*[\\s]*\\* SSR utils for \\\\@vue/server-renderer",
          "\\.__vue_app__=.{0,8000}?const [a-z]+=\"(§§version§§)\",",
          "let [A-Za-z]+=\"(§§version§§)\",..=\"undefined\"!=typeof window&&window.trustedTypes;if\\(..\\)try\\{.=..\\.createPolicy\\(\"vue\",",
          "isCustomElement.{1,5}?compilerOptions.{0,500}exposeProxy.{0,700}\"(§§version§§)\"",
          "\"(§§version§§)\"[\\s\\S]{0,150}\\.createPolicy\\(\"vue\"",
          "devtoolsFormatters[\\s\\S]{50,180}\"(§§version§§)\"[\\s\\S]{50,180}\\.createElement\\(\"template\"\\)"
        ],
        "func": [
          "Vue.version"
        ],
        "ast": [
          "//VariableDeclarator[       /:id/:name == \"Vue\"     ]/CallExpression/FunctionExpression/BlockStatement/ReturnStatement/SequenceExpression/AssignmentExpression[       /:left/:property/:name == \"version\"     ]/$:right/:init/:value     ",
          "//CallExpression[       /:callee//:left/:property/:name == \"Vue\"     ]/:arguments//AssignmentExpression[       /:left/:property/:name == \"version\"     ]/$$:right/:value",
          "//AssignmentExpression[       /:left/:object/:name == \"Vue\" &&       /:left/:property/:name == \"version\"     ]/:right/:value"
        ]
      }
    },
    "ExtJS": {
      "licenses": [
        "GPL-3.0 >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "3.0.0",
          "below": "4.0.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS vulnerability in ExtJS charts.swf",
            "CVE": [
              "CVE-2010-4207",
              "CVE-2012-5881"
            ]
          },
          "info": [
            "https://typo3.org/security/advisory/typo3-core-sa-2014-001/",
            "https://www.acunetix.com/vulnerabilities/web/extjs-charts-swf-cross-site-scripting",
            "https://www.akawebdesign.com/2018/08/14/should-js-frameworks-prevent-xss/"
          ]
        },
        {
          "below": "6.0.0",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Directory traversal and arbitrary file read",
            "CVE": [
              "CVE-2007-2285"
            ]
          },
          "info": [
            "https://packetstormsecurity.com/files/132052/extjs-Arbitrary-File-Read.html",
            "https://www.akawebdesign.com/2018/08/14/should-js-frameworks-prevent-xss/",
            "https://www.cvedetails.com/cve/CVE-2007-2285/"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "6.6.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS in Sencha Ext JS 4 to 6 via getTip() method of Action Columns",
            "CVE": [
              "CVE-2018-8046"
            ]
          },
          "info": [
            "http://seclists.org/fulldisclosure/2018/Jul/8",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-8046"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/extjs/(§§version§§)/.*\\.js"
        ],
        "filename": [
          "/ext-all-(§§version§§)(\\.min)?\\.js",
          "/ext-all-debug-(§§version§§)(\\.min)?\\.js",
          "/ext-base-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "/*!\n * Ext JS Library (§§version§§)",
          "Ext = \\{[\\s]*/\\*[^/]+/[\\s]*version *: *['\"](§§version§§)['\"]",
          "var version *= *['\"](§§version§§)['\"], *Version;[\\s]*Ext.Version *= *Version *= *Ext.extend"
        ],
        "func": [
          "Ext && Ext.versions && Ext.versions.extjs.version",
          "Ext && Ext.version"
        ]
      }
    },
    "svelte": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "2.9.8",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS",
            "retid": "9"
          },
          "info": [
            "https://github.com/sveltejs/svelte/pull/1623"
          ]
        },
        {
          "below": "3.46.5",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS",
            "retid": "8"
          },
          "info": [
            "https://github.com/sveltejs/svelte/pull/7333"
          ]
        },
        {
          "below": "3.49.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS",
            "issue": "7530",
            "githubID": "GHSA-wv8q-r932-8hc7",
            "CVE": [
              "CVE-2022-25875"
            ]
          },
          "info": [
            "https://github.com/sveltejs/svelte/pull/7530"
          ]
        },
        {
          "below": "4.2.19",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Svelte has a potential mXSS vulnerability due to improper HTML escaping",
            "CVE": [
              "CVE-2024-45047"
            ],
            "githubID": "GHSA-8266-84wp-wv5c"
          },
          "info": [
            "https://github.com/advisories/GHSA-8266-84wp-wv5c",
            "https://github.com/sveltejs/svelte/security/advisories/GHSA-8266-84wp-wv5c",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-45047",
            "https://github.com/sveltejs/svelte/commit/83e96e044deb5ecbae2af361ae9e31d3e1ac43a3",
            "https://github.com/sveltejs/svelte"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/svelte@(§§version§§)/"
        ],
        "filename": [
          "svelte[@\\-](§§version§§)(.min)?\\.m?js"
        ],
        "filecontent": [
          "generated by Svelte v\\$\\{['\"](§§version§§)['\"]\\}",
          "generated by Svelte v(§§version§§) \\*/",
          "version: '(§§version§§)' [\\s\\S]{80,200}'SvelteDOMInsert'",
          "VERSION = '(§§version§§)'[\\s\\S]{21,200}parse\\$[0-9][\\s\\S]{10,80}preprocess",
          "var version\\$[0-9] = \"(§§version§§)\";[\\s\\S]{10,30}normalizeOptions\\(options\\)[\\s\\S]{80,200}'SvelteComponent.html'"
        ],
        "func": [
          "svelte.VERSION"
        ]
      }
    },
    "axios": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "0.18.1",
          "severity": "high",
          "cwe": [
            "CWE-20",
            "CWE-755"
          ],
          "identifiers": {
            "summary": "Axios up to and including 0.18.0 allows attackers to cause a denial of service (application crash) by continuing to accepting content after maxContentLength is exceeded",
            "CVE": [
              "CVE-2019-10742"
            ],
            "githubID": "GHSA-42xw-2xvc-qx8m"
          },
          "info": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10742",
            "https://security.snyk.io/vuln/SNYK-JS-AXIOS-174505"
          ]
        },
        {
          "below": "0.21.1",
          "severity": "medium",
          "cwe": [
            "CWE-918"
          ],
          "identifiers": {
            "summary": "Axios NPM package 0.21.0 contains a Server-Side Request Forgery (SSRF) vulnerability",
            "CVE": [
              "CVE-2020-28168"
            ],
            "githubID": "GHSA-4w2v-q235-vp99"
          },
          "info": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28168",
            "https://security.snyk.io/vuln/SNYK-JS-AXIOS-1038255"
          ]
        },
        {
          "below": "0.21.2",
          "severity": "high",
          "cwe": [
            "CWE-1333",
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Axios is vulnerable to Inefficient Regular Expression Complexity",
            "CVE": [
              "CVE-2021-3749"
            ],
            "githubID": "GHSA-cph5-m8f7-6c5x"
          },
          "info": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3749",
            "https://security.snyk.io/vuln/SNYK-JS-AXIOS-1579269"
          ]
        },
        {
          "atOrAbove": "0.8.1",
          "below": "0.28.0",
          "cwe": [
            "CWE-352"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Axios Cross-Site Request Forgery Vulnerability",
            "CVE": [
              "CVE-2023-45857"
            ],
            "githubID": "GHSA-wf5p-g6vw-rhxx"
          },
          "info": [
            "https://github.com/advisories/GHSA-wf5p-g6vw-rhxx",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45857",
            "https://github.com/axios/axios/issues/6006",
            "https://github.com/axios/axios/issues/6022",
            "https://github.com/axios/axios/pull/6028",
            "https://github.com/axios/axios/commit/96ee232bd3ee4de2e657333d4d2191cd389e14d0",
            "https://github.com/axios/axios/releases/tag/v1.6.0",
            "https://security.snyk.io/vuln/SNYK-JS-AXIOS-6032459"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "0.30.0",
          "cwe": [
            "CWE-918"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL",
            "CVE": [
              "CVE-2025-27152"
            ],
            "githubID": "GHSA-jr5f-v2jv-69x6"
          },
          "info": [
            "https://github.com/advisories/GHSA-jr5f-v2jv-69x6",
            "https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-27152",
            "https://github.com/axios/axios/issues/6463",
            "https://github.com/axios/axios/commit/fb8eec214ce7744b5ca787f2c3b8339b2f54b00f",
            "https://github.com/axios/axios",
            "https://github.com/axios/axios/releases/tag/v1.8.2"
          ]
        },
        {
          "atOrAbove": "1.0.0",
          "below": "1.6.0",
          "cwe": [
            "CWE-352"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Axios Cross-Site Request Forgery Vulnerability",
            "CVE": [
              "CVE-2023-45857"
            ],
            "githubID": "GHSA-wf5p-g6vw-rhxx"
          },
          "info": [
            "https://github.com/advisories/GHSA-wf5p-g6vw-rhxx",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45857",
            "https://github.com/axios/axios/issues/6006",
            "https://github.com/axios/axios/issues/6022",
            "https://github.com/axios/axios/pull/6028",
            "https://github.com/axios/axios/commit/96ee232bd3ee4de2e657333d4d2191cd389e14d0",
            "https://github.com/axios/axios/releases/tag/v1.6.0",
            "https://security.snyk.io/vuln/SNYK-JS-AXIOS-6032459"
          ]
        },
        {
          "below": "1.6.8",
          "severity": "medium",
          "cwe": [
            "CWE-200"
          ],
          "identifiers": {
            "summary": "Versions before 1.6.8 depends on follow-redirects before 1.15.6 which could leak the proxy authentication credentials",
            "PR": "6300"
          },
          "info": [
            "https://github.com/axios/axios/pull/6300"
          ]
        },
        {
          "atOrAbove": "1.3.2",
          "below": "1.7.4",
          "cwe": [
            "CWE-918"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Server-Side Request Forgery in axios",
            "CVE": [
              "CVE-2024-39338"
            ],
            "githubID": "GHSA-8hc4-vh64-cxmj"
          },
          "info": [
            "https://github.com/advisories/GHSA-8hc4-vh64-cxmj",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-39338",
            "https://github.com/axios/axios/issues/6463",
            "https://github.com/axios/axios/pull/6539",
            "https://github.com/axios/axios/pull/6543",
            "https://github.com/axios/axios/commit/6b6b605eaf73852fb2dae033f1e786155959de3a",
            "https://github.com/axios/axios",
            "https://github.com/axios/axios/releases",
            "https://github.com/axios/axios/releases/tag/v1.7.4",
            "https://jeffhacks.com/advisories/2024/06/24/CVE-2024-39338.html"
          ]
        },
        {
          "atOrAbove": "1.0.0",
          "below": "1.8.2",
          "cwe": [
            "CWE-918"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL",
            "CVE": [
              "CVE-2025-27152"
            ],
            "githubID": "GHSA-jr5f-v2jv-69x6"
          },
          "info": [
            "https://github.com/advisories/GHSA-jr5f-v2jv-69x6",
            "https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-27152",
            "https://github.com/axios/axios/issues/6463",
            "https://github.com/axios/axios/commit/fb8eec214ce7744b5ca787f2c3b8339b2f54b00f",
            "https://github.com/axios/axios",
            "https://github.com/axios/axios/releases/tag/v1.8.2"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/axios/(§§version§§)/.*\\.js"
        ],
        "filename": [
          "axios-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "/\\*!? *[Aa]xios v(§§version§§) ",
          "// Axios v(§§version§§) C",
          "return\"\\[Axios v(§§version§§)\\] Transitional",
          "\\\"axios\\\",\\\"version\\\":\\\"(§§version§§)\\\""
        ],
        "func": [
          "axios && axios.VERSION"
        ],
        "ast": [
          "//AssignmentExpression[       /:left/:object/:name == \"axios\" &&       /:left/:property/:name == \"VERSION\"     ]/$$:right/:value",
          "//SequenceExpression[       /AssignmentExpression[         /:left/:property/:name == \"AxiosError\"       ]/:left/$:object ==       /AssignmentExpression[         /:left/:property/:name == \"VERSION\"       ]/:left/$:object     ]/AssignmentExpression[       /:left/:property/:name == \"VERSION\"     ]/$$:right/:value"
        ]
      }
    },
    "markdown-it": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "3.0.0",
          "severity": "high",
          "cwe": [
            "CWE-1333"
          ],
          "identifiers": {
            "summary": "Cross-site Scripting (XSS)",
            "CVE": [
              "CVE-2015-10005"
            ],
            "githubID": "GHSA-j5p7-jf4q-742q"
          },
          "info": [
            "https://nvd.nist.gov/vuln/detail/CVE-2015-10005"
          ]
        },
        {
          "below": "4.1.0",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-site Scripting (XSS)",
            "CVE": [
              "CVE-2015-3295"
            ]
          },
          "info": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=2015-3295",
            "https://github.com/markdown-it/markdown-it/blob/master/CHANGELOG.md",
            "https://security.snyk.io/vuln/npm:markdown-it:20160912"
          ]
        },
        {
          "atOrAbove": "4.0.0",
          "below": "4.3.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-site Scripting (XSS)",
            "retid": "7"
          },
          "info": [
            "https://github.com/markdown-it/markdown-it/blob/master/CHANGELOG.md",
            "https://security.snyk.io/vuln/npm:markdown-it:20150702"
          ]
        },
        {
          "below": "10.0.0",
          "severity": "medium",
          "cwe": [
            "CWE-1333"
          ],
          "identifiers": {
            "summary": "Regular Expression Denial of Service (ReDoS)",
            "retid": "6"
          },
          "info": [
            "https://github.com/markdown-it/markdown-it/blob/master/CHANGELOG.md",
            "https://security.snyk.io/vuln/SNYK-JS-MARKDOWNIT-459438"
          ]
        },
        {
          "below": "12.3.2",
          "severity": "medium",
          "cwe": [
            "CWE-1333",
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Regular Expression Denial of Service (ReDoS)",
            "CVE": [
              "CVE-2022-21670"
            ],
            "githubID": "GHSA-6vfc-qv3f-vr6c"
          },
          "info": [
            "https://github.com/markdown-it/markdown-it/blob/master/CHANGELOG.md",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-21670",
            "https://security.snyk.io/vuln/SNYK-JS-MARKDOWNIT-2331914"
          ]
        },
        {
          "below": "13.0.2",
          "severity": "medium",
          "cwe": [
            "CWE-400"
          ],
          "identifiers": {
            "summary": "Fixed crash/infinite loop caused by linkify inline rule",
            "issue": "957"
          },
          "info": [
            "https://github.com/markdown-it/markdown-it/issues/957",
            "https://github.com/markdown-it/markdown-it/compare/13.0.1...13.0.2"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/markdown-it[/@](§§version§§)/?.*\\.js"
        ],
        "filename": [
          "markdown-it-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "/\\*! markdown-it(?:-ins)? (§§version§§)"
        ],
        "func": []
      }
    },
    "jszip": {
      "licenses": [
        "(GPL-3.0 OR MIT) >=0.1.1",
        "MIT >=0.1.0 <0.1.1"
      ],
      "vulnerabilities": [
        {
          "below": "2.7.0",
          "severity": "medium",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype Pollution",
            "CVE": [
              "CVE-2021-23413"
            ],
            "githubID": "GHSA-jg8v-48h5-wgxg"
          },
          "info": [
            "https://github.com/advisories/GHSA-jg8v-48h5-wgxg",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-23413",
            "https://security.snyk.io/vuln/SNYK-JS-JSZIP-1251497"
          ]
        },
        {
          "atOrAbove": "3.0.0",
          "below": "3.7.0",
          "severity": "medium",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "Prototype Pollution",
            "CVE": [
              "CVE-2021-23413"
            ],
            "githubID": "GHSA-jg8v-48h5-wgxg"
          },
          "info": [
            "https://github.com/advisories/GHSA-jg8v-48h5-wgxg",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-23413",
            "https://security.snyk.io/vuln/SNYK-JS-JSZIP-1251497"
          ]
        },
        {
          "below": "3.8.0",
          "severity": "medium",
          "cwe": [
            "CWE-22"
          ],
          "identifiers": {
            "summary": "Santize filenames when files are loaded with loadAsync, to avoid “zip slip” attacks.",
            "retid": "5",
            "CVE": [
              "CVE-2022-48285"
            ],
            "githubID": "GHSA-36fh-84j7-cv5h"
          },
          "info": [
            "https://stuk.github.io/jszip/CHANGES.html"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/jszip[/@](§§version§§)/.*\\.js"
        ],
        "filename": [
          "jszip-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "/\\*![\\s]+JSZip v(§§version§§) "
        ],
        "func": [
          "JSZip && JSZip.version"
        ]
      }
    },
    "AlaSQL": {
      "npmname": "alasql",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "0.7.0",
          "severity": "high",
          "cwe": [
            "CWE-94"
          ],
          "identifiers": {
            "summary": "An arbitrary code execution exists as AlaSQL doesn't sanitize input when characters are placed between square brackets [] or preceded with a backtik (accent grave) ` character. Versions older that 0.7.0 were deprecated in March of 2021 and should no longer be used.",
            "bug": "SNYK-JS-ALASQL-1082932"
          },
          "info": [
            "https://security.snyk.io/vuln/SNYK-JS-ALASQL-1082932"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/alasql[/@](§§version§§)/.*\\.js"
        ],
        "filename": [
          "alasql-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "/\\*!?[ \n]*AlaSQL v(§§version§§)"
        ],
        "func": [
          "alasql && alasql.version"
        ]
      }
    },
    "jquery.datatables": {
      "npmname": "datatables.net",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "1.10.10",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS",
            "CVE": [
              "CVE-2015-6584"
            ]
          },
          "info": [
            "https://github.com/DataTables/DataTablesSrc/commit/ccf86dc5982bd8e16d",
            "https://github.com/advisories/GHSA-4mv4-gmmf-q382",
            "https://www.invicti.com/web-applications-advisories/cve-2015-6384-xss-vulnerability-identified-in-datatables/"
          ]
        },
        {
          "below": "1.10.22",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "datatables.net vulnerable to Prototype Pollution due to incomplete fix",
            "CVE": [
              "CVE-2020-28458"
            ],
            "githubID": "GHSA-m7j4-fhg6-xf5v"
          },
          "info": [
            "https://github.com/advisories/GHSA-m7j4-fhg6-xf5v"
          ]
        },
        {
          "below": "1.10.22",
          "severity": "medium",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "prototype pollution",
            "retid": "4"
          },
          "info": [
            "https://cdn.datatables.net/1.10.22/"
          ]
        },
        {
          "below": "1.10.23",
          "severity": "high",
          "cwe": [
            "CWE-1321"
          ],
          "identifiers": {
            "summary": "prototype pollution",
            "retid": "3"
          },
          "info": [
            "https://cdn.datatables.net/1.10.23/",
            "https://github.com/DataTables/DataTablesSrc/commit/a51cbe99fd3d02aa5582f97d4af1615d11a1ea03"
          ]
        },
        {
          "below": "1.11.3",
          "severity": "low",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "possible XSS",
            "retid": "2"
          },
          "info": [
            "https://cdn.datatables.net/1.11.3/",
            "https://github.com/DataTables/Dist-DataTables/commit/59a8d3f8a3c1138ab08704e783bc52bfe88d7c9b"
          ]
        },
        {
          "below": "1.11.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross site scripting in datatables.net",
            "CVE": [
              "CVE-2021-23445"
            ],
            "githubID": "GHSA-h73q-5wmj-q8pj"
          },
          "info": [
            "https://github.com/advisories/GHSA-h73q-5wmj-q8pj"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/(§§version§§)/(js/)?(jquery.)?dataTables(.min)?.js"
        ],
        "filename": [
          "jquery.dataTables-(§§version§§)(\\.min)?\\.js"
        ],
        "filecontent": [
          "http://www.datatables.net\n +DataTables (§§version§§)",
          "/\\*! DataTables (§§version§§)",
          ".\\.version=\"(§§version§§)\";[\\s]*.\\.settings=\\[\\];[\\s]*.\\.models=\\{[\\s]*\\};[\\s]*.\\.models.oSearch"
        ],
        "func": [
          "DataTable && DataTable.version"
        ]
      }
    },
    "nextjs": {
      "npmname": "next",
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "1.0.0",
          "below": "2.4.1",
          "severity": "high",
          "cwe": [
            "CWE-22"
          ],
          "identifiers": {
            "summary": "Next.js Directory Traversal Vulnerability",
            "CVE": [
              "CVE-2017-16877"
            ],
            "githubID": "GHSA-3f5c-4qxj-vmpf"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-3f5c-4qxj-vmpf"
          ]
        },
        {
          "atOrAbove": "1.0.0",
          "below": "4.2.3",
          "cwe": [
            "CWE-22"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Directory traversal vulnerability in Next.js",
            "CVE": [
              "CVE-2018-6184"
            ],
            "githubID": "GHSA-m34x-wgrh-g897"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-m34x-wgrh-g897"
          ]
        },
        {
          "atOrAbove": "0.9.9",
          "below": "5.1.0",
          "cwe": [
            "CWE-20"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Remote Code Execution in next",
            "githubID": "GHSA-5vj8-3v2h-h38v"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-5vj8-3v2h-h38v"
          ]
        },
        {
          "atOrAbove": "7.0.0",
          "below": "7.0.2",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Next.js has cross site scripting (XSS) vulnerability via the 404 or 500 /_error page",
            "CVE": [
              "CVE-2018-18282"
            ],
            "githubID": "GHSA-qw96-mm2g-c8m7"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-qw96-mm2g-c8m7"
          ]
        },
        {
          "below": "9.3.2",
          "severity": "medium",
          "cwe": [
            "CWE-23"
          ],
          "identifiers": {
            "summary": "Directory Traversal in Next.js",
            "CVE": [
              "CVE-2020-5284"
            ],
            "githubID": "GHSA-fq77-7p7r-83rj"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-fq77-7p7r-83rj"
          ]
        },
        {
          "atOrAbove": "9.5.0",
          "below": "9.5.4",
          "severity": "medium",
          "cwe": [
            "CWE-601"
          ],
          "identifiers": {
            "summary": "Open Redirect in Next.js",
            "CVE": [
              "CVE-2020-15242"
            ],
            "githubID": "GHSA-x56p-c8cg-q435"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-x56p-c8cg-q435"
          ]
        },
        {
          "atOrAbove": "0.9.9",
          "below": "11.1.0",
          "severity": "medium",
          "cwe": [
            "CWE-601"
          ],
          "identifiers": {
            "summary": "Open Redirect in Next.js",
            "CVE": [
              "CVE-2021-37699"
            ],
            "githubID": "GHSA-vxf5-wxwp-m7g9"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-vxf5-wxwp-m7g9"
          ]
        },
        {
          "atOrAbove": "10.0.0",
          "below": "11.1.1",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS in Image Optimization API",
            "CVE": [
              "CVE-2021-39178"
            ],
            "githubID": "GHSA-9gr3-7897-pp7m"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-9gr3-7897-pp7m"
          ]
        },
        {
          "atOrAbove": "0.9.9",
          "below": "11.1.3",
          "severity": "high",
          "cwe": [
            "CWE-20"
          ],
          "identifiers": {
            "summary": "Unexpected server crash in Next.js versions",
            "CVE": [
              "CVE-2021-43803"
            ],
            "githubID": "GHSA-25mp-g6fv-mqxx"
          },
          "info": [
            "https://github.com/advisories/GHSA-25mp-g6fv-mqxx",
            "https://github.com/vercel/next.js/security/advisories/GHSA-25mp-g6fv-mqxx"
          ]
        },
        {
          "atOrAbove": "12.0.0",
          "below": "12.0.5",
          "severity": "high",
          "cwe": [
            "CWE-20"
          ],
          "identifiers": {
            "summary": "Unexpected server crash in Next.js versions",
            "CVE": [
              "CVE-2021-43803"
            ],
            "githubID": "GHSA-25mp-g6fv-mqxx"
          },
          "info": [
            "https://github.com/advisories/GHSA-25mp-g6fv-mqxx",
            "https://github.com/vercel/next.js/security/advisories/GHSA-25mp-g6fv-mqxx"
          ]
        },
        {
          "atOrAbove": "12.0.0",
          "below": "12.0.9",
          "severity": "medium",
          "cwe": [
            "CWE-20",
            "CWE-400"
          ],
          "identifiers": {
            "summary": "DOS Vulnerability for self-hosted next.js apps",
            "CVE": [
              "CVE-2022-21721"
            ],
            "githubID": "GHSA-wr66-vrwm-5g5x"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-wr66-vrwm-5g5x"
          ]
        },
        {
          "atOrAbove": "10.0.0",
          "below": "12.1.0",
          "severity": "medium",
          "cwe": [
            "CWE-451"
          ],
          "identifiers": {
            "summary": "Improper CSP in Image Optimization API",
            "CVE": [
              "CVE-2022-23646"
            ],
            "githubID": "GHSA-fmvm-x8mv-47mj"
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-fmvm-x8mv-47mj"
          ]
        },
        {
          "atOrAbove": "12.2.3",
          "below": "12.2.4",
          "cwe": [
            "CWE-248",
            "CWE-754"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Unexpected server crash in Next.js",
            "githubID": "GHSA-wff4-fpwg-qqv3",
            "CVE": [
              "CVE-2022-36046"
            ]
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-wff4-fpwg-qqv3"
          ]
        },
        {
          "atOrAbove": "11.1.4",
          "below": "12.3.5",
          "cwe": [
            "CWE-285"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Authorization Bypass in Next.js Middleware",
            "CVE": [
              "CVE-2025-29927"
            ],
            "githubID": "GHSA-f82v-jwr5-mffw"
          },
          "info": [
            "https://github.com/advisories/GHSA-f82v-jwr5-mffw",
            "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-29927",
            "https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2",
            "https://github.com/vercel/next.js/commit/5fd3ae8f8542677c6294f32d18022731eab6fe48",
            "https://github.com/vercel/next.js",
            "https://github.com/vercel/next.js/releases/tag/v12.3.5",
            "https://github.com/vercel/next.js/releases/tag/v13.5.9",
            "https://security.netapp.com/advisory/ntap-20250328-0002",
            "https://vercel.com/changelog/vercel-firewall-proactively-protects-against-vulnerability-with-middleware",
            "http://www.openwall.com/lists/oss-security/2025/03/23/3",
            "http://www.openwall.com/lists/oss-security/2025/03/23/4"
          ]
        },
        {
          "atOrAbove": "12.3.5",
          "below": "12.3.6",
          "cwe": [
            "CWE-200"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Next.js may leak x-middleware-subrequest-id to external hosts",
            "CVE": [
              "CVE-2025-30218"
            ],
            "githubID": "GHSA-223j-4rm8-mrmf"
          },
          "info": [
            "https://github.com/advisories/GHSA-223j-4rm8-mrmf",
            "https://github.com/vercel/next.js/security/advisories/GHSA-223j-4rm8-mrmf",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-30218",
            "https://github.com/vercel/next.js",
            "https://vercel.com/changelog/cve-2025-30218-5DREmEH765PoeAsrNNQj3O"
          ]
        },
        {
          "atOrAbove": "0.9.9",
          "below": "13.4.20-canary.13",
          "cwe": [
            "CWE-525"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Next.js missing cache-control header may lead to CDN caching empty reply",
            "CVE": [
              "CVE-2023-46298"
            ],
            "githubID": "GHSA-c59h-r6p8-q9wc"
          },
          "info": [
            "https://github.com/advisories/GHSA-c59h-r6p8-q9wc"
          ]
        },
        {
          "atOrAbove": "13.3.1",
          "below": "13.5.0",
          "cwe": [
            "CWE-400"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Next.js Denial of Service (DoS) condition",
            "CVE": [
              "CVE-2024-39693"
            ],
            "githubID": "GHSA-fq54-2j52-jc42"
          },
          "info": [
            "https://github.com/advisories/GHSA-fq54-2j52-jc42",
            "https://github.com/vercel/next.js/security/advisories/GHSA-fq54-2j52-jc42",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-39693",
            "https://github.com/vercel/next.js"
          ]
        },
        {
          "atOrAbove": "13.4.0",
          "below": "13.5.1",
          "cwe": [
            "CWE-444"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Next.js Vulnerable to HTTP Request Smuggling",
            "CVE": [
              "CVE-2024-34350"
            ],
            "githubID": "GHSA-77r5-gw3j-2mpf"
          },
          "info": [
            "https://github.com/advisories/GHSA-77r5-gw3j-2mpf",
            "https://github.com/vercel/next.js/security/advisories/GHSA-77r5-gw3j-2mpf",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34350",
            "https://github.com/vercel/next.js/commit/44eba020c615f0d9efe431f84ada67b81576f3f5",
            "https://github.com/vercel/next.js",
            "https://github.com/vercel/next.js/compare/v13.5.0...v13.5.1"
          ]
        },
        {
          "atOrAbove": "13.5.1",
          "below": "13.5.7",
          "cwe": [
            "CWE-349",
            "CWE-639"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Next.js Cache Poisoning",
            "CVE": [
              "CVE-2024-46982"
            ],
            "githubID": "GHSA-gp8f-8m3g-qvj9"
          },
          "info": [
            "https://github.com/advisories/GHSA-gp8f-8m3g-qvj9",
            "https://github.com/vercel/next.js/security/advisories/GHSA-gp8f-8m3g-qvj9",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-46982",
            "https://github.com/vercel/next.js/commit/7ed7f125e07ef0517a331009ed7e32691ba403d3",
            "https://github.com/vercel/next.js/commit/bd164d53af259c05f1ab434004bcfdd3837d7cda",
            "https://github.com/vercel/next.js"
          ]
        },
        {
          "atOrAbove": "13.0.0",
          "below": "13.5.8",
          "cwe": [
            "CWE-770"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Next.js Allows a Denial of Service (DoS) with Server Actions",
            "CVE": [
              "CVE-2024-56332"
            ],
            "githubID": "GHSA-7m27-7ghc-44w9"
          },
          "info": [
            "https://github.com/advisories/GHSA-7m27-7ghc-44w9",
            "https://github.com/vercel/next.js/security/advisories/GHSA-7m27-7ghc-44w9",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-56332",
            "https://github.com/vercel/next.js"
          ]
        },
        {
          "atOrAbove": "13.0.0",
          "below": "13.5.9",
          "cwe": [
            "CWE-285"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Authorization Bypass in Next.js Middleware",
            "CVE": [
              "CVE-2025-29927"
            ],
            "githubID": "GHSA-f82v-jwr5-mffw"
          },
          "info": [
            "https://github.com/advisories/GHSA-f82v-jwr5-mffw",
            "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-29927",
            "https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2",
            "https://github.com/vercel/next.js/commit/5fd3ae8f8542677c6294f32d18022731eab6fe48",
            "https://github.com/vercel/next.js",
            "https://github.com/vercel/next.js/releases/tag/v12.3.5",
            "https://github.com/vercel/next.js/releases/tag/v13.5.9",
            "https://security.netapp.com/advisory/ntap-20250328-0002",
            "https://vercel.com/changelog/vercel-firewall-proactively-protects-against-vulnerability-with-middleware",
            "http://www.openwall.com/lists/oss-security/2025/03/23/3",
            "http://www.openwall.com/lists/oss-security/2025/03/23/4"
          ]
        },
        {
          "atOrAbove": "13.5.9",
          "below": "13.5.10",
          "cwe": [
            "CWE-200"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Next.js may leak x-middleware-subrequest-id to external hosts",
            "CVE": [
              "CVE-2025-30218"
            ],
            "githubID": "GHSA-223j-4rm8-mrmf"
          },
          "info": [
            "https://github.com/advisories/GHSA-223j-4rm8-mrmf",
            "https://github.com/vercel/next.js/security/advisories/GHSA-223j-4rm8-mrmf",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-30218",
            "https://github.com/vercel/next.js",
            "https://vercel.com/changelog/cve-2025-30218-5DREmEH765PoeAsrNNQj3O"
          ]
        },
        {
          "atOrAbove": "13.4.0",
          "below": "14.1.1",
          "cwe": [
            "CWE-918"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Next.js Server-Side Request Forgery in Server Actions",
            "CVE": [
              "CVE-2024-34351"
            ],
            "githubID": "GHSA-fr5h-rqp8-mj6g"
          },
          "info": [
            "https://github.com/advisories/GHSA-fr5h-rqp8-mj6g",
            "https://github.com/vercel/next.js/security/advisories/GHSA-fr5h-rqp8-mj6g",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34351",
            "https://github.com/vercel/next.js/pull/62561",
            "https://github.com/vercel/next.js/commit/8f7a6ca7d21a97bc9f7a1bbe10427b5ad74b9085",
            "https://github.com/vercel/next.js"
          ]
        },
        {
          "atOrAbove": "10.0.0",
          "below": "14.2.7",
          "cwe": [
            "CWE-674"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Denial of Service condition in Next.js image optimization",
            "CVE": [
              "CVE-2024-47831"
            ],
            "githubID": "GHSA-g77x-44xx-532m"
          },
          "info": [
            "https://github.com/advisories/GHSA-g77x-44xx-532m",
            "https://github.com/vercel/next.js/security/advisories/GHSA-g77x-44xx-532m",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-47831",
            "https://github.com/vercel/next.js/commit/d11cbc9ff0b1aaefabcba9afe1e562e0b1fde65a",
            "https://github.com/vercel/next.js"
          ]
        },
        {
          "atOrAbove": "14.0.0",
          "below": "14.2.10",
          "cwe": [
            "CWE-349",
            "CWE-639"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Next.js Cache Poisoning",
            "CVE": [
              "CVE-2024-46982"
            ],
            "githubID": "GHSA-gp8f-8m3g-qvj9"
          },
          "info": [
            "https://github.com/advisories/GHSA-gp8f-8m3g-qvj9",
            "https://github.com/vercel/next.js/security/advisories/GHSA-gp8f-8m3g-qvj9",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-46982",
            "https://github.com/vercel/next.js/commit/7ed7f125e07ef0517a331009ed7e32691ba403d3",
            "https://github.com/vercel/next.js/commit/bd164d53af259c05f1ab434004bcfdd3837d7cda",
            "https://github.com/vercel/next.js"
          ]
        },
        {
          "atOrAbove": "9.5.5",
          "below": "14.2.15",
          "cwe": [
            "CWE-285"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Next.js authorization bypass vulnerability",
            "CVE": [
              "CVE-2024-51479"
            ],
            "githubID": "GHSA-7gfc-8cq8-jh5f"
          },
          "info": [
            "https://github.com/advisories/GHSA-7gfc-8cq8-jh5f",
            "https://github.com/vercel/next.js/security/advisories/GHSA-7gfc-8cq8-jh5f",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-51479",
            "https://github.com/vercel/next.js/commit/1c8234eb20bc8afd396b89999a00f06b61d72d7b",
            "https://github.com/vercel/next.js",
            "https://github.com/vercel/next.js/releases/tag/v14.2.15"
          ]
        },
        {
          "atOrAbove": "14.0.0",
          "below": "14.2.21",
          "cwe": [
            "CWE-770"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Next.js Allows a Denial of Service (DoS) with Server Actions",
            "CVE": [
              "CVE-2024-56332"
            ],
            "githubID": "GHSA-7m27-7ghc-44w9"
          },
          "info": [
            "https://github.com/advisories/GHSA-7m27-7ghc-44w9",
            "https://github.com/vercel/next.js/security/advisories/GHSA-7m27-7ghc-44w9",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-56332",
            "https://github.com/vercel/next.js"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "14.2.24",
          "cwe": [
            "CWE-362"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Next.js Race Condition to Cache Poisoning",
            "CVE": [
              "CVE-2025-32421"
            ],
            "githubID": "GHSA-qpjv-v59x-3qc4"
          },
          "info": [
            "https://github.com/advisories/GHSA-qpjv-v59x-3qc4",
            "https://github.com/vercel/next.js/security/advisories/GHSA-qpjv-v59x-3qc4",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-32421",
            "https://github.com/vercel/next.js",
            "https://vercel.com/changelog/cve-2025-32421"
          ]
        },
        {
          "atOrAbove": "14.0.0",
          "below": "14.2.25",
          "cwe": [
            "CWE-285"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Authorization Bypass in Next.js Middleware",
            "CVE": [
              "CVE-2025-29927"
            ],
            "githubID": "GHSA-f82v-jwr5-mffw"
          },
          "info": [
            "https://github.com/advisories/GHSA-f82v-jwr5-mffw",
            "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-29927",
            "https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2",
            "https://github.com/vercel/next.js/commit/5fd3ae8f8542677c6294f32d18022731eab6fe48",
            "https://github.com/vercel/next.js",
            "https://github.com/vercel/next.js/releases/tag/v12.3.5",
            "https://github.com/vercel/next.js/releases/tag/v13.5.9",
            "https://security.netapp.com/advisory/ntap-20250328-0002",
            "https://vercel.com/changelog/vercel-firewall-proactively-protects-against-vulnerability-with-middleware",
            "http://www.openwall.com/lists/oss-security/2025/03/23/3",
            "http://www.openwall.com/lists/oss-security/2025/03/23/4"
          ]
        },
        {
          "atOrAbove": "14.2.25",
          "below": "14.2.26",
          "cwe": [
            "CWE-200"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Next.js may leak x-middleware-subrequest-id to external hosts",
            "CVE": [
              "CVE-2025-30218"
            ],
            "githubID": "GHSA-223j-4rm8-mrmf"
          },
          "info": [
            "https://github.com/advisories/GHSA-223j-4rm8-mrmf",
            "https://github.com/vercel/next.js/security/advisories/GHSA-223j-4rm8-mrmf",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-30218",
            "https://github.com/vercel/next.js",
            "https://vercel.com/changelog/cve-2025-30218-5DREmEH765PoeAsrNNQj3O"
          ]
        },
        {
          "atOrAbove": "13.0",
          "below": "14.2.30",
          "cwe": [
            "CWE-1385"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Information exposure in Next.js dev server due to lack of origin verification",
            "CVE": [
              "CVE-2025-48068"
            ],
            "githubID": "GHSA-3h52-269p-cp9r"
          },
          "info": [
            "https://github.com/advisories/GHSA-3h52-269p-cp9r",
            "https://github.com/vercel/next.js/security/advisories/GHSA-3h52-269p-cp9r",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-48068",
            "https://github.com/vercel/next.js",
            "https://vercel.com/changelog/cve-2025-48068"
          ]
        },
        {
          "atOrAbove": "15.0.0",
          "below": "15.1.2",
          "cwe": [
            "CWE-770"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Next.js Allows a Denial of Service (DoS) with Server Actions",
            "CVE": [
              "CVE-2024-56332"
            ],
            "githubID": "GHSA-7m27-7ghc-44w9"
          },
          "info": [
            "https://github.com/advisories/GHSA-7m27-7ghc-44w9",
            "https://github.com/vercel/next.js/security/advisories/GHSA-7m27-7ghc-44w9",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-56332",
            "https://github.com/vercel/next.js"
          ]
        },
        {
          "atOrAbove": "15.0.0",
          "below": "15.1.6",
          "cwe": [
            "CWE-362"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Next.js Race Condition to Cache Poisoning",
            "CVE": [
              "CVE-2025-32421"
            ],
            "githubID": "GHSA-qpjv-v59x-3qc4"
          },
          "info": [
            "https://github.com/advisories/GHSA-qpjv-v59x-3qc4",
            "https://github.com/vercel/next.js/security/advisories/GHSA-qpjv-v59x-3qc4",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-32421",
            "https://github.com/vercel/next.js",
            "https://vercel.com/changelog/cve-2025-32421"
          ]
        },
        {
          "atOrAbove": "15.0.4-canary.51",
          "below": "15.1.8",
          "cwe": [
            "CWE-444"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "### Summary\nA vulnerability affecting Next.js has been addressed. It impacted versions 15.0.4 through 15.1.8 and involved a cache poisoning bug leading to a Denial of Service (DoS) condition.\n\nUnder certain conditions, this issue may allow a HTTP 204 response to be cached for static pages, leading to the 204 response being served to all users attempting to access the page\n\nMore details: [CVE-2025-49826](https://vercel.com/changelog/cve-2025-49826)\n\n## Credits\n- Allam Rachid [zhero;](https://zhero-web-sec.github.io/research-and-things/)\n- Allam Yasser (inzo)",
            "githubID": "GHSA-67rr-84xm-4c7r",
            "CVE": [
              "CVE-2025-49826"
            ]
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-67rr-84xm-4c7r",
            "https://github.com/vercel/next.js/commit/16bfce64ef2157f2c1dfedcfdb7771bc63103fd2",
            "https://github.com/vercel/next.js/commit/a15b974ed707d63ad4da5b74c1441f5b7b120e93",
            "https://github.com/vercel/next.js/releases/tag/v15.1.8",
            "https://vercel.com/changelog/cve-2025-49826"
          ]
        },
        {
          "atOrAbove": "15.0.0",
          "below": "15.2.2",
          "cwe": [
            "CWE-1385"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Information exposure in Next.js dev server due to lack of origin verification",
            "CVE": [
              "CVE-2025-48068"
            ],
            "githubID": "GHSA-3h52-269p-cp9r"
          },
          "info": [
            "https://github.com/advisories/GHSA-3h52-269p-cp9r",
            "https://github.com/vercel/next.js/security/advisories/GHSA-3h52-269p-cp9r",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-48068",
            "https://github.com/vercel/next.js",
            "https://vercel.com/changelog/cve-2025-48068"
          ]
        },
        {
          "atOrAbove": "15.0.0",
          "below": "15.2.3",
          "cwe": [
            "CWE-285"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Authorization Bypass in Next.js Middleware",
            "CVE": [
              "CVE-2025-29927"
            ],
            "githubID": "GHSA-f82v-jwr5-mffw"
          },
          "info": [
            "https://github.com/advisories/GHSA-f82v-jwr5-mffw",
            "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-29927",
            "https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2",
            "https://github.com/vercel/next.js/commit/5fd3ae8f8542677c6294f32d18022731eab6fe48",
            "https://github.com/vercel/next.js",
            "https://github.com/vercel/next.js/releases/tag/v12.3.5",
            "https://github.com/vercel/next.js/releases/tag/v13.5.9",
            "https://security.netapp.com/advisory/ntap-20250328-0002",
            "https://vercel.com/changelog/vercel-firewall-proactively-protects-against-vulnerability-with-middleware",
            "http://www.openwall.com/lists/oss-security/2025/03/23/3",
            "http://www.openwall.com/lists/oss-security/2025/03/23/4"
          ]
        },
        {
          "atOrAbove": "15.2.3",
          "below": "15.2.4",
          "cwe": [
            "CWE-200"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "Next.js may leak x-middleware-subrequest-id to external hosts",
            "CVE": [
              "CVE-2025-30218"
            ],
            "githubID": "GHSA-223j-4rm8-mrmf"
          },
          "info": [
            "https://github.com/advisories/GHSA-223j-4rm8-mrmf",
            "https://github.com/vercel/next.js/security/advisories/GHSA-223j-4rm8-mrmf",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-30218",
            "https://github.com/vercel/next.js",
            "https://vercel.com/changelog/cve-2025-30218-5DREmEH765PoeAsrNNQj3O"
          ]
        },
        {
          "atOrAbove": "15.3.0",
          "below": "15.3.3",
          "cwe": [
            "CWE-444"
          ],
          "severity": "low",
          "identifiers": {
            "summary": "### Summary\n\nA cache poisoning issue in **Next.js App Router >=15.3.0 and < 15.3.3** may have allowed RSC payloads to be cached and served in place of HTML, under specific conditions involving middleware and redirects. This issue has been fixed in **Next.js 15.3.3**.\n\nUsers on affected versions should **upgrade immediately** and **redeploy** to ensure proper caching behavior.\n\nMore details: [CVE-2025-49005](https://vercel.com/changelog/cve-2025-49005)",
            "githubID": "GHSA-r2fc-ccr8-96c4",
            "CVE": [
              "CVE-2025-49005"
            ]
          },
          "info": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-r2fc-ccr8-96c4",
            "https://github.com/vercel/next.js/issues/79346",
            "https://github.com/vercel/next.js/pull/79939",
            "https://github.com/vercel/next.js/commit/ec202eccf05820b60c6126d6411fe16766ecc066",
            "https://github.com/vercel/next.js/releases/tag/v15.3.3",
            "https://vercel.com/changelog/cve-2025-49005"
          ]
        }
      ],
      "extractors": {
        "filecontent": [
          "version=\"(§§version§§)\".{1,1500}document\\.getElementById\\(\"__NEXT_DATA__\"\\)\\.textContent",
          "document\\.getElementById\\(\"__NEXT_DATA__\"\\)\\.textContent\\);window\\.__NEXT_DATA__=.;.\\.version=\"(§§version§§)\"",
          "=\"(§§version§§)\"[\\s\\S]{10,100}Component[\\s\\S]{1,10}componentDidCatch[\\s\\S]{10,30}componentDidMount"
        ],
        "func": [
          "next && next.version"
        ],
        "ast": [
          "//BlockStatement[       /ExpressionStatement/AssignmentExpression/:left/:property/:name == \"version\" &&       /ExpressionStatement/AssignmentExpression/:left[         /:property/:name == \"__NEXT_DATA__\" &&         /:object/:name == \"window\"       ]     ]/ExpressionStatement/AssignmentExpression[/:left/:property/:name == \"version\"]/:$$right/:value",
          "//AssignmentExpression[       /:left/:object/:name == \"window\" &&       /:left/:property/:name == \"next\"     ]/ObjectExpression/:properties[/:key/:name == \"version\"]/:value/:value"
        ]
      }
    },
    "chart.js": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "2.9.4",
          "severity": "high",
          "cwe": [
            "CWE-1321",
            "CWE-915"
          ],
          "identifiers": {
            "summary": "Prototype pollution in chart.js",
            "CVE": [
              "CVE-2020-7746"
            ],
            "githubID": "GHSA-h68q-55jf-x68w"
          },
          "info": [
            "https://github.com/advisories/GHSA-h68q-55jf-x68w"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/Chart.js/(§§version§§)/chart(\\.min)?\\.js",
          "/Chart.js/(§§version§§)/Chart.bundle(\\.min)?\\.js"
        ],
        "filecontent": [
          "var version=\"(§§version§§)\";const KNOWN_POSITIONS=\\[\"top\",\"bottom\",\"left\",\"right\",\"chartArea\"\\]",
          "/\\*![\\s]+\\* Chart.js v(§§version§§)",
          "/\\*![\\s]+\\* Chart.js[\\s]+\\* http://chartjs.org/[\\s]+\\* Version: (§§version§§)"
        ]
      }
    },
    "froala": {
      "npmname": "froala-editor",
      "licenses": [
        "LicenseRef-Proprietary >=0"
      ],
      "vulnerabilities": [
        {
          "below": "3.2.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Security issue: XSS via pasted content",
            "issue": "3880"
          },
          "info": [
            "https://froala.com/wysiwyg-editor/changelog/#3.2.2"
          ]
        },
        {
          "below": "3.2.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS Issue In Link Insertion",
            "issue": "3270"
          },
          "info": [
            "https://github.com/froala/wysiwyg-editor/issues/3270"
          ]
        },
        {
          "below": "3.2.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "DOM-based cross-site scripting in Froala Editor",
            "githubID": "GHSA-h236-g5gh-vq6c",
            "CVE": [
              "CVE-2019-19935"
            ]
          },
          "info": [
            "https://github.com/advisories/GHSA-h236-g5gh-vq6c"
          ]
        },
        {
          "below": "3.2.7",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Froala WYSIWYG Editor 3.2.6-1 is affected by XSS due to a namespace confusion during parsing.",
            "CVE": [
              "CVE-2021-28114"
            ]
          },
          "info": [
            "https://bishopfox.com/blog/froala-editor-v3-2-6-advisory"
          ]
        },
        {
          "below": "3.2.7",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Froala WYSIWYG Editor 3.2.6 is affected by Cross Site Scripting (XSS). Under certain conditions, a base64 crafted string leads to persistent XSS.",
            "CVE": [
              "CVE-2021-30109"
            ],
            "githubID": "GHSA-cq6w-w5rj-p9x8"
          },
          "info": [
            "https://github.com/froala/wysiwyg-editor/releases/tag/v4.0.11"
          ]
        },
        {
          "below": "4.0.11",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "XSS vulnerability in [insert video]",
            "issue": "3880",
            "githubID": "GHSA-97x5-cc53-cv4v",
            "CVE": [
              "CVE-2020-22864"
            ]
          },
          "info": [
            "https://github.com/froala/wysiwyg-editor/releases/tag/v4.0.11"
          ]
        },
        {
          "below": "4.1.4",
          "atOrAbove": "4.0.1",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Froala Editor v4.0.1 to v4.1.1 was discovered to contain a cross-site scripting (XSS) vulnerability.",
            "CVE": [
              "CVE-2023-41592"
            ],
            "githubID": "GHSA-hvpq-7vcc-5hj5"
          },
          "info": [
            "https://froala.com/wysiwyg-editor/changelog/#4.1.4",
            "https://github.com/advisories/GHSA-hvpq-7vcc-5hj5"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "4.3.1",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Froala WYSIWYG editor allows cross-site scripting (XSS)",
            "CVE": [
              "CVE-2024-51434"
            ],
            "githubID": "GHSA-549p-5c7f-c5p4"
          },
          "info": [
            "https://github.com/advisories/GHSA-549p-5c7f-c5p4",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-51434",
            "https://georgyg.com/home/froala-wysiwyg-editor---xss-cve-2024-51434",
            "https://github.com/froala/wysiwyg-editor"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/froala-editor/(§§version§§)/",
          "/froala-editor@(§§version§§)/"
        ],
        "filecontent": [
          "/\\*![\\s]+\\* froala_editor v(§§version§§)",
          "VERSION:\"(§§version§§)\",INSTANCES:\\[\\],OPTS_MAPPING:\\{\\}"
        ],
        "func": [
          "FroalaEditor.VERSION"
        ]
      }
    },
    "pendo": {
      "licenses": [
        "LicenseRef-Proprietary >=0"
      ],
      "vulnerabilities": [
        {
          "below": "2.15.18",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Patched XSS vulnerability around script loading",
            "retid": "74"
          },
          "info": [
            "https://developers.pendo.io/agent-version-2-15-18/"
          ]
        }
      ],
      "extractors": {
        "filecontent": [
          "// Pendo Agent Wrapper\n//[\\s]+Environment:[\\s]+[^\n]+\n// Agent Version:[\\s]+(§§version§§)"
        ],
        "func": [
          "pendo.VERSION.split('_')[0]"
        ]
      }
    },
    "highcharts": {
      "licenses": [
        "LicenseRef-Proprietary >=0"
      ],
      "vulnerabilities": [
        {
          "below": "6.1.0",
          "severity": "high",
          "cwe": [
            "CWE-1333"
          ],
          "identifiers": {
            "summary": "Regular Expression Denial of Service in highcharts",
            "CVE": [
              "CVE-2018-20801"
            ],
            "githubID": "GHSA-xmc8-cjfr-phx3"
          },
          "info": [
            "https://security.snyk.io/vuln/SNYK-JS-HIGHCHARTS-1290057"
          ]
        },
        {
          "below": "7.2.2",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of `highcharts` prior to 7.2.2 or 8.1.1 are vulnerable to Cross-Site Scripting (XSS)",
            "githubID": "GHSA-gr4j-r575-g665"
          },
          "info": [
            "https://github.com/advisories/GHSA-gr4j-r575-g665",
            "https://github.com/highcharts/highcharts/issues/13559"
          ]
        },
        {
          "atOrAbove": "8.0.0",
          "below": "8.1.1",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Versions of `highcharts` prior to 7.2.2 or 8.1.1 are vulnerable to Cross-Site Scripting (XSS)",
            "githubID": "GHSA-gr4j-r575-g665"
          },
          "info": [
            "https://github.com/advisories/GHSA-gr4j-r575-g665",
            "https://github.com/highcharts/highcharts/issues/13559"
          ]
        },
        {
          "below": "9.0.0",
          "severity": "high",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "summary": "Cross-site Scripting (XSS) and Prototype Pollution in Highcharts < 9.0.0",
            "CVE": [
              "CVE-2021-29489"
            ],
            "githubID": "GHSA-8j65-4pcq-xq95"
          },
          "info": [
            "https://security.snyk.io/vuln/SNYK-JS-HIGHCHARTS-1290057"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "highcharts/(§§version§§)/highcharts(\\.min)?\\.js"
        ],
        "filecontent": [
          "product:\"Highcharts\",version:\"(§§version§§)\"",
          "product=\"Highcharts\"[,;].\\.version=\"(§§version§§)\""
        ]
      }
    },
    "select2": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "0",
          "below": "4.0.6",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Improper Neutralization of Input During Web Page Generation in Select2",
            "CVE": [
              "CVE-2016-10744"
            ],
            "githubID": "GHSA-rf66-hmqf-q3fc"
          },
          "info": [
            "https://github.com/advisories/GHSA-rf66-hmqf-q3fc",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-10744",
            "https://github.com/select2/select2/issues/4587",
            "https://github.com/snipe/snipe-it/pull/6831",
            "https://github.com/snipe/snipe-it/pull/6831/commits/5848d9a10c7d62c73ff6a3858edfae96a429402a",
            "https://github.com/select2/select2"
          ]
        }
      ],
      "extractors": {
        "filecontent": [
          "/\\*!(?:[\\s]+\\*)? Select2 (§§version§§)",
          "/\\*[\\s]+Copyright 20[0-9]{2} [I]gor V[a]ynberg[\\s]+Version: (§§version§§)[\\s\\S]{1,5000}(\\.attr\\(\"class\",\"select2-sizer\"|\\.data\\(document, *\"select2-lastpos\"|document\\)\\.data\\(\"select2-lastpos\"|SingleSelect2, *MultiSelect2|window.Select2 *!== *undefined)"
        ],
        "uri": [
          "(§§version§§)/(js/)?select2(.min)?\\.js"
        ]
      }
    },
    "blueimp-file-upload": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "9.22.1",
          "cwe": [
            "CWE-434"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Unrestricted Upload of File with Dangerous Type in blueimp-file-upload",
            "CVE": [
              "CVE-2018-9206"
            ],
            "githubID": "GHSA-4cj8-g9cp-v5wr"
          },
          "info": [
            "https://github.com/advisories/GHSA-4cj8-g9cp-v5wr",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-9206",
            "https://github.com/advisories/GHSA-4cj8-g9cp-v5wr",
            "https://wpvulndb.com/vulnerabilities/9136",
            "https://www.exploit-db.com/exploits/45790/",
            "https://www.exploit-db.com/exploits/46182/",
            "https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html",
            "http://www.securityfocus.com/bid/105679",
            "http://www.securityfocus.com/bid/106629",
            "http://www.vapidlabs.com/advisory.php?v=204"
          ]
        }
      ],
      "extractors": {
        "filecontent": [
          "/\\*[\\s*]+jQuery File Upload User Interface Plugin (§§version§§)[\\s*]+https://github.com/blueimp"
        ],
        "uri": [
          "/blueimp-file-upload/(§§version§§)/jquery.fileupload(-ui)?(\\.min)?\\.js"
        ]
      }
    },
    "c3": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "0.4.11",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Cross-Site Scripting in c3",
            "CVE": [
              "CVE-2016-1000240"
            ],
            "githubID": "GHSA-gvg7-pp82-cff3"
          },
          "info": [
            "https://github.com/advisories/GHSA-gvg7-pp82-cff3",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-1000240",
            "https://github.com/c3js/c3/issues/1536",
            "https://github.com/c3js/c3/pull/1675",
            "https://github.com/c3js/c3/commit/de3864650300488a63d0541620e9828b00e94b42",
            "https://github.com/c3js/c3",
            "https://www.npmjs.com/advisories/138"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/(§§version§§)/c3(\\.min)?\\.js"
        ],
        "filecontent": [
          "[\\s]+var c3 ?= ?\\{ ?version: ?['\"](§§version§§)['\"] ?\\};[\\s]+var c3_chart_fn,"
        ]
      }
    },
    "lodash": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [
        {
          "below": "4.17.5",
          "cwe": [
            "CWE-471",
            "CWE-1321"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Prototype Pollution in lodash",
            "CVE": [
              "CVE-2018-3721"
            ],
            "githubID": "GHSA-fvqr-27wr-82fm"
          },
          "info": [
            "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-3721",
            "https://github.com/lodash/lodash/commit/d8e069cc3410082e44eb18fcf8e7f3d08ebe1d4a",
            "https://hackerone.com/reports/310443",
            "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
            "https://security.netapp.com/advisory/ntap-20190919-0004/",
            "https://www.npmjs.com/advisories/577"
          ]
        },
        {
          "below": "4.17.11",
          "cwe": [
            "CWE-400"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Prototype Pollution in lodash",
            "CVE": [
              "CVE-2018-16487"
            ],
            "githubID": "GHSA-4xc9-xhrj-v574"
          },
          "info": [
            "https://github.com/advisories/GHSA-4xc9-xhrj-v574",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-16487",
            "https://github.com/lodash/lodash/commit/90e6199a161b6445b01454517b40ef65ebecd2ad",
            "https://hackerone.com/reports/380873",
            "https://github.com/advisories/GHSA-4xc9-xhrj-v574",
            "https://security.netapp.com/advisory/ntap-20190919-0004/",
            "https://www.npmjs.com/advisories/782"
          ]
        },
        {
          "below": "4.17.11",
          "cwe": [
            "CWE-400"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
            "CVE": [
              "CVE-2019-1010266"
            ],
            "githubID": "GHSA-x5rq-j2xg-h7qm"
          },
          "info": [
            "https://github.com/advisories/GHSA-x5rq-j2xg-h7qm",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010266",
            "https://github.com/lodash/lodash/issues/3359",
            "https://github.com/lodash/lodash/commit/5c08f18d365b64063bfbfa686cbb97cdd6267347",
            "https://github.com/lodash/lodash/wiki/Changelog",
            "https://security.netapp.com/advisory/ntap-20190919-0004/",
            "https://snyk.io/vuln/SNYK-JS-LODASH-73639"
          ]
        },
        {
          "below": "4.17.12",
          "cwe": [
            "CWE-1321",
            "CWE-20"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Prototype Pollution in lodash",
            "CVE": [
              "CVE-2019-10744"
            ],
            "githubID": "GHSA-jf85-cpcp-j695"
          },
          "info": [
            "https://github.com/advisories/GHSA-jf85-cpcp-j695",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
            "https://github.com/lodash/lodash/pull/4336",
            "https://access.redhat.com/errata/RHSA-2019:3024",
            "https://security.netapp.com/advisory/ntap-20191004-0005/",
            "https://snyk.io/vuln/SNYK-JS-LODASH-450202",
            "https://support.f5.com/csp/article/K47105354?utm_source=f5support&amp;utm_medium=RSS",
            "https://www.npmjs.com/advisories/1065",
            "https://www.oracle.com/security-alerts/cpujan2021.html",
            "https://www.oracle.com/security-alerts/cpuoct2020.html"
          ]
        },
        {
          "atOrAbove": "3.7.0",
          "below": "4.17.19",
          "cwe": [
            "CWE-1321",
            "CWE-770"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Prototype Pollution in lodash",
            "CVE": [
              "CVE-2020-8203"
            ],
            "githubID": "GHSA-p6mc-m468-83gw"
          },
          "info": [
            "https://github.com/advisories/GHSA-p6mc-m468-83gw",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
            "https://github.com/lodash/lodash/issues/4744",
            "https://github.com/lodash/lodash/issues/4874",
            "https://github.com/github/advisory-database/pull/2884",
            "https://github.com/lodash/lodash/commit/c84fe82760fb2d3e03a63379b297a1cc1a2fce12",
            "https://hackerone.com/reports/712065",
            "https://hackerone.com/reports/864701",
            "https://github.com/lodash/lodash",
            "https://github.com/lodash/lodash/wiki/Changelog#v41719",
            "https://web.archive.org/web/20210914001339/https://github.com/lodash/lodash/issues/4744"
          ]
        },
        {
          "below": "4.17.21",
          "cwe": [
            "CWE-1333",
            "CWE-400"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
            "CVE": [
              "CVE-2020-28500"
            ],
            "githubID": "GHSA-29mw-wpgm-hmr9"
          },
          "info": [
            "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-28500",
            "https://github.com/lodash/lodash/pull/5065",
            "https://github.com/lodash/lodash/pull/5065/commits/02906b8191d3c100c193fe6f7b27d1c40f200bb7",
            "https://github.com/lodash/lodash/commit/c4847ebe7d14540bb28a8b932a9ce1b9ecbfee1a",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
            "https://github.com/lodash/lodash",
            "https://github.com/lodash/lodash/blob/npm/trimEnd.js%23L8",
            "https://security.netapp.com/advisory/ntap-20210312-0006/",
            "https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074896",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074894",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074892",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074895",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074893",
            "https://snyk.io/vuln/SNYK-JS-LODASH-1018905",
            "https://www.oracle.com//security-alerts/cpujul2021.html",
            "https://www.oracle.com/security-alerts/cpujan2022.html",
            "https://www.oracle.com/security-alerts/cpujul2022.html",
            "https://www.oracle.com/security-alerts/cpuoct2021.html"
          ]
        },
        {
          "below": "4.17.21",
          "cwe": [
            "CWE-77",
            "CWE-94"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Command Injection in lodash",
            "CVE": [
              "CVE-2021-23337"
            ],
            "githubID": "GHSA-35jh-r3h4-6jhm"
          },
          "info": [
            "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
            "https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
            "https://github.com/lodash/lodash",
            "https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js#L14851",
            "https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js%23L14851",
            "https://security.netapp.com/advisory/ntap-20210312-0006/",
            "https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074932",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074930",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074928",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074931",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074929",
            "https://snyk.io/vuln/SNYK-JS-LODASH-1040724",
            "https://www.oracle.com//security-alerts/cpujul2021.html",
            "https://www.oracle.com/security-alerts/cpujan2022.html",
            "https://www.oracle.com/security-alerts/cpujul2022.html",
            "https://www.oracle.com/security-alerts/cpuoct2021.html"
          ]
        }
      ],
      "extractors": {
        "filecontent": [
          "/\\*[\\s*!]+(?:@license)?[\\s*]+(?:Lo-Dash|lodash|Lodash) v?(§§version§§)[\\s\\S]{1,200}Build: `lodash modern -o",
          "/\\*[\\s*!]+(?:@license)?[\\s*]+(?:Lo-Dash|lodash|Lodash) v?(§§version§§) <",
          "/\\*[\\s*!]+(?:@license)?[\\s*]+(?:Lo-Dash|lodash|Lodash) v?(§§version§§) lodash.com/license",
          "=\"(§§version§§)(?<=[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2})\"[\\s\\S]{1,300}__lodash_hash_undefined__",
          "/\\*[\\s*]+@license[\\s*]+(?:Lo-Dash|lodhash|Lodash)[\\s\\S]{1,500}var VERSION *= *['\"](§§version§§)['\"]",
          "var VERSION=\"(§§version§§)\";var BIND_FLAG=1,BIND_KEY_FLAG=2,CURRY_BOUND_FLAG=4,CURRY_FLAG=8"
        ],
        "uri": [
          "/(§§version§§)/lodash(\\.min)?\\.js"
        ]
      }
    },
    "ua-parser-js": {
      "licenses": [
        "AGPL-3.0 >=2.0.0-beta.1",
        "MIT >=0.7.20 <2.0.0-beta.1",
        "(GPL-2.0 OR MIT) >=0.3.0 <0.7.20"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "0",
          "below": "0.7.22",
          "cwe": [
            "CWE-400"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Regular Expression Denial of Service in ua-parser-js",
            "CVE": [
              "CVE-2020-7733"
            ],
            "githubID": "GHSA-662x-fhqg-9p8v"
          },
          "info": [
            "https://github.com/advisories/GHSA-662x-fhqg-9p8v",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7733",
            "https://github.com/faisalman/ua-parser-js/commit/233d3bae22a795153a7e6638887ce159c63e557d",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBFAISALMAN-674666",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-674665",
            "https://snyk.io/vuln/SNYK-JS-UAPARSERJS-610226",
            "https://www.oracle.com//security-alerts/cpujul2021.html"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "0.7.22",
          "cwe": [
            "CWE-400"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Regular Expression Denial of Service in ua-parser-js",
            "CVE": [
              "CVE-2020-7733"
            ],
            "githubID": "GHSA-662x-fhqg-9p8v"
          },
          "info": [
            "https://github.com/advisories/GHSA-662x-fhqg-9p8v",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7733",
            "https://github.com/faisalman/ua-parser-js/commit/233d3bae22a795153a7e6638887ce159c63e557d",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBFAISALMAN-674666",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-674665",
            "https://snyk.io/vuln/SNYK-JS-UAPARSERJS-610226",
            "https://www.oracle.com//security-alerts/cpujul2021.html"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "0.7.23",
          "cwe": [
            "CWE-400"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "ua-parser-js Regular Expression Denial of Service vulnerability",
            "CVE": [
              "CVE-2020-7793"
            ],
            "githubID": "GHSA-394c-5j6w-4xmx"
          },
          "info": [
            "https://github.com/advisories/GHSA-394c-5j6w-4xmx",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7793",
            "https://github.com/faisalman/ua-parser-js/commit/6d1f26df051ba681463ef109d36c9cf0f7e32b18",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBFAISALMAN-1050388",
            "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1050387",
            "https://snyk.io/vuln/SNYK-JS-UAPARSERJS-1023599"
          ]
        },
        {
          "atOrAbove": "0.7.14",
          "below": "0.7.24",
          "cwe": [
            "CWE-400"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Regular Expression Denial of Service (ReDoS) in ua-parser-js",
            "CVE": [
              "CVE-2021-27292"
            ],
            "githubID": "GHSA-78cj-fxph-m83p"
          },
          "info": [
            "https://github.com/advisories/GHSA-78cj-fxph-m83p",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-27292",
            "https://github.com/faisalman/ua-parser-js/commit/809439e20e273ce0d25c1d04e111dcf6011eb566",
            "https://github.com/pygments/pygments/commit/2e7e8c4a7b318f4032493773732754e418279a14",
            "https://gist.github.com/b-c-ds/6941d80d6b4e694df4bc269493b7be76"
          ]
        },
        {
          "atOrAbove": "0.7.29",
          "below": "0.7.30",
          "cwe": [
            "CWE-829",
            "CWE-912"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Embedded malware in ua-parser-js",
            "CVE": [],
            "githubID": "GHSA-pjwm-rvh2-c87w"
          },
          "info": [
            "https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
            "https://github.com/faisalman/ua-parser-js/issues/536",
            "https://github.com/faisalman/ua-parser-js/issues/536#issuecomment-949772496",
            "https://github.com/faisalman/ua-parser-js",
            "https://www.npmjs.com/package/ua-parser-js"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "0.7.33",
          "cwe": [
            "CWE-1333",
            "CWE-400"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "ReDoS Vulnerability in ua-parser-js version",
            "CVE": [
              "CVE-2022-25927"
            ],
            "githubID": "GHSA-fhg7-m89q-25r3"
          },
          "info": [
            "https://github.com/advisories/GHSA-fhg7-m89q-25r3",
            "https://github.com/faisalman/ua-parser-js/security/advisories/GHSA-fhg7-m89q-25r3",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-25927",
            "https://github.com/faisalman/ua-parser-js/commit/a6140a17dd0300a35cfc9cff999545f267889411",
            "https://github.com/faisalman/ua-parser-js",
            "https://security.snyk.io/vuln/SNYK-JS-UAPARSERJS-3244450"
          ]
        },
        {
          "atOrAbove": "0.8.0",
          "below": "0.8.1",
          "cwe": [
            "CWE-829",
            "CWE-912"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Embedded malware in ua-parser-js",
            "CVE": [],
            "githubID": "GHSA-pjwm-rvh2-c87w"
          },
          "info": [
            "https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
            "https://github.com/faisalman/ua-parser-js/issues/536",
            "https://github.com/faisalman/ua-parser-js/issues/536#issuecomment-949772496",
            "https://github.com/faisalman/ua-parser-js",
            "https://www.npmjs.com/package/ua-parser-js"
          ]
        },
        {
          "atOrAbove": "1.0.0",
          "below": "1.0.1",
          "cwe": [
            "CWE-829",
            "CWE-912"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Embedded malware in ua-parser-js",
            "CVE": [],
            "githubID": "GHSA-pjwm-rvh2-c87w"
          },
          "info": [
            "https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
            "https://github.com/faisalman/ua-parser-js/issues/536",
            "https://github.com/faisalman/ua-parser-js/issues/536#issuecomment-949772496",
            "https://github.com/faisalman/ua-parser-js",
            "https://www.npmjs.com/package/ua-parser-js"
          ]
        },
        {
          "atOrAbove": "0.8.0",
          "below": "1.0.33",
          "cwe": [
            "CWE-1333",
            "CWE-400"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "ReDoS Vulnerability in ua-parser-js version",
            "CVE": [
              "CVE-2022-25927"
            ],
            "githubID": "GHSA-fhg7-m89q-25r3"
          },
          "info": [
            "https://github.com/advisories/GHSA-fhg7-m89q-25r3",
            "https://github.com/faisalman/ua-parser-js/security/advisories/GHSA-fhg7-m89q-25r3",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-25927",
            "https://github.com/faisalman/ua-parser-js/commit/a6140a17dd0300a35cfc9cff999545f267889411",
            "https://github.com/faisalman/ua-parser-js",
            "https://security.snyk.io/vuln/SNYK-JS-UAPARSERJS-3244450"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/(§§version§§)/ua-parser(.min)?.js",
          "/ua-parser-js@(§§version§§)/"
        ],
        "filecontent": [
          "/\\* UAParser.js v(§§version§§)",
          "/\\*[*!](?:@license)?[\\s]+\\* UAParser.js v(§§version§§)",
          "// UAParser.js v(§§version§§)",
          ".\\.VERSION=\"(§§version§§)\",.\\.BROWSER=\\{NAME:.,MAJOR:\"major\",VERSION:.\\},.\\.CPU=\\{ARCHITECTURE:",
          ".\\.VERSION=\"(§§version§§)\",.\\.BROWSER=.\\(\\[[^\\]]{1,20}\\]\\),.\\.CPU=",
          "LIBVERSION=\"(§§version§§)\",EMPTY=\"\",UNKNOWN=\"\\?\",FUNC_TYPE=\"function\",UNDEF_TYPE=\"undefined\"",
          ".=\"(§§version§§)\",.=\"\",.=\"\\?\",.=\"function\",.=\"undefined\",.=\"object\",(.=\"string\",)?.=\"major\",.=\"model\",.=\"name\",.=\"type\",.=\"vendor\""
        ],
        "func": [
          "UAParser.VERSION",
          "$.ua.version"
        ],
        "ast": [
          "//SequenceExpression[       /AssignmentExpression[         /:left/:property/:name == \"VERSION\"       ]/:left/$:object == //AssignmentExpression[         /:left/:property/:name == \"UAParser\"       ]/$:right     ]/AssignmentExpression[       /:left/:property/:name == \"VERSION\"     ]/$$:right/:value",
          "//IfStatement[       /SequenceExpression/AssignmentExpression[         /:left/:property/:name == \"VERSION\"       ]/:left/$:object ==       /:consequent//AssignmentExpression[         /:left/:property/:name == \"UAParser\"       ]/$:right     ]/SequenceExpression/AssignmentExpression[       /:left/:property/:name == \"VERSION\"     ]/$$:right/:value",
          "//BlockStatement[       /ExpressionStatement         /AssignmentExpression[             /:left/:property/:name == \"VERSION\"           ]/:left/$:object ==         //AssignmentExpression[           /:left/:property/:name == \"UAParser\"         ]/$:right     ]/ExpressionStatement/AssignmentExpression[       /:left/:property/:name == \"VERSION\"     ]/$$:right/:value"
        ]
      }
    },
    "mathjax": {
      "licenses": [
        "Apache-2.0 >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "0",
          "below": "2.7.4",
          "cwe": [
            "CWE-79"
          ],
          "severity": "medium",
          "identifiers": {
            "summary": "Macro in MathJax running untrusted Javascript within a web browser",
            "CVE": [
              "CVE-2018-1999024"
            ],
            "githubID": "GHSA-3c48-6pcv-88rm"
          },
          "info": [
            "https://github.com/advisories/GHSA-3c48-6pcv-88rm",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1999024",
            "https://github.com/mathjax/MathJax/commit/a55da396c18cafb767a26aa9ad96f6f4199852f1",
            "https://blog.bentkowski.info/2018/06/xss-in-google-colaboratory-csp-bypass.html",
            "https://github.com/advisories/GHSA-3c48-6pcv-88rm",
            "https://github.com/mathjax/MathJax"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "2.7.10",
          "cwe": [
            "CWE-1333"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "MathJax Regular expression Denial of Service (ReDoS)",
            "CVE": [
              "CVE-2023-39663"
            ],
            "githubID": "GHSA-v638-q856-grg8"
          },
          "info": [
            "https://github.com/advisories/GHSA-v638-q856-grg8",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-39663",
            "https://github.com/mathjax/MathJax/issues/3074"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/mathjax@(§§version§§)/",
          "/mathjax/(§§version§§)/"
        ],
        "filecontent": [
          "\\.MathJax\\.config\\.startup;{10,100}.\\.VERSION=\"(§§version§§)\"",
          "\\.MathJax=\\{version:\"(§§version§§)\"",
          "MathJax.{0,100}.\\.VERSION=void 0,.\\.VERSION=\"(§§version§§)\"",
          "MathJax\\.version=\"(§§version§§)\";"
        ],
        "func": [
          "MathJax.version"
        ]
      }
    },
    "pdf.js": {
      "bowername": [
        "pdfjs-dist"
      ],
      "npmname": "pdfjs-dist",
      "licenses": [
        "Apache-2.0 >=0"
      ],
      "vulnerabilities": [
        {
          "atOrAbove": "0",
          "below": "1.10.100",
          "cwe": [
            "CWE-94"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Malicious PDF can inject JavaScript into PDF Viewer",
            "CVE": [
              "CVE-2018-5158"
            ],
            "githubID": "GHSA-7jg2-jgv3-fmr4"
          },
          "info": [
            "https://github.com/advisories/GHSA-7jg2-jgv3-fmr4",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-5158",
            "https://github.com/mozilla/pdf.js/pull/9659",
            "https://github.com/mozilla/pdf.js/commit/2dc4af525d1612c98afcd1e6bee57d4788f78f97",
            "https://access.redhat.com/errata/RHSA-2018:1414",
            "https://access.redhat.com/errata/RHSA-2018:1415",
            "https://bugzilla.mozilla.org/show_bug.cgi?id=1452075",
            "https://github.com/mozilla/pdf.js",
            "https://lists.debian.org/debian-lts-announce/2018/05/msg00007.html",
            "https://security.gentoo.org/glsa/201810-01",
            "https://usn.ubuntu.com/3645-1",
            "https://www.debian.org/security/2018/dsa-4199",
            "https://www.mozilla.org/security/advisories/mfsa2018-11",
            "https://www.mozilla.org/security/advisories/mfsa2018-12",
            "http://www.securityfocus.com/bid/104136",
            "http://www.securitytracker.com/id/1040896"
          ]
        },
        {
          "atOrAbove": "2.0.0",
          "below": "2.0.550",
          "cwe": [
            "CWE-94"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "Malicious PDF can inject JavaScript into PDF Viewer",
            "CVE": [
              "CVE-2018-5158"
            ],
            "githubID": "GHSA-7jg2-jgv3-fmr4"
          },
          "info": [
            "https://github.com/advisories/GHSA-7jg2-jgv3-fmr4",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-5158",
            "https://github.com/mozilla/pdf.js/pull/9659",
            "https://github.com/mozilla/pdf.js/commit/2dc4af525d1612c98afcd1e6bee57d4788f78f97",
            "https://access.redhat.com/errata/RHSA-2018:1414",
            "https://access.redhat.com/errata/RHSA-2018:1415",
            "https://bugzilla.mozilla.org/show_bug.cgi?id=1452075",
            "https://github.com/mozilla/pdf.js",
            "https://lists.debian.org/debian-lts-announce/2018/05/msg00007.html",
            "https://security.gentoo.org/glsa/201810-01",
            "https://usn.ubuntu.com/3645-1",
            "https://www.debian.org/security/2018/dsa-4199",
            "https://www.mozilla.org/security/advisories/mfsa2018-11",
            "https://www.mozilla.org/security/advisories/mfsa2018-12",
            "http://www.securityfocus.com/bid/104136",
            "http://www.securitytracker.com/id/1040896"
          ]
        },
        {
          "atOrAbove": "0",
          "below": "4.2.67",
          "cwe": [
            "CWE-754"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "PDF.js vulnerable to arbitrary JavaScript execution upon opening a malicious PDF",
            "CVE": [
              "CVE-2024-4367"
            ],
            "githubID": "GHSA-wgrm-67xf-hhpq"
          },
          "info": [
            "https://github.com/advisories/GHSA-wgrm-67xf-hhpq",
            "https://github.com/mozilla/pdf.js/security/advisories/GHSA-wgrm-67xf-hhpq",
            "https://github.com/mozilla/pdf.js/pull/18015",
            "https://github.com/mozilla/pdf.js/commit/85e64b5c16c9aaef738f421733c12911a441cec6",
            "https://bugzilla.mozilla.org/show_bug.cgi?id=1893645",
            "https://github.com/mozilla/pdf.js"
          ]
        }
      ],
      "extractors": {
        "uri": [
          "/pdf\\.js/(§§version§§)/",
          "/pdfjs-dist@(§§version§§)/"
        ],
        "filecontent": [
          "(?:const|var) pdfjsVersion = ['\"](§§version§§)['\"];",
          "PDFJS.version ?= ?['\"](§§version§§)['\"]",
          "apiVersion: ?['\"](§§version§§)['\"][\\s\\S]*,data(:[a-zA-Z.]{1,6})?,[\\s\\S]*password(:[a-zA-Z.]{1,10})?,[\\s\\S]*disableAutoFetch(:[a-zA-Z.]{1,22})?,[\\s\\S]*rangeChunkSize",
          "messageHandler\\.sendWithPromise\\(\"GetDocRequest\",\\{docId:[a-zA-Z],apiVersion:\"(§§version§§)\""
        ]
      }
    },
    "pdfobject": {
      "licenses": [
        "MIT >=0"
      ],
      "vulnerabilities": [],
      "extractors": {
        "uri": [
          "/pdfobject@(§§version§§)/",
          "/pdfobject/(§§version§§)/pdfobject(\\.min)?\\.js"
        ],
        "filecontent": [
          "\\* +PDFObject v(§§version§§)",
          "/*[\\s]+PDFObject v(§§version§§)",
          "let pdfobjectversion = \"(§§version§§)\";",
          "pdfobjectversion:\"(§§version§§)\""
        ]
      }
    },
    "dont check": {
      "licenses": [],
      "vulnerabilities": [],
      "extractors": {
        "uri": [
          "^http[s]?://(ssl|www).google-analytics.com/ga.js",
          "^http[s]?://apis.google.com/js/plusone.js",
          "^http[s]?://cdn.cxense.com/cx.js"
        ]
      }
    }
  },
  "backdoored": {
    "polyfill.io": [
      {
        "summary": "Reports indiciate that new owner of polyfill.io is serving malicious code. See info for more details.",
        "severity": "high",
        "extractors": [
          "^https://polyfill\\.io/",
          "^https://cdn\\.polyfill\\.io/",
          "^https://[a-z0-9\\-]+\\.polyfill\\.io/",
          "^https://www\\.googie-anaiytics\\.com/",
          "^https://kuurza\\.com/redirect\\?from=bitget",
          "^https://bootcdn.net/",
          "^https://bootcss.com/",
          "^https://staticfile.net/",
          "^https://staticfile.org/",
          "^https://unionadjs.com/",
          "^https://xhsbpza.com/",
          "^https://union.macoms.la/",
          "^https://newcrbpc.com/"
        ],
        "info": [
          "https://blog.cloudflare.com/automatically-replacing-polyfill-io-links-with-cloudflares-mirror-for-a-safer-internet",
          "https://sansec.io/research/polyfill-supply-chain-attack",
          "https://www.securityweek.com/polyfill-supply-chain-attack-hits-over-100k-websites/",
          "https://www.bleepingcomputer.com/news/security/polyfillio-bootcdn-bootcss-staticfile-attack-traced-to-1-operator/"
        ]
      }
    ]
  }
}
},{}]},{},[1])(1)
});
