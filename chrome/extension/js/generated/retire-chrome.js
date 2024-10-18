(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.retirechrome = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
const deepScan = require("../../node/lib/deepscan.js").deepScan;
const retire = require("../../node/lib/retire.js");
exports.repo = require("../../repository/jsrepository-v3.json");
exports.retire = retire;
exports.deepScan = deepScan;

},{"../../node/lib/deepscan.js":2,"../../node/lib/retire.js":3,"../../repository/jsrepository-v3.json":10}],2:[function(require,module,exports){
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
exports.version = '5.2.4';

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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseSource = exports.multiQuery = exports.query = exports.isAvailableFunction = exports.functions = void 0;
const traverse_1 = __importDefault(require("./traverse"));
const parseQuery_1 = require("./parseQuery");
const meriyah_1 = require("meriyah");
const nodeutils_1 = require("./nodeutils");
const debugLogEnabled = false;
const log = {
    debug: (...args) => {
        if (debugLogEnabled)
            console.debug(...args.map(x => typeof (x) == "object" && x != null && "valueOf" in x ? x.valueOf() : x));
    }
};
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
const functionNames = Object.keys(exports.functions);
function isAvailableFunction(name) {
    return functionNames.includes(name);
}
exports.isAvailableFunction = isAvailableFunction;
function breadCrumb(path) {
    return {
        valueOf() {
            if (path.parentPath == undefined)
                return "@" + path.node.type;
            return breadCrumb(path.parentPath) + "." + (path.parentKey == path.key ? path.key : path.parentKey + "[" + path.key + "]") + "@" + path.node.type;
        }
    };
}
function createQuerier() {
    const traverser = (0, traverse_1.default)();
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
                log.debug("ADDING FILTER CHILD", filter.node);
                state.child[state.depth + 1].push(filter);
            }
            if (filter.node.type == "descendant") {
                log.debug("ADDING FILTER DESCENDANT", filter.node);
                state.descendant[state.depth + 1].push(filter);
            }
        }
    }
    function createFNodeAndAddToState(token, result, state) {
        log.debug("ADDING FNODE", token);
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
                log.debug("ATTR MATCH", fnode.node.value, breadCrumb(path));
            return m;
        }
        if (fnode.node.value == "*") {
            return true;
        }
        const m = fnode.node.value == path.node.type;
        if (m)
            log.debug("NODE MATCH", fnode.node.value, breadCrumb(path));
        return m;
    }
    function addIfTokenMatch(fnode, path, state) {
        if (!isMatch(fnode, path))
            return;
        state.matches[state.depth].push([fnode, path]);
        if (fnode.node.filter) {
            const filter = createFilter(fnode.node.filter, []);
            const filteredResult = [];
            state.filters[state.depth].push({ filter: filter, qNode: fnode.node, node: path.node, result: filteredResult });
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
        log.debug("PRIMITIVE", fnode.node.value, nodes);
        fnode.result.push(...nodes);
    }
    function evaluateFilter(filter, path) {
        log.debug("EVALUATING FILTER", filter, breadCrumb(path));
        if ("type" in filter) {
            if (filter.type == "and") {
                const left = evaluateFilter(filter.left, path);
                if (left.length == 0)
                    return [];
                return evaluateFilter(filter.right, path);
            }
            if (filter.type == "or") {
                const left = evaluateFilter(filter.left, path);
                if (left.length > 0)
                    return left;
                return evaluateFilter(filter.right, path);
            }
            if (filter.type == "equals") {
                const left = evaluateFilter(filter.left, path);
                const right = evaluateFilter(filter.right, path);
                return left.filter(x => right.includes(x));
            }
            throw new Error("Unknown filter type: " + filter.type);
        }
        if (filter.node.type == "parent") {
            return resolveFilterWithParent(filter.node, path);
        }
        return filter.result;
    }
    function resolveBinding(path) {
        if (!(0, nodeutils_1.isIdentifier)(path.node))
            return undefined;
        log.debug("RESOLVING BINDING FOR ", path.node);
        const name = path.node.name;
        if (name == undefined || typeof name != "string")
            return undefined;
        //const binding = path.scope.getBinding(name);
        const binding = getBinding(path.scopeId, name);
        if (!binding)
            return undefined;
        log.debug("THIS IS THE BINDING", binding);
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
            log.debug("STEP OUT", startNode, breadCrumb(startPath));
            startNode = startNode.child;
            startPath = startPath.parentPath;
        }
        return resolveDirectly(startNode, startPath);
    }
    function isDefined(value) {
        return value != undefined && value != null;
    }
    let subQueryCounter = 0;
    function resolveDirectly(node, path) {
        let startNode = node;
        const startPath = path;
        let paths = [startPath];
        while (startNode.attribute && startNode.type == "child") {
            const lookup = startNode.value;
            if (!lookup)
                throw new Error("Selector must have a value");
            //log.debug("STEP IN ", lookup, paths.map(p => breadCrumb(p)));
            const nodes = paths.filter(nodeutils_1.isNodePath).map(n => getPrimitiveChildrenOrNodePaths(lookup, n)).flat();
            //log.debug("LOOKUP", lookup, path.node.type, nodes.map(n => n.node));
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
        //log.debug("DIRECT TRAV RESOLVE", startNode, paths.map(p => breadCrumb(p)));
        const result = paths.filter(nodeutils_1.isNodePath).flatMap(path => {
            const subQueryKey = "subquery-" + subQueryCounter++;
            return travHandle({ [subQueryKey]: startNode }, path)[subQueryKey];
        });
        log.debug("DIRECT TRAV RESOLVE RESULT", result);
        return result;
    }
    function addResultIfTokenMatch(fnode, path, state) {
        const filters = state.filters[state.depth].filter(f => f.node == path.node && f.qNode == fnode.node);
        const matchingFilters = filters.filter(f => evaluateFilter(f.filter, path).length > 0);
        log.debug("RESULT MATCH", fnode.node.value, breadCrumb(path), filters.length, matchingFilters.length);
        if (filters.length > 0 && matchingFilters.length == 0)
            return;
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
            log.debug("HAS MATCHING FILTER", fnode.result.length, matchingFilters.length, breadCrumb(path));
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
        log.debug("PARAMETER RESULTS", functionCallResult.functionCall.function, parameterResults, functionResult);
        fnode.result.push(...functionResult);
    }
    function travHandle(queries, root) {
        const results = Object.fromEntries(Object.keys(queries).map(name => [name, []]));
        const state = {
            depth: 0,
            child: [[], []],
            descendant: [[], []],
            filters: [[], []],
            matches: [[]],
            functionCalls: [[]]
        };
        Object.entries(queries).forEach(([name, node]) => {
            createFNodeAndAddToState(node, results[name], state);
        });
        state.child[state.depth + 1].forEach(fnode => addPrimitiveAttributeIfMatch(fnode, root));
        state.descendant.slice(0, state.depth + 1).forEach(fnodes => fnodes.forEach(fnode => addPrimitiveAttributeIfMatch(fnode, root)));
        traverse(root.node, {
            enter(path, state) {
                log.debug("ENTER", breadCrumb(path));
                state.depth++;
                state.child.push([]);
                state.descendant.push([]);
                state.filters.push([]);
                state.matches.push([]);
                state.functionCalls.push([]);
                state.child[state.depth].forEach(fnode => addIfTokenMatch(fnode, path, state));
                state.descendant.slice(0, state.depth + 1).forEach(fnodes => fnodes.forEach(fnode => addIfTokenMatch(fnode, path, state)));
            },
            exit(path, state) {
                log.debug("EXIT", breadCrumb(path));
                // Check for attributes as not all attributes are visited
                state.child[state.depth + 1].forEach(fnode => addPrimitiveAttributeIfMatch(fnode, path));
                state.descendant.forEach(fnodes => fnodes.forEach(fnode => addPrimitiveAttributeIfMatch(fnode, path)));
                state.matches[state.depth].forEach(([fNode, path]) => addResultIfTokenMatch(fNode, path, state));
                state.depth--;
                state.child.pop();
                state.descendant.pop();
                state.filters.pop();
                state.matches.pop();
                state.functionCalls.pop();
            }
        }, root.scopeId, state, root);
        return results;
    }
    function beginHandle(queries, path) {
        const rootPath = createNodePath(path, undefined, undefined, undefined, undefined);
        return travHandle(queries, rootPath);
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
exports.query = query;
function multiQuery(code, namedQueries, returnAST) {
    const start = Date.now();
    const ast = typeof code == "string" ? parseSource(code) : code;
    if (ast == null)
        throw new Error("Could not pase code");
    const queries = Object.fromEntries(Object.entries(namedQueries).map(([name, query]) => [name, (0, parseQuery_1.parse)(query)]));
    const querier = createQuerier();
    const result = querier.beginHandle(queries, ast);
    log.debug("Query time: ", Date.now() - start);
    if (returnAST) {
        return { ...result, __AST: ast };
    }
    return result;
}
exports.multiQuery = multiQuery;
function parseSource(source) {
    try {
        return (0, meriyah_1.parseScript)(source, { module: true, next: true, specDeviation: true });
    }
    catch (e) {
        return (0, meriyah_1.parseScript)(source, { module: false, next: true, specDeviation: true });
    }
}
exports.parseSource = parseSource;

},{"./nodeutils":5,"./parseQuery":6,"./traverse":7,"meriyah":9}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isExportSpecifier = exports.isScopable = exports.isScope = exports.VISITOR_KEYS = exports.isBinding = exports.isVariableDeclaration = exports.isVariableDeclarator = exports.isFunctionExpression = exports.isFunctionDeclaration = exports.isIdentifier = exports.isMemberExpression = exports.isAssignmentExpression = exports.isUpdateExpression = exports.isPrimitive = exports.isLiteral = exports.isNodePath = exports.isNode = void 0;
function isNode(candidate) {
    return typeof candidate === "object" && candidate != null && "type" in candidate;
}
exports.isNode = isNode;
function isNodePath(candidate) {
    return typeof candidate === "object" && candidate != null && "node" in candidate;
}
exports.isNodePath = isNodePath;
function isLiteral(candidate) {
    return isNode(candidate) && candidate.type === "Literal";
}
exports.isLiteral = isLiteral;
function isPrimitive(value) {
    return typeof value == "string" || typeof value == "number" || typeof value == "boolean";
}
exports.isPrimitive = isPrimitive;
function isUpdateExpression(value) {
    return isNode(value) && value.type === "UpdateExpression";
}
exports.isUpdateExpression = isUpdateExpression;
function isAssignmentExpression(node) {
    return node.type === "AssignmentExpression";
}
exports.isAssignmentExpression = isAssignmentExpression;
function isMemberExpression(node) {
    return node.type === "MemberExpression";
}
exports.isMemberExpression = isMemberExpression;
function isIdentifier(node) {
    return node.type === "Identifier";
}
exports.isIdentifier = isIdentifier;
function isFunctionDeclaration(node) {
    return node.type === "FunctionDeclaration";
}
exports.isFunctionDeclaration = isFunctionDeclaration;
function isFunctionExpression(node) {
    return node.type === "FunctionExpression";
}
exports.isFunctionExpression = isFunctionExpression;
function isVariableDeclarator(node) {
    return node.type === "VariableDeclarator";
}
exports.isVariableDeclarator = isVariableDeclarator;
function isVariableDeclaration(node) {
    return node.type === "VariableDeclaration";
}
exports.isVariableDeclaration = isVariableDeclaration;
function isBinding(node, parentNode, grandParentNode) {
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
}
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
    return isFunctionDeclaration(parentNode) || isFunctionExpression(parentNode) || isScopable(node);
}
exports.isScope = isScope;
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
exports.isScopable = isScopable;
function isExportSpecifier(node) {
    return node.type === "ExportSpecifier";
}
exports.isExportSpecifier = isExportSpecifier;

},{}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parse = exports.tokenize = void 0;
const _1 = require(".");
const nodeutils_1 = require("./nodeutils");
const debugLogEnabled = false;
const log = {
    debug: (...args) => {
        if (debugLogEnabled)
            console.debug(...args);
    }
};
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
exports.tokenize = tokenize;
function buildFilter(tokens) {
    log.debug("BUILD FILTER", tokens);
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
    log.debug("BUILD TREE", tokens);
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
            log.debug("FILTER", filter, tokens);
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
    log.debug("BUILD FUNCTION", name, tokens);
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
    log.debug("RESULT", result);
    if (!result)
        throw new Error("No root element found");
    return result;
}
exports.parse = parse;

},{".":4,"./nodeutils":5}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const nodeutils_1 = require("./nodeutils");
const utils_1 = require("./utils");
const debugLogEnabled = false;
const log = {
    debug: (...args) => {
        if (debugLogEnabled)
            console.debug(...args);
    }
};
const scopes = new Array(100000);
function createTraverser() {
    let scopeIdCounter = 0;
    let removedScopes = 0;
    const nodePathsCreated = {};
    function createScope(parentScopeId) {
        const id = scopeIdCounter++;
        scopes[id] = parentScopeId ?? -1;
        return id;
    }
    function getBinding(scopeId, name) {
        const scope = scopes[scopeId];
        if (typeof scope == "number") {
            if (scope == -1)
                return undefined;
            return getBinding(scope, name);
        }
        const s = scope.bindings[name];
        if (s != undefined)
            return s;
        if (scope.parentScopeId != undefined && scope.parentScopeId >= 0) {
            return getBinding(scope.parentScopeId, name);
        }
        return undefined;
    }
    function setBinding(scopeId, name, binding) {
        let scope;
        const s = scopes[scopeId];
        if (typeof s == "number") {
            scope = {
                bindings: {},
                id: scopeId,
                parentScopeId: s == -1 ? undefined : s,
            };
            scopes[scopeId] = scope;
        }
        else {
            scope = s;
        }
        scope.bindings[name] = binding;
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
            children.forEach((child, i) => {
                if (!(0, nodeutils_1.isNode)(child))
                    return;
                const f = key == "body" && ((0, nodeutils_1.isFunctionDeclaration)(node) || (0, nodeutils_1.isFunctionExpression)(node)) ? childScopeId : functionScopeId;
                stack.push(child);
                if ((0, nodeutils_1.isIdentifier)(child)) {
                    const k = Array.isArray(childNodes) ? i : key;
                    registerBinding(stack, childScopeId, f, k, key);
                }
                else {
                    registerBindings(stack, childScopeId, f);
                }
                stack.pop();
            });
        }
        if (childScopeId != scopeId && typeof scopes[childScopeId] == "number") { // Scope has not been populated
            scopes[childScopeId] = scopes[scopeId];
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
            const nodePaths = children.map((child, i) => {
                if ((0, nodeutils_1.isNode)(child)) {
                    return createNodePath(child, Array.isArray(childNodes) ? i : key, key, nodePath.scopeId, nodePath.functionScopeId, nodePath);
                }
                return undefined;
            }).filter(x => x != undefined);
            nodePaths.forEach((childPath) => {
                visitor.enter(childPath, state);
                traverseInner(childPath.node, visitor, nodePath.scopeId, nodePath.functionScopeId, state, childPath);
                visitor.exit(childPath, state);
            });
        }
    }
    const sOut = [];
    function traverse(node, visitor, scopeId, state, path) {
        const fscope = path?.functionScopeId ?? node.extra?.functionScopeId ?? scopeId;
        traverseInner(node, visitor, scopeId, fscope, state, path);
        if (!sOut.includes(scopeIdCounter)) {
            log.debug("Scopes created", scopeIdCounter, " Scopes removed", removedScopes, "Paths created", pathsCreated, bindingNodesVisited);
            sOut.push(scopeIdCounter);
            const k = Object.fromEntries(Object.entries(nodePathsCreated).sort((a, b) => a[1] - b[1]));
            log.debug("Node paths created", k);
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
exports.default = createTraverser;

},{"./nodeutils":5,"./utils":8}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isDefined = exports.toArray = void 0;
function toArray(value) {
    return Array.isArray(value) ? value : [value];
}
exports.toArray = toArray;
function isDefined(value) {
    return value != undefined && value != null;
}
exports.isDefined = isDefined;

},{}],9:[function(require,module,exports){
!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?t(exports):"function"==typeof define&&define.amd?define(["exports"],t):t((e="undefined"!=typeof globalThis?globalThis:e||self).meriyah={})}(this,(function(e){"use strict";const t={0:"Unexpected token",28:"Unexpected token: '%0'",1:"Octal escape sequences are not allowed in strict mode",2:"Octal escape sequences are not allowed in template strings",3:"Unexpected token `#`",4:"Illegal Unicode escape sequence",5:"Invalid code point %0",6:"Invalid hexadecimal escape sequence",8:"Octal literals are not allowed in strict mode",7:"Decimal integer literals with a leading zero are forbidden in strict mode",9:"Expected number in radix %0",146:"Invalid left-hand side assignment to a destructible right-hand side",10:"Non-number found after exponent indicator",11:"Invalid BigIntLiteral",12:"No identifiers allowed directly after numeric literal",13:"Escapes \\8 or \\9 are not syntactically valid escapes",14:"Unterminated string literal",15:"Unterminated template literal",16:"Multiline comment was not closed properly",17:"The identifier contained dynamic unicode escape that was not closed",18:"Illegal character '%0'",19:"Missing hexadecimal digits",20:"Invalid implicit octal",21:"Invalid line break in string literal",22:"Only unicode escapes are legal in identifier names",23:"Expected '%0'",24:"Invalid left-hand side in assignment",25:"Invalid left-hand side in async arrow",26:'Calls to super must be in the "constructor" method of a class expression or class declaration that has a superclass',27:"Member access on super must be in a method",29:"Await expression not allowed in formal parameter",30:"Yield expression not allowed in formal parameter",93:"Unexpected token: 'escaped keyword'",31:"Unary expressions as the left operand of an exponentiation expression must be disambiguated with parentheses",120:"Async functions can only be declared at the top level or inside a block",32:"Unterminated regular expression",33:"Unexpected regular expression flag",34:"Duplicate regular expression flag '%0'",35:"%0 functions must have exactly %1 argument%2",36:"Setter function argument must not be a rest parameter",37:"%0 declaration must have a name in this context",38:"Function name may not contain any reserved words or be eval or arguments in strict mode",39:"The rest operator is missing an argument",40:"A getter cannot be a generator",41:"A setter cannot be a generator",42:"A computed property name must be followed by a colon or paren",131:"Object literal keys that are strings or numbers must be a method or have a colon",44:"Found `* async x(){}` but this should be `async * x(){}`",43:"Getters and setters can not be generators",45:"'%0' can not be generator method",46:"No line break is allowed after '=>'",47:"The left-hand side of the arrow can only be destructed through assignment",48:"The binding declaration is not destructible",49:"Async arrow can not be followed by new expression",50:"Classes may not have a static property named 'prototype'",51:"Class constructor may not be a %0",52:"Duplicate constructor method in class",53:"Invalid increment/decrement operand",54:"Invalid use of `new` keyword on an increment/decrement expression",55:"`=>` is an invalid assignment target",56:"Rest element may not have a trailing comma",57:"Missing initializer in %0 declaration",58:"'for-%0' loop head declarations can not have an initializer",59:"Invalid left-hand side in for-%0 loop: Must have a single binding",60:"Invalid shorthand property initializer",61:"Property name __proto__ appears more than once in object literal",62:"Let is disallowed as a lexically bound name",63:"Invalid use of '%0' inside new expression",64:"Illegal 'use strict' directive in function with non-simple parameter list",65:'Identifier "let" disallowed as left-hand side expression in strict mode',66:"Illegal continue statement",67:"Illegal break statement",68:"Cannot have `let[...]` as a var name in strict mode",69:"Invalid destructuring assignment target",70:"Rest parameter may not have a default initializer",71:"The rest argument must the be last parameter",72:"Invalid rest argument",74:"In strict mode code, functions can only be declared at top level or inside a block",75:"In non-strict mode code, functions can only be declared at top level, inside a block, or as the body of an if statement",76:"Without web compatibility enabled functions can not be declared at top level, inside a block, or as the body of an if statement",77:"Class declaration can't appear in single-statement context",78:"Invalid left-hand side in for-%0",79:"Invalid assignment in for-%0",80:"for await (... of ...) is only valid in async functions and async generators",81:"The first token after the template expression should be a continuation of the template",83:"`let` declaration not allowed here and `let` cannot be a regular var name in strict mode",82:"`let \n [` is a restricted production at the start of a statement",84:"Catch clause requires exactly one parameter, not more (and no trailing comma)",85:"Catch clause parameter does not support default values",86:"Missing catch or finally after try",87:"More than one default clause in switch statement",88:"Illegal newline after throw",89:"Strict mode code may not include a with statement",90:"Illegal return statement",91:"The left hand side of the for-header binding declaration is not destructible",92:"new.target only allowed within functions",94:"'#' not followed by identifier",100:"Invalid keyword",99:"Can not use 'let' as a class name",98:"'A lexical declaration can't define a 'let' binding",97:"Can not use `let` as variable name in strict mode",95:"'%0' may not be used as an identifier in this context",96:"Await is only valid in async functions",101:"The %0 keyword can only be used with the module goal",102:"Unicode codepoint must not be greater than 0x10FFFF",103:"%0 source must be string",104:"Only a identifier can be used to indicate alias",105:"Only '*' or '{...}' can be imported after default",106:"Trailing decorator may be followed by method",107:"Decorators can't be used with a constructor",109:"HTML comments are only allowed with web compatibility (Annex B)",110:"The identifier 'let' must not be in expression position in strict mode",111:"Cannot assign to `eval` and `arguments` in strict mode",112:"The left-hand side of a for-of loop may not start with 'let'",113:"Block body arrows can not be immediately invoked without a group",114:"Block body arrows can not be immediately accessed without a group",115:"Unexpected strict mode reserved word",116:"Unexpected eval or arguments in strict mode",117:"Decorators must not be followed by a semicolon",118:"Calling delete on expression not allowed in strict mode",119:"Pattern can not have a tail",121:"Can not have a `yield` expression on the left side of a ternary",122:"An arrow function can not have a postfix update operator",123:"Invalid object literal key character after generator star",124:"Private fields can not be deleted",126:"Classes may not have a field called constructor",125:"Classes may not have a private element named constructor",127:"A class field initializer may not contain arguments",128:"Generators can only be declared at the top level or inside a block",129:"Async methods are a restricted production and cannot have a newline following it",130:"Unexpected character after object literal property name",132:"Invalid key token",133:"Label '%0' has already been declared",134:"continue statement must be nested within an iteration statement",135:"Undefined label '%0'",136:"Trailing comma is disallowed inside import(...) arguments",137:"import() requires exactly one argument",138:"Cannot use new with import(...)",139:"... is not allowed in import()",140:"Expected '=>'",141:"Duplicate binding '%0'",142:"Cannot export a duplicate name '%0'",145:"Duplicate %0 for-binding",143:"Exported binding '%0' needs to refer to a top-level declared variable",144:"Unexpected private field",148:"Numeric separators are not allowed at the end of numeric literals",147:"Only one underscore is allowed as numeric separator",149:"JSX value should be either an expression or a quoted JSX text",150:"Expected corresponding JSX closing tag for %0",151:"Adjacent JSX elements must be wrapped in an enclosing tag",152:"JSX attributes must only be assigned a non-empty 'expression'",153:"'%0' has already been declared",154:"'%0' shadowed a catch clause binding",155:"Dot property must be an identifier",156:"Encountered invalid input after spread/rest argument",157:"Catch without try",158:"Finally without try",159:"Expected corresponding closing tag for JSX fragment",160:"Coalescing and logical operators used together in the same expression must be disambiguated with parentheses",161:"Invalid tagged template on optional chain",162:"Invalid optional chain from super property",163:"Invalid optional chain from new expression",164:'Cannot use "import.meta" outside a module',165:"Leading decorators must be attached to a class declaration"};class n extends SyntaxError{constructor(e,n,o,r,...s){const a="["+n+":"+o+"]: "+t[r].replace(/%(\d+)/g,((e,t)=>s[t]));super(`${a}`),this.index=e,this.line=n,this.column=o,this.description=a,this.loc={line:n,column:o}}}function o(e,t,...o){throw new n(e.index,e.line,e.column,t,...o)}function r(e){throw new n(e.index,e.line,e.column,e.type,e.params)}function s(e,t,o,r,...s){throw new n(e,t,o,r,...s)}function a(e,t,o,r){throw new n(e,t,o,r)}const i=((e,t)=>{const n=new Uint32Array(104448);let o=0,r=0;for(;o<3701;){const s=e[o++];if(s<0)r-=s;else{let a=e[o++];2&s&&(a=t[a]),1&s?n.fill(a,r,r+=e[o++]):n[r++]=a}}return n})([-1,2,26,2,27,2,5,-1,0,77595648,3,44,2,3,0,14,2,57,2,58,3,0,3,0,3168796671,0,4294956992,2,1,2,0,2,59,3,0,4,0,4294966523,3,0,4,2,16,2,60,2,0,0,4294836735,0,3221225471,0,4294901942,2,61,0,134152192,3,0,2,0,4294951935,3,0,2,0,2683305983,0,2684354047,2,18,2,0,0,4294961151,3,0,2,2,19,2,0,0,608174079,2,0,2,54,2,7,2,6,0,4278222591,3,0,2,2,1,3,0,3,0,4294901711,2,40,0,4089839103,0,2961209759,0,1342439375,0,4294543342,0,3547201023,0,1577204103,0,4194240,0,4294688750,2,2,0,80831,0,4261478351,0,4294549486,2,2,0,2967484831,0,196559,0,3594373100,0,3288319768,0,8469959,2,200,2,3,0,4093640191,0,660618719,0,65487,0,4294828015,0,4092591615,0,1616920031,0,982991,2,3,2,0,0,2163244511,0,4227923919,0,4236247022,2,66,0,4284449919,0,851904,2,4,2,12,0,67076095,-1,2,67,0,1073741743,0,4093607775,-1,0,50331649,0,3265266687,2,33,0,4294844415,0,4278190047,2,20,2,133,-1,3,0,2,2,23,2,0,2,10,2,0,2,15,2,22,3,0,10,2,69,2,0,2,70,2,71,2,72,2,0,2,73,2,0,2,11,0,261632,2,25,3,0,2,2,13,2,4,3,0,18,2,74,2,5,3,0,2,2,75,0,2151677951,2,29,2,9,0,909311,3,0,2,0,814743551,2,42,0,67090432,3,0,2,2,41,2,0,2,6,2,0,2,30,2,8,0,268374015,2,107,2,48,2,0,2,76,0,134153215,-1,2,7,2,0,2,8,0,2684354559,0,67044351,0,3221160064,2,17,-1,3,0,2,0,67051519,0,1046528,3,0,3,2,9,2,0,2,50,0,4294960127,2,10,2,39,2,11,0,4294377472,2,12,3,0,16,2,13,2,0,2,79,2,10,2,0,2,80,2,81,2,82,2,206,2,129,0,1048577,2,83,2,14,-1,2,14,0,131042,2,84,2,85,2,86,2,0,2,34,-83,3,0,7,0,1046559,2,0,2,15,2,0,0,2147516671,2,21,3,87,2,2,0,-16,2,88,0,524222462,2,4,2,0,0,4269801471,2,4,3,0,2,2,28,2,16,3,0,2,2,17,2,0,-1,2,18,-16,3,0,206,-2,3,0,692,2,68,-1,2,18,2,10,3,0,8,2,90,2,128,2,0,0,3220242431,3,0,3,2,19,2,91,2,92,3,0,2,2,93,2,0,2,94,2,45,2,0,0,4351,2,0,2,9,3,0,2,0,67043391,0,3909091327,2,0,2,24,2,9,2,20,3,0,2,0,67076097,2,8,2,0,2,21,0,67059711,0,4236247039,3,0,2,0,939524103,0,8191999,2,98,2,99,2,22,2,23,3,0,3,0,67057663,3,0,349,2,100,2,101,2,7,-264,3,0,11,2,24,3,0,2,2,32,-1,0,3774349439,2,102,2,103,3,0,2,2,19,2,104,3,0,10,2,10,2,18,2,0,2,46,2,0,2,31,2,105,2,25,0,1638399,2,170,2,106,3,0,3,2,20,2,26,2,27,2,5,2,28,2,0,2,8,2,108,-1,2,109,2,110,2,111,-1,3,0,3,2,12,-2,2,0,2,29,-3,2,159,-4,2,20,2,0,2,36,0,1,2,0,2,62,2,6,2,12,2,10,2,0,2,112,-1,3,0,4,2,10,2,23,2,113,2,7,2,0,2,114,2,0,2,115,2,116,2,117,-2,3,0,9,2,21,2,30,2,31,2,118,2,119,-2,2,120,2,121,2,30,2,21,2,8,-2,2,122,2,30,2,32,-2,2,0,2,38,-2,0,4277137519,0,2269118463,-1,3,20,2,-1,2,33,2,37,2,0,3,30,2,2,35,2,19,-3,3,0,2,2,34,-1,2,0,2,35,2,0,2,35,2,0,2,47,-10,2,0,0,203775,-1,2,164,2,20,2,43,2,36,2,18,2,77,2,18,2,123,2,21,3,0,2,2,37,0,2151677888,2,0,2,12,0,4294901764,2,140,2,0,2,52,2,51,0,5242879,3,0,2,0,402644511,-1,2,125,2,38,0,3,-1,2,126,2,39,2,0,0,67045375,2,40,0,4226678271,0,3766565279,0,2039759,-4,3,0,2,0,3288270847,0,3,3,0,2,0,67043519,-5,2,0,0,4282384383,0,1056964609,-1,3,0,2,0,67043345,-1,2,0,2,41,2,42,-1,2,11,2,55,2,37,-5,2,0,2,12,-3,3,0,2,0,2147484671,2,130,0,4190109695,2,49,-2,2,131,0,4244635647,0,27,2,0,2,8,2,43,2,0,2,63,2,18,2,0,2,41,-8,2,53,2,44,0,67043329,2,45,2,46,0,8388351,-2,2,132,0,3028287487,2,47,2,134,0,33259519,2,42,-9,2,21,0,4294836223,0,3355443199,0,67043335,-2,2,64,-2,3,0,28,2,32,-3,3,0,3,2,17,3,0,6,2,78,-81,2,18,3,0,2,2,36,3,0,33,2,25,2,30,-125,3,0,18,2,37,-269,3,0,17,2,41,2,8,2,23,2,0,2,8,2,23,2,48,2,0,2,21,2,49,2,135,2,25,-21,3,0,2,-4,3,0,2,0,4294936575,2,0,0,4294934783,-2,0,196635,3,0,191,2,50,3,0,38,2,30,-1,2,34,-278,2,136,3,0,9,2,137,2,138,2,51,3,0,11,2,7,-72,3,0,3,2,139,0,1677656575,-147,2,0,2,24,2,37,-16,0,4161266656,0,4071,2,201,-4,0,28,-13,3,0,2,2,52,2,0,2,141,2,142,2,56,2,0,2,143,2,144,2,145,3,0,10,2,146,2,147,2,22,3,52,2,3,148,2,3,53,2,0,4294954999,2,0,-16,2,0,2,89,2,0,0,2105343,0,4160749584,2,174,-34,2,8,2,150,-6,0,4194303871,0,4294903771,2,0,2,54,2,97,-3,2,0,0,1073684479,0,17407,-9,2,18,2,17,2,0,2,32,-14,2,18,2,32,-23,2,151,3,0,6,0,8323103,-1,3,0,2,2,55,-37,2,56,2,152,2,153,2,154,2,155,2,156,-105,2,26,-32,3,0,1335,-1,3,0,129,2,32,3,0,6,2,10,3,0,180,2,157,3,0,233,2,158,3,0,18,2,10,-77,3,0,16,2,10,-47,3,0,154,2,6,3,0,130,2,25,-22250,3,0,7,2,25,-6130,3,5,2,-1,0,69207040,3,44,2,3,0,14,2,57,2,58,-3,0,3168731136,0,4294956864,2,1,2,0,2,59,3,0,4,0,4294966275,3,0,4,2,16,2,60,2,0,2,34,-1,2,18,2,61,-1,2,0,0,2047,0,4294885376,3,0,2,0,3145727,0,2617294944,0,4294770688,2,25,2,62,3,0,2,0,131135,2,95,0,70256639,0,71303167,0,272,2,41,2,6,0,32511,2,0,2,42,-1,2,96,2,63,0,4278255616,0,4294836227,0,4294549473,0,600178175,0,2952806400,0,268632067,0,4294543328,0,57540095,0,1577058304,0,1835008,0,4294688736,2,65,2,64,0,33554435,2,127,2,65,2,160,0,131075,0,3594373096,0,67094296,2,64,-1,0,4294828e3,0,603979263,0,654311424,0,3,0,4294828001,0,602930687,2,167,0,393219,0,4294828016,0,671088639,0,2154840064,0,4227858435,0,4236247008,2,66,2,37,-1,2,4,0,917503,2,37,-1,2,67,0,537788335,0,4026531935,-1,0,1,-1,2,33,2,68,0,7936,-3,2,0,0,2147485695,0,1010761728,0,4292984930,0,16387,2,0,2,15,2,22,3,0,10,2,69,2,0,2,70,2,71,2,72,2,0,2,73,2,0,2,12,-1,2,25,3,0,2,2,13,2,4,3,0,18,2,74,2,5,3,0,2,2,75,0,2147745791,3,19,2,0,122879,2,0,2,9,0,276824064,-2,3,0,2,2,41,2,0,0,4294903295,2,0,2,30,2,8,-1,2,18,2,48,2,0,2,76,2,42,-1,2,21,2,0,2,29,-2,0,128,-2,2,28,2,9,0,8160,-1,2,124,0,4227907585,2,0,2,77,2,0,2,78,2,180,2,10,2,39,2,11,-1,0,74440192,3,0,6,-2,3,0,8,2,13,2,0,2,79,2,10,2,0,2,80,2,81,2,82,-3,2,83,2,14,-3,2,84,2,85,2,86,2,0,2,34,-83,3,0,7,0,817183,2,0,2,15,2,0,0,33023,2,21,3,87,2,-17,2,88,0,524157950,2,4,2,0,2,89,2,4,2,0,2,22,2,28,2,16,3,0,2,2,17,2,0,-1,2,18,-16,3,0,206,-2,3,0,692,2,68,-1,2,18,2,10,3,0,8,2,90,0,3072,2,0,0,2147516415,2,10,3,0,2,2,25,2,91,2,92,3,0,2,2,93,2,0,2,94,2,45,0,4294965179,0,7,2,0,2,9,2,92,2,9,-1,0,1761345536,2,95,0,4294901823,2,37,2,20,2,96,2,35,2,97,0,2080440287,2,0,2,34,2,149,0,3296722943,2,0,0,1046675455,0,939524101,0,1837055,2,98,2,99,2,22,2,23,3,0,3,0,7,3,0,349,2,100,2,101,2,7,-264,3,0,11,2,24,3,0,2,2,32,-1,0,2700607615,2,102,2,103,3,0,2,2,19,2,104,3,0,10,2,10,2,18,2,0,2,46,2,0,2,31,2,105,-3,2,106,3,0,3,2,20,-1,3,5,2,2,107,2,0,2,8,2,108,-1,2,109,2,110,2,111,-1,3,0,3,2,12,-2,2,0,2,29,-8,2,20,2,0,2,36,-1,2,0,2,62,2,6,2,30,2,10,2,0,2,112,-1,3,0,4,2,10,2,18,2,113,2,7,2,0,2,114,2,0,2,115,2,116,2,117,-2,3,0,9,2,21,2,30,2,31,2,118,2,119,-2,2,120,2,121,2,30,2,21,2,8,-2,2,122,2,30,2,32,-2,2,0,2,38,-2,0,4277075969,2,30,-1,3,20,2,-1,2,33,2,123,2,0,3,30,2,2,35,2,19,-3,3,0,2,2,34,-1,2,0,2,35,2,0,2,35,2,0,2,78,-10,2,0,0,197631,-2,2,20,2,43,2,77,2,18,0,3,2,18,2,123,2,21,2,124,2,50,-1,0,2490368,2,124,2,25,2,18,2,34,2,124,2,37,0,4294901904,0,4718591,2,124,2,35,0,335544350,-1,2,125,0,2147487743,0,1,-1,2,126,2,39,2,8,-1,2,127,2,65,0,3758161920,0,3,-4,2,0,2,29,0,2147485568,0,3,2,0,2,25,0,176,-5,2,0,2,17,2,188,-1,2,0,2,25,2,205,-1,2,0,0,16779263,-2,2,12,-1,2,37,-5,2,0,2,128,-3,3,0,2,2,129,2,130,0,2147549183,0,2,-2,2,131,2,36,0,10,0,4294965249,0,67633151,0,4026597376,2,0,0,536871935,2,18,2,0,2,41,-8,2,53,2,17,0,1,2,45,2,25,-3,2,132,2,36,2,133,2,134,0,16778239,-10,2,35,0,4294836212,2,9,-3,2,64,-2,3,0,28,2,32,-3,3,0,3,2,17,3,0,6,2,78,-81,2,18,3,0,2,2,36,3,0,33,2,25,0,126,-125,3,0,18,2,37,-269,3,0,17,2,41,2,8,2,18,2,0,2,8,2,18,2,54,2,0,2,25,2,78,2,135,2,25,-21,3,0,2,-4,3,0,2,0,67583,-1,2,104,-2,0,11,3,0,191,2,50,3,0,38,2,30,-1,2,34,-278,2,136,3,0,9,2,137,2,138,2,51,3,0,11,2,7,-72,3,0,3,2,139,2,140,-187,3,0,2,2,52,2,0,2,141,2,142,2,56,2,0,2,143,2,144,2,145,3,0,10,2,146,2,147,2,22,3,52,2,3,148,2,3,53,2,2,149,-57,2,8,2,150,-7,2,18,2,0,2,54,-4,2,0,0,1065361407,0,16384,-9,2,18,2,54,2,0,2,128,-14,2,18,2,128,-23,2,151,3,0,6,2,123,-1,3,0,2,0,2063,-37,2,56,2,152,2,153,2,154,2,155,2,156,-138,3,0,1335,-1,3,0,129,2,32,3,0,6,2,10,3,0,180,2,157,3,0,233,2,158,3,0,18,2,10,-77,3,0,16,2,10,-47,3,0,154,2,6,3,0,130,2,25,-28386,2,0,0,1,-1,2,129,2,0,0,8193,-21,2,198,0,10255,0,4,-11,2,64,2,179,-1,0,71680,-1,2,171,0,4292900864,0,268435519,-5,2,159,-1,2,169,-1,0,6144,-2,2,45,-1,2,163,-1,0,2147532800,2,160,2,166,0,16744448,-2,0,4,-4,2,194,0,205128192,0,1333757536,0,2147483696,0,423953,0,747766272,0,2717763192,0,4286578751,0,278545,2,161,0,4294886464,0,33292336,0,417809,2,161,0,1327482464,0,4278190128,0,700594195,0,1006647527,0,4286497336,0,4160749631,2,162,0,201327104,0,3634348576,0,8323120,2,162,0,202375680,0,2678047264,0,4293984304,2,162,-1,0,983584,0,48,0,58720273,0,3489923072,0,10517376,0,4293066815,0,1,0,2013265920,2,182,2,0,0,2089,0,3221225552,0,201359520,2,0,-2,0,256,0,122880,0,16777216,2,159,0,4160757760,2,0,-6,2,176,-11,0,3263218176,-1,0,49664,0,2160197632,0,8388802,-1,0,12713984,-1,2,163,2,164,2,183,-2,2,172,-20,0,3758096385,-2,2,165,2,191,2,91,2,177,0,4294057984,-2,2,173,2,168,0,4227874816,-2,2,165,-1,2,166,-1,2,178,2,129,0,4026593280,0,14,0,4292919296,-1,2,175,0,939588608,-1,0,805306368,-1,2,129,2,167,2,168,2,169,2,207,2,0,-2,2,170,2,129,-3,0,267386880,-1,0,117440512,0,7168,-1,2,210,2,163,2,171,2,184,-16,2,172,-1,0,1426112704,2,173,-1,2,192,0,271581216,0,2149777408,2,25,2,171,2,129,0,851967,2,185,-1,2,174,2,186,-4,2,175,-20,2,197,2,204,-56,0,3145728,2,187,-10,0,32505856,-1,2,176,-1,0,2147385088,2,91,1,2155905152,2,-3,2,173,2,0,0,67108864,-2,2,177,-6,2,178,2,25,0,1,-1,0,1,-1,2,179,-3,2,123,2,64,-2,2,97,-2,0,32752,2,129,-915,2,170,-1,2,203,-10,2,190,-5,2,181,-6,0,4229232640,2,19,-1,2,180,-1,2,181,-2,0,4227874752,-3,0,2146435072,2,164,-2,0,1006649344,2,129,-1,2,91,0,201375744,-3,0,134217720,2,91,0,4286677377,0,32896,-1,2,175,-3,0,4227907584,-349,0,65520,0,1920,2,182,3,0,264,-11,2,169,-2,2,183,2,0,0,520617856,0,2692743168,0,36,-3,0,524280,-13,2,189,-1,0,4294934272,2,25,2,183,-1,2,213,0,2158720,-3,2,164,0,1,-4,2,129,0,3808625411,0,3489628288,0,4096,0,1207959680,0,3221274624,2,0,-3,2,184,0,120,0,7340032,-2,2,185,2,4,2,25,2,173,3,0,4,2,164,-1,2,186,2,182,-1,0,8176,2,166,2,184,2,211,-1,0,4290773232,2,0,-4,2,173,2,193,0,15728640,2,182,-1,2,171,-1,0,134250480,0,4720640,0,3825467396,3,0,2,-9,2,91,2,178,0,4294967040,2,133,0,4160880640,3,0,2,0,704,0,1849688064,2,187,-1,2,129,0,4294901887,2,0,0,130547712,0,1879048192,2,208,3,0,2,-1,2,188,2,189,-1,0,17829776,0,2025848832,2,212,-2,2,0,-1,0,4286580608,-1,0,29360128,2,196,0,16252928,0,3791388672,2,39,3,0,2,-2,2,202,2,0,-1,2,104,-1,0,66584576,-1,2,195,3,0,9,2,129,-1,0,4294755328,2,0,2,20,-1,2,171,2,183,2,25,2,95,2,25,2,190,2,91,-2,0,245760,2,191,-1,2,159,2,199,0,4227923456,-1,2,192,2,171,2,91,-3,0,4292870145,0,262144,-1,2,92,2,0,0,1073758848,2,193,-1,0,4227921920,2,194,0,68289024,0,528402016,0,4292927536,3,0,4,-2,0,268435456,2,92,-2,2,195,3,0,5,-1,2,196,2,173,2,0,-2,0,4227923936,2,62,-1,2,183,2,95,2,0,2,163,2,175,2,197,3,0,5,-1,2,182,3,0,3,-2,0,2146959360,0,9440640,0,104857600,0,4227923840,3,0,2,0,768,2,198,2,28,-2,2,171,-2,2,199,-1,2,165,2,95,3,0,7,0,512,0,8388608,2,200,2,170,2,189,0,4286578944,3,0,2,0,1152,0,1266679808,2,195,0,576,0,4261707776,2,95,3,0,9,2,165,0,131072,0,939524096,2,183,3,0,2,2,16,-1,0,2147221504,-28,2,183,3,0,3,-3,0,4292902912,-6,2,96,3,0,81,2,25,-2,2,104,-33,2,18,2,178,3,0,125,-18,2,197,3,0,269,-17,2,165,2,129,2,201,-1,2,129,2,193,0,4290822144,-2,0,67174336,0,520093700,2,18,3,0,21,-2,2,184,3,0,3,-2,0,30720,-1,0,32512,3,0,2,0,4294770656,-191,2,181,-38,2,178,2,0,2,202,3,0,278,0,2417033215,-9,0,4294705144,0,4292411391,0,65295,-11,2,182,3,0,72,-3,0,3758159872,0,201391616,3,0,147,-1,2,169,2,203,-3,2,96,2,0,-7,2,178,-1,0,384,-1,0,133693440,-3,2,204,-2,2,107,3,0,3,3,177,2,-2,2,91,2,165,3,0,4,-2,2,192,-1,2,159,0,335552923,2,205,-1,0,538974272,0,2214592512,0,132e3,-10,0,192,-8,2,206,-21,0,134213632,2,158,3,0,34,2,129,0,4294965279,3,0,6,0,100663424,0,63524,-1,2,209,2,148,3,0,3,-1,0,3221282816,0,4294917120,3,0,9,2,25,2,207,-1,2,208,3,0,14,2,25,2,183,3,0,23,0,2147520640,-6,0,4286578784,2,0,-2,0,1006694400,3,0,24,2,36,-1,0,4292870144,3,0,2,0,1,2,173,3,0,6,2,205,0,4110942569,0,1432950139,0,2701658217,0,4026532864,0,4026532881,2,0,2,46,3,0,8,-1,2,175,-2,2,177,0,98304,0,65537,2,178,-5,2,209,2,0,2,77,2,199,2,182,0,4294770176,2,107,3,0,4,-30,2,188,0,3758153728,-3,0,125829120,-2,2,183,0,4294897664,2,175,-1,2,195,-1,2,171,0,4294754304,3,0,2,-10,2,177,0,3758145536,2,210,2,211,0,4026548160,2,212,-4,2,213,-1,2,204,0,4227923967,3,0,32,-1335,2,0,-129,2,183,-6,2,173,-180,0,65532,-233,2,174,-18,2,173,3,0,77,-16,2,173,3,0,47,-154,2,166,-130,2,18,3,0,22250,-7,2,18,3,0,6128],[4294967295,4294967291,4092460543,4294828031,4294967294,134217726,4294903807,268435455,2147483647,1048575,1073741823,3892314111,134217727,1061158911,536805376,4294910143,4294901759,32767,4294901760,262143,536870911,8388607,4160749567,4294902783,4294918143,65535,67043328,2281701374,4294967264,2097151,4194303,255,67108863,4294967039,511,524287,131071,127,3238002687,4294902271,4294549487,33554431,1023,4294901888,4286578687,4294705152,4294770687,67043583,2047999,67043343,16777215,4294902e3,4292870143,4294966783,16383,67047423,4294967279,262083,20511,4290772991,41943039,493567,4294959104,603979775,65536,602799615,805044223,4294965206,8191,1031749119,4294917631,2134769663,4286578493,4282253311,4294942719,33540095,4294905855,63,15,2868854591,1608515583,265232348,534519807,2147614720,1060109444,4093640016,17376,2139062143,224,4169138175,4294909951,4286578688,4294967292,4294965759,65734655,4294966272,4294967280,32768,8289918,4294934399,4294901775,4294965375,1602223615,4294967259,4294443008,268369920,4292804608,4294967232,486341884,4294963199,3087007615,1073692671,4128527,4279238655,4294902015,4160684047,4290246655,469499899,4294967231,134086655,4294966591,2445279231,3670015,31,4294967288,4294705151,3221208447,4294549472,4095,2147483648,4285526655,4294966527,4294966143,64,4294966719,3774873592,1877934080,262151,2555904,536807423,67043839,3758096383,3959414372,3755993023,2080374783,4294835295,4294967103,4160749565,4294934527,4087,2016,2147446655,184024726,2862017156,1593309078,268434431,268434414,4294901763,4294901761,536870912,2952790016,202506752,139264,402653184,3758096384,4261412864,63488,1610612736,4227922944,49152,57344,65280,3233808384,3221225472,65534,61440,57152,4293918720,4290772992,25165824,4227915776,4278190080,4026531840,4227858432,4160749568,3758129152,4294836224,4194304,251658240,196608,4294963200,2143289344,2097152,64512,417808,4227923712,12582912,4294967168,50331648,65528,65472,15360,4294966784,65408,4294965248,16,12288,4294934528,2080374784,4294950912,65024,1073741824,4261477888,524288]);function l(e){return e.column++,e.currentChar=e.source.charCodeAt(++e.index)}function c(e,t){if(55296!=(64512&t))return 0;const n=e.source.charCodeAt(e.index+1);return 56320!=(64512&n)?0:(t=e.currentChar=65536+((1023&t)<<10)+(1023&n),1&i[0+(t>>>5)]>>>t||o(e,18,p(t)),e.index++,e.column++,1)}function u(e,t){e.currentChar=e.source.charCodeAt(++e.index),e.flags|=1,4&t||(e.column=0,e.line++)}function d(e){e.flags|=1,e.currentChar=e.source.charCodeAt(++e.index),e.column=0,e.line++}function p(e){return e<=65535?String.fromCharCode(e):String.fromCharCode(e>>>10)+String.fromCharCode(1023&e)}function f(e){return e<65?e-48:e-65+10&15}const k=[0,0,0,0,0,0,0,0,0,0,1032,0,0,2056,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8192,0,3,0,0,8192,0,0,0,256,0,33024,0,0,242,242,114,114,114,114,114,114,594,594,0,0,16384,0,0,0,0,67,67,67,67,67,67,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,1,0,0,4099,0,71,71,71,71,71,71,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,16384,0,0,0,0],g=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0],m=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0];function b(e){return e<=127?g[e]:1&i[34816+(e>>>5)]>>>e}function h(e){return e<=127?m[e]:1&i[0+(e>>>5)]>>>e||8204===e||8205===e}const P=["SingleLine","MultiLine","HTMLOpen","HTMLClose","HashbangComment"];function y(e,t,n,r,s,a,i,l){return 2048&r&&o(e,0),x(e,t,n,s,a,i,l)}function x(e,t,n,o,r,s,a){const{index:i}=e;for(e.tokenPos=e.index,e.linePos=e.line,e.colPos=e.column;e.index<e.end;){if(8&k[e.currentChar]){const n=13===e.currentChar;d(e),n&&e.index<e.end&&10===e.currentChar&&(e.currentChar=t.charCodeAt(++e.index));break}if((8232^e.currentChar)<=1){d(e);break}l(e),e.tokenPos=e.index,e.linePos=e.line,e.colPos=e.column}if(e.onComment){const n={start:{line:s,column:a},end:{line:e.linePos,column:e.colPos}};e.onComment(P[255&o],t.slice(i,e.tokenPos),r,e.tokenPos,n)}return 1|n}function v(e,t,n){const{index:r}=e;for(;e.index<e.end;)if(e.currentChar<43){let o=!1;for(;42===e.currentChar;)if(o||(n&=-5,o=!0),47===l(e)){if(l(e),e.onComment){const n={start:{line:e.linePos,column:e.colPos},end:{line:e.line,column:e.column}};e.onComment(P[1],t.slice(r,e.index-2),r-2,e.index,n)}return e.tokenPos=e.index,e.linePos=e.line,e.colPos=e.column,n}if(o)continue;8&k[e.currentChar]?13===e.currentChar?(n|=5,d(e)):(u(e,n),n=-5&n|1):l(e)}else(8232^e.currentChar)<=1?(n=-5&n|1,d(e)):(n&=-5,l(e));o(e,16)}function w(e,t){const n=e.index;let r=0;e:for(;;){const t=e.currentChar;if(l(e),1&r)r&=-2;else switch(t){case 47:if(r)break;break e;case 92:r|=1;break;case 91:r|=2;break;case 93:r&=1;break;case 13:case 10:case 8232:case 8233:o(e,32)}if(e.index>=e.source.length)return o(e,32)}const s=e.index-1;let a=0,i=e.currentChar;const{index:c}=e;for(;h(i);){switch(i){case 103:2&a&&o(e,34,"g"),a|=2;break;case 105:1&a&&o(e,34,"i"),a|=1;break;case 109:4&a&&o(e,34,"m"),a|=4;break;case 117:16&a&&o(e,34,"u"),a|=16;break;case 121:8&a&&o(e,34,"y"),a|=8;break;case 115:32&a&&o(e,34,"s"),a|=32;break;case 100:64&a&&o(e,34,"d"),a|=64;break;default:o(e,33)}i=l(e)}const u=e.source.slice(c,e.index),d=e.source.slice(n,s);return e.tokenRegExp={pattern:d,flags:u},512&t&&(e.tokenRaw=e.source.slice(e.tokenPos,e.index)),e.tokenValue=function(e,t,n){try{return new RegExp(t,n)}catch(r){try{return new RegExp(t,n.replace("d","")),null}catch(t){o(e,32)}}}(e,d,u),65540}function q(e,t,n){const{index:r}=e;let s="",a=l(e),i=e.index;for(;!(8&k[a]);){if(a===n)return s+=e.source.slice(i,e.index),l(e),512&t&&(e.tokenRaw=e.source.slice(r,e.index)),e.tokenValue=s,134283267;if(!(8&~a)&&92===a){if(s+=e.source.slice(i,e.index),a=l(e),a<127||8232===a||8233===a){const n=C(e,t,a);n>=0?s+=p(n):E(e,n,0)}else s+=p(a);i=e.index+1}e.index>=e.end&&o(e,14),a=l(e)}o(e,14)}function C(e,t,n){switch(n){case 98:return 8;case 102:return 12;case 114:return 13;case 110:return 10;case 116:return 9;case 118:return 11;case 13:if(e.index<e.end){const t=e.source.charCodeAt(e.index+1);10===t&&(e.index=e.index+1,e.currentChar=t)}case 10:case 8232:case 8233:return e.column=-1,e.line++,-1;case 48:case 49:case 50:case 51:{let o=n-48,r=e.index+1,s=e.column+1;if(r<e.end){const n=e.source.charCodeAt(r);if(32&k[n]){if(1024&t)return-2;if(e.currentChar=n,o=o<<3|n-48,r++,s++,r<e.end){const t=e.source.charCodeAt(r);32&k[t]&&(e.currentChar=t,o=o<<3|t-48,r++,s++)}e.flags|=64,e.index=r-1,e.column=s-1}else if((0!==o||512&k[n])&&1024&t)return-2}return o}case 52:case 53:case 54:case 55:{if(1024&t)return-2;let o=n-48;const r=e.index+1,s=e.column+1;if(r<e.end){const t=e.source.charCodeAt(r);32&k[t]&&(o=o<<3|t-48,e.currentChar=t,e.index=r,e.column=s)}return e.flags|=64,o}case 120:{const t=l(e);if(!(64&k[t]))return-4;const n=f(t),o=l(e);if(!(64&k[o]))return-4;return n<<4|f(o)}case 117:{const t=l(e);if(123===e.currentChar){let t=0;for(;64&k[l(e)];)if(t=t<<4|f(e.currentChar),t>1114111)return-5;return e.currentChar<1||125!==e.currentChar?-4:t}{if(!(64&k[t]))return-4;const n=e.source.charCodeAt(e.index+1);if(!(64&k[n]))return-4;const o=e.source.charCodeAt(e.index+2);if(!(64&k[o]))return-4;const r=e.source.charCodeAt(e.index+3);return 64&k[r]?(e.index+=3,e.column+=3,e.currentChar=e.source.charCodeAt(e.index),f(t)<<12|f(n)<<8|f(o)<<4|f(r)):-4}}case 56:case 57:if(!(256&t))return-3;default:return n}}function E(e,t,n){switch(t){case-1:return;case-2:o(e,n?2:1);case-3:o(e,13);case-4:o(e,6);case-5:o(e,102)}}function S(e,t){const{index:n}=e;let r=67174409,s="",a=l(e);for(;96!==a;){if(36===a&&123===e.source.charCodeAt(e.index+1)){l(e),r=67174408;break}if(8&~a||92!==a)e.index<e.end&&13===a&&10===e.source.charCodeAt(e.index)&&(s+=p(a),e.currentChar=e.source.charCodeAt(++e.index)),((83&a)<3&&10===a||(8232^a)<=1)&&(e.column=-1,e.line++),s+=p(a);else if(a=l(e),a>126)s+=p(a);else{const n=C(e,1024|t,a);if(n>=0)s+=p(n);else{if(-1!==n&&65536&t){s=void 0,a=A(e,a),a<0&&(r=67174408);break}E(e,n,1)}}e.index>=e.end&&o(e,15),a=l(e)}return l(e),e.tokenValue=s,e.tokenRaw=e.source.slice(n+1,e.index-(67174409===r?1:2)),r}function A(e,t){for(;96!==t;){switch(t){case 36:{const n=e.index+1;if(n<e.end&&123===e.source.charCodeAt(n))return e.index=n,e.column++,-t;break}case 10:case 8232:case 8233:e.column=-1,e.line++}e.index>=e.end&&o(e,15),t=l(e)}return t}function L(e,t){return e.index>=e.end&&o(e,0),e.index--,e.column--,S(e,t)}function D(e,t,n){let r=e.currentChar,s=0,i=9,c=64&n?0:1,u=0,d=0;if(64&n)s="."+V(e,r),r=e.currentChar,110===r&&o(e,11);else{if(48===r)if(r=l(e),120==(32|r)){for(n=136,r=l(e);4160&k[r];)95!==r?(d=1,s=16*s+f(r),u++,r=l(e)):(d||o(e,147),d=0,r=l(e));0!==u&&d||o(e,0===u?19:148)}else if(111==(32|r)){for(n=132,r=l(e);4128&k[r];)95!==r?(d=1,s=8*s+(r-48),u++,r=l(e)):(d||o(e,147),d=0,r=l(e));0!==u&&d||o(e,0===u?0:148)}else if(98==(32|r)){for(n=130,r=l(e);4224&k[r];)95!==r?(d=1,s=2*s+(r-48),u++,r=l(e)):(d||o(e,147),d=0,r=l(e));0!==u&&d||o(e,0===u?0:148)}else if(32&k[r])for(1024&t&&o(e,1),n=1;16&k[r];){if(512&k[r]){n=32,c=0;break}s=8*s+(r-48),r=l(e)}else 512&k[r]?(1024&t&&o(e,1),e.flags|=64,n=32):95===r&&o(e,0);if(48&n){if(c){for(;i>=0&&4112&k[r];)95!==r?(d=0,s=10*s+(r-48),r=l(e),--i):(r=l(e),(95===r||32&n)&&a(e.index,e.line,e.index+1,147),d=1);if(d&&a(e.index,e.line,e.index+1,148),i>=0&&!b(r)&&46!==r)return e.tokenValue=s,512&t&&(e.tokenRaw=e.source.slice(e.tokenPos,e.index)),134283266}s+=V(e,r),r=e.currentChar,46===r&&(95===l(e)&&o(e,0),n=64,s+="."+V(e,e.currentChar),r=e.currentChar)}}const p=e.index;let g=0;if(110===r&&128&n)g=1,r=l(e);else if(101==(32|r)){r=l(e),256&k[r]&&(r=l(e));const{index:t}=e;16&k[r]||o(e,10),s+=e.source.substring(p,t)+V(e,r),r=e.currentChar}return(e.index<e.end&&16&k[r]||b(r))&&o(e,12),g?(e.tokenRaw=e.source.slice(e.tokenPos,e.index),e.tokenValue=BigInt(s),134283389):(e.tokenValue=15&n?s:32&n?parseFloat(e.source.substring(e.tokenPos,e.index)):+s,512&t&&(e.tokenRaw=e.source.slice(e.tokenPos,e.index)),134283266)}function V(e,t){let n=0,o=e.index,r="";for(;4112&k[t];)if(95!==t)n=0,t=l(e);else{const{index:s}=e;95===(t=l(e))&&a(e.index,e.line,e.index+1,147),n=1,r+=e.source.substring(o,s),o=e.index}return n&&a(e.index,e.line,e.index+1,148),r+e.source.substring(o,e.index)}const T=["end of source","identifier","number","string","regular expression","false","true","null","template continuation","template tail","=>","(","{",".","...","}",")",";",",","[","]",":","?","'",'"',"</","/>","++","--","=","<<=",">>=",">>>=","**=","+=","-=","*=","/=","%=","^=","|=","&=","||=","&&=","??=","typeof","delete","void","!","~","+","-","in","instanceof","*","%","/","**","&&","||","===","!==","==","!=","<=",">=","<",">","<<",">>",">>>","&","|","^","var","let","const","break","case","catch","class","continue","debugger","default","do","else","export","extends","finally","for","function","if","import","new","return","super","switch","this","throw","try","while","with","implements","interface","package","private","protected","public","static","yield","as","async","await","constructor","get","set","from","of","enum","eval","arguments","escaped keyword","escaped future reserved keyword","reserved if strict","#","BigIntLiteral","??","?.","WhiteSpace","Illegal","LineTerminator","PrivateField","Template","@","target","meta","LineFeed","Escaped","JSXText"],R=Object.create(null,{this:{value:86113},function:{value:86106},if:{value:20571},return:{value:20574},var:{value:86090},else:{value:20565},for:{value:20569},new:{value:86109},in:{value:8738868},typeof:{value:16863277},while:{value:20580},case:{value:20558},break:{value:20557},try:{value:20579},catch:{value:20559},delete:{value:16863278},throw:{value:86114},switch:{value:86112},continue:{value:20561},default:{value:20563},instanceof:{value:8476725},do:{value:20564},void:{value:16863279},finally:{value:20568},async:{value:209007},await:{value:209008},class:{value:86096},const:{value:86092},constructor:{value:12401},debugger:{value:20562},export:{value:20566},extends:{value:20567},false:{value:86021},from:{value:12404},get:{value:12402},implements:{value:36966},import:{value:86108},interface:{value:36967},let:{value:241739},null:{value:86023},of:{value:274549},package:{value:36968},private:{value:36969},protected:{value:36970},public:{value:36971},set:{value:12403},static:{value:36972},super:{value:86111},true:{value:86022},with:{value:20581},yield:{value:241773},enum:{value:86134},eval:{value:537079927},as:{value:77934},arguments:{value:537079928},target:{value:143494},meta:{value:143495}});function I(e,t,n){for(;m[l(e)];);return e.tokenValue=e.source.slice(e.tokenPos,e.index),92!==e.currentChar&&e.currentChar<=126?R[e.tokenValue]||208897:U(e,t,0,n)}function N(e,t){const n=O(e);return h(n)||o(e,4),e.tokenValue=p(n),U(e,t,1,4&k[n])}function U(e,t,n,r){let s=e.index;for(;e.index<e.end;)if(92===e.currentChar){e.tokenValue+=e.source.slice(s,e.index),n=1;const t=O(e);h(t)||o(e,4),r=r&&4&k[t],e.tokenValue+=p(t),s=e.index}else{if(!h(e.currentChar)&&!c(e,e.currentChar))break;l(e)}e.index<=e.end&&(e.tokenValue+=e.source.slice(s,e.index));const a=e.tokenValue.length;if(r&&a>=2&&a<=11){const o=R[e.tokenValue];return void 0===o?208897:n?209008===o?4196352&t?121:o:1024&t?36972===o?122:36864&~o?20480&~o?143483:268435456&t&&!(8192&t)?o:121:122:!(268435456&t)||8192&t||20480&~o?241773===o?268435456&t?143483:2097152&t?121:o:209007===o?143483:36864&~o?121:o:o:o}return 208897}function B(e){return b(l(e))||o(e,94),131}function O(e){return 117!==e.source.charCodeAt(e.index+1)&&o(e,4),e.currentChar=e.source.charCodeAt(e.index+=2),function(e){let t=0;const n=e.currentChar;if(123===n){const n=e.index-2;for(;64&k[l(e)];)t=t<<4|f(e.currentChar),t>1114111&&a(n,e.line,e.index+1,102);return 125!==e.currentChar&&a(n,e.line,e.index-1,6),l(e),t}64&k[n]||o(e,6);const r=e.source.charCodeAt(e.index+1);64&k[r]||o(e,6);const s=e.source.charCodeAt(e.index+2);64&k[s]||o(e,6);const i=e.source.charCodeAt(e.index+3);64&k[i]||o(e,6);return t=f(n)<<12|f(r)<<8|f(s)<<4|f(i),e.currentChar=e.source.charCodeAt(e.index+=4),t}(e)}const G=[129,129,129,129,129,129,129,129,129,128,136,128,128,130,129,129,129,129,129,129,129,129,129,129,129,129,129,129,129,129,129,129,128,16842800,134283267,131,208897,8457015,8455751,134283267,67174411,16,8457014,25233970,18,25233971,67108877,8457016,134283266,134283266,134283266,134283266,134283266,134283266,134283266,134283266,134283266,134283266,21,1074790417,8456258,1077936157,8456259,22,133,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,69271571,137,20,8455497,208897,132,4096,4096,4096,4096,4096,4096,4096,208897,4096,208897,208897,4096,208897,4096,208897,4096,208897,4096,4096,4096,208897,4096,4096,208897,4096,4096,2162700,8455240,1074790415,16842801,129];function F(e,t){if(e.flags=1^(1|e.flags),e.startPos=e.index,e.startColumn=e.column,e.startLine=e.line,e.token=j(e,t,0),e.onToken&&1048576!==e.token){const t={start:{line:e.linePos,column:e.colPos},end:{line:e.line,column:e.column}};e.onToken(function(e){switch(e){case 134283266:return"NumericLiteral";case 134283267:return"StringLiteral";case 86021:case 86022:return"BooleanLiteral";case 86023:return"NullLiteral";case 65540:return"RegularExpression";case 67174408:case 67174409:case 132:return"TemplateLiteral";default:return 143360&~e?4096&~e?"Punctuator":"Keyword":"Identifier"}}(e.token),e.tokenPos,e.index,t)}}function j(e,t,n){const r=0===e.index,s=e.source;let a=e.index,c=e.line,f=e.column;for(;e.index<e.end;){e.tokenPos=e.index,e.colPos=e.column,e.linePos=e.line;let g=e.currentChar;if(g<=126){const i=G[g];switch(i){case 67174411:case 16:case 2162700:case 1074790415:case 69271571:case 20:case 21:case 1074790417:case 18:case 16842801:case 133:case 129:return l(e),i;case 208897:return I(e,t,0);case 4096:return I(e,t,1);case 134283266:return D(e,t,144);case 134283267:return q(e,t,g);case 132:return S(e,t);case 137:return N(e,t);case 131:return B(e);case 128:l(e);break;case 130:n|=5,d(e);break;case 136:u(e,n),n=-5&n|1;break;case 8456258:let p=l(e);if(e.index<e.end){if(60===p)return e.index<e.end&&61===l(e)?(l(e),4194334):8456516;if(61===p)return l(e),8456256;if(33===p){const o=e.index+1;if(o+1<e.end&&45===s.charCodeAt(o)&&45==s.charCodeAt(o+1)){e.column+=3,e.currentChar=s.charCodeAt(e.index+=3),n=y(e,s,n,t,2,e.tokenPos,e.linePos,e.colPos),a=e.tokenPos,c=e.linePos,f=e.colPos;continue}return 8456258}if(47===p){if(!(16&t))return 8456258;const n=e.index+1;if(n<e.end&&(p=s.charCodeAt(n),42===p||47===p))break;return l(e),25}}return 8456258;case 1077936157:{l(e);const t=e.currentChar;return 61===t?61===l(e)?(l(e),8455996):8455998:62===t?(l(e),10):1077936157}case 16842800:return 61!==l(e)?16842800:61!==l(e)?8455999:(l(e),8455997);case 8457015:return 61!==l(e)?8457015:(l(e),4194342);case 8457014:{if(l(e),e.index>=e.end)return 8457014;const t=e.currentChar;return 61===t?(l(e),4194340):42!==t?8457014:61!==l(e)?8457273:(l(e),4194337)}case 8455497:return 61!==l(e)?8455497:(l(e),4194343);case 25233970:{l(e);const t=e.currentChar;return 43===t?(l(e),33619995):61===t?(l(e),4194338):25233970}case 25233971:{l(e);const i=e.currentChar;if(45===i){if(l(e),(1&n||r)&&62===e.currentChar){256&t||o(e,109),l(e),n=y(e,s,n,t,3,a,c,f),a=e.tokenPos,c=e.linePos,f=e.colPos;continue}return 33619996}return 61===i?(l(e),4194339):25233971}case 8457016:if(l(e),e.index<e.end){const o=e.currentChar;if(47===o){l(e),n=x(e,s,n,0,e.tokenPos,e.linePos,e.colPos),a=e.tokenPos,c=e.linePos,f=e.colPos;continue}if(42===o){l(e),n=v(e,s,n),a=e.tokenPos,c=e.linePos,f=e.colPos;continue}if(32768&t)return w(e,t);if(61===o)return l(e),4259877}return 8457016;case 67108877:const k=l(e);if(k>=48&&k<=57)return D(e,t,80);if(46===k){const t=e.index+1;if(t<e.end&&46===s.charCodeAt(t))return e.column+=2,e.currentChar=s.charCodeAt(e.index+=2),14}return 67108877;case 8455240:{l(e);const t=e.currentChar;return 124===t?(l(e),61===e.currentChar?(l(e),4194346):8979003):61===t?(l(e),4194344):8455240}case 8456259:{l(e);const t=e.currentChar;if(61===t)return l(e),8456257;if(62!==t)return 8456259;if(l(e),e.index<e.end){const t=e.currentChar;if(62===t)return 61===l(e)?(l(e),4194336):8456518;if(61===t)return l(e),4194335}return 8456517}case 8455751:{l(e);const t=e.currentChar;return 38===t?(l(e),61===e.currentChar?(l(e),4194347):8979258):61===t?(l(e),4194345):8455751}case 22:{let t=l(e);if(63===t)return l(e),61===e.currentChar?(l(e),4194348):276889982;if(46===t){const n=e.index+1;if(n<e.end&&(t=s.charCodeAt(n),!(t>=48&&t<=57)))return l(e),67108991}return 22}}}else{if((8232^g)<=1){n=-5&n|1,d(e);continue}if(55296==(64512&g)||1&i[34816+(g>>>5)]>>>g)return 56320==(64512&g)&&(g=(1023&g)<<10|1023&g|65536,1&i[0+(g>>>5)]>>>g||o(e,18,p(g)),e.index++,e.currentChar=g),e.column++,e.tokenValue="",U(e,t,0,0);if(160===(k=g)||65279===k||133===k||5760===k||k>=8192&&k<=8203||8239===k||8287===k||12288===k||8201===k||65519===k){l(e);continue}o(e,18,p(g))}}var k;return 1048576}const H={AElig:"Æ",AMP:"&",Aacute:"Á",Abreve:"Ă",Acirc:"Â",Acy:"А",Afr:"𝔄",Agrave:"À",Alpha:"Α",Amacr:"Ā",And:"⩓",Aogon:"Ą",Aopf:"𝔸",ApplyFunction:"⁡",Aring:"Å",Ascr:"𝒜",Assign:"≔",Atilde:"Ã",Auml:"Ä",Backslash:"∖",Barv:"⫧",Barwed:"⌆",Bcy:"Б",Because:"∵",Bernoullis:"ℬ",Beta:"Β",Bfr:"𝔅",Bopf:"𝔹",Breve:"˘",Bscr:"ℬ",Bumpeq:"≎",CHcy:"Ч",COPY:"©",Cacute:"Ć",Cap:"⋒",CapitalDifferentialD:"ⅅ",Cayleys:"ℭ",Ccaron:"Č",Ccedil:"Ç",Ccirc:"Ĉ",Cconint:"∰",Cdot:"Ċ",Cedilla:"¸",CenterDot:"·",Cfr:"ℭ",Chi:"Χ",CircleDot:"⊙",CircleMinus:"⊖",CirclePlus:"⊕",CircleTimes:"⊗",ClockwiseContourIntegral:"∲",CloseCurlyDoubleQuote:"”",CloseCurlyQuote:"’",Colon:"∷",Colone:"⩴",Congruent:"≡",Conint:"∯",ContourIntegral:"∮",Copf:"ℂ",Coproduct:"∐",CounterClockwiseContourIntegral:"∳",Cross:"⨯",Cscr:"𝒞",Cup:"⋓",CupCap:"≍",DD:"ⅅ",DDotrahd:"⤑",DJcy:"Ђ",DScy:"Ѕ",DZcy:"Џ",Dagger:"‡",Darr:"↡",Dashv:"⫤",Dcaron:"Ď",Dcy:"Д",Del:"∇",Delta:"Δ",Dfr:"𝔇",DiacriticalAcute:"´",DiacriticalDot:"˙",DiacriticalDoubleAcute:"˝",DiacriticalGrave:"`",DiacriticalTilde:"˜",Diamond:"⋄",DifferentialD:"ⅆ",Dopf:"𝔻",Dot:"¨",DotDot:"⃜",DotEqual:"≐",DoubleContourIntegral:"∯",DoubleDot:"¨",DoubleDownArrow:"⇓",DoubleLeftArrow:"⇐",DoubleLeftRightArrow:"⇔",DoubleLeftTee:"⫤",DoubleLongLeftArrow:"⟸",DoubleLongLeftRightArrow:"⟺",DoubleLongRightArrow:"⟹",DoubleRightArrow:"⇒",DoubleRightTee:"⊨",DoubleUpArrow:"⇑",DoubleUpDownArrow:"⇕",DoubleVerticalBar:"∥",DownArrow:"↓",DownArrowBar:"⤓",DownArrowUpArrow:"⇵",DownBreve:"̑",DownLeftRightVector:"⥐",DownLeftTeeVector:"⥞",DownLeftVector:"↽",DownLeftVectorBar:"⥖",DownRightTeeVector:"⥟",DownRightVector:"⇁",DownRightVectorBar:"⥗",DownTee:"⊤",DownTeeArrow:"↧",Downarrow:"⇓",Dscr:"𝒟",Dstrok:"Đ",ENG:"Ŋ",ETH:"Ð",Eacute:"É",Ecaron:"Ě",Ecirc:"Ê",Ecy:"Э",Edot:"Ė",Efr:"𝔈",Egrave:"È",Element:"∈",Emacr:"Ē",EmptySmallSquare:"◻",EmptyVerySmallSquare:"▫",Eogon:"Ę",Eopf:"𝔼",Epsilon:"Ε",Equal:"⩵",EqualTilde:"≂",Equilibrium:"⇌",Escr:"ℰ",Esim:"⩳",Eta:"Η",Euml:"Ë",Exists:"∃",ExponentialE:"ⅇ",Fcy:"Ф",Ffr:"𝔉",FilledSmallSquare:"◼",FilledVerySmallSquare:"▪",Fopf:"𝔽",ForAll:"∀",Fouriertrf:"ℱ",Fscr:"ℱ",GJcy:"Ѓ",GT:">",Gamma:"Γ",Gammad:"Ϝ",Gbreve:"Ğ",Gcedil:"Ģ",Gcirc:"Ĝ",Gcy:"Г",Gdot:"Ġ",Gfr:"𝔊",Gg:"⋙",Gopf:"𝔾",GreaterEqual:"≥",GreaterEqualLess:"⋛",GreaterFullEqual:"≧",GreaterGreater:"⪢",GreaterLess:"≷",GreaterSlantEqual:"⩾",GreaterTilde:"≳",Gscr:"𝒢",Gt:"≫",HARDcy:"Ъ",Hacek:"ˇ",Hat:"^",Hcirc:"Ĥ",Hfr:"ℌ",HilbertSpace:"ℋ",Hopf:"ℍ",HorizontalLine:"─",Hscr:"ℋ",Hstrok:"Ħ",HumpDownHump:"≎",HumpEqual:"≏",IEcy:"Е",IJlig:"Ĳ",IOcy:"Ё",Iacute:"Í",Icirc:"Î",Icy:"И",Idot:"İ",Ifr:"ℑ",Igrave:"Ì",Im:"ℑ",Imacr:"Ī",ImaginaryI:"ⅈ",Implies:"⇒",Int:"∬",Integral:"∫",Intersection:"⋂",InvisibleComma:"⁣",InvisibleTimes:"⁢",Iogon:"Į",Iopf:"𝕀",Iota:"Ι",Iscr:"ℐ",Itilde:"Ĩ",Iukcy:"І",Iuml:"Ï",Jcirc:"Ĵ",Jcy:"Й",Jfr:"𝔍",Jopf:"𝕁",Jscr:"𝒥",Jsercy:"Ј",Jukcy:"Є",KHcy:"Х",KJcy:"Ќ",Kappa:"Κ",Kcedil:"Ķ",Kcy:"К",Kfr:"𝔎",Kopf:"𝕂",Kscr:"𝒦",LJcy:"Љ",LT:"<",Lacute:"Ĺ",Lambda:"Λ",Lang:"⟪",Laplacetrf:"ℒ",Larr:"↞",Lcaron:"Ľ",Lcedil:"Ļ",Lcy:"Л",LeftAngleBracket:"⟨",LeftArrow:"←",LeftArrowBar:"⇤",LeftArrowRightArrow:"⇆",LeftCeiling:"⌈",LeftDoubleBracket:"⟦",LeftDownTeeVector:"⥡",LeftDownVector:"⇃",LeftDownVectorBar:"⥙",LeftFloor:"⌊",LeftRightArrow:"↔",LeftRightVector:"⥎",LeftTee:"⊣",LeftTeeArrow:"↤",LeftTeeVector:"⥚",LeftTriangle:"⊲",LeftTriangleBar:"⧏",LeftTriangleEqual:"⊴",LeftUpDownVector:"⥑",LeftUpTeeVector:"⥠",LeftUpVector:"↿",LeftUpVectorBar:"⥘",LeftVector:"↼",LeftVectorBar:"⥒",Leftarrow:"⇐",Leftrightarrow:"⇔",LessEqualGreater:"⋚",LessFullEqual:"≦",LessGreater:"≶",LessLess:"⪡",LessSlantEqual:"⩽",LessTilde:"≲",Lfr:"𝔏",Ll:"⋘",Lleftarrow:"⇚",Lmidot:"Ŀ",LongLeftArrow:"⟵",LongLeftRightArrow:"⟷",LongRightArrow:"⟶",Longleftarrow:"⟸",Longleftrightarrow:"⟺",Longrightarrow:"⟹",Lopf:"𝕃",LowerLeftArrow:"↙",LowerRightArrow:"↘",Lscr:"ℒ",Lsh:"↰",Lstrok:"Ł",Lt:"≪",Map:"⤅",Mcy:"М",MediumSpace:" ",Mellintrf:"ℳ",Mfr:"𝔐",MinusPlus:"∓",Mopf:"𝕄",Mscr:"ℳ",Mu:"Μ",NJcy:"Њ",Nacute:"Ń",Ncaron:"Ň",Ncedil:"Ņ",Ncy:"Н",NegativeMediumSpace:"​",NegativeThickSpace:"​",NegativeThinSpace:"​",NegativeVeryThinSpace:"​",NestedGreaterGreater:"≫",NestedLessLess:"≪",NewLine:"\n",Nfr:"𝔑",NoBreak:"⁠",NonBreakingSpace:" ",Nopf:"ℕ",Not:"⫬",NotCongruent:"≢",NotCupCap:"≭",NotDoubleVerticalBar:"∦",NotElement:"∉",NotEqual:"≠",NotEqualTilde:"≂̸",NotExists:"∄",NotGreater:"≯",NotGreaterEqual:"≱",NotGreaterFullEqual:"≧̸",NotGreaterGreater:"≫̸",NotGreaterLess:"≹",NotGreaterSlantEqual:"⩾̸",NotGreaterTilde:"≵",NotHumpDownHump:"≎̸",NotHumpEqual:"≏̸",NotLeftTriangle:"⋪",NotLeftTriangleBar:"⧏̸",NotLeftTriangleEqual:"⋬",NotLess:"≮",NotLessEqual:"≰",NotLessGreater:"≸",NotLessLess:"≪̸",NotLessSlantEqual:"⩽̸",NotLessTilde:"≴",NotNestedGreaterGreater:"⪢̸",NotNestedLessLess:"⪡̸",NotPrecedes:"⊀",NotPrecedesEqual:"⪯̸",NotPrecedesSlantEqual:"⋠",NotReverseElement:"∌",NotRightTriangle:"⋫",NotRightTriangleBar:"⧐̸",NotRightTriangleEqual:"⋭",NotSquareSubset:"⊏̸",NotSquareSubsetEqual:"⋢",NotSquareSuperset:"⊐̸",NotSquareSupersetEqual:"⋣",NotSubset:"⊂⃒",NotSubsetEqual:"⊈",NotSucceeds:"⊁",NotSucceedsEqual:"⪰̸",NotSucceedsSlantEqual:"⋡",NotSucceedsTilde:"≿̸",NotSuperset:"⊃⃒",NotSupersetEqual:"⊉",NotTilde:"≁",NotTildeEqual:"≄",NotTildeFullEqual:"≇",NotTildeTilde:"≉",NotVerticalBar:"∤",Nscr:"𝒩",Ntilde:"Ñ",Nu:"Ν",OElig:"Œ",Oacute:"Ó",Ocirc:"Ô",Ocy:"О",Odblac:"Ő",Ofr:"𝔒",Ograve:"Ò",Omacr:"Ō",Omega:"Ω",Omicron:"Ο",Oopf:"𝕆",OpenCurlyDoubleQuote:"“",OpenCurlyQuote:"‘",Or:"⩔",Oscr:"𝒪",Oslash:"Ø",Otilde:"Õ",Otimes:"⨷",Ouml:"Ö",OverBar:"‾",OverBrace:"⏞",OverBracket:"⎴",OverParenthesis:"⏜",PartialD:"∂",Pcy:"П",Pfr:"𝔓",Phi:"Φ",Pi:"Π",PlusMinus:"±",Poincareplane:"ℌ",Popf:"ℙ",Pr:"⪻",Precedes:"≺",PrecedesEqual:"⪯",PrecedesSlantEqual:"≼",PrecedesTilde:"≾",Prime:"″",Product:"∏",Proportion:"∷",Proportional:"∝",Pscr:"𝒫",Psi:"Ψ",QUOT:'"',Qfr:"𝔔",Qopf:"ℚ",Qscr:"𝒬",RBarr:"⤐",REG:"®",Racute:"Ŕ",Rang:"⟫",Rarr:"↠",Rarrtl:"⤖",Rcaron:"Ř",Rcedil:"Ŗ",Rcy:"Р",Re:"ℜ",ReverseElement:"∋",ReverseEquilibrium:"⇋",ReverseUpEquilibrium:"⥯",Rfr:"ℜ",Rho:"Ρ",RightAngleBracket:"⟩",RightArrow:"→",RightArrowBar:"⇥",RightArrowLeftArrow:"⇄",RightCeiling:"⌉",RightDoubleBracket:"⟧",RightDownTeeVector:"⥝",RightDownVector:"⇂",RightDownVectorBar:"⥕",RightFloor:"⌋",RightTee:"⊢",RightTeeArrow:"↦",RightTeeVector:"⥛",RightTriangle:"⊳",RightTriangleBar:"⧐",RightTriangleEqual:"⊵",RightUpDownVector:"⥏",RightUpTeeVector:"⥜",RightUpVector:"↾",RightUpVectorBar:"⥔",RightVector:"⇀",RightVectorBar:"⥓",Rightarrow:"⇒",Ropf:"ℝ",RoundImplies:"⥰",Rrightarrow:"⇛",Rscr:"ℛ",Rsh:"↱",RuleDelayed:"⧴",SHCHcy:"Щ",SHcy:"Ш",SOFTcy:"Ь",Sacute:"Ś",Sc:"⪼",Scaron:"Š",Scedil:"Ş",Scirc:"Ŝ",Scy:"С",Sfr:"𝔖",ShortDownArrow:"↓",ShortLeftArrow:"←",ShortRightArrow:"→",ShortUpArrow:"↑",Sigma:"Σ",SmallCircle:"∘",Sopf:"𝕊",Sqrt:"√",Square:"□",SquareIntersection:"⊓",SquareSubset:"⊏",SquareSubsetEqual:"⊑",SquareSuperset:"⊐",SquareSupersetEqual:"⊒",SquareUnion:"⊔",Sscr:"𝒮",Star:"⋆",Sub:"⋐",Subset:"⋐",SubsetEqual:"⊆",Succeeds:"≻",SucceedsEqual:"⪰",SucceedsSlantEqual:"≽",SucceedsTilde:"≿",SuchThat:"∋",Sum:"∑",Sup:"⋑",Superset:"⊃",SupersetEqual:"⊇",Supset:"⋑",THORN:"Þ",TRADE:"™",TSHcy:"Ћ",TScy:"Ц",Tab:"\t",Tau:"Τ",Tcaron:"Ť",Tcedil:"Ţ",Tcy:"Т",Tfr:"𝔗",Therefore:"∴",Theta:"Θ",ThickSpace:"  ",ThinSpace:" ",Tilde:"∼",TildeEqual:"≃",TildeFullEqual:"≅",TildeTilde:"≈",Topf:"𝕋",TripleDot:"⃛",Tscr:"𝒯",Tstrok:"Ŧ",Uacute:"Ú",Uarr:"↟",Uarrocir:"⥉",Ubrcy:"Ў",Ubreve:"Ŭ",Ucirc:"Û",Ucy:"У",Udblac:"Ű",Ufr:"𝔘",Ugrave:"Ù",Umacr:"Ū",UnderBar:"_",UnderBrace:"⏟",UnderBracket:"⎵",UnderParenthesis:"⏝",Union:"⋃",UnionPlus:"⊎",Uogon:"Ų",Uopf:"𝕌",UpArrow:"↑",UpArrowBar:"⤒",UpArrowDownArrow:"⇅",UpDownArrow:"↕",UpEquilibrium:"⥮",UpTee:"⊥",UpTeeArrow:"↥",Uparrow:"⇑",Updownarrow:"⇕",UpperLeftArrow:"↖",UpperRightArrow:"↗",Upsi:"ϒ",Upsilon:"Υ",Uring:"Ů",Uscr:"𝒰",Utilde:"Ũ",Uuml:"Ü",VDash:"⊫",Vbar:"⫫",Vcy:"В",Vdash:"⊩",Vdashl:"⫦",Vee:"⋁",Verbar:"‖",Vert:"‖",VerticalBar:"∣",VerticalLine:"|",VerticalSeparator:"❘",VerticalTilde:"≀",VeryThinSpace:" ",Vfr:"𝔙",Vopf:"𝕍",Vscr:"𝒱",Vvdash:"⊪",Wcirc:"Ŵ",Wedge:"⋀",Wfr:"𝔚",Wopf:"𝕎",Wscr:"𝒲",Xfr:"𝔛",Xi:"Ξ",Xopf:"𝕏",Xscr:"𝒳",YAcy:"Я",YIcy:"Ї",YUcy:"Ю",Yacute:"Ý",Ycirc:"Ŷ",Ycy:"Ы",Yfr:"𝔜",Yopf:"𝕐",Yscr:"𝒴",Yuml:"Ÿ",ZHcy:"Ж",Zacute:"Ź",Zcaron:"Ž",Zcy:"З",Zdot:"Ż",ZeroWidthSpace:"​",Zeta:"Ζ",Zfr:"ℨ",Zopf:"ℤ",Zscr:"𝒵",aacute:"á",abreve:"ă",ac:"∾",acE:"∾̳",acd:"∿",acirc:"â",acute:"´",acy:"а",aelig:"æ",af:"⁡",afr:"𝔞",agrave:"à",alefsym:"ℵ",aleph:"ℵ",alpha:"α",amacr:"ā",amalg:"⨿",amp:"&",and:"∧",andand:"⩕",andd:"⩜",andslope:"⩘",andv:"⩚",ang:"∠",ange:"⦤",angle:"∠",angmsd:"∡",angmsdaa:"⦨",angmsdab:"⦩",angmsdac:"⦪",angmsdad:"⦫",angmsdae:"⦬",angmsdaf:"⦭",angmsdag:"⦮",angmsdah:"⦯",angrt:"∟",angrtvb:"⊾",angrtvbd:"⦝",angsph:"∢",angst:"Å",angzarr:"⍼",aogon:"ą",aopf:"𝕒",ap:"≈",apE:"⩰",apacir:"⩯",ape:"≊",apid:"≋",apos:"'",approx:"≈",approxeq:"≊",aring:"å",ascr:"𝒶",ast:"*",asymp:"≈",asympeq:"≍",atilde:"ã",auml:"ä",awconint:"∳",awint:"⨑",bNot:"⫭",backcong:"≌",backepsilon:"϶",backprime:"‵",backsim:"∽",backsimeq:"⋍",barvee:"⊽",barwed:"⌅",barwedge:"⌅",bbrk:"⎵",bbrktbrk:"⎶",bcong:"≌",bcy:"б",bdquo:"„",becaus:"∵",because:"∵",bemptyv:"⦰",bepsi:"϶",bernou:"ℬ",beta:"β",beth:"ℶ",between:"≬",bfr:"𝔟",bigcap:"⋂",bigcirc:"◯",bigcup:"⋃",bigodot:"⨀",bigoplus:"⨁",bigotimes:"⨂",bigsqcup:"⨆",bigstar:"★",bigtriangledown:"▽",bigtriangleup:"△",biguplus:"⨄",bigvee:"⋁",bigwedge:"⋀",bkarow:"⤍",blacklozenge:"⧫",blacksquare:"▪",blacktriangle:"▴",blacktriangledown:"▾",blacktriangleleft:"◂",blacktriangleright:"▸",blank:"␣",blk12:"▒",blk14:"░",blk34:"▓",block:"█",bne:"=⃥",bnequiv:"≡⃥",bnot:"⌐",bopf:"𝕓",bot:"⊥",bottom:"⊥",bowtie:"⋈",boxDL:"╗",boxDR:"╔",boxDl:"╖",boxDr:"╓",boxH:"═",boxHD:"╦",boxHU:"╩",boxHd:"╤",boxHu:"╧",boxUL:"╝",boxUR:"╚",boxUl:"╜",boxUr:"╙",boxV:"║",boxVH:"╬",boxVL:"╣",boxVR:"╠",boxVh:"╫",boxVl:"╢",boxVr:"╟",boxbox:"⧉",boxdL:"╕",boxdR:"╒",boxdl:"┐",boxdr:"┌",boxh:"─",boxhD:"╥",boxhU:"╨",boxhd:"┬",boxhu:"┴",boxminus:"⊟",boxplus:"⊞",boxtimes:"⊠",boxuL:"╛",boxuR:"╘",boxul:"┘",boxur:"└",boxv:"│",boxvH:"╪",boxvL:"╡",boxvR:"╞",boxvh:"┼",boxvl:"┤",boxvr:"├",bprime:"‵",breve:"˘",brvbar:"¦",bscr:"𝒷",bsemi:"⁏",bsim:"∽",bsime:"⋍",bsol:"\\",bsolb:"⧅",bsolhsub:"⟈",bull:"•",bullet:"•",bump:"≎",bumpE:"⪮",bumpe:"≏",bumpeq:"≏",cacute:"ć",cap:"∩",capand:"⩄",capbrcup:"⩉",capcap:"⩋",capcup:"⩇",capdot:"⩀",caps:"∩︀",caret:"⁁",caron:"ˇ",ccaps:"⩍",ccaron:"č",ccedil:"ç",ccirc:"ĉ",ccups:"⩌",ccupssm:"⩐",cdot:"ċ",cedil:"¸",cemptyv:"⦲",cent:"¢",centerdot:"·",cfr:"𝔠",chcy:"ч",check:"✓",checkmark:"✓",chi:"χ",cir:"○",cirE:"⧃",circ:"ˆ",circeq:"≗",circlearrowleft:"↺",circlearrowright:"↻",circledR:"®",circledS:"Ⓢ",circledast:"⊛",circledcirc:"⊚",circleddash:"⊝",cire:"≗",cirfnint:"⨐",cirmid:"⫯",cirscir:"⧂",clubs:"♣",clubsuit:"♣",colon:":",colone:"≔",coloneq:"≔",comma:",",commat:"@",comp:"∁",compfn:"∘",complement:"∁",complexes:"ℂ",cong:"≅",congdot:"⩭",conint:"∮",copf:"𝕔",coprod:"∐",copy:"©",copysr:"℗",crarr:"↵",cross:"✗",cscr:"𝒸",csub:"⫏",csube:"⫑",csup:"⫐",csupe:"⫒",ctdot:"⋯",cudarrl:"⤸",cudarrr:"⤵",cuepr:"⋞",cuesc:"⋟",cularr:"↶",cularrp:"⤽",cup:"∪",cupbrcap:"⩈",cupcap:"⩆",cupcup:"⩊",cupdot:"⊍",cupor:"⩅",cups:"∪︀",curarr:"↷",curarrm:"⤼",curlyeqprec:"⋞",curlyeqsucc:"⋟",curlyvee:"⋎",curlywedge:"⋏",curren:"¤",curvearrowleft:"↶",curvearrowright:"↷",cuvee:"⋎",cuwed:"⋏",cwconint:"∲",cwint:"∱",cylcty:"⌭",dArr:"⇓",dHar:"⥥",dagger:"†",daleth:"ℸ",darr:"↓",dash:"‐",dashv:"⊣",dbkarow:"⤏",dblac:"˝",dcaron:"ď",dcy:"д",dd:"ⅆ",ddagger:"‡",ddarr:"⇊",ddotseq:"⩷",deg:"°",delta:"δ",demptyv:"⦱",dfisht:"⥿",dfr:"𝔡",dharl:"⇃",dharr:"⇂",diam:"⋄",diamond:"⋄",diamondsuit:"♦",diams:"♦",die:"¨",digamma:"ϝ",disin:"⋲",div:"÷",divide:"÷",divideontimes:"⋇",divonx:"⋇",djcy:"ђ",dlcorn:"⌞",dlcrop:"⌍",dollar:"$",dopf:"𝕕",dot:"˙",doteq:"≐",doteqdot:"≑",dotminus:"∸",dotplus:"∔",dotsquare:"⊡",doublebarwedge:"⌆",downarrow:"↓",downdownarrows:"⇊",downharpoonleft:"⇃",downharpoonright:"⇂",drbkarow:"⤐",drcorn:"⌟",drcrop:"⌌",dscr:"𝒹",dscy:"ѕ",dsol:"⧶",dstrok:"đ",dtdot:"⋱",dtri:"▿",dtrif:"▾",duarr:"⇵",duhar:"⥯",dwangle:"⦦",dzcy:"џ",dzigrarr:"⟿",eDDot:"⩷",eDot:"≑",eacute:"é",easter:"⩮",ecaron:"ě",ecir:"≖",ecirc:"ê",ecolon:"≕",ecy:"э",edot:"ė",ee:"ⅇ",efDot:"≒",efr:"𝔢",eg:"⪚",egrave:"è",egs:"⪖",egsdot:"⪘",el:"⪙",elinters:"⏧",ell:"ℓ",els:"⪕",elsdot:"⪗",emacr:"ē",empty:"∅",emptyset:"∅",emptyv:"∅",emsp13:" ",emsp14:" ",emsp:" ",eng:"ŋ",ensp:" ",eogon:"ę",eopf:"𝕖",epar:"⋕",eparsl:"⧣",eplus:"⩱",epsi:"ε",epsilon:"ε",epsiv:"ϵ",eqcirc:"≖",eqcolon:"≕",eqsim:"≂",eqslantgtr:"⪖",eqslantless:"⪕",equals:"=",equest:"≟",equiv:"≡",equivDD:"⩸",eqvparsl:"⧥",erDot:"≓",erarr:"⥱",escr:"ℯ",esdot:"≐",esim:"≂",eta:"η",eth:"ð",euml:"ë",euro:"€",excl:"!",exist:"∃",expectation:"ℰ",exponentiale:"ⅇ",fallingdotseq:"≒",fcy:"ф",female:"♀",ffilig:"ﬃ",fflig:"ﬀ",ffllig:"ﬄ",ffr:"𝔣",filig:"ﬁ",fjlig:"fj",flat:"♭",fllig:"ﬂ",fltns:"▱",fnof:"ƒ",fopf:"𝕗",forall:"∀",fork:"⋔",forkv:"⫙",fpartint:"⨍",frac12:"½",frac13:"⅓",frac14:"¼",frac15:"⅕",frac16:"⅙",frac18:"⅛",frac23:"⅔",frac25:"⅖",frac34:"¾",frac35:"⅗",frac38:"⅜",frac45:"⅘",frac56:"⅚",frac58:"⅝",frac78:"⅞",frasl:"⁄",frown:"⌢",fscr:"𝒻",gE:"≧",gEl:"⪌",gacute:"ǵ",gamma:"γ",gammad:"ϝ",gap:"⪆",gbreve:"ğ",gcirc:"ĝ",gcy:"г",gdot:"ġ",ge:"≥",gel:"⋛",geq:"≥",geqq:"≧",geqslant:"⩾",ges:"⩾",gescc:"⪩",gesdot:"⪀",gesdoto:"⪂",gesdotol:"⪄",gesl:"⋛︀",gesles:"⪔",gfr:"𝔤",gg:"≫",ggg:"⋙",gimel:"ℷ",gjcy:"ѓ",gl:"≷",glE:"⪒",gla:"⪥",glj:"⪤",gnE:"≩",gnap:"⪊",gnapprox:"⪊",gne:"⪈",gneq:"⪈",gneqq:"≩",gnsim:"⋧",gopf:"𝕘",grave:"`",gscr:"ℊ",gsim:"≳",gsime:"⪎",gsiml:"⪐",gt:">",gtcc:"⪧",gtcir:"⩺",gtdot:"⋗",gtlPar:"⦕",gtquest:"⩼",gtrapprox:"⪆",gtrarr:"⥸",gtrdot:"⋗",gtreqless:"⋛",gtreqqless:"⪌",gtrless:"≷",gtrsim:"≳",gvertneqq:"≩︀",gvnE:"≩︀",hArr:"⇔",hairsp:" ",half:"½",hamilt:"ℋ",hardcy:"ъ",harr:"↔",harrcir:"⥈",harrw:"↭",hbar:"ℏ",hcirc:"ĥ",hearts:"♥",heartsuit:"♥",hellip:"…",hercon:"⊹",hfr:"𝔥",hksearow:"⤥",hkswarow:"⤦",hoarr:"⇿",homtht:"∻",hookleftarrow:"↩",hookrightarrow:"↪",hopf:"𝕙",horbar:"―",hscr:"𝒽",hslash:"ℏ",hstrok:"ħ",hybull:"⁃",hyphen:"‐",iacute:"í",ic:"⁣",icirc:"î",icy:"и",iecy:"е",iexcl:"¡",iff:"⇔",ifr:"𝔦",igrave:"ì",ii:"ⅈ",iiiint:"⨌",iiint:"∭",iinfin:"⧜",iiota:"℩",ijlig:"ĳ",imacr:"ī",image:"ℑ",imagline:"ℐ",imagpart:"ℑ",imath:"ı",imof:"⊷",imped:"Ƶ",in:"∈",incare:"℅",infin:"∞",infintie:"⧝",inodot:"ı",int:"∫",intcal:"⊺",integers:"ℤ",intercal:"⊺",intlarhk:"⨗",intprod:"⨼",iocy:"ё",iogon:"į",iopf:"𝕚",iota:"ι",iprod:"⨼",iquest:"¿",iscr:"𝒾",isin:"∈",isinE:"⋹",isindot:"⋵",isins:"⋴",isinsv:"⋳",isinv:"∈",it:"⁢",itilde:"ĩ",iukcy:"і",iuml:"ï",jcirc:"ĵ",jcy:"й",jfr:"𝔧",jmath:"ȷ",jopf:"𝕛",jscr:"𝒿",jsercy:"ј",jukcy:"є",kappa:"κ",kappav:"ϰ",kcedil:"ķ",kcy:"к",kfr:"𝔨",kgreen:"ĸ",khcy:"х",kjcy:"ќ",kopf:"𝕜",kscr:"𝓀",lAarr:"⇚",lArr:"⇐",lAtail:"⤛",lBarr:"⤎",lE:"≦",lEg:"⪋",lHar:"⥢",lacute:"ĺ",laemptyv:"⦴",lagran:"ℒ",lambda:"λ",lang:"⟨",langd:"⦑",langle:"⟨",lap:"⪅",laquo:"«",larr:"←",larrb:"⇤",larrbfs:"⤟",larrfs:"⤝",larrhk:"↩",larrlp:"↫",larrpl:"⤹",larrsim:"⥳",larrtl:"↢",lat:"⪫",latail:"⤙",late:"⪭",lates:"⪭︀",lbarr:"⤌",lbbrk:"❲",lbrace:"{",lbrack:"[",lbrke:"⦋",lbrksld:"⦏",lbrkslu:"⦍",lcaron:"ľ",lcedil:"ļ",lceil:"⌈",lcub:"{",lcy:"л",ldca:"⤶",ldquo:"“",ldquor:"„",ldrdhar:"⥧",ldrushar:"⥋",ldsh:"↲",le:"≤",leftarrow:"←",leftarrowtail:"↢",leftharpoondown:"↽",leftharpoonup:"↼",leftleftarrows:"⇇",leftrightarrow:"↔",leftrightarrows:"⇆",leftrightharpoons:"⇋",leftrightsquigarrow:"↭",leftthreetimes:"⋋",leg:"⋚",leq:"≤",leqq:"≦",leqslant:"⩽",les:"⩽",lescc:"⪨",lesdot:"⩿",lesdoto:"⪁",lesdotor:"⪃",lesg:"⋚︀",lesges:"⪓",lessapprox:"⪅",lessdot:"⋖",lesseqgtr:"⋚",lesseqqgtr:"⪋",lessgtr:"≶",lesssim:"≲",lfisht:"⥼",lfloor:"⌊",lfr:"𝔩",lg:"≶",lgE:"⪑",lhard:"↽",lharu:"↼",lharul:"⥪",lhblk:"▄",ljcy:"љ",ll:"≪",llarr:"⇇",llcorner:"⌞",llhard:"⥫",lltri:"◺",lmidot:"ŀ",lmoust:"⎰",lmoustache:"⎰",lnE:"≨",lnap:"⪉",lnapprox:"⪉",lne:"⪇",lneq:"⪇",lneqq:"≨",lnsim:"⋦",loang:"⟬",loarr:"⇽",lobrk:"⟦",longleftarrow:"⟵",longleftrightarrow:"⟷",longmapsto:"⟼",longrightarrow:"⟶",looparrowleft:"↫",looparrowright:"↬",lopar:"⦅",lopf:"𝕝",loplus:"⨭",lotimes:"⨴",lowast:"∗",lowbar:"_",loz:"◊",lozenge:"◊",lozf:"⧫",lpar:"(",lparlt:"⦓",lrarr:"⇆",lrcorner:"⌟",lrhar:"⇋",lrhard:"⥭",lrm:"‎",lrtri:"⊿",lsaquo:"‹",lscr:"𝓁",lsh:"↰",lsim:"≲",lsime:"⪍",lsimg:"⪏",lsqb:"[",lsquo:"‘",lsquor:"‚",lstrok:"ł",lt:"<",ltcc:"⪦",ltcir:"⩹",ltdot:"⋖",lthree:"⋋",ltimes:"⋉",ltlarr:"⥶",ltquest:"⩻",ltrPar:"⦖",ltri:"◃",ltrie:"⊴",ltrif:"◂",lurdshar:"⥊",luruhar:"⥦",lvertneqq:"≨︀",lvnE:"≨︀",mDDot:"∺",macr:"¯",male:"♂",malt:"✠",maltese:"✠",map:"↦",mapsto:"↦",mapstodown:"↧",mapstoleft:"↤",mapstoup:"↥",marker:"▮",mcomma:"⨩",mcy:"м",mdash:"—",measuredangle:"∡",mfr:"𝔪",mho:"℧",micro:"µ",mid:"∣",midast:"*",midcir:"⫰",middot:"·",minus:"−",minusb:"⊟",minusd:"∸",minusdu:"⨪",mlcp:"⫛",mldr:"…",mnplus:"∓",models:"⊧",mopf:"𝕞",mp:"∓",mscr:"𝓂",mstpos:"∾",mu:"μ",multimap:"⊸",mumap:"⊸",nGg:"⋙̸",nGt:"≫⃒",nGtv:"≫̸",nLeftarrow:"⇍",nLeftrightarrow:"⇎",nLl:"⋘̸",nLt:"≪⃒",nLtv:"≪̸",nRightarrow:"⇏",nVDash:"⊯",nVdash:"⊮",nabla:"∇",nacute:"ń",nang:"∠⃒",nap:"≉",napE:"⩰̸",napid:"≋̸",napos:"ŉ",napprox:"≉",natur:"♮",natural:"♮",naturals:"ℕ",nbsp:" ",nbump:"≎̸",nbumpe:"≏̸",ncap:"⩃",ncaron:"ň",ncedil:"ņ",ncong:"≇",ncongdot:"⩭̸",ncup:"⩂",ncy:"н",ndash:"–",ne:"≠",neArr:"⇗",nearhk:"⤤",nearr:"↗",nearrow:"↗",nedot:"≐̸",nequiv:"≢",nesear:"⤨",nesim:"≂̸",nexist:"∄",nexists:"∄",nfr:"𝔫",ngE:"≧̸",nge:"≱",ngeq:"≱",ngeqq:"≧̸",ngeqslant:"⩾̸",nges:"⩾̸",ngsim:"≵",ngt:"≯",ngtr:"≯",nhArr:"⇎",nharr:"↮",nhpar:"⫲",ni:"∋",nis:"⋼",nisd:"⋺",niv:"∋",njcy:"њ",nlArr:"⇍",nlE:"≦̸",nlarr:"↚",nldr:"‥",nle:"≰",nleftarrow:"↚",nleftrightarrow:"↮",nleq:"≰",nleqq:"≦̸",nleqslant:"⩽̸",nles:"⩽̸",nless:"≮",nlsim:"≴",nlt:"≮",nltri:"⋪",nltrie:"⋬",nmid:"∤",nopf:"𝕟",not:"¬",notin:"∉",notinE:"⋹̸",notindot:"⋵̸",notinva:"∉",notinvb:"⋷",notinvc:"⋶",notni:"∌",notniva:"∌",notnivb:"⋾",notnivc:"⋽",npar:"∦",nparallel:"∦",nparsl:"⫽⃥",npart:"∂̸",npolint:"⨔",npr:"⊀",nprcue:"⋠",npre:"⪯̸",nprec:"⊀",npreceq:"⪯̸",nrArr:"⇏",nrarr:"↛",nrarrc:"⤳̸",nrarrw:"↝̸",nrightarrow:"↛",nrtri:"⋫",nrtrie:"⋭",nsc:"⊁",nsccue:"⋡",nsce:"⪰̸",nscr:"𝓃",nshortmid:"∤",nshortparallel:"∦",nsim:"≁",nsime:"≄",nsimeq:"≄",nsmid:"∤",nspar:"∦",nsqsube:"⋢",nsqsupe:"⋣",nsub:"⊄",nsubE:"⫅̸",nsube:"⊈",nsubset:"⊂⃒",nsubseteq:"⊈",nsubseteqq:"⫅̸",nsucc:"⊁",nsucceq:"⪰̸",nsup:"⊅",nsupE:"⫆̸",nsupe:"⊉",nsupset:"⊃⃒",nsupseteq:"⊉",nsupseteqq:"⫆̸",ntgl:"≹",ntilde:"ñ",ntlg:"≸",ntriangleleft:"⋪",ntrianglelefteq:"⋬",ntriangleright:"⋫",ntrianglerighteq:"⋭",nu:"ν",num:"#",numero:"№",numsp:" ",nvDash:"⊭",nvHarr:"⤄",nvap:"≍⃒",nvdash:"⊬",nvge:"≥⃒",nvgt:">⃒",nvinfin:"⧞",nvlArr:"⤂",nvle:"≤⃒",nvlt:"<⃒",nvltrie:"⊴⃒",nvrArr:"⤃",nvrtrie:"⊵⃒",nvsim:"∼⃒",nwArr:"⇖",nwarhk:"⤣",nwarr:"↖",nwarrow:"↖",nwnear:"⤧",oS:"Ⓢ",oacute:"ó",oast:"⊛",ocir:"⊚",ocirc:"ô",ocy:"о",odash:"⊝",odblac:"ő",odiv:"⨸",odot:"⊙",odsold:"⦼",oelig:"œ",ofcir:"⦿",ofr:"𝔬",ogon:"˛",ograve:"ò",ogt:"⧁",ohbar:"⦵",ohm:"Ω",oint:"∮",olarr:"↺",olcir:"⦾",olcross:"⦻",oline:"‾",olt:"⧀",omacr:"ō",omega:"ω",omicron:"ο",omid:"⦶",ominus:"⊖",oopf:"𝕠",opar:"⦷",operp:"⦹",oplus:"⊕",or:"∨",orarr:"↻",ord:"⩝",order:"ℴ",orderof:"ℴ",ordf:"ª",ordm:"º",origof:"⊶",oror:"⩖",orslope:"⩗",orv:"⩛",oscr:"ℴ",oslash:"ø",osol:"⊘",otilde:"õ",otimes:"⊗",otimesas:"⨶",ouml:"ö",ovbar:"⌽",par:"∥",para:"¶",parallel:"∥",parsim:"⫳",parsl:"⫽",part:"∂",pcy:"п",percnt:"%",period:".",permil:"‰",perp:"⊥",pertenk:"‱",pfr:"𝔭",phi:"φ",phiv:"ϕ",phmmat:"ℳ",phone:"☎",pi:"π",pitchfork:"⋔",piv:"ϖ",planck:"ℏ",planckh:"ℎ",plankv:"ℏ",plus:"+",plusacir:"⨣",plusb:"⊞",pluscir:"⨢",plusdo:"∔",plusdu:"⨥",pluse:"⩲",plusmn:"±",plussim:"⨦",plustwo:"⨧",pm:"±",pointint:"⨕",popf:"𝕡",pound:"£",pr:"≺",prE:"⪳",prap:"⪷",prcue:"≼",pre:"⪯",prec:"≺",precapprox:"⪷",preccurlyeq:"≼",preceq:"⪯",precnapprox:"⪹",precneqq:"⪵",precnsim:"⋨",precsim:"≾",prime:"′",primes:"ℙ",prnE:"⪵",prnap:"⪹",prnsim:"⋨",prod:"∏",profalar:"⌮",profline:"⌒",profsurf:"⌓",prop:"∝",propto:"∝",prsim:"≾",prurel:"⊰",pscr:"𝓅",psi:"ψ",puncsp:" ",qfr:"𝔮",qint:"⨌",qopf:"𝕢",qprime:"⁗",qscr:"𝓆",quaternions:"ℍ",quatint:"⨖",quest:"?",questeq:"≟",quot:'"',rAarr:"⇛",rArr:"⇒",rAtail:"⤜",rBarr:"⤏",rHar:"⥤",race:"∽̱",racute:"ŕ",radic:"√",raemptyv:"⦳",rang:"⟩",rangd:"⦒",range:"⦥",rangle:"⟩",raquo:"»",rarr:"→",rarrap:"⥵",rarrb:"⇥",rarrbfs:"⤠",rarrc:"⤳",rarrfs:"⤞",rarrhk:"↪",rarrlp:"↬",rarrpl:"⥅",rarrsim:"⥴",rarrtl:"↣",rarrw:"↝",ratail:"⤚",ratio:"∶",rationals:"ℚ",rbarr:"⤍",rbbrk:"❳",rbrace:"}",rbrack:"]",rbrke:"⦌",rbrksld:"⦎",rbrkslu:"⦐",rcaron:"ř",rcedil:"ŗ",rceil:"⌉",rcub:"}",rcy:"р",rdca:"⤷",rdldhar:"⥩",rdquo:"”",rdquor:"”",rdsh:"↳",real:"ℜ",realine:"ℛ",realpart:"ℜ",reals:"ℝ",rect:"▭",reg:"®",rfisht:"⥽",rfloor:"⌋",rfr:"𝔯",rhard:"⇁",rharu:"⇀",rharul:"⥬",rho:"ρ",rhov:"ϱ",rightarrow:"→",rightarrowtail:"↣",rightharpoondown:"⇁",rightharpoonup:"⇀",rightleftarrows:"⇄",rightleftharpoons:"⇌",rightrightarrows:"⇉",rightsquigarrow:"↝",rightthreetimes:"⋌",ring:"˚",risingdotseq:"≓",rlarr:"⇄",rlhar:"⇌",rlm:"‏",rmoust:"⎱",rmoustache:"⎱",rnmid:"⫮",roang:"⟭",roarr:"⇾",robrk:"⟧",ropar:"⦆",ropf:"𝕣",roplus:"⨮",rotimes:"⨵",rpar:")",rpargt:"⦔",rppolint:"⨒",rrarr:"⇉",rsaquo:"›",rscr:"𝓇",rsh:"↱",rsqb:"]",rsquo:"’",rsquor:"’",rthree:"⋌",rtimes:"⋊",rtri:"▹",rtrie:"⊵",rtrif:"▸",rtriltri:"⧎",ruluhar:"⥨",rx:"℞",sacute:"ś",sbquo:"‚",sc:"≻",scE:"⪴",scap:"⪸",scaron:"š",sccue:"≽",sce:"⪰",scedil:"ş",scirc:"ŝ",scnE:"⪶",scnap:"⪺",scnsim:"⋩",scpolint:"⨓",scsim:"≿",scy:"с",sdot:"⋅",sdotb:"⊡",sdote:"⩦",seArr:"⇘",searhk:"⤥",searr:"↘",searrow:"↘",sect:"§",semi:";",seswar:"⤩",setminus:"∖",setmn:"∖",sext:"✶",sfr:"𝔰",sfrown:"⌢",sharp:"♯",shchcy:"щ",shcy:"ш",shortmid:"∣",shortparallel:"∥",shy:"­",sigma:"σ",sigmaf:"ς",sigmav:"ς",sim:"∼",simdot:"⩪",sime:"≃",simeq:"≃",simg:"⪞",simgE:"⪠",siml:"⪝",simlE:"⪟",simne:"≆",simplus:"⨤",simrarr:"⥲",slarr:"←",smallsetminus:"∖",smashp:"⨳",smeparsl:"⧤",smid:"∣",smile:"⌣",smt:"⪪",smte:"⪬",smtes:"⪬︀",softcy:"ь",sol:"/",solb:"⧄",solbar:"⌿",sopf:"𝕤",spades:"♠",spadesuit:"♠",spar:"∥",sqcap:"⊓",sqcaps:"⊓︀",sqcup:"⊔",sqcups:"⊔︀",sqsub:"⊏",sqsube:"⊑",sqsubset:"⊏",sqsubseteq:"⊑",sqsup:"⊐",sqsupe:"⊒",sqsupset:"⊐",sqsupseteq:"⊒",squ:"□",square:"□",squarf:"▪",squf:"▪",srarr:"→",sscr:"𝓈",ssetmn:"∖",ssmile:"⌣",sstarf:"⋆",star:"☆",starf:"★",straightepsilon:"ϵ",straightphi:"ϕ",strns:"¯",sub:"⊂",subE:"⫅",subdot:"⪽",sube:"⊆",subedot:"⫃",submult:"⫁",subnE:"⫋",subne:"⊊",subplus:"⪿",subrarr:"⥹",subset:"⊂",subseteq:"⊆",subseteqq:"⫅",subsetneq:"⊊",subsetneqq:"⫋",subsim:"⫇",subsub:"⫕",subsup:"⫓",succ:"≻",succapprox:"⪸",succcurlyeq:"≽",succeq:"⪰",succnapprox:"⪺",succneqq:"⪶",succnsim:"⋩",succsim:"≿",sum:"∑",sung:"♪",sup1:"¹",sup2:"²",sup3:"³",sup:"⊃",supE:"⫆",supdot:"⪾",supdsub:"⫘",supe:"⊇",supedot:"⫄",suphsol:"⟉",suphsub:"⫗",suplarr:"⥻",supmult:"⫂",supnE:"⫌",supne:"⊋",supplus:"⫀",supset:"⊃",supseteq:"⊇",supseteqq:"⫆",supsetneq:"⊋",supsetneqq:"⫌",supsim:"⫈",supsub:"⫔",supsup:"⫖",swArr:"⇙",swarhk:"⤦",swarr:"↙",swarrow:"↙",swnwar:"⤪",szlig:"ß",target:"⌖",tau:"τ",tbrk:"⎴",tcaron:"ť",tcedil:"ţ",tcy:"т",tdot:"⃛",telrec:"⌕",tfr:"𝔱",there4:"∴",therefore:"∴",theta:"θ",thetasym:"ϑ",thetav:"ϑ",thickapprox:"≈",thicksim:"∼",thinsp:" ",thkap:"≈",thksim:"∼",thorn:"þ",tilde:"˜",times:"×",timesb:"⊠",timesbar:"⨱",timesd:"⨰",tint:"∭",toea:"⤨",top:"⊤",topbot:"⌶",topcir:"⫱",topf:"𝕥",topfork:"⫚",tosa:"⤩",tprime:"‴",trade:"™",triangle:"▵",triangledown:"▿",triangleleft:"◃",trianglelefteq:"⊴",triangleq:"≜",triangleright:"▹",trianglerighteq:"⊵",tridot:"◬",trie:"≜",triminus:"⨺",triplus:"⨹",trisb:"⧍",tritime:"⨻",trpezium:"⏢",tscr:"𝓉",tscy:"ц",tshcy:"ћ",tstrok:"ŧ",twixt:"≬",twoheadleftarrow:"↞",twoheadrightarrow:"↠",uArr:"⇑",uHar:"⥣",uacute:"ú",uarr:"↑",ubrcy:"ў",ubreve:"ŭ",ucirc:"û",ucy:"у",udarr:"⇅",udblac:"ű",udhar:"⥮",ufisht:"⥾",ufr:"𝔲",ugrave:"ù",uharl:"↿",uharr:"↾",uhblk:"▀",ulcorn:"⌜",ulcorner:"⌜",ulcrop:"⌏",ultri:"◸",umacr:"ū",uml:"¨",uogon:"ų",uopf:"𝕦",uparrow:"↑",updownarrow:"↕",upharpoonleft:"↿",upharpoonright:"↾",uplus:"⊎",upsi:"υ",upsih:"ϒ",upsilon:"υ",upuparrows:"⇈",urcorn:"⌝",urcorner:"⌝",urcrop:"⌎",uring:"ů",urtri:"◹",uscr:"𝓊",utdot:"⋰",utilde:"ũ",utri:"▵",utrif:"▴",uuarr:"⇈",uuml:"ü",uwangle:"⦧",vArr:"⇕",vBar:"⫨",vBarv:"⫩",vDash:"⊨",vangrt:"⦜",varepsilon:"ϵ",varkappa:"ϰ",varnothing:"∅",varphi:"ϕ",varpi:"ϖ",varpropto:"∝",varr:"↕",varrho:"ϱ",varsigma:"ς",varsubsetneq:"⊊︀",varsubsetneqq:"⫋︀",varsupsetneq:"⊋︀",varsupsetneqq:"⫌︀",vartheta:"ϑ",vartriangleleft:"⊲",vartriangleright:"⊳",vcy:"в",vdash:"⊢",vee:"∨",veebar:"⊻",veeeq:"≚",vellip:"⋮",verbar:"|",vert:"|",vfr:"𝔳",vltri:"⊲",vnsub:"⊂⃒",vnsup:"⊃⃒",vopf:"𝕧",vprop:"∝",vrtri:"⊳",vscr:"𝓋",vsubnE:"⫋︀",vsubne:"⊊︀",vsupnE:"⫌︀",vsupne:"⊋︀",vzigzag:"⦚",wcirc:"ŵ",wedbar:"⩟",wedge:"∧",wedgeq:"≙",weierp:"℘",wfr:"𝔴",wopf:"𝕨",wp:"℘",wr:"≀",wreath:"≀",wscr:"𝓌",xcap:"⋂",xcirc:"◯",xcup:"⋃",xdtri:"▽",xfr:"𝔵",xhArr:"⟺",xharr:"⟷",xi:"ξ",xlArr:"⟸",xlarr:"⟵",xmap:"⟼",xnis:"⋻",xodot:"⨀",xopf:"𝕩",xoplus:"⨁",xotime:"⨂",xrArr:"⟹",xrarr:"⟶",xscr:"𝓍",xsqcup:"⨆",xuplus:"⨄",xutri:"△",xvee:"⋁",xwedge:"⋀",yacute:"ý",yacy:"я",ycirc:"ŷ",ycy:"ы",yen:"¥",yfr:"𝔶",yicy:"ї",yopf:"𝕪",yscr:"𝓎",yucy:"ю",yuml:"ÿ",zacute:"ź",zcaron:"ž",zcy:"з",zdot:"ż",zeetrf:"ℨ",zeta:"ζ",zfr:"𝔷",zhcy:"ж",zigrarr:"⇝",zopf:"𝕫",zscr:"𝓏",zwj:"‍",zwnj:"‌"},J={0:65533,128:8364,130:8218,131:402,132:8222,133:8230,134:8224,135:8225,136:710,137:8240,138:352,139:8249,140:338,142:381,145:8216,146:8217,147:8220,148:8221,149:8226,150:8211,151:8212,152:732,153:8482,154:353,155:8250,156:339,158:382,159:376};function M(e){return e.replace(/&(?:[a-zA-Z]+|#[xX][\da-fA-F]+|#\d+);/g,(e=>{if("#"===e.charAt(1)){const t=e.charAt(2);return function(e){if(e>=55296&&e<=57343||e>1114111)return"�";e in J&&(e=J[e]);return String.fromCodePoint(e)}("X"===t||"x"===t?parseInt(e.slice(3),16):parseInt(e.slice(2),10))}return H[e.slice(1,-1)]||e}))}function z(e,t){return e.startPos=e.tokenPos=e.index,e.startColumn=e.colPos=e.column,e.startLine=e.linePos=e.line,e.token=8192&k[e.currentChar]?function(e,t){const n=e.currentChar;let r=l(e);const s=e.index;for(;r!==n;)e.index>=e.end&&o(e,14),r=l(e);r!==n&&o(e,14);e.tokenValue=e.source.slice(s,e.index),l(e),512&t&&(e.tokenRaw=e.source.slice(e.tokenPos,e.index));return 134283267}(e,t):j(e,t,0),e.token}function X(e,t){if(e.startPos=e.tokenPos=e.index,e.startColumn=e.colPos=e.column,e.startLine=e.linePos=e.line,e.index>=e.end)return e.token=1048576;switch(G[e.source.charCodeAt(e.index)]){case 8456258:l(e),47===e.currentChar?(l(e),e.token=25):e.token=8456258;break;case 2162700:l(e),e.token=2162700;break;default:{let n=0;for(;e.index<e.end;){const t=k[e.source.charCodeAt(e.index)];if(1024&t?(n|=5,d(e)):2048&t?(u(e,n),n=-5&n|1):l(e),16384&k[e.currentChar])break}const o=e.source.slice(e.tokenPos,e.index);512&t&&(e.tokenRaw=o),e.tokenValue=M(o),e.token=138}}return e.token}function _(e){if(!(143360&~e.token)){const{index:t}=e;let n=e.currentChar;for(;32770&k[n];)n=l(e);e.tokenValue+=e.source.slice(t,e.index)}return e.token=208897,e.token}function $(e,t){!(1&e.flags)&&1048576&~e.token&&o(e,28,T[255&e.token]),W(e,t,1074790417)||e.onInsertedSemicolon?.(e.startPos)}function Y(e,t,n,o){return t-n<13&&"use strict"===o&&(!(1048576&~e.token)||1&e.flags)?1:0}function Z(e,t,n){return e.token!==n?0:(F(e,t),1)}function W(e,t,n){return e.token===n&&(F(e,t),!0)}function K(e,t,n){e.token!==n&&o(e,23,T[255&n]),F(e,t)}function Q(e,t){switch(t.type){case"ArrayExpression":t.type="ArrayPattern";const n=t.elements;for(let t=0,o=n.length;t<o;++t){const o=n[t];o&&Q(e,o)}return;case"ObjectExpression":t.type="ObjectPattern";const r=t.properties;for(let t=0,n=r.length;t<n;++t)Q(e,r[t]);return;case"AssignmentExpression":return t.type="AssignmentPattern","="!==t.operator&&o(e,69),delete t.operator,void Q(e,t.left);case"Property":return void Q(e,t.value);case"SpreadElement":t.type="RestElement",Q(e,t.argument)}}function ee(e,t,n,r,s){1024&t&&(36864&~r||o(e,115),s||537079808&~r||o(e,116)),20480&~r||o(e,100),24&n&&241739===r&&o(e,98),4196352&t&&209008===r&&o(e,96),2098176&t&&241773===r&&o(e,95,"yield")}function te(e,t,n){1024&t&&(36864&~n||o(e,115),537079808&~n||o(e,116),122===n&&o(e,93),121===n&&o(e,93)),20480&~n||o(e,100),4196352&t&&209008===n&&o(e,96),2098176&t&&241773===n&&o(e,95,"yield")}function ne(e,t,n){return 209008===n&&(4196352&t&&o(e,96),e.destructible|=128),241773===n&&2097152&t&&o(e,95,"yield"),!(20480&~n&&36864&~n&&122!=n)}function oe(e,t,n,r){for(;t;){if(t["$"+n])return r&&o(e,134),1;r&&t.loop&&(r=0),t=t.$}return 0}function re(e,t,n,o,r,s){return 2&t&&(s.start=n,s.end=e.startPos,s.range=[n,e.startPos]),4&t&&(s.loc={start:{line:o,column:r},end:{line:e.startLine,column:e.startColumn}},e.sourceFile&&(s.loc.source=e.sourceFile)),s}function se(e){switch(e.type){case"JSXIdentifier":return e.name;case"JSXNamespacedName":return e.namespace+":"+e.name;case"JSXMemberExpression":return se(e.object)+"."+se(e.property)}}function ae(e,t,n){const o=le({parent:void 0,type:2},1024);return ue(e,t,o,n,1,0),o}function ie(e,t,...n){const{index:o,line:r,column:s}=e;return{type:t,params:n,index:o,line:r,column:s}}function le(e,t){return{parent:e,type:t,scopeError:void 0}}function ce(e,t,n,o,r,s){4&r?de(e,t,n,o,r):ue(e,t,n,o,r,s),64&s&&pe(e,o)}function ue(e,t,n,r,s,a){const i=n["#"+r];!i||2&i||(1&s?n.scopeError=ie(e,141,r):256&t&&64&i&&2&a||o(e,141,r)),128&n.type&&n.parent["#"+r]&&!(2&n.parent["#"+r])&&o(e,141,r),1024&n.type&&i&&!(2&i)&&1&s&&(n.scopeError=ie(e,141,r)),64&n.type&&768&n.parent["#"+r]&&o(e,154,r),n["#"+r]=s}function de(e,t,n,r,s){let a=n;for(;a&&!(256&a.type);){const i=a["#"+r];248&i&&(256&t&&!(1024&t)&&(128&s&&68&i||128&i&&68&s)||o(e,141,r)),a===n&&1&i&&1&s&&(a.scopeError=ie(e,141,r)),768&i&&(512&i&&256&t&&!(1024&t)||o(e,141,r)),a["#"+r]=s,a=a.parent}}function pe(e,t){void 0!==e.exportedNames&&""!==t&&(e.exportedNames["#"+t]&&o(e,142,t),e.exportedNames["#"+t]=1)}function fe(e,t){void 0!==e.exportedBindings&&""!==t&&(e.exportedBindings["#"+t]=1)}function ke(e,t){return 2098176&e?!(2048&e&&209008===t)&&(!(2097152&e&&241773===t)&&!(143360&~t&&12288&~t)):!(143360&~t&&12288&~t&&36864&~t)}function ge(e,t,n){537079808&~n||(1024&t&&o(e,116),e.flags|=512),ke(t,n)||o(e,0)}function me(e,t,n){let r,s,a,i="";null!=t&&(t.module&&(n|=3072),t.next&&(n|=1),t.loc&&(n|=4),t.ranges&&(n|=2),t.uniqueKeyInPattern&&(n|=536870912),t.lexical&&(n|=64),t.webcompat&&(n|=256),t.directives&&(n|=520),t.globalReturn&&(n|=32),t.raw&&(n|=512),t.preserveParens&&(n|=128),t.impliedStrict&&(n|=1024),t.jsx&&(n|=16),t.source&&(i=t.source),null!=t.onComment&&(r=Array.isArray(t.onComment)?function(e,t){return function(n,o,r,s,a){const i={type:n,value:o};2&e&&(i.start=r,i.end=s,i.range=[r,s]),4&e&&(i.loc=a),t.push(i)}}(n,t.onComment):t.onComment),null!=t.onInsertedSemicolon&&(s=t.onInsertedSemicolon),null!=t.onToken&&(a=Array.isArray(t.onToken)?function(e,t){return function(n,o,r,s){const a={token:n};2&e&&(a.start=o,a.end=r,a.range=[o,r]),4&e&&(a.loc=s),t.push(a)}}(n,t.onToken):t.onToken));const c=function(e,t,n,o,r){return{source:e,flags:0,index:0,line:1,column:0,startPos:0,end:e.length,tokenPos:0,startColumn:0,colPos:0,linePos:1,startLine:1,sourceFile:t,tokenValue:"",token:1048576,tokenRaw:"",tokenRegExp:void 0,currentChar:e.charCodeAt(0),exportedNames:[],exportedBindings:[],assignable:1,destructible:0,onComment:n,onToken:o,onInsertedSemicolon:r,leadingDecorators:[]}}(e,i,r,a,s);1&n&&function(e){const t=e.source;35===e.currentChar&&33===t.charCodeAt(e.index+1)&&(l(e),l(e),x(e,t,0,4,e.tokenPos,e.linePos,e.colPos))}(c);const u=64&n?{parent:void 0,type:2}:void 0;let d=[],p="script";if(2048&n){if(p="module",d=function(e,t,n){F(e,32768|t);const o=[];if(8&t)for(;134283267===e.token;){const{tokenPos:n,linePos:r,colPos:s,token:a}=e;o.push(qe(e,t,ot(e,t),a,n,r,s))}for(;1048576!==e.token;)o.push(be(e,t,n));return o}(c,8192|n,u),u)for(const e in c.exportedBindings)"#"!==e[0]||u[e]||o(c,143,e.slice(1))}else d=function(e,t,n){F(e,268468224|t);const o=[];for(;134283267===e.token;){const{index:n,tokenPos:r,tokenValue:s,linePos:a,colPos:i,token:l}=e,c=ot(e,t);Y(e,n,r,s)&&(t|=1024),o.push(qe(e,t,c,l,r,a,i))}for(;1048576!==e.token;)o.push(he(e,t,n,4,{}));return o}(c,8192|n,u);const f={type:"Program",sourceType:p,body:d};return 2&n&&(f.start=0,f.end=e.length,f.range=[0,e.length]),4&n&&(f.loc={start:{line:1,column:0},end:{line:c.line,column:c.column}},c.sourceFile&&(f.loc.source=i)),f}function be(e,t,n){let r;switch(e.leadingDecorators=xt(e,t),e.token){case 20566:r=function(e,t,n){const r=e.tokenPos,s=e.linePos,a=e.colPos;F(e,32768|t);const i=[];let l,c=null,u=null;if(W(e,32768|t,20563)){switch(e.token){case 86106:c=rt(e,t,n,4,1,1,0,e.tokenPos,e.linePos,e.colPos);break;case 133:case 86096:c=yt(e,t,n,1,e.tokenPos,e.linePos,e.colPos);break;case 209007:const{tokenPos:o,linePos:r,colPos:s}=e;c=nt(e,t);const{flags:a}=e;1&a||(86106===e.token?c=rt(e,t,n,4,1,1,1,o,r,s):67174411===e.token?(c=Pt(e,t,c,1,1,0,a,o,r,s),c=ze(e,t,c,0,0,o,r,s),c=Ge(e,t,0,0,o,r,s,c)):143360&e.token&&(n&&(n=ae(e,t,e.tokenValue)),c=nt(e,t),c=gt(e,t,n,[c],1,o,r,s)));break;default:c=Ue(e,t,1,0,e.tokenPos,e.linePos,e.colPos),$(e,32768|t)}return n&&pe(e,"default"),re(e,t,r,s,a,{type:"ExportDefaultDeclaration",declaration:c})}switch(e.token){case 8457014:{F(e,t);let i=null;return W(e,t,77934)&&(n&&pe(e,e.tokenValue),i=nt(e,t)),K(e,t,12404),134283267!==e.token&&o(e,103,"Export"),u=ot(e,t),$(e,32768|t),re(e,t,r,s,a,{type:"ExportAllDeclaration",source:u,exported:i})}case 2162700:{F(e,t);const r=[],s=[];for(;143360&e.token;){const{tokenPos:a,tokenValue:l,linePos:c,colPos:u}=e,d=nt(e,t);let p;77934===e.token?(F(e,t),134217728&~e.token||o(e,104),n&&(r.push(e.tokenValue),s.push(l)),p=nt(e,t)):(n&&(r.push(e.tokenValue),s.push(e.tokenValue)),p=d),i.push(re(e,t,a,c,u,{type:"ExportSpecifier",local:d,exported:p})),1074790415!==e.token&&K(e,t,18)}if(K(e,t,1074790415),W(e,t,12404))134283267!==e.token&&o(e,103,"Export"),u=ot(e,t);else if(n){let t=0,n=r.length;for(;t<n;t++)pe(e,r[t]);for(t=0,n=s.length;t<n;t++)fe(e,s[t])}$(e,32768|t);break}case 86096:c=yt(e,t,n,2,e.tokenPos,e.linePos,e.colPos);break;case 86106:c=rt(e,t,n,4,1,2,0,e.tokenPos,e.linePos,e.colPos);break;case 241739:c=Se(e,t,n,8,64,e.tokenPos,e.linePos,e.colPos);break;case 86092:c=Se(e,t,n,16,64,e.tokenPos,e.linePos,e.colPos);break;case 86090:c=Ae(e,t,n,64,e.tokenPos,e.linePos,e.colPos);break;case 209007:const{tokenPos:d,linePos:p,colPos:f}=e;if(F(e,t),!(1&e.flags)&&86106===e.token){c=rt(e,t,n,4,1,2,1,d,p,f),n&&(l=c.id?c.id.name:"",pe(e,l));break}default:o(e,28,T[255&e.token])}return re(e,t,r,s,a,{type:"ExportNamedDeclaration",declaration:c,specifiers:i,source:u})}(e,t,n);break;case 86108:r=function(e,t,n){const r=e.tokenPos,s=e.linePos,a=e.colPos;F(e,t);let i=null;const{tokenPos:l,linePos:c,colPos:u}=e;let d=[];if(134283267===e.token)i=ot(e,t);else{if(143360&e.token){if(d=[re(e,t,l,c,u,{type:"ImportDefaultSpecifier",local:Ve(e,t,n)})],W(e,t,18))switch(e.token){case 8457014:d.push(Te(e,t,n));break;case 2162700:Re(e,t,n,d);break;default:o(e,105)}}else switch(e.token){case 8457014:d=[Te(e,t,n)];break;case 2162700:Re(e,t,n,d);break;case 67174411:return Ne(e,t,r,s,a);case 67108877:return Ie(e,t,r,s,a);default:o(e,28,T[255&e.token])}i=function(e,t){W(e,t,12404)||o(e,28,T[255&e.token]);134283267!==e.token&&o(e,103,"Import");return ot(e,t)}(e,t)}return $(e,32768|t),re(e,t,r,s,a,{type:"ImportDeclaration",specifiers:d,source:i})}(e,t,n);break;default:r=he(e,t,n,4,{})}return e.leadingDecorators.length&&o(e,165),r}function he(e,t,n,r,s){const a=e.tokenPos,i=e.linePos,l=e.colPos;switch(e.token){case 86106:return rt(e,t,n,r,1,0,0,a,i,l);case 133:case 86096:return yt(e,t,n,0,a,i,l);case 86092:return Se(e,t,n,16,0,a,i,l);case 241739:return function(e,t,n,r,s,a,i){const{token:l,tokenValue:c}=e;let u=nt(e,t);if(2240512&e.token){const o=Le(e,t,n,8,0);return $(e,32768|t),re(e,t,s,a,i,{type:"VariableDeclaration",kind:"let",declarations:o})}e.assignable=1,1024&t&&o(e,83);if(21===e.token)return ve(e,t,n,r,{},c,u,l,0,s,a,i);if(10===e.token){let n;64&t&&(n=ae(e,t,c)),e.flags=128^(128|e.flags),u=gt(e,t,n,[u],0,s,a,i)}else u=ze(e,t,u,0,0,s,a,i),u=Ge(e,t,0,0,s,a,i,u);18===e.token&&(u=Be(e,t,0,s,a,i,u));return xe(e,t,u,s,a,i)}(e,t,n,r,a,i,l);case 20566:o(e,101,"export");case 86108:switch(F(e,t),e.token){case 67174411:return Ne(e,t,a,i,l);case 67108877:return Ie(e,t,a,i,l);default:o(e,101,"import")}case 209007:return we(e,t,n,r,s,1,a,i,l);default:return Pe(e,t,n,r,s,1,a,i,l)}}function Pe(e,t,n,r,s,a,i,l,c){switch(e.token){case 86090:return Ae(e,t,n,0,i,l,c);case 20574:return function(e,t,n,r,s){!(32&t)&&8192&t&&o(e,90);F(e,32768|t);const a=1&e.flags||1048576&e.token?null:Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos);return $(e,32768|t),re(e,t,n,r,s,{type:"ReturnStatement",argument:a})}(e,t,i,l,c);case 20571:return function(e,t,n,o,r,s,a){F(e,t),K(e,32768|t,67174411),e.assignable=1;const i=Oe(e,t,0,1,e.tokenPos,e.line,e.colPos);K(e,32768|t,16);const l=Ce(e,t,n,o,e.tokenPos,e.linePos,e.colPos);let c=null;20565===e.token&&(F(e,32768|t),c=Ce(e,t,n,o,e.tokenPos,e.linePos,e.colPos));return re(e,t,r,s,a,{type:"IfStatement",test:i,consequent:l,alternate:c})}(e,t,n,s,i,l,c);case 20569:return function(e,t,n,r,s,a,i){F(e,t);const l=((4194304&t)>0||(2048&t)>0&&(8192&t)>0)&&W(e,t,209008);K(e,32768|t,67174411),n&&(n=le(n,1));let c,u=null,d=null,p=0,f=null,k=86090===e.token||241739===e.token||86092===e.token;const{token:g,tokenPos:m,linePos:b,colPos:h}=e;k?241739===g?(f=nt(e,t),2240512&e.token?(8738868===e.token?1024&t&&o(e,65):f=re(e,t,m,b,h,{type:"VariableDeclaration",kind:"let",declarations:Le(e,134217728|t,n,8,32)}),e.assignable=1):1024&t?o(e,65):(k=!1,e.assignable=1,f=ze(e,t,f,0,0,m,b,h),274549===e.token&&o(e,112))):(F(e,t),f=re(e,t,m,b,h,86090===g?{type:"VariableDeclaration",kind:"var",declarations:Le(e,134217728|t,n,4,32)}:{type:"VariableDeclaration",kind:"const",declarations:Le(e,134217728|t,n,16,32)}),e.assignable=1):1074790417===g?l&&o(e,80):2097152&~g?f=Me(e,134217728|t,1,0,1,m,b,h):(f=2162700===g?ut(e,t,void 0,1,0,0,2,32,m,b,h):at(e,t,void 0,1,0,0,2,32,m,b,h),p=e.destructible,256&t&&64&p&&o(e,61),e.assignable=16&p?2:1,f=ze(e,134217728|t,f,0,0,e.tokenPos,e.linePos,e.colPos));if(!(262144&~e.token)){if(274549===e.token){2&e.assignable&&o(e,78,l?"await":"of"),Q(e,f),F(e,32768|t),c=Ue(e,t,1,0,e.tokenPos,e.linePos,e.colPos),K(e,32768|t,16);return re(e,t,s,a,i,{type:"ForOfStatement",left:f,right:c,body:Ee(e,t,n,r),await:l})}2&e.assignable&&o(e,78,"in"),Q(e,f),F(e,32768|t),l&&o(e,80),c=Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos),K(e,32768|t,16);return re(e,t,s,a,i,{type:"ForInStatement",body:Ee(e,t,n,r),left:f,right:c})}l&&o(e,80);k||(8&p&&1077936157!==e.token&&o(e,78,"loop"),f=Ge(e,134217728|t,0,0,m,b,h,f));18===e.token&&(f=Be(e,t,0,e.tokenPos,e.linePos,e.colPos,f));K(e,32768|t,1074790417),1074790417!==e.token&&(u=Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos));K(e,32768|t,1074790417),16!==e.token&&(d=Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos));K(e,32768|t,16);const P=Ee(e,t,n,r);return re(e,t,s,a,i,{type:"ForStatement",init:f,test:u,update:d,body:P})}(e,t,n,s,i,l,c);case 20564:return function(e,t,n,o,r,s,a){F(e,32768|t);const i=Ee(e,t,n,o);K(e,t,20580),K(e,32768|t,67174411);const l=Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos);return K(e,32768|t,16),W(e,32768|t,1074790417),re(e,t,r,s,a,{type:"DoWhileStatement",body:i,test:l})}(e,t,n,s,i,l,c);case 20580:return function(e,t,n,o,r,s,a){F(e,t),K(e,32768|t,67174411);const i=Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos);K(e,32768|t,16);const l=Ee(e,t,n,o);return re(e,t,r,s,a,{type:"WhileStatement",test:i,body:l})}(e,t,n,s,i,l,c);case 86112:return function(e,t,n,r,s,a,i){F(e,t),K(e,32768|t,67174411);const l=Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos);K(e,t,16),K(e,t,2162700);const c=[];let u=0;n&&(n=le(n,8));for(;1074790415!==e.token;){const{tokenPos:s,linePos:a,colPos:i}=e;let l=null;const d=[];for(W(e,32768|t,20558)?l=Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos):(K(e,32768|t,20563),u&&o(e,87),u=1),K(e,32768|t,21);20558!==e.token&&1074790415!==e.token&&20563!==e.token;)d.push(he(e,4096|t,n,2,{$:r}));c.push(re(e,t,s,a,i,{type:"SwitchCase",test:l,consequent:d}))}return K(e,32768|t,1074790415),re(e,t,s,a,i,{type:"SwitchStatement",discriminant:l,cases:c})}(e,t,n,s,i,l,c);case 1074790417:return function(e,t,n,o,r){return F(e,32768|t),re(e,t,n,o,r,{type:"EmptyStatement"})}(e,t,i,l,c);case 2162700:return ye(e,t,n?le(n,2):n,s,i,l,c);case 86114:return function(e,t,n,r,s){F(e,32768|t),1&e.flags&&o(e,88);const a=Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos);return $(e,32768|t),re(e,t,n,r,s,{type:"ThrowStatement",argument:a})}(e,t,i,l,c);case 20557:return function(e,t,n,r,s,a){F(e,32768|t);let i=null;if(!(1&e.flags)&&143360&e.token){const{tokenValue:r}=e;i=nt(e,32768|t),oe(e,n,r,0)||o(e,135,r)}else 135168&t||o(e,67);return $(e,32768|t),re(e,t,r,s,a,{type:"BreakStatement",label:i})}(e,t,s,i,l,c);case 20561:return function(e,t,n,r,s,a){131072&t||o(e,66);F(e,t);let i=null;if(!(1&e.flags)&&143360&e.token){const{tokenValue:r}=e;i=nt(e,32768|t),oe(e,n,r,1)||o(e,135,r)}return $(e,32768|t),re(e,t,r,s,a,{type:"ContinueStatement",label:i})}(e,t,s,i,l,c);case 20579:return function(e,t,n,r,s,a,i){F(e,32768|t);const l=n?le(n,32):void 0,c=ye(e,t,l,{$:r},e.tokenPos,e.linePos,e.colPos),{tokenPos:u,linePos:d,colPos:p}=e,f=W(e,32768|t,20559)?function(e,t,n,r,s,a,i){let l=null,c=n;W(e,t,67174411)&&(n&&(n=le(n,4)),l=St(e,t,n,2097152&~e.token?512:256,0,e.tokenPos,e.linePos,e.colPos),18===e.token?o(e,84):1077936157===e.token&&o(e,85),K(e,32768|t,16),n&&(c=le(n,64)));const u=ye(e,t,c,{$:r},e.tokenPos,e.linePos,e.colPos);return re(e,t,s,a,i,{type:"CatchClause",param:l,body:u})}(e,t,n,r,u,d,p):null;let k=null;if(20568===e.token){F(e,32768|t);k=ye(e,t,l?le(n,4):void 0,{$:r},e.tokenPos,e.linePos,e.colPos)}f||k||o(e,86);return re(e,t,s,a,i,{type:"TryStatement",block:c,handler:f,finalizer:k})}(e,t,n,s,i,l,c);case 20581:return function(e,t,n,r,s,a,i){F(e,t),1024&t&&o(e,89);K(e,32768|t,67174411);const l=Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos);K(e,32768|t,16);const c=Pe(e,t,n,2,r,0,e.tokenPos,e.linePos,e.colPos);return re(e,t,s,a,i,{type:"WithStatement",object:l,body:c})}(e,t,n,s,i,l,c);case 20562:return function(e,t,n,o,r){return F(e,32768|t),$(e,32768|t),re(e,t,n,o,r,{type:"DebuggerStatement"})}(e,t,i,l,c);case 209007:return we(e,t,n,r,s,0,i,l,c);case 20559:o(e,157);case 20568:o(e,158);case 86106:o(e,1024&t?74:256&t?75:76);case 86096:o(e,77);default:return function(e,t,n,r,s,a,i,l,c){const{tokenValue:u,token:d}=e;let p;if(241739===d)p=nt(e,t),1024&t&&o(e,83),69271571===e.token&&o(e,82);else p=_e(e,t,2,0,1,0,1,e.tokenPos,e.linePos,e.colPos);if(143360&d&&21===e.token)return ve(e,t,n,r,s,u,p,d,a,i,l,c);p=ze(e,t,p,0,0,i,l,c),p=Ge(e,t,0,0,i,l,c,p),18===e.token&&(p=Be(e,t,0,i,l,c,p));return xe(e,t,p,i,l,c)}(e,t,n,r,s,a,i,l,c)}}function ye(e,t,n,o,r,s,a){const i=[];for(K(e,32768|t,2162700);1074790415!==e.token;)i.push(he(e,t,n,2,{$:o}));return K(e,32768|t,1074790415),re(e,t,r,s,a,{type:"BlockStatement",body:i})}function xe(e,t,n,o,r,s){return $(e,32768|t),re(e,t,o,r,s,{type:"ExpressionStatement",expression:n})}function ve(e,t,n,r,s,a,i,l,c,u,d,p){ee(e,t,0,l,1),function(e,t,n){let r=t;for(;r;)r["$"+n]&&o(e,133,n),r=r.$;t["$"+n]=1}(e,s,a),F(e,32768|t);return re(e,t,u,d,p,{type:"LabeledStatement",label:i,body:c&&!(1024&t)&&256&t&&86106===e.token?rt(e,t,le(n,2),r,0,0,0,e.tokenPos,e.linePos,e.colPos):Pe(e,t,n,r,s,c,e.tokenPos,e.linePos,e.colPos)})}function we(e,t,n,r,s,a,i,l,c){const{token:u,tokenValue:d}=e;let p=nt(e,t);if(21===e.token)return ve(e,t,n,r,s,d,p,u,1,i,l,c);const f=1&e.flags;if(!f){if(86106===e.token)return a||o(e,120),rt(e,t,n,r,1,0,1,i,l,c);if(!(143360&~e.token))return p=ht(e,t,1,i,l,c),18===e.token&&(p=Be(e,t,0,i,l,c,p)),xe(e,t,p,i,l,c)}return 67174411===e.token?p=Pt(e,t,p,1,1,0,f,i,l,c):(10===e.token&&(ge(e,t,u),p=ft(e,t,e.tokenValue,p,0,1,0,i,l,c)),e.assignable=1),p=ze(e,t,p,0,0,i,l,c),p=Ge(e,t,0,0,i,l,c,p),e.assignable=1,18===e.token&&(p=Be(e,t,0,i,l,c,p)),xe(e,t,p,i,l,c)}function qe(e,t,n,o,r,s,a){return 1074790417!==o&&(e.assignable=2,n=ze(e,t,n,0,0,r,s,a),1074790417!==e.token&&(n=Ge(e,t,0,0,r,s,a,n),18===e.token&&(n=Be(e,t,0,r,s,a,n))),$(e,32768|t)),8&t&&"Literal"===n.type&&"string"==typeof n.value?re(e,t,r,s,a,{type:"ExpressionStatement",expression:n,directive:n.raw.slice(1,-1)}):re(e,t,r,s,a,{type:"ExpressionStatement",expression:n})}function Ce(e,t,n,o,r,s,a){return 1024&t||!(256&t)||86106!==e.token?Pe(e,t,n,0,{$:o},0,e.tokenPos,e.linePos,e.colPos):rt(e,t,le(n,2),0,0,0,0,r,s,a)}function Ee(e,t,n,o){return Pe(e,134217728^(134217728|t)|131072,n,0,{loop:1,$:o},0,e.tokenPos,e.linePos,e.colPos)}function Se(e,t,n,o,r,s,a,i){F(e,t);const l=Le(e,t,n,o,r);return $(e,32768|t),re(e,t,s,a,i,{type:"VariableDeclaration",kind:8&o?"let":"const",declarations:l})}function Ae(e,t,n,o,r,s,a){F(e,t);const i=Le(e,t,n,4,o);return $(e,32768|t),re(e,t,r,s,a,{type:"VariableDeclaration",kind:"var",declarations:i})}function Le(e,t,n,r,s){let a=1;const i=[De(e,t,n,r,s)];for(;W(e,t,18);)a++,i.push(De(e,t,n,r,s));return a>1&&32&s&&262144&e.token&&o(e,59,T[255&e.token]),i}function De(e,t,n,r,a){const{token:i,tokenPos:l,linePos:c,colPos:u}=e;let d=null;const p=St(e,t,n,r,a,l,c,u);return 1077936157===e.token?(F(e,32768|t),d=Ue(e,t,1,0,e.tokenPos,e.linePos,e.colPos),!(32&a)&&2097152&i||(274549===e.token||8738868===e.token&&(2097152&i||!(4&r)||1024&t))&&s(l,e.line,e.index-3,58,274549===e.token?"of":"in")):(16&r||(2097152&i)>0)&&262144&~e.token&&o(e,57,16&r?"const":"destructuring"),re(e,t,l,c,u,{type:"VariableDeclarator",id:p,init:d})}function Ve(e,t,n){return ke(t,e.token)||o(e,115),537079808&~e.token||o(e,116),n&&ue(e,t,n,e.tokenValue,8,0),nt(e,t)}function Te(e,t,n){const{tokenPos:o,linePos:r,colPos:a}=e;return F(e,t),K(e,t,77934),134217728&~e.token||s(o,e.line,e.index,28,T[255&e.token]),re(e,t,o,r,a,{type:"ImportNamespaceSpecifier",local:Ve(e,t,n)})}function Re(e,t,n,r){for(F(e,t);143360&e.token;){let{token:s,tokenValue:a,tokenPos:i,linePos:l,colPos:c}=e;const u=nt(e,t);let d;W(e,t,77934)?(134217728&~e.token&&18!==e.token?ee(e,t,16,e.token,0):o(e,104),a=e.tokenValue,d=nt(e,t)):(ee(e,t,16,s,0),d=u),n&&ue(e,t,n,a,8,0),r.push(re(e,t,i,l,c,{type:"ImportSpecifier",local:d,imported:u})),1074790415!==e.token&&K(e,t,18)}return K(e,t,1074790415),r}function Ie(e,t,n,o,r){let s=$e(e,t,re(e,t,n,o,r,{type:"Identifier",name:"import"}),n,o,r);return s=ze(e,t,s,0,0,n,o,r),s=Ge(e,t,0,0,n,o,r,s),18===e.token&&(s=Be(e,t,0,n,o,r,s)),xe(e,t,s,n,o,r)}function Ne(e,t,n,o,r){let s=Ye(e,t,0,n,o,r);return s=ze(e,t,s,0,0,n,o,r),18===e.token&&(s=Be(e,t,0,n,o,r,s)),xe(e,t,s,n,o,r)}function Ue(e,t,n,o,r,s,a){let i=_e(e,t,2,0,n,o,1,r,s,a);return i=ze(e,t,i,o,0,r,s,a),Ge(e,t,o,0,r,s,a,i)}function Be(e,t,n,o,r,s,a){const i=[a];for(;W(e,32768|t,18);)i.push(Ue(e,t,1,n,e.tokenPos,e.linePos,e.colPos));return re(e,t,o,r,s,{type:"SequenceExpression",expressions:i})}function Oe(e,t,n,o,r,s,a){const i=Ue(e,t,o,n,r,s,a);return 18===e.token?Be(e,t,n,r,s,a,i):i}function Ge(e,t,n,r,s,a,i,l){const{token:c}=e;if(!(4194304&~c)){2&e.assignable&&o(e,24),(!r&&1077936157===c&&"ArrayExpression"===l.type||"ObjectExpression"===l.type)&&Q(e,l),F(e,32768|t);const u=Ue(e,t,1,n,e.tokenPos,e.linePos,e.colPos);return e.assignable=2,re(e,t,s,a,i,r?{type:"AssignmentPattern",left:l,right:u}:{type:"AssignmentExpression",left:l,operator:T[255&c],right:u})}return 8454144&~c||(l=He(e,t,n,s,a,i,4,c,l)),W(e,32768|t,22)&&(l=je(e,t,l,s,a,i)),l}function Fe(e,t,n,o,r,s,a,i){const{token:l}=e;F(e,32768|t);const c=Ue(e,t,1,n,e.tokenPos,e.linePos,e.colPos);return i=re(e,t,r,s,a,o?{type:"AssignmentPattern",left:i,right:c}:{type:"AssignmentExpression",left:i,operator:T[255&l],right:c}),e.assignable=2,i}function je(e,t,n,o,r,s){const a=Ue(e,134217728^(134217728|t),1,0,e.tokenPos,e.linePos,e.colPos);K(e,32768|t,21),e.assignable=1;const i=Ue(e,t,1,0,e.tokenPos,e.linePos,e.colPos);return e.assignable=2,re(e,t,o,r,s,{type:"ConditionalExpression",test:n,consequent:a,alternate:i})}function He(e,t,n,r,s,a,i,l,c){const u=8738868&-((134217728&t)>0);let d,p;for(e.assignable=2;8454144&e.token&&(d=e.token,p=3840&d,(524288&d&&268435456&l||524288&l&&268435456&d)&&o(e,160),!(p+((8457273===d)<<8)-((u===d)<<12)<=i));)F(e,32768|t),c=re(e,t,r,s,a,{type:524288&d||268435456&d?"LogicalExpression":"BinaryExpression",left:c,right:He(e,t,n,e.tokenPos,e.linePos,e.colPos,p,d,Me(e,t,0,n,1,e.tokenPos,e.linePos,e.colPos)),operator:T[255&d]});return 1077936157===e.token&&o(e,24),c}function Je(e,t,n,a,i,l){const{tokenPos:c,linePos:u,colPos:d}=e;K(e,32768|t,2162700);const p=[],f=t;if(1074790415!==e.token){for(;134283267===e.token;){const{index:n,tokenPos:o,tokenValue:r,token:a}=e,i=ot(e,t);Y(e,n,o,r)&&(t|=1024,128&e.flags&&s(e.index,e.line,e.tokenPos,64),64&e.flags&&s(e.index,e.line,e.tokenPos,8)),p.push(qe(e,t,i,a,o,e.linePos,e.colPos))}1024&t&&(i&&(537079808&~i||o(e,116),36864&~i||o(e,38)),512&e.flags&&o(e,116),256&e.flags&&o(e,115)),!(64&t&&n&&void 0!==l)||1024&f||8192&t||r(l)}for(e.flags=832^(832|e.flags),e.destructible=256^(256|e.destructible);1074790415!==e.token;)p.push(he(e,t,n,4,{}));return K(e,24&a?32768|t:t,1074790415),e.flags&=-193,1077936157===e.token&&o(e,24),re(e,t,c,u,d,{type:"BlockStatement",body:p})}function Me(e,t,n,o,r,s,a,i){return ze(e,t,_e(e,t,2,0,n,o,r,s,a,i),o,0,s,a,i)}function ze(e,t,n,r,s,a,i,l){if(33619968&~e.token||1&e.flags){if(!(67108864&~e.token)){switch(t=134217728^(134217728|t),e.token){case 67108877:F(e,8192^(268443648|t)),16384&t&&131===e.token&&"super"===e.tokenValue&&o(e,27),e.assignable=1;n=re(e,t,a,i,l,{type:"MemberExpression",object:n,computed:!1,property:Xe(e,65536|t)});break;case 69271571:{let o=!1;2048&~e.flags||(o=!0,e.flags=2048^(2048|e.flags)),F(e,32768|t);const{tokenPos:s,linePos:c,colPos:u}=e,d=Oe(e,t,r,1,s,c,u);K(e,t,20),e.assignable=1,n=re(e,t,a,i,l,{type:"MemberExpression",object:n,computed:!0,property:d}),o&&(e.flags|=2048);break}case 67174411:{if(!(1024&~e.flags))return e.flags=1024^(1024|e.flags),n;let o=!1;2048&~e.flags||(o=!0,e.flags=2048^(2048|e.flags));const s=tt(e,t,r);e.assignable=2,n=re(e,t,a,i,l,{type:"CallExpression",callee:n,arguments:s}),o&&(e.flags|=2048);break}case 67108991:F(e,8192^(268443648|t)),e.flags|=2048,e.assignable=2,n=function(e,t,n,r,s,a){let i,l=!1;69271571!==e.token&&67174411!==e.token||2048&~e.flags||(l=!0,e.flags=2048^(2048|e.flags));if(69271571===e.token){F(e,32768|t);const{tokenPos:o,linePos:l,colPos:c}=e,u=Oe(e,t,0,1,o,l,c);K(e,t,20),e.assignable=2,i=re(e,t,r,s,a,{type:"MemberExpression",object:n,computed:!0,optional:!0,property:u})}else if(67174411===e.token){const o=tt(e,t,0);e.assignable=2,i=re(e,t,r,s,a,{type:"CallExpression",callee:n,arguments:o,optional:!0})}else{143360&e.token||o(e,155);const l=nt(e,t);e.assignable=2,i=re(e,t,r,s,a,{type:"MemberExpression",object:n,computed:!1,optional:!0,property:l})}l&&(e.flags|=2048);return i}(e,t,n,a,i,l);break;default:2048&~e.flags||o(e,161),e.assignable=2,n=re(e,t,a,i,l,{type:"TaggedTemplateExpression",tag:n,quasi:67174408===e.token?Ke(e,65536|t):We(e,t,e.tokenPos,e.linePos,e.colPos)})}n=ze(e,t,n,0,1,a,i,l)}}else n=function(e,t,n,r,s,a){2&e.assignable&&o(e,53);const{token:i}=e;return F(e,t),e.assignable=2,re(e,t,r,s,a,{type:"UpdateExpression",argument:n,operator:T[255&i],prefix:!1})}(e,t,n,a,i,l);return 0!==s||2048&~e.flags||(e.flags=2048^(2048|e.flags),n=re(e,t,a,i,l,{type:"ChainExpression",expression:n})),n}function Xe(e,t){return 143360&e.token||131===e.token||o(e,155),1&t&&131===e.token?Ct(e,t,e.tokenPos,e.linePos,e.colPos):nt(e,t)}function _e(e,t,n,r,a,i,l,c,u,d){if(!(143360&~e.token)){switch(e.token){case 209008:return function(e,t,n,r,a,i,l){if(r&&(e.destructible|=128),4194304&t||2048&t&&8192&t){n&&o(e,0),8388608&t&&s(e.index,e.line,e.index,29),F(e,32768|t);const r=Me(e,t,0,0,1,e.tokenPos,e.linePos,e.colPos);return 8457273===e.token&&o(e,31),e.assignable=2,re(e,t,a,i,l,{type:"AwaitExpression",argument:r})}return 2048&t&&o(e,96),pt(e,t,a,i,l)}(e,t,r,i,c,u,d);case 241773:return function(e,t,n,r,s,a,i){if(n&&(e.destructible|=256),2097152&t){F(e,32768|t),8388608&t&&o(e,30),r||o(e,24),22===e.token&&o(e,121);let n=null,l=!1;return 1&e.flags||(l=W(e,32768|t,8457014),(77824&e.token||l)&&(n=Ue(e,t,1,0,e.tokenPos,e.linePos,e.colPos))),e.assignable=2,re(e,t,s,a,i,{type:"YieldExpression",argument:n,delegate:l})}return 1024&t&&o(e,95,"yield"),pt(e,t,s,a,i)}(e,t,i,a,c,u,d);case 209007:return function(e,t,n,r,s,a,i,l,c){const{token:u}=e,d=nt(e,t),{flags:p}=e;if(!(1&p)){if(86106===e.token)return st(e,t,1,n,i,l,c);if(!(143360&~e.token))return r||o(e,0),ht(e,t,s,i,l,c)}return a||67174411!==e.token?10===e.token?(ge(e,t,u),a&&o(e,49),ft(e,t,e.tokenValue,d,a,s,0,i,l,c)):(e.assignable=1,d):Pt(e,t,d,s,1,0,p,i,l,c)}(e,t,i,l,a,r,c,u,d)}const{token:p,tokenValue:f}=e,k=nt(e,65536|t);return 10===e.token?(l||o(e,0),ge(e,t,p),ft(e,t,f,k,r,a,0,c,u,d)):(16384&t&&537079928===p&&o(e,127),241739===p&&(1024&t&&o(e,110),24&n&&o(e,98)),e.assignable=1024&t&&!(537079808&~p)?2:1,k)}if(!(134217728&~e.token))return ot(e,t);switch(e.token){case 33619995:case 33619996:return function(e,t,n,r,s,a,i){n&&o(e,54),r||o(e,0);const{token:l}=e;F(e,32768|t);const c=Me(e,t,0,0,1,e.tokenPos,e.linePos,e.colPos);return 2&e.assignable&&o(e,53),e.assignable=2,re(e,t,s,a,i,{type:"UpdateExpression",argument:c,operator:T[255&l],prefix:!0})}(e,t,r,l,c,u,d);case 16863278:case 16842800:case 16842801:case 25233970:case 25233971:case 16863277:case 16863279:return function(e,t,n,r,s,a,i){n||o(e,0);const l=e.token;F(e,32768|t);const c=Me(e,t,0,i,1,e.tokenPos,e.linePos,e.colPos);var u;return 8457273===e.token&&o(e,31),1024&t&&16863278===l&&("Identifier"===c.type?o(e,118):(u=c).property&&"PrivateIdentifier"===u.property.type&&o(e,124)),e.assignable=2,re(e,t,r,s,a,{type:"UnaryExpression",operator:T[255&l],argument:c,prefix:!0})}(e,t,l,c,u,d,i);case 86106:return st(e,t,0,i,c,u,d);case 2162700:return function(e,t,n,r,s,a,i){const l=ut(e,t,void 0,n,r,0,2,0,s,a,i);256&t&&64&e.destructible&&o(e,61);8&e.destructible&&o(e,60);return l}(e,t,a?0:1,i,c,u,d);case 69271571:return function(e,t,n,r,s,a,i){const l=at(e,t,void 0,n,r,0,2,0,s,a,i);256&t&&64&e.destructible&&o(e,61);8&e.destructible&&o(e,60);return l}(e,t,a?0:1,i,c,u,d);case 67174411:return function(e,t,n,r,s,a,i,l){e.flags=128^(128|e.flags);const{tokenPos:c,linePos:u,colPos:d}=e;F(e,268468224|t);const p=64&t?le({parent:void 0,type:2},1024):void 0;if(t=134217728^(134217728|t),W(e,t,16))return kt(e,t,p,[],n,0,a,i,l);let f,k=0;e.destructible&=-385;let g=[],m=0,b=0;const{tokenPos:h,linePos:P,colPos:y}=e;e.assignable=1;for(;16!==e.token;){const{token:n,tokenPos:a,linePos:i,colPos:l}=e;if(143360&n)p&&ue(e,t,p,e.tokenValue,1,0),f=_e(e,t,r,0,1,1,1,a,i,l),16===e.token||18===e.token?2&e.assignable?(k|=16,b=1):537079808&~n&&36864&~n||(b=1):(1077936157===e.token?b=1:k|=16,f=ze(e,t,f,1,0,a,i,l),16!==e.token&&18!==e.token&&(f=Ge(e,t,1,0,a,i,l,f)));else{if(2097152&~n){if(14===n){f=lt(e,t,p,16,r,s,0,1,0,a,i,l),16&e.destructible&&o(e,72),b=1,!m||16!==e.token&&18!==e.token||g.push(f),k|=8;break}if(k|=16,f=Ue(e,t,1,1,a,i,l),!m||16!==e.token&&18!==e.token||g.push(f),18===e.token&&(m||(m=1,g=[f])),m){for(;W(e,32768|t,18);)g.push(Ue(e,t,1,1,e.tokenPos,e.linePos,e.colPos));e.assignable=2,f=re(e,t,h,P,y,{type:"SequenceExpression",expressions:g})}return K(e,t,16),e.destructible=k,f}f=2162700===n?ut(e,268435456|t,p,0,1,0,r,s,a,i,l):at(e,268435456|t,p,0,1,0,r,s,a,i,l),k|=e.destructible,b=1,e.assignable=2,16!==e.token&&18!==e.token&&(8&k&&o(e,119),f=ze(e,t,f,0,0,a,i,l),k|=16,16!==e.token&&18!==e.token&&(f=Ge(e,t,0,0,a,i,l,f)))}if(!m||16!==e.token&&18!==e.token||g.push(f),!W(e,32768|t,18))break;if(m||(m=1,g=[f]),16===e.token){k|=8;break}}m&&(e.assignable=2,f=re(e,t,h,P,y,{type:"SequenceExpression",expressions:g}));K(e,t,16),16&k&&8&k&&o(e,146);if(k|=256&e.destructible?256:128&e.destructible?128:0,10===e.token)return 48&k&&o(e,47),4196352&t&&128&k&&o(e,29),2098176&t&&256&k&&o(e,30),b&&(e.flags|=128),kt(e,t,p,m?g:[f],n,0,a,i,l);8&k&&o(e,140);return e.destructible=256^(256|e.destructible)|k,128&t?re(e,t,c,u,d,{type:"ParenthesizedExpression",expression:f}):f}(e,65536|t,a,1,0,c,u,d);case 86021:case 86022:case 86023:return function(e,t,n,o,r){const s=T[255&e.token],a=86023===e.token?null:"true"===s;return F(e,t),e.assignable=2,re(e,t,n,o,r,512&t?{type:"Literal",value:a,raw:s}:{type:"Literal",value:a})}(e,t,c,u,d);case 86113:return function(e,t){const{tokenPos:n,linePos:o,colPos:r}=e;return F(e,t),e.assignable=2,re(e,t,n,o,r,{type:"ThisExpression"})}(e,t);case 65540:return function(e,t,n,o,r){const{tokenRaw:s,tokenRegExp:a,tokenValue:i}=e;return F(e,t),e.assignable=2,re(e,t,n,o,r,512&t?{type:"Literal",value:i,regex:a,raw:s}:{type:"Literal",value:i,regex:a})}(e,t,c,u,d);case 133:case 86096:return function(e,t,n,r,s,a){let i=null,l=null;t=16777216^(16778240|t);const c=xt(e,t);c.length&&(r=e.tokenPos,s=e.linePos,a=e.colPos);F(e,t),4096&e.token&&20567!==e.token&&(ne(e,t,e.token)&&o(e,115),537079808&~e.token||o(e,116),i=nt(e,t));let u=t;W(e,32768|t,20567)?(l=Me(e,t,0,n,0,e.tokenPos,e.linePos,e.colPos),u|=524288):u=524288^(524288|u);const d=wt(e,u,t,void 0,2,0,n);return e.assignable=2,re(e,t,r,s,a,1&t?{type:"ClassExpression",id:i,superClass:l,decorators:c,body:d}:{type:"ClassExpression",id:i,superClass:l,body:d})}(e,t,i,c,u,d);case 86111:return function(e,t,n,r,s){switch(F(e,t),e.token){case 67108991:o(e,162);case 67174411:524288&t||o(e,26),16384&t&&!(33554432&t)&&o(e,27),e.assignable=2;break;case 69271571:case 67108877:262144&t||o(e,27),16384&t&&!(33554432&t)&&o(e,27),e.assignable=1;break;default:o(e,28,"super")}return re(e,t,n,r,s,{type:"Super"})}(e,t,c,u,d);case 67174409:return We(e,t,c,u,d);case 67174408:return Ke(e,t);case 86109:return function(e,t,n,r,s,a){const i=nt(e,32768|t),{tokenPos:l,linePos:c,colPos:u}=e;if(W(e,t,67108877)){if(67108864&t&&143494===e.token)return e.assignable=2,function(e,t,n,o,r,s){const a=nt(e,t);return re(e,t,o,r,s,{type:"MetaProperty",meta:n,property:a})}(e,t,i,r,s,a);o(e,92)}e.assignable=2,16842752&~e.token||o(e,63,T[255&e.token]);const d=_e(e,t,2,1,0,n,1,l,c,u);t=134217728^(134217728|t),67108991===e.token&&o(e,163);const p=bt(e,t,d,n,l,c,u);return e.assignable=2,re(e,t,r,s,a,{type:"NewExpression",callee:p,arguments:67174411===e.token?tt(e,t,n):[]})}(e,t,i,c,u,d);case 134283389:return Ze(e,t,c,u,d);case 131:return Ct(e,t,c,u,d);case 86108:return function(e,t,n,r,s,a,i){let l=nt(e,t);if(67108877===e.token)return $e(e,t,l,s,a,i);n&&o(e,138);return l=Ye(e,t,r,s,a,i),e.assignable=2,ze(e,t,l,r,0,s,a,i)}(e,t,r,i,c,u,d);case 8456258:if(16&t)return Lt(e,t,1,c,u,d);default:if(ke(t,e.token))return pt(e,t,c,u,d);o(e,28,T[255&e.token])}}function $e(e,t,n,r,s,a){return 2048&t||o(e,164),F(e,t),143495!==e.token&&"meta"!==e.tokenValue&&o(e,28,T[255&e.token]),e.assignable=2,re(e,t,r,s,a,{type:"MetaProperty",meta:n,property:nt(e,t)})}function Ye(e,t,n,r,s,a){K(e,32768|t,67174411),14===e.token&&o(e,139);const i=Ue(e,t,1,n,e.tokenPos,e.linePos,e.colPos);return K(e,t,16),re(e,t,r,s,a,{type:"ImportExpression",source:i})}function Ze(e,t,n,o,r){const{tokenRaw:s,tokenValue:a}=e;return F(e,t),e.assignable=2,re(e,t,n,o,r,512&t?{type:"Literal",value:a,bigint:s.slice(0,-1),raw:s}:{type:"Literal",value:a,bigint:s.slice(0,-1)})}function We(e,t,n,o,r){e.assignable=2;const{tokenValue:s,tokenRaw:a,tokenPos:i,linePos:l,colPos:c}=e;K(e,t,67174409);return re(e,t,n,o,r,{type:"TemplateLiteral",expressions:[],quasis:[Qe(e,t,s,a,i,l,c,!0)]})}function Ke(e,t){t=134217728^(134217728|t);const{tokenValue:n,tokenRaw:r,tokenPos:s,linePos:a,colPos:i}=e;K(e,32768|t,67174408);const l=[Qe(e,t,n,r,s,a,i,!1)],c=[Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos)];for(1074790415!==e.token&&o(e,81);67174409!==(e.token=L(e,t));){const{tokenValue:n,tokenRaw:r,tokenPos:s,linePos:a,colPos:i}=e;K(e,32768|t,67174408),l.push(Qe(e,t,n,r,s,a,i,!1)),c.push(Oe(e,t,0,1,e.tokenPos,e.linePos,e.colPos)),1074790415!==e.token&&o(e,81)}{const{tokenValue:n,tokenRaw:o,tokenPos:r,linePos:s,colPos:a}=e;K(e,t,67174409),l.push(Qe(e,t,n,o,r,s,a,!0))}return re(e,t,s,a,i,{type:"TemplateLiteral",expressions:c,quasis:l})}function Qe(e,t,n,o,r,s,a,i){const l=re(e,t,r,s,a,{type:"TemplateElement",value:{cooked:n,raw:o},tail:i}),c=i?1:2;return 2&t&&(l.start+=1,l.range[0]+=1,l.end-=c,l.range[1]-=c),4&t&&(l.loc.start.column+=1,l.loc.end.column-=c),l}function et(e,t,n,o,r){K(e,32768|(t=134217728^(134217728|t)),14);const s=Ue(e,t,1,0,e.tokenPos,e.linePos,e.colPos);return e.assignable=1,re(e,t,n,o,r,{type:"SpreadElement",argument:s})}function tt(e,t,n){F(e,32768|t);const o=[];if(16===e.token)return F(e,65536|t),o;for(;16!==e.token&&(14===e.token?o.push(et(e,t,e.tokenPos,e.linePos,e.colPos)):o.push(Ue(e,t,1,n,e.tokenPos,e.linePos,e.colPos)),18===e.token)&&(F(e,32768|t),16!==e.token););return K(e,t,16),o}function nt(e,t){const{tokenValue:n,tokenPos:o,linePos:r,colPos:s}=e;return F(e,t),re(e,t,o,r,s,{type:"Identifier",name:n})}function ot(e,t){const{tokenValue:n,tokenRaw:o,tokenPos:r,linePos:s,colPos:a}=e;return 134283389===e.token?Ze(e,t,r,s,a):(F(e,t),e.assignable=2,re(e,t,r,s,a,512&t?{type:"Literal",value:n,raw:o}:{type:"Literal",value:n}))}function rt(e,t,n,r,s,a,i,l,c,u){F(e,32768|t);const d=s?Z(e,t,8457014):0;let p,f=null,k=n?{parent:void 0,type:2}:void 0;if(67174411===e.token)1&a||o(e,37,"Function");else{const s=!(4&r)||8192&t&&2048&t?64:4;te(e,t|(3072&t)<<11,e.token),n&&(4&s?de(e,t,n,e.tokenValue,s):ue(e,t,n,e.tokenValue,s,r),k=le(k,256),a&&2&a&&pe(e,e.tokenValue)),p=e.token,143360&e.token?f=nt(e,t):o(e,28,T[255&e.token])}t=32243712^(32243712|t)|67108864|2*i+d<<21|(d?0:268435456),n&&(k=le(k,512));return re(e,t,l,c,u,{type:"FunctionDeclaration",id:f,params:mt(e,8388608|t,k,0,1),body:Je(e,143360^(143360|t),n?le(k,128):k,8,p,n?k.scopeError:void 0),async:1===i,generator:1===d})}function st(e,t,n,o,r,s,a){F(e,32768|t);const i=Z(e,t,8457014),l=2*n+i<<21;let c,u=null,d=64&t?{parent:void 0,type:2}:void 0;(176128&e.token)>0&&(te(e,32243712^(32243712|t)|l,e.token),d&&(d=le(d,256)),c=e.token,u=nt(e,t)),t=32243712^(32243712|t)|67108864|l|(i?0:268435456),d&&(d=le(d,512));const p=mt(e,8388608|t,d,o,1),f=Je(e,-134377473&t,d?le(d,128):d,0,c,void 0);return e.assignable=2,re(e,t,r,s,a,{type:"FunctionExpression",id:u,params:p,body:f,async:1===n,generator:1===i})}function at(e,t,n,r,s,a,i,l,c,u,d){F(e,32768|t);const p=[];let f=0;for(t=134217728^(134217728|t);20!==e.token;)if(W(e,32768|t,18))p.push(null);else{let r;const{token:c,tokenPos:u,linePos:d,colPos:k,tokenValue:g}=e;if(143360&c)if(r=_e(e,t,i,0,1,s,1,u,d,k),1077936157===e.token){2&e.assignable&&o(e,24),F(e,32768|t),n&&ce(e,t,n,g,i,l);const c=Ue(e,t,1,s,e.tokenPos,e.linePos,e.colPos);r=re(e,t,u,d,k,a?{type:"AssignmentPattern",left:r,right:c}:{type:"AssignmentExpression",operator:"=",left:r,right:c}),f|=256&e.destructible?256:128&e.destructible?128:0}else 18===e.token||20===e.token?(2&e.assignable?f|=16:n&&ce(e,t,n,g,i,l),f|=256&e.destructible?256:128&e.destructible?128:0):(f|=1&i?32:2&i?0:16,r=ze(e,t,r,s,0,u,d,k),18!==e.token&&20!==e.token?(1077936157!==e.token&&(f|=16),r=Ge(e,t,s,a,u,d,k,r)):1077936157!==e.token&&(f|=2&e.assignable?16:32));else 2097152&c?(r=2162700===e.token?ut(e,t,n,0,s,a,i,l,u,d,k):at(e,t,n,0,s,a,i,l,u,d,k),f|=e.destructible,e.assignable=16&e.destructible?2:1,18===e.token||20===e.token?2&e.assignable&&(f|=16):8&e.destructible?o(e,69):(r=ze(e,t,r,s,0,u,d,k),f=2&e.assignable?16:0,18!==e.token&&20!==e.token?r=Ge(e,t,s,a,u,d,k,r):1077936157!==e.token&&(f|=2&e.assignable?16:32))):14===c?(r=lt(e,t,n,20,i,l,0,s,a,u,d,k),f|=e.destructible,18!==e.token&&20!==e.token&&o(e,28,T[255&e.token])):(r=Me(e,t,1,0,1,u,d,k),18!==e.token&&20!==e.token?(r=Ge(e,t,s,a,u,d,k,r),3&i||67174411!==c||(f|=16)):2&e.assignable?f|=16:67174411===c&&(f|=1&e.assignable&&3&i?32:16));if(p.push(r),!W(e,32768|t,18))break;if(20===e.token)break}K(e,t,20);const k=re(e,t,c,u,d,{type:a?"ArrayPattern":"ArrayExpression",elements:p});return!r&&4194304&e.token?it(e,t,f,s,a,c,u,d,k):(e.destructible=f,k)}function it(e,t,n,r,s,a,i,l,c){1077936157!==e.token&&o(e,24),F(e,32768|t),16&n&&o(e,24),s||Q(e,c);const{tokenPos:u,linePos:d,colPos:p}=e,f=Ue(e,t,1,r,u,d,p);return e.destructible=72^(72|n)|(128&e.destructible?128:0)|(256&e.destructible?256:0),re(e,t,a,i,l,s?{type:"AssignmentPattern",left:c,right:f}:{type:"AssignmentExpression",left:c,operator:"=",right:f})}function lt(e,t,n,r,s,a,i,l,c,u,d,p){F(e,32768|t);let f=null,k=0,{token:g,tokenValue:m,tokenPos:b,linePos:h,colPos:P}=e;if(143360&g)e.assignable=1,f=_e(e,t,s,0,1,l,1,b,h,P),g=e.token,f=ze(e,t,f,l,0,b,h,P),18!==e.token&&e.token!==r&&(2&e.assignable&&1077936157===e.token&&o(e,69),k|=16,f=Ge(e,t,l,c,b,h,P,f)),2&e.assignable?k|=16:g===r||18===g?n&&ce(e,t,n,m,s,a):k|=32,k|=128&e.destructible?128:0;else if(g===r)o(e,39);else{if(!(2097152&g)){k|=32,f=Me(e,t,1,l,1,e.tokenPos,e.linePos,e.colPos);const{token:n,tokenPos:s,linePos:a,colPos:i}=e;return 1077936157===n&&n!==r&&18!==n?(2&e.assignable&&o(e,24),f=Ge(e,t,l,c,s,a,i,f),k|=16):(18===n?k|=16:n!==r&&(f=Ge(e,t,l,c,s,a,i,f)),k|=1&e.assignable?32:16),e.destructible=k,e.token!==r&&18!==e.token&&o(e,156),re(e,t,u,d,p,{type:c?"RestElement":"SpreadElement",argument:f})}f=2162700===e.token?ut(e,t,n,1,l,c,s,a,b,h,P):at(e,t,n,1,l,c,s,a,b,h,P),g=e.token,1077936157!==g&&g!==r&&18!==g?(8&e.destructible&&o(e,69),f=ze(e,t,f,l,0,b,h,P),k|=2&e.assignable?16:0,4194304&~e.token?(8454144&~e.token||(f=He(e,t,1,b,h,P,4,g,f)),W(e,32768|t,22)&&(f=je(e,t,f,b,h,P)),k|=2&e.assignable?16:32):(1077936157!==e.token&&(k|=16),f=Ge(e,t,l,c,b,h,P,f))):k|=1074790415===r&&1077936157!==g?16:e.destructible}if(e.token!==r)if(1&s&&(k|=i?16:32),W(e,32768|t,1077936157)){16&k&&o(e,24),Q(e,f);const n=Ue(e,t,1,l,e.tokenPos,e.linePos,e.colPos);f=re(e,t,b,h,P,c?{type:"AssignmentPattern",left:f,right:n}:{type:"AssignmentExpression",left:f,operator:"=",right:n}),k=16}else k|=16;return e.destructible=k,re(e,t,u,d,p,{type:c?"RestElement":"SpreadElement",argument:f})}function ct(e,t,n,s,a,i,l){const c=64&n?14680064:31981568;let u=64&(t=(t|c)^c|(88&n)<<18|100925440)?le({parent:void 0,type:2},512):void 0;const d=function(e,t,n,s,a,i){K(e,t,67174411);const l=[];if(e.flags=128^(128|e.flags),16===e.token)return 512&s&&o(e,35,"Setter","one",""),F(e,t),l;256&s&&o(e,35,"Getter","no","s");512&s&&14===e.token&&o(e,36);t=134217728^(134217728|t);let c=0,u=0;for(;18!==e.token;){let r=null;const{tokenPos:d,linePos:p,colPos:f}=e;if(143360&e.token?(1024&t||(36864&~e.token||(e.flags|=256),537079808&~e.token||(e.flags|=512)),r=At(e,t,n,1|s,0,d,p,f)):(2162700===e.token?r=ut(e,t,n,1,i,1,a,0,d,p,f):69271571===e.token?r=at(e,t,n,1,i,1,a,0,d,p,f):14===e.token&&(r=lt(e,t,n,16,a,0,0,i,1,d,p,f)),u=1,48&e.destructible&&o(e,48)),1077936157===e.token){F(e,32768|t),u=1;r=re(e,t,d,p,f,{type:"AssignmentPattern",left:r,right:Ue(e,t,1,0,e.tokenPos,e.linePos,e.colPos)})}if(c++,l.push(r),!W(e,t,18))break;if(16===e.token)break}512&s&&1!==c&&o(e,35,"Setter","one","");n&&void 0!==n.scopeError&&r(n.scopeError);u&&(e.flags|=128);return K(e,t,16),l}(e,8388608|t,u,n,1,s);u&&(u=le(u,128));return re(e,t,a,i,l,{type:"FunctionExpression",params:d,body:Je(e,-134230017&t,u,0,void 0,void 0),async:(16&n)>0,generator:(8&n)>0,id:null})}function ut(e,t,n,r,a,i,l,c,u,d,p){F(e,t);const f=[];let k=0,g=0;for(t=134217728^(134217728|t);1074790415!==e.token;){const{token:r,tokenValue:u,linePos:d,colPos:p,tokenPos:m}=e;if(14===r)f.push(lt(e,t,n,1074790415,l,c,0,a,i,m,d,p));else{let b,h=0,P=null;const y=e.token;if(143360&e.token||121===e.token)if(P=nt(e,t),18===e.token||1074790415===e.token||1077936157===e.token)if(h|=4,1024&t&&!(537079808&~r)?k|=16:ee(e,t,l,r,0),n&&ce(e,t,n,u,l,c),W(e,32768|t,1077936157)){k|=8;const n=Ue(e,t,1,a,e.tokenPos,e.linePos,e.colPos);k|=256&e.destructible?256:128&e.destructible?128:0,b=re(e,t,m,d,p,{type:"AssignmentPattern",left:536870912&t?Object.assign({},P):P,right:n})}else k|=(209008===r?128:0)|(121===r?16:0),b=536870912&t?Object.assign({},P):P;else if(W(e,32768|t,21)){const{tokenPos:s,linePos:d,colPos:p}=e;if("__proto__"===u&&g++,143360&e.token){const o=e.token,r=e.tokenValue;k|=121===y?16:0,b=_e(e,t,l,0,1,a,1,s,d,p);const{token:u}=e;b=ze(e,t,b,a,0,s,d,p),18===e.token||1074790415===e.token?1077936157===u||1074790415===u||18===u?(k|=128&e.destructible?128:0,2&e.assignable?k|=16:!n||143360&~o||ce(e,t,n,r,l,c)):k|=1&e.assignable?32:16:4194304&~e.token?(k|=16,8454144&~e.token||(b=He(e,t,1,s,d,p,4,u,b)),W(e,32768|t,22)&&(b=je(e,t,b,s,d,p))):(2&e.assignable?k|=16:1077936157!==u?k|=32:n&&ce(e,t,n,r,l,c),b=Ge(e,t,a,i,s,d,p,b))}else 2097152&~e.token?(b=Me(e,t,1,a,1,s,d,p),k|=1&e.assignable?32:16,18===e.token||1074790415===e.token?2&e.assignable&&(k|=16):(b=ze(e,t,b,a,0,s,d,p),k=2&e.assignable?16:0,18!==e.token&&1074790415!==r&&(1077936157!==e.token&&(k|=16),b=Ge(e,t,a,i,s,d,p,b)))):(b=69271571===e.token?at(e,t,n,0,a,i,l,c,s,d,p):ut(e,t,n,0,a,i,l,c,s,d,p),k=e.destructible,e.assignable=16&k?2:1,18===e.token||1074790415===e.token?2&e.assignable&&(k|=16):8&e.destructible?o(e,69):(b=ze(e,t,b,a,0,s,d,p),k=2&e.assignable?16:0,4194304&~e.token?(8454144&~e.token||(b=He(e,t,1,s,d,p,4,r,b)),W(e,32768|t,22)&&(b=je(e,t,b,s,d,p)),k|=2&e.assignable?16:32):b=Fe(e,t,a,i,s,d,p,b)))}else 69271571===e.token?(k|=16,209007===r&&(h|=16),h|=2|(12402===r?256:12403===r?512:1),P=dt(e,t,a),k|=e.assignable,b=ct(e,t,h,a,e.tokenPos,e.linePos,e.colPos)):143360&e.token?(k|=16,121===r&&o(e,93),209007===r&&(1&e.flags&&o(e,129),h|=16),P=nt(e,t),h|=12402===r?256:12403===r?512:1,b=ct(e,t,h,a,e.tokenPos,e.linePos,e.colPos)):67174411===e.token?(k|=16,h|=1,b=ct(e,t,h,a,e.tokenPos,e.linePos,e.colPos)):8457014===e.token?(k|=16,12402===r?o(e,40):12403===r?o(e,41):143483===r&&o(e,93),F(e,t),h|=9|(209007===r?16:0),143360&e.token?P=nt(e,t):134217728&~e.token?69271571===e.token?(h|=2,P=dt(e,t,a),k|=e.assignable):o(e,28,T[255&e.token]):P=ot(e,t),b=ct(e,t,h,a,e.tokenPos,e.linePos,e.colPos)):134217728&~e.token?o(e,130):(209007===r&&(h|=16),h|=12402===r?256:12403===r?512:1,k|=16,P=ot(e,t),b=ct(e,t,h,a,e.tokenPos,e.linePos,e.colPos));else if(134217728&~e.token)if(69271571===e.token)if(P=dt(e,t,a),k|=256&e.destructible?256:0,h|=2,21===e.token){F(e,32768|t);const{tokenPos:s,linePos:u,colPos:d,tokenValue:p,token:f}=e;if(143360&e.token){b=_e(e,t,l,0,1,a,1,s,u,d);const{token:o}=e;b=ze(e,t,b,a,0,s,u,d),4194304&~e.token?18===e.token||1074790415===e.token?1077936157===o||1074790415===o||18===o?2&e.assignable?k|=16:!n||143360&~f||ce(e,t,n,p,l,c):k|=1&e.assignable?32:16:(k|=16,b=Ge(e,t,a,i,s,u,d,b)):(k|=2&e.assignable?16:1077936157===o?0:32,b=Fe(e,t,a,i,s,u,d,b))}else 2097152&~e.token?(b=Me(e,t,1,0,1,s,u,d),k|=1&e.assignable?32:16,18===e.token||1074790415===e.token?2&e.assignable&&(k|=16):(b=ze(e,t,b,a,0,s,u,d),k=1&e.assignable?0:16,18!==e.token&&1074790415!==e.token&&(1077936157!==e.token&&(k|=16),b=Ge(e,t,a,i,s,u,d,b)))):(b=69271571===e.token?at(e,t,n,0,a,i,l,c,s,u,d):ut(e,t,n,0,a,i,l,c,s,u,d),k=e.destructible,e.assignable=16&k?2:1,18===e.token||1074790415===e.token?2&e.assignable&&(k|=16):8&k?o(e,60):(b=ze(e,t,b,a,0,s,u,d),k=2&e.assignable?16|k:0,4194304&~e.token?(8454144&~e.token||(b=He(e,t,1,s,u,d,4,r,b)),W(e,32768|t,22)&&(b=je(e,t,b,s,u,d)),k|=2&e.assignable?16:32):(1077936157!==e.token&&(k|=16),b=Fe(e,t,a,i,s,u,d,b))))}else 67174411===e.token?(h|=1,b=ct(e,t,h,a,e.tokenPos,d,p),k=16):o(e,42);else if(8457014===r)if(K(e,32768|t,8457014),h|=8,143360&e.token){const{token:n,line:o,index:r}=e;P=nt(e,t),h|=1,67174411===e.token?(k|=16,b=ct(e,t,h,a,e.tokenPos,e.linePos,e.colPos)):s(r,o,r,209007===n?44:12402===n||12403===e.token?43:45,T[255&n])}else 134217728&~e.token?69271571===e.token?(k|=16,h|=3,P=dt(e,t,a),b=ct(e,t,h,a,e.tokenPos,e.linePos,e.colPos)):o(e,123):(k|=16,P=ot(e,t),h|=1,b=ct(e,t,h,a,m,d,p));else o(e,28,T[255&r]);else if(P=ot(e,t),21===e.token){K(e,32768|t,21);const{tokenPos:o,linePos:s,colPos:d}=e;if("__proto__"===u&&g++,143360&e.token){b=_e(e,t,l,0,1,a,1,o,s,d);const{token:r,tokenValue:u}=e;b=ze(e,t,b,a,0,o,s,d),18===e.token||1074790415===e.token?1077936157===r||1074790415===r||18===r?2&e.assignable?k|=16:n&&ce(e,t,n,u,l,c):k|=1&e.assignable?32:16:1077936157===e.token?(2&e.assignable&&(k|=16),b=Ge(e,t,a,i,o,s,d,b)):(k|=16,b=Ge(e,t,a,i,o,s,d,b))}else 2097152&~e.token?(b=Me(e,t,1,0,1,o,s,d),k|=1&e.assignable?32:16,18===e.token||1074790415===e.token?2&e.assignable&&(k|=16):(b=ze(e,t,b,a,0,o,s,d),k=1&e.assignable?0:16,18!==e.token&&1074790415!==e.token&&(1077936157!==e.token&&(k|=16),b=Ge(e,t,a,i,o,s,d,b)))):(b=69271571===e.token?at(e,t,n,0,a,i,l,c,o,s,d):ut(e,t,n,0,a,i,l,c,o,s,d),k=e.destructible,e.assignable=16&k?2:1,18===e.token||1074790415===e.token?2&e.assignable&&(k|=16):8&~e.destructible&&(b=ze(e,t,b,a,0,o,s,d),k=2&e.assignable?16:0,4194304&~e.token?(8454144&~e.token||(b=He(e,t,1,o,s,d,4,r,b)),W(e,32768|t,22)&&(b=je(e,t,b,o,s,d)),k|=2&e.assignable?16:32):b=Fe(e,t,a,i,o,s,d,b)))}else 67174411===e.token?(h|=1,b=ct(e,t,h,a,e.tokenPos,e.linePos,e.colPos),k=16|e.assignable):o(e,131);k|=128&e.destructible?128:0,e.destructible=k,f.push(re(e,t,m,d,p,{type:"Property",key:P,value:b,kind:768&h?512&h?"set":"get":"init",computed:(2&h)>0,method:(1&h)>0,shorthand:(4&h)>0}))}if(k|=e.destructible,18!==e.token)break;F(e,t)}K(e,t,1074790415),g>1&&(k|=64);const m=re(e,t,u,d,p,{type:i?"ObjectPattern":"ObjectExpression",properties:f});return!r&&4194304&e.token?it(e,t,k,a,i,u,d,p,m):(e.destructible=k,m)}function dt(e,t,n){F(e,32768|t);const o=Ue(e,134217728^(134217728|t),1,n,e.tokenPos,e.linePos,e.colPos);return K(e,t,20),o}function pt(e,t,n,o,r){const{tokenValue:s}=e,a=nt(e,t);if(e.assignable=1,10===e.token){let i;return 64&t&&(i=ae(e,t,s)),e.flags=128^(128|e.flags),gt(e,t,i,[a],0,n,o,r)}return a}function ft(e,t,n,r,s,a,i,l,c,u){a||o(e,55),s&&o(e,49),e.flags&=-129;return gt(e,t,64&t?ae(e,t,n):void 0,[r],i,l,c,u)}function kt(e,t,n,r,s,a,i,l,c){s||o(e,55);for(let t=0;t<r.length;++t)Q(e,r[t]);return gt(e,t,n,r,a,i,l,c)}function gt(e,t,n,s,a,i,l,c){1&e.flags&&o(e,46),K(e,32768|t,10),t=15728640^(15728640|t)|a<<22;const u=2162700!==e.token;let d;if(n&&void 0!==n.scopeError&&r(n.scopeError),u)d=Ue(e,16384&t?33554432|t:t,1,0,e.tokenPos,e.linePos,e.colPos);else{switch(n&&(n=le(n,128)),d=Je(e,134246400^(134246400|t),n,16,void 0,void 0),e.token){case 69271571:1&e.flags||o(e,113);break;case 67108877:case 67174409:case 22:o(e,114);case 67174411:1&e.flags||o(e,113),e.flags|=1024}8454144&~e.token||1&e.flags||o(e,28,T[255&e.token]),33619968&~e.token||o(e,122)}return e.assignable=2,re(e,t,i,l,c,{type:"ArrowFunctionExpression",params:s,body:d,async:1===a,expression:u})}function mt(e,t,n,s,a){K(e,t,67174411),e.flags=128^(128|e.flags);const i=[];if(W(e,t,16))return i;t=134217728^(134217728|t);let l=0;for(;18!==e.token;){let r;const{tokenPos:c,linePos:u,colPos:d}=e;if(143360&e.token?(1024&t||(36864&~e.token||(e.flags|=256),537079808&~e.token||(e.flags|=512)),r=At(e,t,n,1|a,0,c,u,d)):(2162700===e.token?r=ut(e,t,n,1,s,1,a,0,c,u,d):69271571===e.token?r=at(e,t,n,1,s,1,a,0,c,u,d):14===e.token?r=lt(e,t,n,16,a,0,0,s,1,c,u,d):o(e,28,T[255&e.token]),l=1,48&e.destructible&&o(e,48)),1077936157===e.token){F(e,32768|t),l=1;r=re(e,t,c,u,d,{type:"AssignmentPattern",left:r,right:Ue(e,t,1,s,e.tokenPos,e.linePos,e.colPos)})}if(i.push(r),!W(e,t,18))break;if(16===e.token)break}return l&&(e.flags|=128),n&&(l||1024&t)&&void 0!==n.scopeError&&r(n.scopeError),K(e,t,16),i}function bt(e,t,n,o,r,s,a){const{token:i}=e;if(67108864&i){if(67108877===i){F(e,268435456|t),e.assignable=1;return bt(e,t,re(e,t,r,s,a,{type:"MemberExpression",object:n,computed:!1,property:Xe(e,t)}),0,r,s,a)}if(69271571===i){F(e,32768|t);const{tokenPos:i,linePos:l,colPos:c}=e,u=Oe(e,t,o,1,i,l,c);return K(e,t,20),e.assignable=1,bt(e,t,re(e,t,r,s,a,{type:"MemberExpression",object:n,computed:!0,property:u}),0,r,s,a)}if(67174408===i||67174409===i)return e.assignable=2,bt(e,t,re(e,t,r,s,a,{type:"TaggedTemplateExpression",tag:n,quasi:67174408===e.token?Ke(e,65536|t):We(e,t,e.tokenPos,e.linePos,e.colPos)}),0,r,s,a)}return n}function ht(e,t,n,r,s,a){return 209008===e.token&&o(e,29),2098176&t&&241773===e.token&&o(e,30),537079808&~e.token||(e.flags|=512),ft(e,t,e.tokenValue,nt(e,t),0,n,1,r,s,a)}function Pt(e,t,n,r,s,a,i,l,c,u){F(e,32768|t);const d=64&t?le({parent:void 0,type:2},1024):void 0;if(W(e,t=134217728^(134217728|t),16))return 10===e.token?(1&i&&o(e,46),kt(e,t,d,[],r,1,l,c,u)):re(e,t,l,c,u,{type:"CallExpression",callee:n,arguments:[]});let p=0,f=null,k=0;e.destructible=384^(384|e.destructible);const g=[];for(;16!==e.token;){const{token:r,tokenPos:i,linePos:m,colPos:b}=e;if(143360&r)d&&ue(e,t,d,e.tokenValue,s,0),f=_e(e,t,s,0,1,1,1,i,m,b),16===e.token||18===e.token?2&e.assignable?(p|=16,k=1):537079808&~r?36864&~r||(e.flags|=256):e.flags|=512:(1077936157===e.token?k=1:p|=16,f=ze(e,t,f,1,0,i,m,b),16!==e.token&&18!==e.token&&(f=Ge(e,t,1,0,i,m,b,f)));else if(2097152&r)f=2162700===r?ut(e,t,d,0,1,0,s,a,i,m,b):at(e,t,d,0,1,0,s,a,i,m,b),p|=e.destructible,k=1,16!==e.token&&18!==e.token&&(8&p&&o(e,119),f=ze(e,t,f,0,0,i,m,b),p|=16,8454144&~e.token||(f=He(e,t,1,l,c,u,4,r,f)),W(e,32768|t,22)&&(f=je(e,t,f,l,c,u)));else{if(14!==r){for(f=Ue(e,t,1,0,i,m,b),p=e.assignable,g.push(f);W(e,32768|t,18);)g.push(Ue(e,t,1,0,i,m,b));return p|=e.assignable,K(e,t,16),e.destructible=16|p,e.assignable=2,re(e,t,l,c,u,{type:"CallExpression",callee:n,arguments:g})}f=lt(e,t,d,16,s,a,1,1,0,i,m,b),p|=(16===e.token?0:16)|e.destructible,k=1}if(g.push(f),!W(e,32768|t,18))break}return K(e,t,16),p|=256&e.destructible?256:128&e.destructible?128:0,10===e.token?(48&p&&o(e,25),(1&e.flags||1&i)&&o(e,46),128&p&&o(e,29),2098176&t&&256&p&&o(e,30),k&&(e.flags|=128),kt(e,t,d,g,r,1,l,c,u)):(8&p&&o(e,60),e.assignable=2,re(e,t,l,c,u,{type:"CallExpression",callee:n,arguments:g}))}function yt(e,t,n,r,s,a,i){let l=xt(e,t=16777216^(16778240|t));l.length&&(s=e.tokenPos,a=e.linePos,i=e.colPos),e.leadingDecorators.length&&(e.leadingDecorators.push(...l),l=e.leadingDecorators,e.leadingDecorators=[]),F(e,t);let c=null,u=null;const{tokenValue:d}=e;4096&e.token&&20567!==e.token?(ne(e,t,e.token)&&o(e,115),537079808&~e.token||o(e,116),n&&(ue(e,t,n,d,32,0),r&&2&r&&pe(e,d)),c=nt(e,t)):1&r||o(e,37,"Class");let p=t;W(e,32768|t,20567)?(u=Me(e,t,0,0,0,e.tokenPos,e.linePos,e.colPos),p|=524288):p=524288^(524288|p);const f=wt(e,p,t,n,2,8,0);return re(e,t,s,a,i,1&t?{type:"ClassDeclaration",id:c,superClass:u,decorators:l,body:f}:{type:"ClassDeclaration",id:c,superClass:u,body:f})}function xt(e,t){const n=[];if(1&t)for(;133===e.token;)n.push(vt(e,t,e.tokenPos,e.linePos,e.colPos));return n}function vt(e,t,n,o,r){F(e,32768|t);let s=_e(e,t,2,0,1,0,1,n,o,r);return s=ze(e,t,s,0,0,n,o,r),re(e,t,n,o,r,{type:"Decorator",expression:s})}function wt(e,t,n,r,s,a,i){const{tokenPos:l,linePos:c,colPos:u}=e;K(e,32768|t,2162700),t=134217728^(134217728|t);let d=32&e.flags;e.flags=32^(32|e.flags);const p=[];let f;for(;1074790415!==e.token;){let a=0;f=xt(e,t),a=f.length,a>0&&"constructor"===e.tokenValue&&o(e,107),1074790415===e.token&&o(e,106),W(e,t,1074790417)?a>0&&o(e,117):p.push(qt(e,t,r,n,s,f,0,i,e.tokenPos,e.linePos,e.colPos))}return K(e,8&a?32768|t:t,1074790415),e.flags=-33&e.flags|d,re(e,t,l,c,u,{type:"ClassBody",body:p})}function qt(e,t,n,r,s,a,i,l,c,u,d){let p=i?32:0,f=null;const{token:k,tokenPos:g,linePos:m,colPos:b}=e;if(176128&k)switch(f=nt(e,t),k){case 36972:if(!i&&67174411!==e.token&&1048576&~e.token&&1077936157!==e.token)return qt(e,t,n,r,s,a,1,l,c,u,d);break;case 209007:if(67174411!==e.token&&!(1&e.flags)){if(1&t&&!(1073741824&~e.token))return Et(e,t,f,p,a,g,m,b);p|=16|(Z(e,t,8457014)?8:0)}break;case 12402:if(67174411!==e.token){if(1&t&&!(1073741824&~e.token))return Et(e,t,f,p,a,g,m,b);p|=256}break;case 12403:if(67174411!==e.token){if(1&t&&!(1073741824&~e.token))return Et(e,t,f,p,a,g,m,b);p|=512}}else if(69271571===k)p|=2,f=dt(e,r,l);else if(134217728&~k)if(8457014===k)p|=8,F(e,t);else if(1&t&&131===e.token)p|=4096,f=Ct(e,16384|t,g,m,b);else if(1&t&&!(1073741824&~e.token))p|=128;else{if(i&&2162700===k)return function(e,t,n,o,r,s){n&&(n=le(n,2));const a=540672;t=(t|a)^a|262144;const{body:i}=ye(e,t,n,{},o,r,s);return re(e,t,o,r,s,{type:"StaticBlock",body:i})}(e,t,n,g,m,b);122===k?(f=nt(e,t),67174411!==e.token&&o(e,28,T[255&e.token])):o(e,28,T[255&e.token])}else f=ot(e,t);if(792&p&&(143360&e.token?f=nt(e,t):134217728&~e.token?69271571===e.token?(p|=2,f=dt(e,t,0)):122===e.token?f=nt(e,t):1&t&&131===e.token?(p|=4096,f=Ct(e,t,g,m,b)):o(e,132):f=ot(e,t)),2&p||("constructor"===e.tokenValue?(1073741824&~e.token?32&p||67174411!==e.token||(920&p?o(e,51,"accessor"):524288&t||(32&e.flags?o(e,52):e.flags|=32)):o(e,126),p|=64):!(4096&p)&&824&p&&"prototype"===e.tokenValue&&o(e,50)),1&t&&67174411!==e.token)return Et(e,t,f,p,a,g,m,b);const h=ct(e,t,p,l,e.tokenPos,e.linePos,e.colPos);return re(e,t,c,u,d,1&t?{type:"MethodDefinition",kind:!(32&p)&&64&p?"constructor":256&p?"get":512&p?"set":"method",static:(32&p)>0,computed:(2&p)>0,key:f,decorators:a,value:h}:{type:"MethodDefinition",kind:!(32&p)&&64&p?"constructor":256&p?"get":512&p?"set":"method",static:(32&p)>0,computed:(2&p)>0,key:f,value:h})}function Ct(e,t,n,r,s){F(e,t);const{tokenValue:a}=e;return"constructor"===a&&o(e,125),F(e,t),re(e,t,n,r,s,{type:"PrivateIdentifier",name:a})}function Et(e,t,n,r,s,a,i,l){let c=null;if(8&r&&o(e,0),1077936157===e.token){F(e,32768|t);const{tokenPos:n,linePos:s,colPos:u}=e;537079928===e.token&&o(e,116);const d=64&r?14680064:31981568;c=_e(e,16384|(t=(t|d)^d|(88&r)<<18|100925440),2,0,1,0,1,n,s,u),!(1073741824&~e.token)&&4194304&~e.token||(c=ze(e,16384|t,c,0,0,n,s,u),c=Ge(e,16384|t,0,0,n,s,u,c),18===e.token&&(c=Be(e,t,0,a,i,l,c)))}return re(e,t,a,i,l,{type:"PropertyDefinition",key:n,value:c,static:(32&r)>0,computed:(2&r)>0,decorators:s})}function St(e,t,n,r,s,a,i,l){if(143360&e.token)return At(e,t,n,r,s,a,i,l);2097152&~e.token&&o(e,28,T[255&e.token]);const c=69271571===e.token?at(e,t,n,1,0,1,r,s,a,i,l):ut(e,t,n,1,0,1,r,s,a,i,l);return 16&e.destructible&&o(e,48),32&e.destructible&&o(e,48),c}function At(e,t,n,r,s,a,i,l){const{tokenValue:c,token:u}=e;return 1024&t&&(537079808&~u?36864&~u||o(e,115):o(e,116)),20480&~u||o(e,100),2099200&t&&241773===u&&o(e,30),241739===u&&24&r&&o(e,98),4196352&t&&209008===u&&o(e,96),F(e,t),n&&ce(e,t,n,c,r,s),re(e,t,a,i,l,{type:"Identifier",name:c})}function Lt(e,t,n,r,s,a){if(F(e,t),8456259===e.token)return re(e,t,r,s,a,{type:"JSXFragment",openingFragment:Dt(e,t,r,s,a),children:Tt(e,t),closingFragment:Vt(e,t,n,e.tokenPos,e.linePos,e.colPos)});let i=null,l=[];const c=function(e,t,n,r,s,a){143360&~e.token&&4096&~e.token&&o(e,0);const i=It(e,t,e.tokenPos,e.linePos,e.colPos),l=function(e,t){const n=[];for(;8457016!==e.token&&8456259!==e.token&&1048576!==e.token;)n.push(Ut(e,t,e.tokenPos,e.linePos,e.colPos));return n}(e,t),c=8457016===e.token;8456259===e.token?X(e,t):(K(e,t,8457016),n?K(e,t,8456259):X(e,t));return re(e,t,r,s,a,{type:"JSXOpeningElement",name:i,attributes:l,selfClosing:c})}(e,t,n,r,s,a);if(!c.selfClosing){l=Tt(e,t),i=function(e,t,n,o,r,s){K(e,t,25);const a=It(e,t,e.tokenPos,e.linePos,e.colPos);n?K(e,t,8456259):e.token=X(e,t);return re(e,t,o,r,s,{type:"JSXClosingElement",name:a})}(e,t,n,e.tokenPos,e.linePos,e.colPos);const r=se(i.name);se(c.name)!==r&&o(e,150,r)}return re(e,t,r,s,a,{type:"JSXElement",children:l,openingElement:c,closingElement:i})}function Dt(e,t,n,o,r){return X(e,t),re(e,t,n,o,r,{type:"JSXOpeningFragment"})}function Vt(e,t,n,o,r,s){return K(e,t,25),K(e,t,8456259),re(e,t,o,r,s,{type:"JSXClosingFragment"})}function Tt(e,t){const n=[];for(;25!==e.token;)e.index=e.tokenPos=e.startPos,e.column=e.colPos=e.startColumn,e.line=e.linePos=e.startLine,X(e,t),n.push(Rt(e,t,e.tokenPos,e.linePos,e.colPos));return n}function Rt(e,t,n,r,s){return 138===e.token?function(e,t,n,o,r){X(e,t);const s={type:"JSXText",value:e.tokenValue};512&t&&(s.raw=e.tokenRaw);return re(e,t,n,o,r,s)}(e,t,n,r,s):2162700===e.token?Ot(e,t,0,0,n,r,s):8456258===e.token?Lt(e,t,0,n,r,s):void o(e,0)}function It(e,t,n,o,r){_(e);let s=Gt(e,t,n,o,r);if(21===e.token)return Bt(e,t,s,n,o,r);for(;W(e,t,67108877);)_(e),s=Nt(e,t,s,n,o,r);return s}function Nt(e,t,n,o,r,s){return re(e,t,o,r,s,{type:"JSXMemberExpression",object:n,property:Gt(e,t,e.tokenPos,e.linePos,e.colPos)})}function Ut(e,t,n,r,s){if(2162700===e.token)return function(e,t,n,o,r){F(e,t),K(e,t,14);const s=Ue(e,t,1,0,e.tokenPos,e.linePos,e.colPos);return K(e,t,1074790415),re(e,t,n,o,r,{type:"JSXSpreadAttribute",argument:s})}(e,t,n,r,s);_(e);let a=null,i=Gt(e,t,n,r,s);if(21===e.token&&(i=Bt(e,t,i,n,r,s)),1077936157===e.token){const n=z(e,t),{tokenPos:r,linePos:s,colPos:i}=e;switch(n){case 134283267:a=ot(e,t);break;case 8456258:a=Lt(e,t,1,r,s,i);break;case 2162700:a=Ot(e,t,1,1,r,s,i);break;default:o(e,149)}}return re(e,t,n,r,s,{type:"JSXAttribute",value:a,name:i})}function Bt(e,t,n,o,r,s){K(e,t,21);return re(e,t,o,r,s,{type:"JSXNamespacedName",namespace:n,name:Gt(e,t,e.tokenPos,e.linePos,e.colPos)})}function Ot(e,t,n,r,s,a,i){F(e,32768|t);const{tokenPos:l,linePos:c,colPos:u}=e;if(14===e.token)return function(e,t,n,o,r){K(e,t,14);const s=Ue(e,t,1,0,e.tokenPos,e.linePos,e.colPos);return K(e,t,1074790415),re(e,t,n,o,r,{type:"JSXSpreadChild",expression:s})}(e,t,s,a,i);let d=null;return 1074790415===e.token?(r&&o(e,152),d=function(e,t,n,o,r){return e.startPos=e.tokenPos,e.startLine=e.linePos,e.startColumn=e.colPos,re(e,t,n,o,r,{type:"JSXEmptyExpression"})}(e,t,e.startPos,e.startLine,e.startColumn)):d=Ue(e,t,1,0,l,c,u),n?K(e,t,1074790415):X(e,t),re(e,t,s,a,i,{type:"JSXExpressionContainer",expression:d})}function Gt(e,t,n,o,r){const{tokenValue:s}=e;return F(e,t),re(e,t,n,o,r,{type:"JSXIdentifier",name:s})}var Ft=Object.freeze({__proto__:null});e.ESTree=Ft,e.parse=function(e,t){return me(e,t,0)},e.parseModule=function(e,t){return me(e,t,3072)},e.parseScript=function(e,t){return me(e,t,0)},e.version="4.5.0"}));

},{}],10:[function(require,module,exports){
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
          "(?:\\*|//) Knockout JavaScript library v(§§version§§)"
        ],
        "hashes": {}
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
            ]
          },
          "info": [
            "http://www.cvedetails.com/cve/CVE-2013-4941/"
          ]
        },
        {
          "atOrAbove": "3.5.0",
          "below": "3.9.2",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4942"
            ]
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
          "below": "3.10.3",
          "severity": "medium",
          "cwe": [
            "CWE-79"
          ],
          "identifiers": {
            "CVE": [
              "CVE-2013-4940"
            ]
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
          "below": "1.9.1",
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
          "/react-dom@(§§version§§)/"
        ],
        "filecontent": [
          "version:\"(§§version§§)[a-z0-9\\-]*\"[\\s,]*rendererPackageName:\"react-dom\"",
          "/\\*\\* @license React v(§§version§§)[\\s]*\\* react-dom\\."
        ],
        "ast": [
          "//ObjectExpression/Property[/:key/:name == \"reconcilerVersion\"]/$$:value/:value",
          "//ObjectExpression[       /Property[/:key/:name == \"rendererPackageName\" && /:value/:value == \"react-dom\"]     ]/Property[/:key/:name == \"version\"]/:value/:value"
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
              "CVE-2022-31129",
              "CVE-2023-22467"
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
          "Vue.version = '(§§version§§)';",
          "'(§§version§§)'[^\\n]{0,8000}Vue compiler",
          "\\* Original file: /npm/vue@(§§version§§)/dist/vue.(global|common).js",
          "const version[ ]*=[ ]*\"(§§version§§)\";[\\s]*/\\*\\*[\\s]*\\* SSR utils for \\\\@vue/server-renderer",
          "\\.__vue_app__=.{0,8000}?const [a-z]+=\"(§§version§§)\","
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
          "below": "0.21.3",
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
          "/\\* *axios v(§§version§§) ",
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
          "severity": "high",
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
          "/(§§version§§)/(js/)?jquery.dataTables(.min)?.js"
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
          "atOrAbove": "13.4.0",
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
          "=\"(§§version§§)\"[\\s\\S]{1,300}__lodash_hash_undefined__",
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
          "/(§§version§§)/ua-parser(.min)?.js"
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
            "CWE-79"
          ],
          "severity": "high",
          "identifiers": {
            "summary": "PDF.js vulnerable to arbitrary JavaScript execution upon opening a malicious PDF",
            "CVE": [
              "CVE-2024-34342",
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
