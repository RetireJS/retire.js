(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.retirechrome = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
const deepScan = require("../../node/lib/deepscan.js").deepScan;
const retire = require("../../node/lib/retire.js");
exports.repo = require("../../repository/jsrepository-v5.json");
exports.retire = retire;
exports.deepScan = deepScan;

},{"../../node/lib/deepscan.js":2,"../../node/lib/retire.js":3,"../../repository/jsrepository-v5.json":6}],2:[function(require,module,exports){
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
exports.version = '5.4.0';

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
        if (isDefined(vulns[i].excludes) && vulns[i].excludes.includes(result.version)) {
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
/**
 * ASTronomical - AST query language for JavaScript
 * @license Apache-2.0
 * Copyright (c) Erlend Oftedal
 */
"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  default: () => createTraverser,
  functions: () => functions,
  isAvailableFunction: () => isAvailableFunction,
  multiQuery: () => multiQuery,
  parseSource: () => parseSource,
  query: () => query
});
module.exports = __toCommonJS(index_exports);

// src/nodeutils.ts
var isNode = (candidate) => {
  return typeof candidate === "object" && candidate != null && "type" in candidate;
};
var isNodePath = (candidate) => {
  return typeof candidate === "object" && candidate != null && "node" in candidate;
};
var isPrimitive = (value) => {
  return typeof value == "string" || typeof value == "number" || typeof value == "boolean";
};
var isUpdateExpression = (value) => {
  return isNode(value) && value.type === "UpdateExpression";
};
var isAssignmentExpression = (node) => {
  return node.type === "AssignmentExpression";
};
var isMemberExpression = (node) => {
  return node.type === "MemberExpression";
};
var isIdentifier = (node) => {
  return node.type === "Identifier";
};
var isFunctionDeclaration = (node) => {
  return node.type === "FunctionDeclaration";
};
var isFunctionExpression = (node) => {
  return node.type === "FunctionExpression";
};
var isVariableDeclarator = (node) => {
  return node.type === "VariableDeclarator";
};
var isVariableDeclaration = (node) => {
  return node.type === "VariableDeclaration";
};
var isBinding = (node, parentNode, grandParentNode) => {
  if (grandParentNode && node.type === "Identifier" && parentNode.type === "Property" && grandParentNode.type === "ObjectExpression") {
    return false;
  }
  const keys = bindingIdentifiersKeys[parentNode.type] ?? [];
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const val = (
      // @ts-expect-error key must present in parent
      parentNode[key]
    );
    if (Array.isArray(val)) {
      if (val.indexOf(node) >= 0) return true;
    } else {
      if (val === node) return true;
    }
  }
  return false;
};
var bindingIdentifiersKeys = {
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
  VariableDeclarator: ["id"]
};
var VISITOR_KEYS = {
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
  StaticBlock: ["body"]
};
function isBlockStatement(node) {
  return node.type === "BlockStatement";
}
function isFunction(node) {
  return node.type === "FunctionDeclaration" || node.type === "FunctionExpression";
}
function isCatchClause(node) {
  return node.type === "CatchClause";
}
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

// src/parseQuery.ts
var debugLogEnabled = false;
var log = debugLogEnabled ? {
  debug: (...args) => {
    console.debug(...args);
  }
} : void 0;
var visitorKeys = Object.keys(VISITOR_KEYS);
var supportedIdentifiers = {};
for (let i = 0; i < visitorKeys.length; i++) {
  const k = visitorKeys[i];
  supportedIdentifiers[k] = k;
}
var NodeType = {
  PARENT: 241,
  CHILD: 242,
  DESCENDANT: 243,
  AND: 244,
  OR: 245,
  EQUALS: 246,
  LITERAL: 247,
  FUNCTION: 248
};
function isIdentifierToken(token) {
  if (token == void 0) return false;
  if (token.tokenType != 0 /* IDENTIFIER */ && token.tokenType != 1 /* WILDCARD */) return false;
  if (!token.value) return false;
  if (!(token.value in supportedIdentifiers) && token.value != "*") {
    throw new Error("Unsupported identifier: " + token.value);
  }
  ;
  return true;
}
var whitespace = " \n\r	";
function isCharacter(charcode) {
  return charcode >= 65 && charcode <= 90 || charcode >= 97 && charcode <= 122;
}
function isInteger(charcode) {
  return charcode >= 48 && charcode <= 57;
}
function tokenize(input) {
  let s = 0;
  const result = [];
  while (s < input.length) {
    while (whitespace.includes(input[s])) s++;
    if (s >= input.length) break;
    if (input[s] == "/") {
      if (input[s + 1] == "/") {
        result.push({ tokenType: 2 /* DESCENDANT */ });
        s += 2;
        continue;
      }
      result.push({ tokenType: 3 /* CHILD */ });
      s++;
      continue;
    }
    if (input[s] == ":") {
      result.push({ tokenType: 9 /* ATTRIBUTESELECTOR */ });
      s++;
      continue;
    }
    if (input[s] == "$" && input[s + 1] == "$") {
      result.push({ tokenType: 10 /* RESOLVESELECTOR */ });
      s += 2;
      continue;
    }
    if (input[s] == "$") {
      result.push({ tokenType: 11 /* BINDINGSELECTOR */ });
      s++;
      continue;
    }
    if (input[s] == "[") {
      result.push({ tokenType: 12 /* FILTERBEGIN */ });
      s++;
      continue;
    }
    if (input[s] == "]") {
      result.push({ tokenType: 13 /* FILTEREND */ });
      s++;
      continue;
    }
    if (input[s] == ",") {
      result.push({ tokenType: 14 /* SEPARATOR */ });
      s++;
      continue;
    }
    if (input[s] == "(") {
      result.push({ tokenType: 15 /* PARAMETERSBEGIN */ });
      s++;
      continue;
    }
    if (input[s] == "f" && input[s + 1] == "n" && input[s + 2] == ":") {
      result.push({ tokenType: 17 /* FUNCTION */ });
      s += 3;
      continue;
    }
    if (input[s] == ")") {
      result.push({ tokenType: 16 /* PARAMETERSEND */ });
      s++;
      continue;
    }
    if (input[s] == "&" && input[s + 1] == "&") {
      result.push({ tokenType: 5 /* AND */ });
      s += 2;
      continue;
    }
    if (input[s] == "|" && input[s + 1] == "|") {
      result.push({ tokenType: 6 /* OR */ });
      s += 2;
      continue;
    }
    if (input[s] == "=" && input[s + 1] == "=") {
      result.push({ tokenType: 7 /* EQUALS */ });
      s += 2;
      continue;
    }
    if (input[s] == "'" || input[s] == '"') {
      const begin = input[s];
      const start = s;
      s++;
      while (s < input.length && input[s] != begin) s++;
      result.push({ tokenType: 8 /* LITERAL */, value: input.slice(start + 1, s) });
      s++;
      continue;
    }
    if (input[s] == "." && input[s + 1] == ".") {
      result.push({ tokenType: 4 /* PARENT */ });
      s += 2;
      continue;
    }
    if (input[s] == "*") {
      result.push({ tokenType: 1 /* WILDCARD */, value: "*" });
      s++;
      continue;
    }
    const charCode = input.charCodeAt(s);
    if (isCharacter(charCode)) {
      const start = s;
      while (s < input.length && isCharacter(input.charCodeAt(s))) s++;
      result.push({ tokenType: 0 /* IDENTIFIER */, value: input.slice(start, s) });
      continue;
    }
    if (isInteger(charCode)) {
      const start = s;
      while (s < input.length && isInteger(input.charCodeAt(s))) s++;
      result.push({ tokenType: 8 /* LITERAL */, value: input.slice(start, s) });
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
  if (next.tokenType == 5 /* AND */) {
    return {
      type: NodeType.AND,
      left: p,
      right: buildFilter(tokens)
    };
  }
  if (next.tokenType == 6 /* OR */) {
    return {
      type: NodeType.OR,
      left: p,
      right: buildFilter(tokens)
    };
  }
  if (next.tokenType == 7 /* EQUALS */) {
    const right = buildFilter(tokens);
    if (right.type == NodeType.OR || right.type == NodeType.AND) {
      return {
        type: right.type,
        left: {
          type: NodeType.EQUALS,
          left: p,
          right: right.left
        },
        right: right.right
      };
    }
    if (right.type == NodeType.EQUALS) throw new Error("Unexpected equals in equals");
    return {
      type: NodeType.EQUALS,
      left: p,
      right
    };
  }
  if (next.tokenType == 13 /* FILTEREND */) {
    tokens.shift();
    return p;
  }
  throw new Error("Unexpected token in filter: " + next?.tokenType);
}
var subNodes = [3 /* CHILD */, 2 /* DESCENDANT */];
function buildTree(tokens) {
  log?.debug("BUILD TREE", tokens);
  if (tokens.length == 0) throw new Error("Unexpected end of input");
  const token = tokens.shift();
  if (token == void 0) throw new Error("Unexpected end of input");
  if (token.tokenType == 4 /* PARENT */) {
    return {
      type: NodeType.PARENT,
      child: buildTree(tokens)
    };
  }
  if (subNodes.includes(token.tokenType)) {
    let next = tokens.shift();
    if (next?.tokenType == 17 /* FUNCTION */) {
      const name = tokens.shift();
      if (name == void 0 || name.tokenType != 0 /* IDENTIFIER */ || name.value == void 0 || typeof name.value != "string") throw new Error("Unexpected token: " + name?.tokenType + ". Expecting function name");
      const value = name.value;
      if (!isAvailableFunction(value)) {
        throw new Error("Unsupported function: " + name.value);
      }
      return buildFunctionCall(value, tokens);
    }
    if (next?.tokenType == 4 /* PARENT */) {
      return { type: NodeType.PARENT, child: buildTree(tokens) };
    }
    const modifiers = [];
    while (next && (next?.tokenType == 9 /* ATTRIBUTESELECTOR */ || next?.tokenType == 11 /* BINDINGSELECTOR */ || next?.tokenType == 10 /* RESOLVESELECTOR */)) {
      modifiers.push(next);
      next = tokens.shift();
    }
    const isAttribute = modifiers.some((m) => m.tokenType == 9 /* ATTRIBUTESELECTOR */);
    const isBinding2 = modifiers.some((m) => m.tokenType == 11 /* BINDINGSELECTOR */);
    const isResolve = modifiers.some((m) => m.tokenType == 10 /* RESOLVESELECTOR */);
    if (isResolve && isBinding2) throw new Error("Cannot have both resolve and binding");
    if (!next || !next.value || !isAttribute && !isIdentifierToken(next)) throw new Error("Unexpected or missing token: " + next?.tokenType);
    const identifer = next.value;
    let filter = void 0;
    if (tokens.length > 0 && tokens[0].tokenType == 12 /* FILTERBEGIN */) {
      filter = buildFilter(tokens);
      log?.debug("FILTER", filter, tokens);
    }
    let child = void 0;
    if (tokens.length > 0 && subNodes.includes(tokens[0].tokenType)) {
      child = buildTree(tokens);
    }
    if (typeof identifer != "string") throw new Error("Identifier must be a string");
    let nodeType = NodeType.CHILD;
    if (token.tokenType == 2 /* DESCENDANT */) {
      nodeType = NodeType.DESCENDANT;
    } else if (token.tokenType != 3 /* CHILD */) {
      throw new Error("Unexpected token:" + token.tokenType);
    }
    return {
      type: nodeType,
      value: identifer,
      attribute: isAttribute,
      binding: isBinding2,
      resolve: isResolve,
      filter,
      child
    };
  }
  if (token.tokenType == 8 /* LITERAL */) {
    return {
      type: NodeType.LITERAL,
      value: token.value
    };
  }
  throw new Error("Unexpected token: " + token.tokenType);
}
function buildFunctionCall(name, tokens) {
  log?.debug("BUILD FUNCTION", name, tokens);
  const parameters = [];
  const next = tokens.shift();
  if (next?.tokenType != 15 /* PARAMETERSBEGIN */) throw new Error("Unexpected token: " + next?.tokenType);
  while (tokens.length > 0 && tokens[0].tokenType != 16 /* PARAMETERSEND */) {
    parameters.push(buildTree(tokens));
    if (tokens[0].tokenType == 14 /* SEPARATOR */) tokens.shift();
  }
  if (tokens.length == 0) throw new Error("Unexpected end of input");
  tokens.shift();
  return {
    type: NodeType.FUNCTION,
    function: name,
    parameters
  };
}
function parse(input) {
  const tokens = tokenize(input);
  const result = buildTree(tokens);
  log?.debug("RESULT", result);
  if (!result) throw new Error("No root element found");
  return result;
}

// src/index.ts
var import_meriyah = require("meriyah");

// src/utils.ts
function toArray(value) {
  return Array.isArray(value) ? value : [value];
}
function isDefined(value) {
  return value != void 0 && value != null;
}

// src/index.ts
var debugLogEnabled2 = false;
var log2 = debugLogEnabled2 ? {
  debug: (...args) => {
    console.debug(...args);
  }
} : void 0;
var functions = {
  "join": {
    fn: (result) => {
      if (result.length != 2) throw new Error("Invalid number of arugments for join");
      const [values, separators] = result;
      if (separators.length != 1) throw new Error("Invalid number of separators for join");
      const separator = separators[0];
      if (typeof separator != "string") throw new Error("Separator must be a string");
      if (values.length == 0) return [];
      return [values.join(separator)];
    }
  },
  "concat": {
    fn: (result) => {
      const flattened = [];
      for (let i = 0; i < result.length; i++) {
        if (result[i].length === 0) return [];
        for (let j = 0; j < result[i].length; j++) {
          flattened.push(result[i][j]);
        }
      }
      return [flattened.join("")];
    }
  },
  "first": {
    fn: (result) => {
      if (result.length != 1) throw new Error("Invalid number of arugments for first");
      if (result[0].length == 0) return [];
      return [result[0][0]];
    }
  },
  "nthchild": {
    fn: (result) => {
      if (result.length != 2) throw new Error("Invalid number of arguments for nthchild");
      if (result[1].length != 1) throw new Error("Invalid number of arguments for nthchild");
      const x = result[1][0];
      const number = typeof x == "number" ? x : parseInt(x);
      return [result[0][number]];
    }
  }
};
var functionNames = new Set(Object.keys(functions));
function isAvailableFunction(name) {
  return functionNames.has(name);
}
function breadCrumb(path) {
  if (!debugLogEnabled2) return "";
  return {
    //Using the toString trick here to avoid calculating the breadcrumb if debug logging is off
    valueOf() {
      if (path.parentPath == void 0) return "@" + path.node.type;
      return breadCrumb(path.parentPath) + "." + (path.parentKey == path.key ? path.key : path.parentKey + "[" + path.key + "]") + "@" + path.node.type;
    }
  };
}
function createQuerier() {
  const traverser = createTraverser();
  const { getChildren, getPrimitiveChildren, getPrimitiveChildrenOrNodePaths, getBinding, createNodePath, traverse } = traverser;
  function createFilter(filter, filterResult) {
    if (filter.type == NodeType.AND || filter.type == NodeType.OR || filter.type == NodeType.EQUALS) {
      return {
        type: filter.type,
        left: createFilter(filter.left, []),
        right: createFilter(filter.right, [])
      };
    } else if (filter.type == NodeType.LITERAL) {
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
      result
    };
  }
  function addFilterChildrenToState(filter, state) {
    if ("type" in filter && (filter.type == NodeType.AND || filter.type == NodeType.OR || filter.type == NodeType.EQUALS)) {
      addFilterChildrenToState(filter.left, state);
      addFilterChildrenToState(filter.right, state);
    } else if ("node" in filter) {
      if (filter.node.type == NodeType.CHILD) {
        log2?.debug("ADDING FILTER CHILD", filter.node);
        state.child[state.depth + 1].push(filter);
      }
      if (filter.node.type == NodeType.DESCENDANT) {
        log2?.debug("ADDING FILTER DESCENDANT", filter.node);
        state.descendant[state.depth + 1].push(filter);
      }
    }
  }
  function createFNodeAndAddToState(token, result, state) {
    log2?.debug("ADDING FNODE", token);
    const fnode = createFNode(token, result);
    if (token.type == NodeType.CHILD) {
      state.child[state.depth + 1].push(fnode);
    } else if (token.type == NodeType.DESCENDANT) {
      state.descendant[state.depth + 1].push(fnode);
    }
    return fnode;
  }
  function isMatch(fnode, path) {
    if (fnode.node.attribute) {
      const m2 = fnode.node.value == path.parentKey || fnode.node.value == path.key;
      if (m2) log2?.debug("ATTR MATCH", fnode.node.value, breadCrumb(path));
      return m2;
    }
    if (fnode.node.value == "*") {
      return true;
    }
    const m = fnode.node.value == path.node.type;
    if (m) log2?.debug("NODE MATCH", fnode.node.value, breadCrumb(path));
    return m;
  }
  function addIfTokenMatch(fnode, path, state) {
    if (!isMatch(fnode, path)) return;
    state.matches[state.depth].push([fnode, path]);
    if (fnode.node.filter) {
      const filter = createFilter(fnode.node.filter, []);
      const filteredResult = [];
      const f = { filter, qNode: fnode.node, node: path.node, result: filteredResult };
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
        if (child.type == NodeType.FUNCTION) {
          const fr = addFunction(fnode, child, path, state);
          state.functionCalls[state.depth].push(fr);
        } else {
          createFNodeAndAddToState(child, filteredResult, state);
        }
      }
    } else {
      const child = fnode.node.child;
      if (child?.type == NodeType.FUNCTION) {
        const fr = addFunction(fnode, child, path, state);
        state.functionCalls[state.depth].push(fr);
      } else if (child && !fnode.node.binding && !fnode.node.resolve) {
        createFNodeAndAddToState(child, fnode.result, state);
      }
    }
  }
  function addFunction(rootNode, functionCall, path, state) {
    const functionNode = { node: rootNode.node, functionCall, parameters: [], result: [] };
    for (const param of functionCall.parameters) {
      if (param.type == NodeType.LITERAL) {
        functionNode.parameters.push({ node: param, result: [param.value] });
      } else {
        if (param.type == NodeType.FUNCTION) {
          functionNode.parameters.push(addFunction(functionNode, param, path, state));
        } else {
          functionNode.parameters.push(createFNodeAndAddToState(param, [], state));
        }
      }
    }
    return functionNode;
  }
  function addPrimitiveAttributeIfMatch(fnode, path) {
    if (!fnode.node.attribute || fnode.node.value == void 0) return;
    if (fnode.node.child || fnode.node.filter) return;
    if (!Object.hasOwn(path.node, fnode.node.value)) return;
    const nodes = getPrimitiveChildren(fnode.node.value, path);
    if (nodes.length == 0) return;
    log2?.debug("PRIMITIVE", fnode.node.value, nodes);
    fnode.result.push(...nodes);
  }
  function evaluateFilter(filter, path) {
    log2?.debug("EVALUATING FILTER", filter, breadCrumb(path));
    if ("type" in filter) {
      if (filter.type == NodeType.AND) {
        const left = evaluateFilter(filter.left, path);
        if (left.length == 0) {
          return [];
        }
        const r = evaluateFilter(filter.right, path);
        return r;
      }
      if (filter.type == NodeType.OR) {
        const left = evaluateFilter(filter.left, path);
        if (left.length > 0) {
          return left;
        }
        const r = evaluateFilter(filter.right, path);
        return r;
      }
      if (filter.type == NodeType.EQUALS) {
        const left = evaluateFilter(filter.left, path);
        const right = evaluateFilter(filter.right, path);
        if (right.length > 3) {
          const rightSet = new Set(right);
          const r2 = [];
          for (let i = 0; i < left.length; i++) {
            if (rightSet.has(left[i])) r2.push(left[i]);
          }
          return r2;
        }
        const r = [];
        for (let i = 0; i < left.length; i++) {
          if (right.includes(left[i])) r.push(left[i]);
        }
        return r;
      }
      throw new Error("Unknown filter type: " + filter.type);
    }
    if (filter.node.type == NodeType.PARENT) {
      const r = resolveFilterWithParent(filter.node, path);
      return r;
    }
    return filter.result;
  }
  function resolveBinding(path) {
    if (!isIdentifier(path.node)) return void 0;
    log2?.debug("RESOLVING BINDING FOR ", path.node);
    const name = path.node.name;
    if (name == void 0 || typeof name != "string") return void 0;
    const binding = getBinding(path.scopeId, name);
    if (!binding) return void 0;
    log2?.debug("THIS IS THE BINDING", binding);
    return binding.path;
  }
  function resolveFilterWithParent(node, path) {
    let startNode = node;
    let startPath = path;
    while (startNode.type == NodeType.PARENT) {
      if (!startNode.child) throw new Error("Parent filter must have child");
      if (!startPath.parentPath) return [];
      log2?.debug("STEP OUT", startNode, breadCrumb(startPath));
      startNode = startNode.child;
      startPath = startPath.parentPath;
    }
    return resolveDirectly(startNode, startPath);
  }
  let subQueryCounter = 0;
  const memo = /* @__PURE__ */ new Map();
  function resolveDirectly(node, path) {
    let startNode = node;
    const startPath = path;
    let paths = [startPath];
    while (startNode.attribute && startNode.type == NodeType.CHILD) {
      const lookup = startNode.value;
      if (!lookup) throw new Error("Selector must have a value");
      const nodes = [];
      for (let i = 0; i < paths.length; i++) {
        const p = paths[i];
        if (!isNodePath(p)) continue;
        const arr = getPrimitiveChildrenOrNodePaths(lookup, p);
        for (let j = 0; j < arr.length; j++) {
          nodes.push(arr[j]);
        }
      }
      if (nodes.length == 0) return [];
      paths = nodes;
      if (startNode.resolve) {
        const resolved = [];
        for (let i = 0; i < paths.length; i++) {
          const p = paths[i];
          if (!isNodePath(p)) continue;
          const binding = resolveBinding(p);
          if (!binding) continue;
          const children = getChildren("init", binding);
          for (let j = 0; j < children.length; j++) {
            resolved.push(children[j]);
          }
        }
        if (resolved.length > 0) paths = resolved;
      } else if (startNode.binding) {
        const bindings = [];
        for (let i = 0; i < paths.length; i++) {
          const p = paths[i];
          if (!isNodePath(p)) continue;
          const binding = resolveBinding(p);
          if (binding) bindings.push(binding);
        }
        paths = bindings;
      }
      const filter = startNode.filter;
      if (filter) {
        const filtered = [];
        for (let i = 0; i < paths.length; i++) {
          const p = paths[i];
          if (!isNodePath(p)) continue;
          if (travHandle({ subquery: filter }, p).subquery.length > 0) {
            filtered.push(p);
          }
        }
        paths = filtered;
      }
      if (!startNode.child) {
        const results = new Array(paths.length);
        for (let i = 0; i < paths.length; i++) {
          const p = paths[i];
          results[i] = isPrimitive(p) ? p : p.node;
        }
        return results;
      }
      startNode = startNode.child;
    }
    const result = [];
    for (const path2 of paths) {
      if (isNodePath(path2)) {
        if (memo.has(startNode) && memo.get(startNode).has(path2)) {
          const cached = memo.get(startNode).get(path2);
          for (let i = 0; i < cached.length; i++) {
            result.push(cached[i]);
          }
        } else {
          const subQueryKey = "subquery-" + subQueryCounter++;
          const subQueryResult = travHandle({ [subQueryKey]: startNode }, path2)[subQueryKey];
          if (!memo.has(startNode)) memo.set(startNode, /* @__PURE__ */ new Map());
          memo.get(startNode)?.set(path2, subQueryResult);
          for (let i = 0; i < subQueryResult.length; i++) {
            result.push(subQueryResult[i]);
          }
        }
      }
    }
    log2?.debug("DIRECT TRAV RESOLVE RESULT", result);
    return result;
  }
  function addResultIfTokenMatch(fnode, path, state) {
    const matchingFilters = [];
    const filters = [];
    const nodeFilters = state.filtersMap[state.depth].get(fnode.node);
    if (nodeFilters) {
      for (let i = 0; i < nodeFilters.length; i++) {
        const f = nodeFilters[i];
        if (f.qNode !== fnode.node) continue;
        if (f.node !== path.node) continue;
        filters.push(f);
      }
      for (let i = 0; i < filters.length; i++) {
        const f = filters[i];
        if (evaluateFilter(f.filter, path).length > 0) {
          matchingFilters.push(f);
        }
      }
      if (filters.length > 0 && matchingFilters.length == 0) return;
    }
    if (fnode.node.resolve) {
      const binding = resolveBinding(path);
      const resolved = binding ? getChildren("init", binding)[0] : void 0;
      if (fnode.node.child) {
        const result = resolveDirectly(fnode.node.child, resolved ?? path);
        for (let i = 0; i < result.length; i++) {
          fnode.result.push(result[i]);
        }
      } else {
        fnode.result.push(path.node);
      }
    } else if (fnode.node.binding) {
      const binding = resolveBinding(path);
      if (binding) {
        if (fnode.node.child) {
          const result = resolveDirectly(fnode.node.child, binding);
          for (let i = 0; i < result.length; i++) {
            fnode.result.push(result[i]);
          }
        } else {
          fnode.result.push(binding.node);
        }
      }
    } else if (!fnode.node.child) {
      fnode.result.push(path.node);
    } else if (fnode.node.child.type == NodeType.FUNCTION) {
      const functionCallResult = state.functionCalls[state.depth].find((f) => f.node == fnode.node);
      if (!functionCallResult) throw new Error("Did not find expected function call for " + fnode.node.child.function);
      resolveFunctionCalls(fnode, functionCallResult, path, state);
    } else if (matchingFilters.length > 0) {
      log2?.debug("HAS MATCHING FILTER", fnode.result.length, matchingFilters.length, breadCrumb(path));
      for (let i = 0; i < matchingFilters.length; i++) {
        const filterResult = matchingFilters[i].result;
        for (let j = 0; j < filterResult.length; j++) {
          fnode.result.push(filterResult[j]);
        }
      }
    }
  }
  function resolveFunctionCalls(fnode, functionCallResult, path, state) {
    const parameterResults = [];
    for (let i = 0; i < functionCallResult.parameters.length; i++) {
      const p = functionCallResult.parameters[i];
      if ("parameters" in p) {
        resolveFunctionCalls(p, p, path, state);
        parameterResults.push(p.result);
      } else {
        parameterResults.push(p.result);
      }
    }
    const functionResult = functions[functionCallResult.functionCall.function].fn(parameterResults);
    log2?.debug("PARAMETER RESULTS", functionCallResult.functionCall.function, parameterResults, functionResult);
    for (let i = 0; i < functionResult.length; i++) {
      fnode.result.push(functionResult[i]);
    }
  }
  function travHandle(queries, root) {
    const results = {};
    const queryKeys = Object.keys(queries);
    for (let i = 0; i < queryKeys.length; i++) {
      results[queryKeys[i]] = [];
    }
    const state = {
      depth: 0,
      child: [[], []],
      descendant: [[], []],
      filters: [[], []],
      filtersMap: [/* @__PURE__ */ new Map(), /* @__PURE__ */ new Map()],
      matches: [[]],
      functionCalls: [[]]
    };
    for (const [name, node] of Object.entries(queries)) {
      createFNodeAndAddToState(node, results[name], state);
    }
    const childAtDepth = state.child[state.depth + 1];
    for (let i = 0; i < childAtDepth.length; i++) {
      addPrimitiveAttributeIfMatch(childAtDepth[i], root);
    }
    const descendantSlice = state.descendant.slice(0, state.depth + 1);
    for (let i = 0; i < descendantSlice.length; i++) {
      const fnodes = descendantSlice[i];
      for (let j = 0; j < fnodes.length; j++) {
        addPrimitiveAttributeIfMatch(fnodes[j], root);
      }
    }
    traverse(root.node, {
      enter(path, state2) {
        state2.depth++;
        state2.child.push([]);
        state2.descendant.push([]);
        state2.filters.push([]);
        state2.filtersMap.push(/* @__PURE__ */ new Map());
        state2.matches.push([]);
        state2.functionCalls.push([]);
        for (const fnode of state2.child[state2.depth]) {
          addIfTokenMatch(fnode, path, state2);
        }
        for (const fnodes of state2.descendant.slice(0, state2.depth + 1)) {
          for (const fnode of fnodes) {
            addIfTokenMatch(fnode, path, state2);
          }
        }
      },
      exit(path, state2) {
        log2?.debug("EXIT", breadCrumb(path));
        const childAtDepthPlusOne = state2.child[state2.depth + 1];
        for (let i = 0; i < childAtDepthPlusOne.length; i++) {
          addPrimitiveAttributeIfMatch(childAtDepthPlusOne[i], path);
        }
        for (let i = 0; i < state2.descendant.length; i++) {
          const fnodes = state2.descendant[i];
          for (let j = 0; j < fnodes.length; j++) {
            addPrimitiveAttributeIfMatch(fnodes[j], path);
          }
        }
        const matchesAtDepth = state2.matches[state2.depth];
        for (let i = 0; i < matchesAtDepth.length; i++) {
          addResultIfTokenMatch(matchesAtDepth[i][0], matchesAtDepth[i][1], state2);
        }
        state2.depth--;
        state2.child.pop();
        state2.descendant.pop();
        state2.filters.pop();
        state2.filtersMap.pop();
        state2.matches.pop();
        state2.functionCalls.pop();
      }
    }, root.scopeId, state, root);
    return results;
  }
  function beginHandle(queries, path) {
    const rootPath = createNodePath(path, void 0, void 0, void 0, void 0);
    const r = travHandle(queries, rootPath);
    memo.clear();
    return r;
  }
  return {
    beginHandle
  };
}
var defaultKey = "__default__";
function query(code, query2, returnAST) {
  const result = multiQuery(code, { [defaultKey]: query2 }, returnAST);
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
  if (ast == null) throw new Error("Could not pase code");
  const queries = {};
  const entries = Object.entries(namedQueries);
  for (let i = 0; i < entries.length; i++) {
    const [name, queryStr] = entries[i];
    queries[name] = parse(queryStr);
  }
  const querier = createQuerier();
  const result = querier.beginHandle(queries, ast);
  log2?.debug("Query time: ", Date.now() - start);
  if (returnAST) {
    return { ...result, __AST: ast };
  }
  return result;
}
function parseSource(source, optimize = true) {
  const parsingOptions = optimize ? { loc: false, ranges: false } : { loc: true, ranges: true };
  try {
    return (0, import_meriyah.parseScript)(source, { module: true, next: true, ...parsingOptions });
  } catch (e) {
    return (0, import_meriyah.parseScript)(source, { module: false, next: true, ...parsingOptions, webcompat: true });
  }
}
function createTraverser() {
  let scopeIdCounter = 0;
  const scopes = /* @__PURE__ */ new Map();
  let removedScopes = 0;
  const nodePathsCreated = {};
  function createScope(parentScopeId) {
    const id = scopeIdCounter++;
    if (parentScopeId != void 0) {
      scopes.set(id, parentScopeId ?? -1);
    }
    return id;
  }
  function getBinding(scopeId, name) {
    let currentScope = scopes.get(scopeId);
    while (currentScope !== void 0) {
      if (typeof currentScope !== "number") {
        if (currentScope.bindings[name]) {
          return currentScope.bindings[name];
        }
        if (currentScope.parentScopeId === -1) break;
        currentScope = scopes.get(currentScope.parentScopeId);
      } else {
        if (currentScope === -1 || currentScope == void 0) break;
        currentScope = scopes.get(currentScope);
      }
    }
    return void 0;
  }
  function setBinding(scopeId, name, binding) {
    let scope = scopes.get(scopeId);
    if (typeof scope === "number" || scope === void 0) {
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
        const len = r.length;
        const result = new Array(len);
        for (let i = 0; i < len; i++) {
          result[i] = createNodePath(r[i], i, key, path.scopeId, path.functionScopeId, path);
        }
        return result;
      } else if (r != void 0) {
        return [createNodePath(r, key, key, path.scopeId, path.functionScopeId, path)];
      }
    }
    return [];
  }
  function getPrimitiveChildren(key, path) {
    if (key in path.node) {
      const r = path.node[key];
      const arr = toArray(r);
      const result = [];
      for (let i = 0; i < arr.length; i++) {
        const item = arr[i];
        if (isDefined(item) && isPrimitive(item)) {
          result.push(item);
        }
      }
      return result;
    }
    return [];
  }
  function getPrimitiveChildrenOrNodePaths(key, path) {
    if (key in path.node) {
      const r = path.node[key];
      if (Array.isArray(r)) {
        const len = r.length;
        const result = new Array(len);
        for (let i = 0; i < len; i++) {
          const n = r[i];
          result[i] = isPrimitive(n) ? n : createNodePath(n, i, key, path.scopeId, path.functionScopeId, path);
        }
        return result;
      } else if (r != void 0) {
        return [
          isPrimitive(r) ? r : createNodePath(r, key, key, path.scopeId, path.functionScopeId, path)
        ];
      }
    }
    return [];
  }
  const nodePathMap = /* @__PURE__ */ new WeakMap();
  function createNodePath(node, key, parentKey, scopeId, functionScopeId, nodePath) {
    if (nodePathMap.has(node)) {
      const path2 = nodePathMap.get(node);
      if (nodePath && isExportSpecifier(nodePath.node) && key == "exported" && path2.key == "local") {
        path2.key = "exported";
        path2.parentPath = nodePath;
        return path2;
      }
      if (key != void 0) path2.key = typeof key == "number" ? key.toString() : key;
      if (parentKey != void 0) path2.parentKey = parentKey;
      if (nodePath != void 0) path2.parentPath = nodePath;
      return path2;
    }
    const finalScope = (node.extra && node.extra.scopeId != void 0 ? node.extra.scopeId : scopeId) ?? createScope();
    const finalFScope = (node.extra && node.extra.functionScopeId != void 0 ? node.extra.functionScopeId : functionScopeId) ?? finalScope;
    const path = {
      node,
      scopeId: finalScope,
      functionScopeId: finalFScope,
      parentPath: nodePath,
      key: typeof key == "number" ? key.toString() : key,
      parentKey
    };
    if (isNode(node)) {
      nodePathMap.set(node, path);
    }
    nodePathsCreated[node.type] = (nodePathsCreated[node.type] ?? 0) + 1;
    pathsCreated++;
    return path;
  }
  function registerBinding(stack, scopeId, functionScopeId, key, parentKey) {
    const node = stack[stack.length - 1];
    if (!isIdentifier(node)) return;
    const parentNode = stack[stack.length - 2];
    if (isAssignmentExpression(parentNode) || isMemberExpression(parentNode) || isUpdateExpression(parentNode) || isExportSpecifier(parentNode)) return;
    const grandParentNode = stack[stack.length - 3];
    if (!isBinding(node, parentNode, grandParentNode)) return;
    if (key == "id" && !isVariableDeclarator(parentNode)) {
      setBinding(functionScopeId, node.name, { path: createNodePath(node, void 0, void 0, scopeId, functionScopeId) });
      return;
    }
    if (isVariableDeclarator(parentNode) && isVariableDeclaration(grandParentNode)) {
      if (grandParentNode.kind == "var") {
        setBinding(functionScopeId, node.name, { path: createNodePath(parentNode, void 0, void 0, scopeId, functionScopeId) });
        return;
      } else {
        setBinding(scopeId, node.name, { path: createNodePath(parentNode, void 0, void 0, scopeId, functionScopeId) });
        return;
      }
    }
    if (isScope(node, parentNode)) {
      setBinding(scopeId, node.name, { path: createNodePath(node, key, parentKey, scopeId, functionScopeId) });
    }
  }
  let bindingNodesVisited = 0;
  function registerBindings(stack, scopeId, functionScopeId) {
    const node = stack[stack.length - 1];
    if (!isNode(node)) return;
    if (node.extra?.scopeId != void 0) return;
    node.extra = node.extra ?? {};
    node.extra.scopeId = scopeId;
    bindingNodesVisited++;
    const keys = VISITOR_KEYS[node.type];
    if (keys.length == 0) return;
    let childScopeId = scopeId;
    if (isScopable(node)) {
      childScopeId = createScope(scopeId);
    }
    for (let keyIdx = 0; keyIdx < keys.length; keyIdx++) {
      const key = keys[keyIdx];
      const childNodes = node[key];
      const children = toArray(childNodes);
      for (let i = 0; i < children.length; i++) {
        const child = children[i];
        if (!isDefined(child) || !isNode(child)) continue;
        const f = key === "body" && (isFunctionDeclaration(node) || isFunctionExpression(node)) ? childScopeId : functionScopeId;
        stack.push(child);
        if (isIdentifier(child)) {
          const k = Array.isArray(childNodes) ? i : key;
          registerBinding(stack, childScopeId, f, k, key);
        } else {
          registerBindings(stack, childScopeId, f);
        }
        stack.pop();
      }
    }
    if (childScopeId != scopeId && typeof scopes.get(childScopeId) == "number") {
      scopes.set(childScopeId, scopes.get(scopeId));
      removedScopes++;
    }
  }
  function traverseInner(node, visitor, scopeId, functionScopeId, state, path) {
    const nodePath = path ?? createNodePath(node, void 0, void 0, scopeId, functionScopeId);
    const keys = VISITOR_KEYS[node.type];
    if (nodePath.parentPath) {
      const stack = [];
      if (nodePath.parentPath.parentPath?.node) stack.push(nodePath.parentPath.parentPath.node);
      stack.push(nodePath.parentPath.node, nodePath.node);
      registerBindings(stack, nodePath.scopeId, nodePath.functionScopeId);
    }
    const stateTyped = state;
    const hasDescendantQueries = stateTyped.descendant && stateTyped.descendant.some((arr) => arr.length > 0);
    const hasChildQueriesAtNextDepth = stateTyped.child && stateTyped.child[stateTyped.depth + 1] && stateTyped.child[stateTyped.depth + 1].length > 0;
    if (!hasDescendantQueries && !hasChildQueriesAtNextDepth) {
      return;
    }
    for (let keyIdx = 0; keyIdx < keys.length; keyIdx++) {
      const key = keys[keyIdx];
      const childNodes = node[key];
      const children = Array.isArray(childNodes) ? childNodes : childNodes ? [childNodes] : [];
      const nodePaths = [];
      for (let i = 0; i < children.length; i++) {
        const child = children[i];
        if (isNode(child)) {
          const childPath = createNodePath(child, Array.isArray(childNodes) ? i : key, key, nodePath.scopeId, nodePath.functionScopeId, nodePath);
          nodePaths.push(childPath);
        }
      }
      for (let i = 0; i < nodePaths.length; i++) {
        const childPath = nodePaths[i];
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
      log2?.debug("Scopes created", scopeIdCounter, " Scopes removed", removedScopes, "Paths created", pathsCreated, bindingNodesVisited);
      sOut.push(scopeIdCounter);
      const k = Object.fromEntries(Object.entries(nodePathsCreated).sort((a, b) => a[1] - b[1]));
      log2?.debug("Node paths created", k);
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  functions,
  isAvailableFunction,
  multiQuery,
  parseSource,
  query
});

},{"meriyah":5}],5:[function(require,module,exports){
!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?t(exports):"function"==typeof define&&define.amd?define(["exports"],t):t((e="undefined"!=typeof globalThis?globalThis:e||self).meriyah={})}(this,(function(e){"use strict";const t=((e,t)=>{const r=new Uint32Array(69632);let n=0,o=0;for(;n<2571;){const a=e[n++];if(a<0)o-=a;else{let i=e[n++];2&a&&(i=t[i]),1&a?r.fill(i,o,o+=e[n++]):r[o++]=i}}return r})([-1,2,26,2,27,2,5,-1,0,77595648,3,44,2,3,0,14,2,63,2,64,3,0,3,0,3168796671,0,4294956992,2,1,2,0,2,41,3,0,4,0,4294966523,3,0,4,2,16,2,65,2,0,0,4294836735,0,3221225471,0,4294901942,2,66,0,134152192,3,0,2,0,4294951935,3,0,2,0,2683305983,0,2684354047,2,18,2,0,0,4294961151,3,0,2,2,19,2,0,0,608174079,2,0,2,60,2,7,2,6,0,4286611199,3,0,2,2,1,3,0,3,0,4294901711,2,40,0,4089839103,0,2961209759,0,1342439375,0,4294543342,0,3547201023,0,1577204103,0,4194240,0,4294688750,2,2,0,80831,0,4261478351,0,4294549486,2,2,0,2967484831,0,196559,0,3594373100,0,3288319768,0,8469959,0,65472,2,3,0,4093640191,0,660618719,0,65487,0,4294828015,0,4092591615,0,1616920031,0,982991,2,3,2,0,0,2163244511,0,4227923919,0,4236247022,2,71,0,4284449919,0,851904,2,4,2,12,0,67076095,-1,2,72,0,1073741743,0,4093607775,-1,0,50331649,0,3265266687,2,33,0,4294844415,0,4278190047,2,20,2,137,-1,3,0,2,2,23,2,0,2,10,2,0,2,15,2,22,3,0,10,2,74,2,0,2,75,2,76,2,77,2,0,2,78,2,0,2,11,0,261632,2,25,3,0,2,2,13,2,4,3,0,18,2,79,2,5,3,0,2,2,80,0,2151677951,2,29,2,9,0,909311,3,0,2,0,814743551,2,49,0,67090432,3,0,2,2,42,2,0,2,6,2,0,2,30,2,8,0,268374015,2,110,2,51,2,0,2,81,0,134153215,-1,2,7,2,0,2,8,0,2684354559,0,67044351,0,3221160064,2,17,-1,3,0,2,2,53,0,1046528,3,0,3,2,9,2,0,2,54,0,4294960127,2,10,2,6,2,11,0,4294377472,2,12,3,0,16,2,13,2,0,2,82,2,10,2,0,2,83,2,84,2,85,0,12288,2,55,0,1048577,2,86,2,14,-1,2,14,0,131042,2,87,2,88,2,89,2,0,2,34,-83,3,0,7,0,1046559,2,0,2,15,2,0,0,2147516671,2,21,3,90,2,2,0,-16,2,91,0,524222462,2,4,2,0,0,4269801471,2,4,3,0,2,2,28,2,16,3,0,2,2,17,2,0,-1,2,18,-16,3,0,206,-2,3,0,692,2,73,-1,2,18,2,10,3,0,8,2,93,2,133,2,0,0,3220242431,3,0,3,2,19,2,94,2,95,3,0,2,2,96,2,0,2,97,2,46,2,0,0,4351,2,0,2,9,3,0,2,0,67043391,0,3909091327,2,0,2,24,2,9,2,20,3,0,2,0,67076097,2,8,2,0,2,21,0,67059711,0,4236247039,3,0,2,0,939524103,0,8191999,2,101,2,102,2,22,2,23,3,0,3,0,67057663,3,0,349,2,103,2,104,2,7,-264,3,0,11,2,24,3,0,2,2,32,-1,0,3774349439,2,105,2,106,3,0,2,2,19,2,107,3,0,10,2,10,2,18,2,0,2,47,2,0,2,31,2,108,2,25,0,1638399,0,57344,2,109,3,0,3,2,20,2,26,2,27,2,5,2,28,2,0,2,8,2,111,-1,2,112,2,113,2,114,-1,3,0,3,2,12,-2,2,0,2,29,-3,0,536870912,-4,2,20,2,0,2,36,0,1,2,0,2,67,2,6,2,12,2,10,2,0,2,115,-1,3,0,4,2,10,2,23,2,116,2,7,2,0,2,117,2,0,2,118,2,119,2,120,2,0,2,9,3,0,9,2,21,2,30,2,31,2,121,2,122,-2,2,123,2,124,2,30,2,21,2,8,-2,2,125,2,30,2,32,-2,2,0,2,39,-2,0,4277137519,0,2269118463,-1,3,20,2,-1,2,33,2,38,2,0,3,30,2,2,35,2,19,-3,3,0,2,2,34,-1,2,0,2,35,2,0,2,35,2,0,2,48,2,0,0,4294950463,2,37,-7,2,0,0,203775,2,57,0,4026531840,2,20,2,43,2,36,2,18,2,37,2,18,2,126,2,21,3,0,2,2,38,0,2151677888,2,0,2,12,0,4294901764,2,144,2,0,2,58,2,56,0,5242879,3,0,2,0,402644511,-1,2,128,2,39,0,3,-1,2,129,2,130,2,0,0,67045375,2,40,0,4226678271,0,3766565279,0,2039759,2,132,2,41,0,1046437,0,6,3,0,2,0,3288270847,0,3,3,0,2,0,67043519,-5,2,0,0,4282384383,0,1056964609,-1,3,0,2,0,67043345,-1,2,0,2,42,2,23,2,50,2,11,2,61,2,38,-5,2,0,2,12,-3,3,0,2,0,2147484671,2,134,0,4190109695,2,52,-2,2,135,0,4244635647,0,27,2,0,2,8,2,43,2,0,2,68,2,18,2,0,2,42,-6,2,0,2,45,2,59,2,44,2,45,2,46,2,47,0,8388351,-2,2,136,0,3028287487,2,48,2,138,0,33259519,2,49,-9,2,21,0,4294836223,0,3355443199,0,134152199,-2,2,69,-2,3,0,28,2,32,-3,3,0,3,2,17,3,0,6,2,50,-81,2,18,3,0,2,2,36,3,0,33,2,25,2,30,3,0,124,2,12,3,0,18,2,38,-213,2,0,2,32,-54,3,0,17,2,42,2,8,2,23,2,0,2,8,2,23,2,51,2,0,2,21,2,52,2,139,2,25,-13,2,0,2,53,-6,3,0,2,-4,3,0,2,0,4294936575,2,0,0,4294934783,-2,0,196635,3,0,191,2,54,3,0,38,2,30,2,55,2,34,-278,2,140,3,0,9,2,141,2,142,2,56,3,0,11,2,7,-72,3,0,3,2,143,0,1677656575,-130,2,26,-16,2,0,2,24,2,38,-16,0,4161266656,0,4071,0,15360,-4,2,57,-13,3,0,2,2,58,2,0,2,145,2,146,2,62,2,0,2,147,2,148,2,149,3,0,10,2,150,2,151,2,22,3,58,2,3,152,2,3,59,2,0,4294954999,2,0,-16,2,0,2,92,2,0,0,2105343,0,4160749584,0,65534,-34,2,8,2,154,-6,0,4194303871,0,4294903771,2,0,2,60,2,100,-3,2,0,0,1073684479,0,17407,-9,2,18,2,17,2,0,2,32,-14,2,18,2,32,-6,2,18,2,12,-15,2,155,3,0,6,0,8323103,-1,3,0,2,2,61,-37,2,62,2,156,2,157,2,158,2,159,2,160,-105,2,26,-32,3,0,1335,-1,3,0,129,2,32,3,0,6,2,10,3,0,180,2,161,3,0,233,2,162,3,0,18,2,10,-77,3,0,16,2,10,-47,3,0,154,2,6,3,0,130,2,25,-22250,3,0,7,2,25,-6130,3,5,2,-1,0,69207040,3,44,2,3,0,14,2,63,2,64,-3,0,3168731136,0,4294956864,2,1,2,0,2,41,3,0,4,0,4294966275,3,0,4,2,16,2,65,2,0,2,34,-1,2,18,2,66,-1,2,0,0,2047,0,4294885376,3,0,2,0,3145727,0,2617294944,0,4294770688,2,25,2,67,3,0,2,0,131135,2,98,0,70256639,0,71303167,0,272,2,42,2,6,0,32511,2,0,2,49,-1,2,99,2,68,0,4278255616,0,4294836227,0,4294549473,0,600178175,0,2952806400,0,268632067,0,4294543328,0,57540095,0,1577058304,0,1835008,0,4294688736,2,70,2,69,0,33554435,2,131,2,70,0,2952790016,0,131075,0,3594373096,0,67094296,2,69,-1,0,4294828e3,0,603979263,0,654311424,0,3,0,4294828001,0,602930687,0,1610612736,0,393219,0,4294828016,0,671088639,0,2154840064,0,4227858435,0,4236247008,2,71,2,38,-1,2,4,0,917503,2,38,-1,2,72,0,537788335,0,4026531935,-1,0,1,-1,2,33,2,73,0,7936,-3,2,0,0,2147485695,0,1010761728,0,4292984930,0,16387,2,0,2,15,2,22,3,0,10,2,74,2,0,2,75,2,76,2,77,2,0,2,78,2,0,2,12,-1,2,25,3,0,2,2,13,2,4,3,0,18,2,79,2,5,3,0,2,2,80,0,2147745791,3,19,2,0,122879,2,0,2,9,0,276824064,-2,3,0,2,2,42,2,0,0,4294903295,2,0,2,30,2,8,-1,2,18,2,51,2,0,2,81,2,49,-1,2,21,2,0,2,29,-2,0,128,-2,2,28,2,9,0,8160,-1,2,127,0,4227907585,2,0,2,37,2,0,2,50,0,4227915776,2,10,2,6,2,11,-1,0,74440192,3,0,6,-2,3,0,8,2,13,2,0,2,82,2,10,2,0,2,83,2,84,2,85,-3,2,86,2,14,-3,2,87,2,88,2,89,2,0,2,34,-83,3,0,7,0,817183,2,0,2,15,2,0,0,33023,2,21,3,90,2,-17,2,91,0,524157950,2,4,2,0,2,92,2,4,2,0,2,22,2,28,2,16,3,0,2,2,17,2,0,-1,2,18,-16,3,0,206,-2,3,0,692,2,73,-1,2,18,2,10,3,0,8,2,93,0,3072,2,0,0,2147516415,2,10,3,0,2,2,25,2,94,2,95,3,0,2,2,96,2,0,2,97,2,46,0,4294965179,0,7,2,0,2,9,2,95,2,9,-1,0,1761345536,2,98,0,4294901823,2,38,2,20,2,99,2,35,2,100,0,2080440287,2,0,2,34,2,153,0,3296722943,2,0,0,1046675455,0,939524101,0,1837055,2,101,2,102,2,22,2,23,3,0,3,0,7,3,0,349,2,103,2,104,2,7,-264,3,0,11,2,24,3,0,2,2,32,-1,0,2700607615,2,105,2,106,3,0,2,2,19,2,107,3,0,10,2,10,2,18,2,0,2,47,2,0,2,31,2,108,-3,2,109,3,0,3,2,20,-1,3,5,2,2,110,2,0,2,8,2,111,-1,2,112,2,113,2,114,-1,3,0,3,2,12,-2,2,0,2,29,-8,2,20,2,0,2,36,-1,2,0,2,67,2,6,2,30,2,10,2,0,2,115,-1,3,0,4,2,10,2,18,2,116,2,7,2,0,2,117,2,0,2,118,2,119,2,120,2,0,2,9,3,0,9,2,21,2,30,2,31,2,121,2,122,-2,2,123,2,124,2,30,2,21,2,8,-2,2,125,2,30,2,32,-2,2,0,2,39,-2,0,4277075969,2,30,-1,3,20,2,-1,2,33,2,126,2,0,3,30,2,2,35,2,19,-3,3,0,2,2,34,-1,2,0,2,35,2,0,2,35,2,0,2,50,2,98,0,4294934591,2,37,-7,2,0,0,197631,2,57,-1,2,20,2,43,2,37,2,18,0,3,2,18,2,126,2,21,2,127,2,54,-1,0,2490368,2,127,2,25,2,18,2,34,2,127,2,38,0,4294901904,0,4718591,2,127,2,35,0,335544350,-1,2,128,0,2147487743,0,1,-1,2,129,2,130,2,8,-1,2,131,2,70,0,3758161920,0,3,2,132,0,12582911,0,655360,-1,2,0,2,29,0,2147485568,0,3,2,0,2,25,0,176,-5,2,0,2,17,0,251658240,-1,2,0,2,25,0,16,-1,2,0,0,16779263,-2,2,12,-1,2,38,-5,2,0,2,133,-3,3,0,2,2,55,2,134,0,2147549183,0,2,-2,2,135,2,36,0,10,0,4294965249,0,67633151,0,4026597376,2,0,0,536871935,2,18,2,0,2,42,-6,2,0,0,1,2,59,2,17,0,1,2,46,2,25,-3,2,136,2,36,2,137,2,138,0,16778239,-10,2,35,0,4294836212,2,9,-3,2,69,-2,3,0,28,2,32,-3,3,0,3,2,17,3,0,6,2,50,-81,2,18,3,0,2,2,36,3,0,33,2,25,0,126,3,0,124,2,12,3,0,18,2,38,-213,2,10,-55,3,0,17,2,42,2,8,2,18,2,0,2,8,2,18,2,60,2,0,2,25,2,50,2,139,2,25,-13,2,0,2,73,-6,3,0,2,-4,3,0,2,0,67583,-1,2,107,-2,0,11,3,0,191,2,54,3,0,38,2,30,2,55,2,34,-278,2,140,3,0,9,2,141,2,142,2,56,3,0,11,2,7,-72,3,0,3,2,143,2,144,-187,3,0,2,2,58,2,0,2,145,2,146,2,62,2,0,2,147,2,148,2,149,3,0,10,2,150,2,151,2,22,3,58,2,3,152,2,3,59,2,2,153,-57,2,8,2,154,-7,2,18,2,0,2,60,-4,2,0,0,1065361407,0,16384,-9,2,18,2,60,2,0,2,133,-14,2,18,2,133,-6,2,18,0,81919,-15,2,155,3,0,6,2,126,-1,3,0,2,0,2063,-37,2,62,2,156,2,157,2,158,2,159,2,160,-138,3,0,1335,-1,3,0,129,2,32,3,0,6,2,10,3,0,180,2,161,3,0,233,2,162,3,0,18,2,10,-77,3,0,16,2,10,-47,3,0,154,2,6,3,0,130,2,25,-28386],[4294967295,4294967291,4092460543,4294828031,4294967294,134217726,4294903807,268435455,2147483647,1048575,1073741823,3892314111,134217727,1061158911,536805376,4294910143,4294901759,32767,4294901760,262143,536870911,8388607,4160749567,4294902783,4294918143,65535,67043328,2281701374,4294967264,2097151,4194303,255,67108863,4294967039,511,524287,131071,63,127,3238002687,4294549487,4290772991,33554431,4294901888,4286578687,67043329,4294705152,4294770687,67043583,1023,15,2047999,67043343,67051519,16777215,2147483648,4294902e3,28,4292870143,4294966783,16383,67047423,4294967279,262083,20511,41943039,493567,4294959104,603979775,65536,602799615,805044223,4294965206,8191,1031749119,4294917631,2134769663,4286578493,4282253311,4294942719,33540095,4294905855,2868854591,1608515583,265232348,534519807,2147614720,1060109444,4093640016,17376,2139062143,224,4169138175,4294909951,4286578688,4294967292,4294965759,535511039,4294966272,4294967280,32768,8289918,4294934399,4294901775,4294965375,1602223615,4294967259,4294443008,268369920,4292804608,4294967232,486341884,4294963199,3087007615,1073692671,4128527,4279238655,4294902015,4160684047,4290246655,469499899,4294967231,134086655,4294966591,2445279231,3670015,31,4294967288,4294705151,3221208447,4294902271,4294549472,4294921215,4095,4285526655,4294966527,4294966143,64,4294966719,3774873592,1877934080,262151,2555904,536807423,67043839,3758096383,3959414372,3755993023,2080374783,4294835295,4294967103,4160749565,4294934527,4087,2016,2147446655,184024726,2862017156,1593309078,268434431,268434414,4294901763,4294901761]),r=e=>!!(1&t[34816+(e>>>5)]>>>e);function n(e){return e.column++,e.currentChar=e.source.charCodeAt(++e.index)}function o(e){const t=e.currentChar;if(55296!=(64512&t))return 0;const r=e.source.charCodeAt(e.index+1);return 56320!=(64512&r)?0:65536+((1023&t)<<10)+(1023&r)}function a(e,t){e.currentChar=e.source.charCodeAt(++e.index),e.flags|=1,4&t||(e.column=0,e.line++)}function i(e){e.flags|=1,e.currentChar=e.source.charCodeAt(++e.index),e.column=0,e.line++}function s(e){return e<65?e-48:e-65+10&15}function c(e){switch(e){case 134283266:return"NumericLiteral";case 134283267:return"StringLiteral";case 86021:case 86022:return"BooleanLiteral";case 86023:return"NullLiteral";case 65540:return"RegularExpression";case 67174408:case 67174409:case 131:return"TemplateLiteral";default:return 143360&~e?4096&~e?"Punctuator":"Keyword":"Identifier"}}const l=[0,0,0,0,0,0,0,0,0,0,1032,0,0,2056,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8192,0,3,0,0,8192,0,0,0,256,0,33024,0,0,242,242,114,114,114,114,114,114,594,594,0,0,16384,0,0,0,0,67,67,67,67,67,67,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,1,0,0,4099,0,71,71,71,71,71,71,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,16384,0,0,0,0],u=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0],p=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0];function d(e){return e<=127?u[e]>0:r(e)}function g(e){return e<=127?p[e]>0:(e=>!!(1&t[0+(e>>>5)]>>>e))(e)||8204===e||8205===e}const f=["SingleLine","MultiLine","HTMLOpen","HTMLClose","HashbangComment"];function k(e,t,r,n,o,a){return 2&n&&e.report(0),h(e,t,r,o,a)}function h(e,t,r,o,a){const{index:s}=e;for(e.tokenIndex=e.index,e.tokenLine=e.line,e.tokenColumn=e.column;e.index<e.end;){if(8&l[e.currentChar]){const r=13===e.currentChar;i(e),r&&e.index<e.end&&10===e.currentChar&&(e.currentChar=t.charCodeAt(++e.index));break}if((8232^e.currentChar)<=1){i(e);break}n(e),e.tokenIndex=e.index,e.tokenLine=e.line,e.tokenColumn=e.column}if(e.options.onComment){const r={start:{line:a.line,column:a.column},end:{line:e.tokenLine,column:e.tokenColumn}};e.options.onComment(f[255&o],t.slice(s,e.tokenIndex),a.index,e.tokenIndex,r)}return 1|r}function m(e,t,r){const{index:o}=e;for(;e.index<e.end;)if(e.currentChar<43){let s=!1;for(;42===e.currentChar;)if(s||(r&=-5,s=!0),47===n(e)){if(n(e),e.options.onComment){const r={start:{line:e.tokenLine,column:e.tokenColumn},end:{line:e.line,column:e.column}};e.options.onComment(f[1],t.slice(o,e.index-2),o-2,e.index,r)}return e.tokenIndex=e.index,e.tokenLine=e.line,e.tokenColumn=e.column,r}if(s)continue;8&l[e.currentChar]?13===e.currentChar?(r|=5,i(e)):(a(e,r),r=-5&r|1):n(e)}else(8232^e.currentChar)<=1?(r=-5&r|1,i(e)):(r&=-5,n(e));e.report(18)}var b,T;function y(e){const t=e.index;let r=b.Empty;e:for(;;){const t=e.currentChar;if(n(e),r&b.Escape)r&=~b.Escape;else switch(t){case 47:if(r)break;break e;case 92:r|=b.Escape;break;case 91:r|=b.Class;break;case 93:r&=b.Escape}if(13!==t&&10!==t&&8232!==t&&8233!==t||e.report(34),e.index>=e.source.length)return e.report(34)}const o=e.index-1;let a=T.Empty,i=e.currentChar;const{index:s}=e;for(;g(i);){switch(i){case 103:a&T.Global&&e.report(36,"g"),a|=T.Global;break;case 105:a&T.IgnoreCase&&e.report(36,"i"),a|=T.IgnoreCase;break;case 109:a&T.Multiline&&e.report(36,"m"),a|=T.Multiline;break;case 117:a&T.Unicode&&e.report(36,"u"),a&T.UnicodeSets&&e.report(36,"vu"),a|=T.Unicode;break;case 118:a&T.Unicode&&e.report(36,"uv"),a&T.UnicodeSets&&e.report(36,"v"),a|=T.UnicodeSets;break;case 121:a&T.Sticky&&e.report(36,"y"),a|=T.Sticky;break;case 115:a&T.DotAll&&e.report(36,"s"),a|=T.DotAll;break;case 100:a&T.Indices&&e.report(36,"d"),a|=T.Indices;break;default:e.report(35)}i=n(e)}const c=e.source.slice(s,e.index),l=e.source.slice(t,o);return e.tokenRegExp={pattern:l,flags:c},e.options.raw&&(e.tokenRaw=e.source.slice(e.tokenIndex,e.index)),e.tokenValue=function(e,t,r){try{return new RegExp(t,r)}catch{try{return new RegExp(t,r),null}catch{e.report(34)}}}(e,l,c),65540}function x(e,t,r){const{index:o}=e;let a="",i=n(e),s=e.index;for(;!(8&l[i]);){if(i===r)return a+=e.source.slice(s,e.index),n(e),e.options.raw&&(e.tokenRaw=e.source.slice(o,e.index)),e.tokenValue=a,134283267;if(8&~i||92!==i)8232!==i&&8233!==i||(e.column=-1,e.line++);else{if(a+=e.source.slice(s,e.index),i=n(e),i<127||8232===i||8233===i){const r=w(e,t,i);r>=0?a+=String.fromCodePoint(r):S(e,r,0)}else a+=String.fromCodePoint(i);s=e.index+1}e.index>=e.end&&e.report(16),i=n(e)}e.report(16)}function w(e,t,r,o=0){switch(r){case 98:return 8;case 102:return 12;case 114:return 13;case 110:return 10;case 116:return 9;case 118:return 11;case 13:if(e.index<e.end){const t=e.source.charCodeAt(e.index+1);10===t&&(e.index=e.index+1,e.currentChar=t)}case 10:case 8232:case 8233:return e.column=-1,e.line++,-1;case 48:case 49:case 50:case 51:{let n=r-48,a=e.index+1,i=e.column+1;if(a<e.end){const r=e.source.charCodeAt(a);if(32&l[r]){if(1&t||o)return-2;if(e.currentChar=r,n=n<<3|r-48,a++,i++,a<e.end){const t=e.source.charCodeAt(a);32&l[t]&&(e.currentChar=t,n=n<<3|t-48,a++,i++)}e.flags|=64}else if(0!==n||512&l[r]){if(1&t||o)return-2;e.flags|=64}e.index=a-1,e.column=i-1}return n}case 52:case 53:case 54:case 55:{if(o||1&t)return-2;let n=r-48;const a=e.index+1,i=e.column+1;if(a<e.end){const t=e.source.charCodeAt(a);32&l[t]&&(n=n<<3|t-48,e.currentChar=t,e.index=a,e.column=i)}return e.flags|=64,n}case 120:{const t=n(e);if(!(64&l[t]))return-4;const r=s(t),o=n(e);if(!(64&l[o]))return-4;return r<<4|s(o)}case 117:{const t=n(e);if(123===e.currentChar){let t=0;for(;64&l[n(e)];)if(t=t<<4|s(e.currentChar),t>1114111)return-5;return e.currentChar<1||125!==e.currentChar?-4:t}{if(!(64&l[t]))return-4;const r=e.source.charCodeAt(e.index+1);if(!(64&l[r]))return-4;const n=e.source.charCodeAt(e.index+2);if(!(64&l[n]))return-4;const o=e.source.charCodeAt(e.index+3);return 64&l[o]?(e.index+=3,e.column+=3,e.currentChar=e.source.charCodeAt(e.index),s(t)<<12|s(r)<<8|s(n)<<4|s(o)):-4}}case 56:case 57:if(o||!e.options.webcompat||1&t)return-3;e.flags|=4096;default:return r}}function S(e,t,r){switch(t){case-1:return;case-2:e.report(r?2:1);case-3:e.report(r?3:14);case-4:e.report(7);case-5:e.report(104)}}function v(e,t){const{index:r}=e;let o=67174409,a="",i=n(e);for(;96!==i;){if(36===i&&123===e.source.charCodeAt(e.index+1)){n(e),o=67174408;break}if(92===i)if(i=n(e),i>126)a+=String.fromCodePoint(i);else{const{index:r,line:n,column:s}=e,c=w(e,1|t,i,1);if(c>=0)a+=String.fromCodePoint(c);else{if(-1!==c&&64&t){e.index=r,e.line=n,e.column=s,a=null,i=C(e,i),i<0&&(o=67174408);break}S(e,c,1)}}else e.index<e.end&&(13===i&&10===e.source.charCodeAt(e.index)&&(a+=String.fromCodePoint(i),e.currentChar=e.source.charCodeAt(++e.index)),((83&i)<3&&10===i||(8232^i)<=1)&&(e.column=-1,e.line++),a+=String.fromCodePoint(i));e.index>=e.end&&e.report(17),i=n(e)}return n(e),e.tokenValue=a,e.tokenRaw=e.source.slice(r+1,e.index-(67174409===o?1:2)),o}function C(e,t){for(;96!==t;){switch(t){case 36:{const r=e.index+1;if(r<e.end&&123===e.source.charCodeAt(r))return e.index=r,e.column++,-t;break}case 10:case 8232:case 8233:e.column=-1,e.line++}e.index>=e.end&&e.report(17),t=n(e)}return t}function q(e,t){return e.index>=e.end&&e.report(0),e.index--,e.column--,v(e,t)}!function(e){e[e.Empty=0]="Empty",e[e.Escape=1]="Escape",e[e.Class=2]="Class"}(b||(b={})),function(e){e[e.Empty=0]="Empty",e[e.IgnoreCase=1]="IgnoreCase",e[e.Global=2]="Global",e[e.Multiline=4]="Multiline",e[e.Unicode=16]="Unicode",e[e.Sticky=8]="Sticky",e[e.DotAll=32]="DotAll",e[e.Indices=64]="Indices",e[e.UnicodeSets=128]="UnicodeSets"}(T||(T={}));const E={0:"Unexpected token",30:"Unexpected token: '%0'",1:"Octal escape sequences are not allowed in strict mode",2:"Octal escape sequences are not allowed in template strings",3:"\\8 and \\9 are not allowed in template strings",4:"Private identifier #%0 is not defined",5:"Illegal Unicode escape sequence",6:"Invalid code point %0",7:"Invalid hexadecimal escape sequence",9:"Octal literals are not allowed in strict mode",8:"Decimal integer literals with a leading zero are forbidden in strict mode",10:"Expected number in radix %0",151:"Invalid left-hand side assignment to a destructible right-hand side",11:"Non-number found after exponent indicator",12:"Invalid BigIntLiteral",13:"No identifiers allowed directly after numeric literal",14:"Escapes \\8 or \\9 are not syntactically valid escapes",15:"Escapes \\8 or \\9 are not allowed in strict mode",16:"Unterminated string literal",17:"Unterminated template literal",18:"Multiline comment was not closed properly",19:"The identifier contained dynamic unicode escape that was not closed",20:"Illegal character '%0'",21:"Missing hexadecimal digits",22:"Invalid implicit octal",23:"Invalid line break in string literal",24:"Only unicode escapes are legal in identifier names",25:"Expected '%0'",26:"Invalid left-hand side in assignment",27:"Invalid left-hand side in async arrow",28:'Calls to super must be in the "constructor" method of a class expression or class declaration that has a superclass',29:"Member access on super must be in a method",31:"Await expression not allowed in formal parameter",32:"Yield expression not allowed in formal parameter",95:"Unexpected token: 'escaped keyword'",33:"Unary expressions as the left operand of an exponentiation expression must be disambiguated with parentheses",123:"Async functions can only be declared at the top level or inside a block",34:"Unterminated regular expression",35:"Unexpected regular expression flag",36:"Duplicate regular expression flag '%0'",37:"%0 functions must have exactly %1 argument%2",38:"Setter function argument must not be a rest parameter",39:"%0 declaration must have a name in this context",40:"Function name may not contain any reserved words or be eval or arguments in strict mode",41:"The rest operator is missing an argument",42:"A getter cannot be a generator",43:"A setter cannot be a generator",44:"A computed property name must be followed by a colon or paren",134:"Object literal keys that are strings or numbers must be a method or have a colon",46:"Found `* async x(){}` but this should be `async * x(){}`",45:"Getters and setters can not be generators",47:"'%0' can not be generator method",48:"No line break is allowed after '=>'",49:"The left-hand side of the arrow can only be destructed through assignment",50:"The binding declaration is not destructible",51:"Async arrow can not be followed by new expression",52:"Classes may not have a static property named 'prototype'",53:"Class constructor may not be a %0",54:"Duplicate constructor method in class",55:"Invalid increment/decrement operand",56:"Invalid use of `new` keyword on an increment/decrement expression",57:"`=>` is an invalid assignment target",58:"Rest element may not have a trailing comma",59:"Missing initializer in %0 declaration",60:"'for-%0' loop head declarations can not have an initializer",61:"Invalid left-hand side in for-%0 loop: Must have a single binding",62:"Invalid shorthand property initializer",63:"Property name __proto__ appears more than once in object literal",64:"Let is disallowed as a lexically bound name",65:"Invalid use of '%0' inside new expression",66:"Illegal 'use strict' directive in function with non-simple parameter list",67:'Identifier "let" disallowed as left-hand side expression in strict mode',68:"Illegal continue statement",69:"Illegal break statement",70:"Cannot have `let[...]` as a var name in strict mode",71:"Invalid destructuring assignment target",72:"Rest parameter may not have a default initializer",73:"The rest argument must the be last parameter",74:"Invalid rest argument",76:"In strict mode code, functions can only be declared at top level or inside a block",77:"In non-strict mode code, functions can only be declared at top level, inside a block, or as the body of an if statement",78:"Without web compatibility enabled functions can not be declared at top level, inside a block, or as the body of an if statement",79:"Class declaration can't appear in single-statement context",80:"Invalid left-hand side in for-%0",81:"Invalid assignment in for-%0",82:"for await (... of ...) is only valid in async functions and async generators",83:"The first token after the template expression should be a continuation of the template",85:"`let` declaration not allowed here and `let` cannot be a regular var name in strict mode",84:"`let \n [` is a restricted production at the start of a statement",86:"Catch clause requires exactly one parameter, not more (and no trailing comma)",87:"Catch clause parameter does not support default values",88:"Missing catch or finally after try",89:"More than one default clause in switch statement",90:"Illegal newline after throw",91:"Strict mode code may not include a with statement",92:"Illegal return statement",93:"The left hand side of the for-header binding declaration is not destructible",94:"new.target only allowed within functions or static blocks",96:"'#' not followed by identifier",102:"Invalid keyword",101:"Can not use 'let' as a class name",100:"'A lexical declaration can't define a 'let' binding",99:"Can not use `let` as variable name in strict mode",97:"'%0' may not be used as an identifier in this context",98:"Await is only valid in async functions",103:"The %0 keyword can only be used with the module goal",104:"Unicode codepoint must not be greater than 0x10FFFF",105:"%0 source must be string",106:"Only a identifier or string can be used to indicate alias",107:"Only '*' or '{...}' can be imported after default",108:"Trailing decorator may be followed by method",109:"Decorators can't be used with a constructor",110:"Can not use `await` as identifier in module or async func",111:"Can not use `await` as identifier in module",112:"HTML comments are only allowed with web compatibility (Annex B)",113:"The identifier 'let' must not be in expression position in strict mode",114:"Cannot assign to `eval` and `arguments` in strict mode",115:"The left-hand side of a for-of loop may not start with 'let'",116:"Block body arrows can not be immediately invoked without a group",117:"Block body arrows can not be immediately accessed without a group",118:"Unexpected strict mode reserved word",119:"Unexpected eval or arguments in strict mode",120:"Decorators must not be followed by a semicolon",121:"Calling delete on expression not allowed in strict mode",122:"Pattern can not have a tail",124:"Can not have a `yield` expression on the left side of a ternary",125:"An arrow function can not have a postfix update operator",126:"Invalid object literal key character after generator star",127:"Private fields can not be deleted",129:"Classes may not have a field called constructor",128:"Classes may not have a private element named constructor",130:"A class field initializer or static block may not contain arguments",131:"Generators can only be declared at the top level or inside a block",132:"Async methods are a restricted production and cannot have a newline following it",133:"Unexpected character after object literal property name",135:"Invalid key token",136:"Label '%0' has already been declared",137:"continue statement must be nested within an iteration statement",138:"Undefined label '%0'",139:"Trailing comma is disallowed inside import(...) arguments",140:"Invalid binding in JSON import",141:"import() requires exactly one argument",142:"Cannot use new with import(...)",143:"... is not allowed in import()",144:"Expected '=>'",145:"Duplicate binding '%0'",146:"Duplicate private identifier #%0",147:"Cannot export a duplicate name '%0'",150:"Duplicate %0 for-binding",148:"Exported binding '%0' needs to refer to a top-level declared variable",149:"Unexpected private field",153:"Numeric separators are not allowed at the end of numeric literals",152:"Only one underscore is allowed as numeric separator",154:"JSX value should be either an expression or a quoted JSX text",155:"Expected corresponding JSX closing tag for %0",156:"Adjacent JSX elements must be wrapped in an enclosing tag",157:"JSX attributes must only be assigned a non-empty 'expression'",158:"'%0' has already been declared",159:"'%0' shadowed a catch clause binding",160:"Dot property must be an identifier",161:"Encountered invalid input after spread/rest argument",162:"Catch without try",163:"Finally without try",164:"Expected corresponding closing tag for JSX fragment",165:"Coalescing and logical operators used together in the same expression must be disambiguated with parentheses",166:"Invalid tagged template on optional chain",167:"Invalid optional chain from super property",168:"Invalid optional chain from new expression",169:'Cannot use "import.meta" outside a module',170:"Leading decorators must be attached to a class declaration",171:"An export name cannot include a lone surrogate, found %0",172:"A string literal cannot be used as an exported binding without `from`",173:"Private fields can't be accessed on super",174:"The only valid meta property for import is 'import.meta'",175:"'import.meta' must not contain escaped characters",176:'cannot use "await" as identifier inside an async function',177:'cannot use "await" in static blocks'};class N extends SyntaxError{start;end;range;loc;description;constructor(e,t,r,...n){const o=E[r].replace(/%(\d+)/g,((e,t)=>n[t]));super("["+e.line+":"+e.column+"-"+t.line+":"+t.column+"]: "+o),this.start=e.index,this.end=t.index,this.range=[e.index,t.index],this.loc={start:{line:e.line,column:e.column},end:{line:t.line,column:t.column}},this.description=o}}function L(e,t,r){let o=e.currentChar,a=0,i=9,c=64&r?0:1,u=0,p=0;if(64&r)a="."+A(e,o),o=e.currentChar,110===o&&e.report(12);else{if(48===o)if(o=n(e),120==(32|o)){for(r=136,o=n(e);4160&l[o];)95!==o?(p=1,a=16*a+s(o),u++,o=n(e)):(p||e.report(152),p=0,o=n(e));0!==u&&p||e.report(0===u?21:153)}else if(111==(32|o)){for(r=132,o=n(e);4128&l[o];)95!==o?(p=1,a=8*a+(o-48),u++,o=n(e)):(p||e.report(152),p=0,o=n(e));0!==u&&p||e.report(0===u?0:153)}else if(98==(32|o)){for(r=130,o=n(e);4224&l[o];)95!==o?(p=1,a=2*a+(o-48),u++,o=n(e)):(p||e.report(152),p=0,o=n(e));0!==u&&p||e.report(0===u?0:153)}else if(32&l[o])for(1&t&&e.report(1),r=1;16&l[o];){if(512&l[o]){r=32,c=0;break}a=8*a+(o-48),o=n(e)}else 512&l[o]?(1&t&&e.report(1),e.flags|=64,r=32):95===o&&e.report(0);if(48&r){if(c){for(;i>=0&&4112&l[o];)if(95!==o)p=0,a=10*a+(o-48),o=n(e),--i;else{if(o=n(e),95===o||32&r)throw new N(e.currentLocation,{index:e.index+1,line:e.line,column:e.column},152);p=1}if(p)throw new N(e.currentLocation,{index:e.index+1,line:e.line,column:e.column},153);if(i>=0&&!d(o)&&46!==o)return e.tokenValue=a,e.options.raw&&(e.tokenRaw=e.source.slice(e.tokenIndex,e.index)),134283266}a+=A(e,o),o=e.currentChar,46===o&&(95===n(e)&&e.report(0),r=64,a+="."+A(e,e.currentChar),o=e.currentChar)}}const g=e.index;let f=0;if(110===o&&128&r)f=1,o=n(e);else if(101==(32|o)){o=n(e),256&l[o]&&(o=n(e));const{index:t}=e;16&l[o]||e.report(11),a+=e.source.substring(g,t)+A(e,o),o=e.currentChar}return(e.index<e.end&&16&l[o]||d(o))&&e.report(13),f?(e.tokenRaw=e.source.slice(e.tokenIndex,e.index),e.tokenValue=BigInt(e.tokenRaw.slice(0,-1).replaceAll("_","")),134283388):(e.tokenValue=15&r?a:32&r?parseFloat(e.source.substring(e.tokenIndex,e.index)):+a,e.options.raw&&(e.tokenRaw=e.source.slice(e.tokenIndex,e.index)),134283266)}function A(e,t){let r=0,o=e.index,a="";for(;4112&l[t];)if(95!==t)r=0,t=n(e);else{const{index:i}=e;if(95===(t=n(e)))throw new N(e.currentLocation,{index:e.index+1,line:e.line,column:e.column},152);r=1,a+=e.source.substring(o,i),o=e.index}if(r)throw new N(e.currentLocation,{index:e.index+1,line:e.line,column:e.column},153);return a+e.source.substring(o,e.index)}const I=["end of source","identifier","number","string","regular expression","false","true","null","template continuation","template tail","=>","(","{",".","...","}",")",";",",","[","]",":","?","'",'"',"++","--","=","<<=",">>=",">>>=","**=","+=","-=","*=","/=","%=","^=","|=","&=","||=","&&=","??=","typeof","delete","void","!","~","+","-","in","instanceof","*","%","/","**","&&","||","===","!==","==","!=","<=",">=","<",">","<<",">>",">>>","&","|","^","var","let","const","break","case","catch","class","continue","debugger","default","do","else","export","extends","finally","for","function","if","import","new","return","super","switch","this","throw","try","while","with","implements","interface","package","private","protected","public","static","yield","as","async","await","constructor","get","set","accessor","from","of","enum","eval","arguments","escaped keyword","escaped future reserved keyword","reserved if strict","#","BigIntLiteral","??","?.","WhiteSpace","Illegal","LineTerminator","PrivateField","Template","@","target","meta","LineFeed","Escaped","JSXText"],V={this:86111,function:86104,if:20569,return:20572,var:86088,else:20563,for:20567,new:86107,in:8673330,typeof:16863275,while:20578,case:20556,break:20555,try:20577,catch:20557,delete:16863276,throw:86112,switch:86110,continue:20559,default:20561,instanceof:8411187,do:20562,void:16863277,finally:20566,async:209005,await:209006,class:86094,const:86090,constructor:12399,debugger:20560,export:20564,extends:20565,false:86021,from:209011,get:209008,implements:36964,import:86106,interface:36965,let:241737,null:86023,of:471156,package:36966,private:36967,protected:36968,public:36969,set:209009,static:36970,super:86109,true:86022,with:20579,yield:241771,enum:86133,eval:537079926,as:77932,arguments:537079927,target:209029,meta:209030,accessor:12402};function D(e,t){!(1&e.flags)&&1048576&~e.getToken()&&e.report(30,I[255&e.getToken()]),U(e,t,1074790417)||e.options.onInsertedSemicolon?.(e.startIndex)}function R(e,t,r,n){return t-r<13&&"use strict"===n&&(!(1048576&~e.getToken())||1&e.flags)?1:0}function B(e,t,r){return e.getToken()!==r?0:(Q(e,t),1)}function U(e,t,r){return e.getToken()===r&&(Q(e,t),!0)}function P(e,t,r){e.getToken()!==r&&e.report(25,I[255&r]),Q(e,t)}function O(e,t){switch(t.type){case"ArrayExpression":{t.type="ArrayPattern";const{elements:r}=t;for(let t=0,n=r.length;t<n;++t){const n=r[t];n&&O(e,n)}return}case"ObjectExpression":{t.type="ObjectPattern";const{properties:r}=t;for(let t=0,n=r.length;t<n;++t)O(e,r[t]);return}case"AssignmentExpression":return t.type="AssignmentPattern","="!==t.operator&&e.report(71),delete t.operator,void O(e,t.left);case"Property":return void O(e,t.value);case"SpreadElement":t.type="RestElement",O(e,t.argument)}}function G(e,t,r,n,o){1&t&&(36864&~n||e.report(118),o||537079808&~n||e.report(119)),20480&~n&&-2147483528!==n||e.report(102),24&r&&73==(255&n)&&e.report(100),2050&t&&209006===n&&e.report(110),1025&t&&241771===n&&e.report(97,"yield")}function j(e,t,r){1&t&&(36864&~r||e.report(118),537079808&~r||e.report(119),-2147483527===r&&e.report(95),-2147483528===r&&e.report(95)),20480&~r||e.report(102),2050&t&&209006===r&&e.report(110),1025&t&&241771===r&&e.report(97,"yield")}function F(e,t,r){return 209006===r&&(2050&t&&e.report(110),e.destructible|=128),241771===r&&1024&t&&e.report(97,"yield"),!(20480&~r&&36864&~r&&-2147483527!=r)}function J(e,t,r,n){for(;t;){if(t["$"+r])return n&&e.report(137),1;n&&t.loop&&(n=0),t=t.$}return 0}function M(e){switch(e.type){case"JSXIdentifier":return e.name;case"JSXNamespacedName":return e.namespace+":"+e.name;case"JSXMemberExpression":return M(e.object)+"."+M(e.property)}}function H(e,t){return 1025&e?!(2&e&&209006===t)&&(!(1024&e&&241771===t)&&!(12288&~t)):!(12288&~t&&36864&~t)}function z(e,t,r){537079808&~r||(1&t&&e.report(119),e.flags|=512),H(t,r)||e.report(0)}function X(e,t){return Object.hasOwn(e,t)?e[t]:void 0}function _(e,t,r){for(;p[n(e)];);return e.tokenValue=e.source.slice(e.tokenIndex,e.index),92!==e.currentChar&&e.currentChar<=126?X(V,e.tokenValue)??208897:Y(e,t,0,r)}function $(e,t){const r=K(e);return d(r)||e.report(5),e.tokenValue=String.fromCodePoint(r),Y(e,t,1,4&l[r])}function Y(e,t,r,a){let i=e.index;for(;e.index<e.end;)if(92===e.currentChar){e.tokenValue+=e.source.slice(i,e.index),r=1;const t=K(e);g(t)||e.report(5),a=a&&4&l[t],e.tokenValue+=String.fromCodePoint(t),i=e.index}else{const t=o(e);if(t>0)g(t)||e.report(20,String.fromCodePoint(t)),e.currentChar=t,e.index++,e.column++;else if(!g(e.currentChar))break;n(e)}e.index<=e.end&&(e.tokenValue+=e.source.slice(i,e.index));const{length:s}=e.tokenValue;if(a&&s>=2&&s<=11){const n=X(V,e.tokenValue);return void 0===n?208897|(r?-2147483648:0):r?209006===n?2050&t?-2147483528:-2147483648|n:1&t?36970===n?-2147483527:36864&~n?20480&~n?-2147274630:262144&t&&!(8&t)?-2147483648|n:-2147483528:-2147483527:!(262144&t)||8&t||20480&~n?241771===n?262144&t?-2147274630:1024&t?-2147483528:-2147483648|n:209005===n?-2147274630:36864&~n?-2147483528:12288|n|-2147483648:-2147483648|n:n}return 208897|(r?-2147483648:0)}function Z(e){let t=n(e);if(92===t)return 130;const r=o(e);return r&&(t=r),d(t)||e.report(96),130}function K(e){return 117!==e.source.charCodeAt(e.index+1)&&e.report(5),e.currentChar=e.source.charCodeAt(e.index+=2),e.column+=2,function(e){let t=0;const r=e.currentChar;if(123===r){const r=e.index-2;for(;64&l[n(e)];)if(t=t<<4|s(e.currentChar),t>1114111)throw new N({index:r,line:e.line,column:e.column},e.currentLocation,104);if(125!==e.currentChar)throw new N({index:r,line:e.line,column:e.column},e.currentLocation,7);return n(e),t}64&l[r]||e.report(7);const o=e.source.charCodeAt(e.index+1);64&l[o]||e.report(7);const a=e.source.charCodeAt(e.index+2);64&l[a]||e.report(7);const i=e.source.charCodeAt(e.index+3);64&l[i]||e.report(7);return t=s(r)<<12|s(o)<<8|s(a)<<4|s(i),e.currentChar=e.source.charCodeAt(e.index+=4),e.column+=4,t}(e)}const W=[128,128,128,128,128,128,128,128,128,127,135,127,127,129,128,128,128,128,128,128,128,128,128,128,128,128,128,128,128,128,128,128,127,16842798,134283267,130,208897,8391477,8390213,134283267,67174411,16,8391476,25233968,18,25233969,67108877,8457014,134283266,134283266,134283266,134283266,134283266,134283266,134283266,134283266,134283266,134283266,21,1074790417,8456256,1077936155,8390721,22,132,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,208897,69271571,136,20,8389959,208897,131,4096,4096,4096,4096,4096,4096,4096,208897,4096,208897,208897,4096,208897,4096,208897,4096,208897,4096,4096,4096,208897,4096,4096,208897,4096,4096,2162700,8389702,1074790415,16842799,128];function Q(e,t){e.flags=1^(1|e.flags),e.startIndex=e.index,e.startColumn=e.column,e.startLine=e.line,e.setToken(ee(e,t,0))}function ee(e,t,s){const c=0===e.index,{source:l}=e;let u=e.currentLocation;for(;e.index<e.end;){e.tokenIndex=e.index,e.tokenColumn=e.column,e.tokenLine=e.line;let d=e.currentChar;if(d<=126){const r=W[d];switch(r){case 67174411:case 16:case 2162700:case 1074790415:case 69271571:case 20:case 21:case 1074790417:case 18:case 16842799:case 132:case 128:return n(e),r;case 208897:return _(e,t,0);case 4096:return _(e,t,1);case 134283266:return L(e,t,144);case 134283267:return x(e,t,d);case 131:return v(e,t);case 136:return $(e,t);case 130:return Z(e);case 127:n(e);break;case 129:s|=5,i(e);break;case 135:a(e,s),s=-5&s|1;break;case 8456256:{const r=n(e);if(e.index<e.end){if(60===r)return e.index<e.end&&61===n(e)?(n(e),4194332):8390978;if(61===r)return n(e),8390718;if(33===r){const r=e.index+1;if(r+1<e.end&&45===l.charCodeAt(r)&&45==l.charCodeAt(r+1)){e.column+=3,e.currentChar=l.charCodeAt(e.index+=3),s=k(e,l,s,t,2,e.tokenStart),u=e.tokenStart;continue}return 8456256}}return 8456256}case 1077936155:{n(e);const t=e.currentChar;return 61===t?61===n(e)?(n(e),8390458):8390460:62===t?(n(e),10):1077936155}case 16842798:return 61!==n(e)?16842798:61!==n(e)?8390461:(n(e),8390459);case 8391477:return 61!==n(e)?8391477:(n(e),4194340);case 8391476:{if(n(e),e.index>=e.end)return 8391476;const t=e.currentChar;return 61===t?(n(e),4194338):42!==t?8391476:61!==n(e)?8391735:(n(e),4194335)}case 8389959:return 61!==n(e)?8389959:(n(e),4194341);case 25233968:{n(e);const t=e.currentChar;return 43===t?(n(e),33619993):61===t?(n(e),4194336):25233968}case 25233969:{n(e);const r=e.currentChar;if(45===r){if(n(e),(1&s||c)&&62===e.currentChar){e.options.webcompat||e.report(112),n(e),s=k(e,l,s,t,3,u),u=e.tokenStart;continue}return 33619994}return 61===r?(n(e),4194337):25233969}case 8457014:if(n(e),e.index<e.end){const r=e.currentChar;if(47===r){n(e),s=h(e,l,s,0,e.tokenStart),u=e.tokenStart;continue}if(42===r){n(e),s=m(e,l,s),u=e.tokenStart;continue}if(32&t)return y(e);if(61===r)return n(e),4259875}return 8457014;case 67108877:{const r=n(e);if(r>=48&&r<=57)return L(e,t,80);if(46===r){const t=e.index+1;if(t<e.end&&46===l.charCodeAt(t))return e.column+=2,e.currentChar=l.charCodeAt(e.index+=2),14}return 67108877}case 8389702:{n(e);const t=e.currentChar;return 124===t?(n(e),61===e.currentChar?(n(e),4194344):8913465):61===t?(n(e),4194342):8389702}case 8390721:{n(e);const t=e.currentChar;if(61===t)return n(e),8390719;if(62!==t)return 8390721;if(n(e),e.index<e.end){const t=e.currentChar;if(62===t)return 61===n(e)?(n(e),4194334):8390980;if(61===t)return n(e),4194333}return 8390979}case 8390213:{n(e);const t=e.currentChar;return 38===t?(n(e),61===e.currentChar?(n(e),4194345):8913720):61===t?(n(e),4194343):8390213}case 22:{let t=n(e);if(63===t)return n(e),61===e.currentChar?(n(e),4194346):276824445;if(46===t){const r=e.index+1;if(r<e.end&&(t=l.charCodeAt(r),!(t>=48&&t<=57)))return n(e),67108990}return 22}}}else{if((8232^d)<=1){s=-5&s|1,i(e);continue}const a=o(e);if(a>0&&(d=a),r(d))return e.tokenValue="",Y(e,t,0,0);if(160===(p=d)||65279===p||133===p||5760===p||p>=8192&&p<=8203||8239===p||8287===p||12288===p||8201===p||65519===p){n(e);continue}e.report(20,String.fromCodePoint(d))}}var p;return 1048576}const te={AElig:"Æ",AMP:"&",Aacute:"Á",Abreve:"Ă",Acirc:"Â",Acy:"А",Afr:"𝔄",Agrave:"À",Alpha:"Α",Amacr:"Ā",And:"⩓",Aogon:"Ą",Aopf:"𝔸",ApplyFunction:"⁡",Aring:"Å",Ascr:"𝒜",Assign:"≔",Atilde:"Ã",Auml:"Ä",Backslash:"∖",Barv:"⫧",Barwed:"⌆",Bcy:"Б",Because:"∵",Bernoullis:"ℬ",Beta:"Β",Bfr:"𝔅",Bopf:"𝔹",Breve:"˘",Bscr:"ℬ",Bumpeq:"≎",CHcy:"Ч",COPY:"©",Cacute:"Ć",Cap:"⋒",CapitalDifferentialD:"ⅅ",Cayleys:"ℭ",Ccaron:"Č",Ccedil:"Ç",Ccirc:"Ĉ",Cconint:"∰",Cdot:"Ċ",Cedilla:"¸",CenterDot:"·",Cfr:"ℭ",Chi:"Χ",CircleDot:"⊙",CircleMinus:"⊖",CirclePlus:"⊕",CircleTimes:"⊗",ClockwiseContourIntegral:"∲",CloseCurlyDoubleQuote:"”",CloseCurlyQuote:"’",Colon:"∷",Colone:"⩴",Congruent:"≡",Conint:"∯",ContourIntegral:"∮",Copf:"ℂ",Coproduct:"∐",CounterClockwiseContourIntegral:"∳",Cross:"⨯",Cscr:"𝒞",Cup:"⋓",CupCap:"≍",DD:"ⅅ",DDotrahd:"⤑",DJcy:"Ђ",DScy:"Ѕ",DZcy:"Џ",Dagger:"‡",Darr:"↡",Dashv:"⫤",Dcaron:"Ď",Dcy:"Д",Del:"∇",Delta:"Δ",Dfr:"𝔇",DiacriticalAcute:"´",DiacriticalDot:"˙",DiacriticalDoubleAcute:"˝",DiacriticalGrave:"`",DiacriticalTilde:"˜",Diamond:"⋄",DifferentialD:"ⅆ",Dopf:"𝔻",Dot:"¨",DotDot:"⃜",DotEqual:"≐",DoubleContourIntegral:"∯",DoubleDot:"¨",DoubleDownArrow:"⇓",DoubleLeftArrow:"⇐",DoubleLeftRightArrow:"⇔",DoubleLeftTee:"⫤",DoubleLongLeftArrow:"⟸",DoubleLongLeftRightArrow:"⟺",DoubleLongRightArrow:"⟹",DoubleRightArrow:"⇒",DoubleRightTee:"⊨",DoubleUpArrow:"⇑",DoubleUpDownArrow:"⇕",DoubleVerticalBar:"∥",DownArrow:"↓",DownArrowBar:"⤓",DownArrowUpArrow:"⇵",DownBreve:"̑",DownLeftRightVector:"⥐",DownLeftTeeVector:"⥞",DownLeftVector:"↽",DownLeftVectorBar:"⥖",DownRightTeeVector:"⥟",DownRightVector:"⇁",DownRightVectorBar:"⥗",DownTee:"⊤",DownTeeArrow:"↧",Downarrow:"⇓",Dscr:"𝒟",Dstrok:"Đ",ENG:"Ŋ",ETH:"Ð",Eacute:"É",Ecaron:"Ě",Ecirc:"Ê",Ecy:"Э",Edot:"Ė",Efr:"𝔈",Egrave:"È",Element:"∈",Emacr:"Ē",EmptySmallSquare:"◻",EmptyVerySmallSquare:"▫",Eogon:"Ę",Eopf:"𝔼",Epsilon:"Ε",Equal:"⩵",EqualTilde:"≂",Equilibrium:"⇌",Escr:"ℰ",Esim:"⩳",Eta:"Η",Euml:"Ë",Exists:"∃",ExponentialE:"ⅇ",Fcy:"Ф",Ffr:"𝔉",FilledSmallSquare:"◼",FilledVerySmallSquare:"▪",Fopf:"𝔽",ForAll:"∀",Fouriertrf:"ℱ",Fscr:"ℱ",GJcy:"Ѓ",GT:">",Gamma:"Γ",Gammad:"Ϝ",Gbreve:"Ğ",Gcedil:"Ģ",Gcirc:"Ĝ",Gcy:"Г",Gdot:"Ġ",Gfr:"𝔊",Gg:"⋙",Gopf:"𝔾",GreaterEqual:"≥",GreaterEqualLess:"⋛",GreaterFullEqual:"≧",GreaterGreater:"⪢",GreaterLess:"≷",GreaterSlantEqual:"⩾",GreaterTilde:"≳",Gscr:"𝒢",Gt:"≫",HARDcy:"Ъ",Hacek:"ˇ",Hat:"^",Hcirc:"Ĥ",Hfr:"ℌ",HilbertSpace:"ℋ",Hopf:"ℍ",HorizontalLine:"─",Hscr:"ℋ",Hstrok:"Ħ",HumpDownHump:"≎",HumpEqual:"≏",IEcy:"Е",IJlig:"Ĳ",IOcy:"Ё",Iacute:"Í",Icirc:"Î",Icy:"И",Idot:"İ",Ifr:"ℑ",Igrave:"Ì",Im:"ℑ",Imacr:"Ī",ImaginaryI:"ⅈ",Implies:"⇒",Int:"∬",Integral:"∫",Intersection:"⋂",InvisibleComma:"⁣",InvisibleTimes:"⁢",Iogon:"Į",Iopf:"𝕀",Iota:"Ι",Iscr:"ℐ",Itilde:"Ĩ",Iukcy:"І",Iuml:"Ï",Jcirc:"Ĵ",Jcy:"Й",Jfr:"𝔍",Jopf:"𝕁",Jscr:"𝒥",Jsercy:"Ј",Jukcy:"Є",KHcy:"Х",KJcy:"Ќ",Kappa:"Κ",Kcedil:"Ķ",Kcy:"К",Kfr:"𝔎",Kopf:"𝕂",Kscr:"𝒦",LJcy:"Љ",LT:"<",Lacute:"Ĺ",Lambda:"Λ",Lang:"⟪",Laplacetrf:"ℒ",Larr:"↞",Lcaron:"Ľ",Lcedil:"Ļ",Lcy:"Л",LeftAngleBracket:"⟨",LeftArrow:"←",LeftArrowBar:"⇤",LeftArrowRightArrow:"⇆",LeftCeiling:"⌈",LeftDoubleBracket:"⟦",LeftDownTeeVector:"⥡",LeftDownVector:"⇃",LeftDownVectorBar:"⥙",LeftFloor:"⌊",LeftRightArrow:"↔",LeftRightVector:"⥎",LeftTee:"⊣",LeftTeeArrow:"↤",LeftTeeVector:"⥚",LeftTriangle:"⊲",LeftTriangleBar:"⧏",LeftTriangleEqual:"⊴",LeftUpDownVector:"⥑",LeftUpTeeVector:"⥠",LeftUpVector:"↿",LeftUpVectorBar:"⥘",LeftVector:"↼",LeftVectorBar:"⥒",Leftarrow:"⇐",Leftrightarrow:"⇔",LessEqualGreater:"⋚",LessFullEqual:"≦",LessGreater:"≶",LessLess:"⪡",LessSlantEqual:"⩽",LessTilde:"≲",Lfr:"𝔏",Ll:"⋘",Lleftarrow:"⇚",Lmidot:"Ŀ",LongLeftArrow:"⟵",LongLeftRightArrow:"⟷",LongRightArrow:"⟶",Longleftarrow:"⟸",Longleftrightarrow:"⟺",Longrightarrow:"⟹",Lopf:"𝕃",LowerLeftArrow:"↙",LowerRightArrow:"↘",Lscr:"ℒ",Lsh:"↰",Lstrok:"Ł",Lt:"≪",Map:"⤅",Mcy:"М",MediumSpace:" ",Mellintrf:"ℳ",Mfr:"𝔐",MinusPlus:"∓",Mopf:"𝕄",Mscr:"ℳ",Mu:"Μ",NJcy:"Њ",Nacute:"Ń",Ncaron:"Ň",Ncedil:"Ņ",Ncy:"Н",NegativeMediumSpace:"​",NegativeThickSpace:"​",NegativeThinSpace:"​",NegativeVeryThinSpace:"​",NestedGreaterGreater:"≫",NestedLessLess:"≪",NewLine:"\n",Nfr:"𝔑",NoBreak:"⁠",NonBreakingSpace:" ",Nopf:"ℕ",Not:"⫬",NotCongruent:"≢",NotCupCap:"≭",NotDoubleVerticalBar:"∦",NotElement:"∉",NotEqual:"≠",NotEqualTilde:"≂̸",NotExists:"∄",NotGreater:"≯",NotGreaterEqual:"≱",NotGreaterFullEqual:"≧̸",NotGreaterGreater:"≫̸",NotGreaterLess:"≹",NotGreaterSlantEqual:"⩾̸",NotGreaterTilde:"≵",NotHumpDownHump:"≎̸",NotHumpEqual:"≏̸",NotLeftTriangle:"⋪",NotLeftTriangleBar:"⧏̸",NotLeftTriangleEqual:"⋬",NotLess:"≮",NotLessEqual:"≰",NotLessGreater:"≸",NotLessLess:"≪̸",NotLessSlantEqual:"⩽̸",NotLessTilde:"≴",NotNestedGreaterGreater:"⪢̸",NotNestedLessLess:"⪡̸",NotPrecedes:"⊀",NotPrecedesEqual:"⪯̸",NotPrecedesSlantEqual:"⋠",NotReverseElement:"∌",NotRightTriangle:"⋫",NotRightTriangleBar:"⧐̸",NotRightTriangleEqual:"⋭",NotSquareSubset:"⊏̸",NotSquareSubsetEqual:"⋢",NotSquareSuperset:"⊐̸",NotSquareSupersetEqual:"⋣",NotSubset:"⊂⃒",NotSubsetEqual:"⊈",NotSucceeds:"⊁",NotSucceedsEqual:"⪰̸",NotSucceedsSlantEqual:"⋡",NotSucceedsTilde:"≿̸",NotSuperset:"⊃⃒",NotSupersetEqual:"⊉",NotTilde:"≁",NotTildeEqual:"≄",NotTildeFullEqual:"≇",NotTildeTilde:"≉",NotVerticalBar:"∤",Nscr:"𝒩",Ntilde:"Ñ",Nu:"Ν",OElig:"Œ",Oacute:"Ó",Ocirc:"Ô",Ocy:"О",Odblac:"Ő",Ofr:"𝔒",Ograve:"Ò",Omacr:"Ō",Omega:"Ω",Omicron:"Ο",Oopf:"𝕆",OpenCurlyDoubleQuote:"“",OpenCurlyQuote:"‘",Or:"⩔",Oscr:"𝒪",Oslash:"Ø",Otilde:"Õ",Otimes:"⨷",Ouml:"Ö",OverBar:"‾",OverBrace:"⏞",OverBracket:"⎴",OverParenthesis:"⏜",PartialD:"∂",Pcy:"П",Pfr:"𝔓",Phi:"Φ",Pi:"Π",PlusMinus:"±",Poincareplane:"ℌ",Popf:"ℙ",Pr:"⪻",Precedes:"≺",PrecedesEqual:"⪯",PrecedesSlantEqual:"≼",PrecedesTilde:"≾",Prime:"″",Product:"∏",Proportion:"∷",Proportional:"∝",Pscr:"𝒫",Psi:"Ψ",QUOT:'"',Qfr:"𝔔",Qopf:"ℚ",Qscr:"𝒬",RBarr:"⤐",REG:"®",Racute:"Ŕ",Rang:"⟫",Rarr:"↠",Rarrtl:"⤖",Rcaron:"Ř",Rcedil:"Ŗ",Rcy:"Р",Re:"ℜ",ReverseElement:"∋",ReverseEquilibrium:"⇋",ReverseUpEquilibrium:"⥯",Rfr:"ℜ",Rho:"Ρ",RightAngleBracket:"⟩",RightArrow:"→",RightArrowBar:"⇥",RightArrowLeftArrow:"⇄",RightCeiling:"⌉",RightDoubleBracket:"⟧",RightDownTeeVector:"⥝",RightDownVector:"⇂",RightDownVectorBar:"⥕",RightFloor:"⌋",RightTee:"⊢",RightTeeArrow:"↦",RightTeeVector:"⥛",RightTriangle:"⊳",RightTriangleBar:"⧐",RightTriangleEqual:"⊵",RightUpDownVector:"⥏",RightUpTeeVector:"⥜",RightUpVector:"↾",RightUpVectorBar:"⥔",RightVector:"⇀",RightVectorBar:"⥓",Rightarrow:"⇒",Ropf:"ℝ",RoundImplies:"⥰",Rrightarrow:"⇛",Rscr:"ℛ",Rsh:"↱",RuleDelayed:"⧴",SHCHcy:"Щ",SHcy:"Ш",SOFTcy:"Ь",Sacute:"Ś",Sc:"⪼",Scaron:"Š",Scedil:"Ş",Scirc:"Ŝ",Scy:"С",Sfr:"𝔖",ShortDownArrow:"↓",ShortLeftArrow:"←",ShortRightArrow:"→",ShortUpArrow:"↑",Sigma:"Σ",SmallCircle:"∘",Sopf:"𝕊",Sqrt:"√",Square:"□",SquareIntersection:"⊓",SquareSubset:"⊏",SquareSubsetEqual:"⊑",SquareSuperset:"⊐",SquareSupersetEqual:"⊒",SquareUnion:"⊔",Sscr:"𝒮",Star:"⋆",Sub:"⋐",Subset:"⋐",SubsetEqual:"⊆",Succeeds:"≻",SucceedsEqual:"⪰",SucceedsSlantEqual:"≽",SucceedsTilde:"≿",SuchThat:"∋",Sum:"∑",Sup:"⋑",Superset:"⊃",SupersetEqual:"⊇",Supset:"⋑",THORN:"Þ",TRADE:"™",TSHcy:"Ћ",TScy:"Ц",Tab:"\t",Tau:"Τ",Tcaron:"Ť",Tcedil:"Ţ",Tcy:"Т",Tfr:"𝔗",Therefore:"∴",Theta:"Θ",ThickSpace:"  ",ThinSpace:" ",Tilde:"∼",TildeEqual:"≃",TildeFullEqual:"≅",TildeTilde:"≈",Topf:"𝕋",TripleDot:"⃛",Tscr:"𝒯",Tstrok:"Ŧ",Uacute:"Ú",Uarr:"↟",Uarrocir:"⥉",Ubrcy:"Ў",Ubreve:"Ŭ",Ucirc:"Û",Ucy:"У",Udblac:"Ű",Ufr:"𝔘",Ugrave:"Ù",Umacr:"Ū",UnderBar:"_",UnderBrace:"⏟",UnderBracket:"⎵",UnderParenthesis:"⏝",Union:"⋃",UnionPlus:"⊎",Uogon:"Ų",Uopf:"𝕌",UpArrow:"↑",UpArrowBar:"⤒",UpArrowDownArrow:"⇅",UpDownArrow:"↕",UpEquilibrium:"⥮",UpTee:"⊥",UpTeeArrow:"↥",Uparrow:"⇑",Updownarrow:"⇕",UpperLeftArrow:"↖",UpperRightArrow:"↗",Upsi:"ϒ",Upsilon:"Υ",Uring:"Ů",Uscr:"𝒰",Utilde:"Ũ",Uuml:"Ü",VDash:"⊫",Vbar:"⫫",Vcy:"В",Vdash:"⊩",Vdashl:"⫦",Vee:"⋁",Verbar:"‖",Vert:"‖",VerticalBar:"∣",VerticalLine:"|",VerticalSeparator:"❘",VerticalTilde:"≀",VeryThinSpace:" ",Vfr:"𝔙",Vopf:"𝕍",Vscr:"𝒱",Vvdash:"⊪",Wcirc:"Ŵ",Wedge:"⋀",Wfr:"𝔚",Wopf:"𝕎",Wscr:"𝒲",Xfr:"𝔛",Xi:"Ξ",Xopf:"𝕏",Xscr:"𝒳",YAcy:"Я",YIcy:"Ї",YUcy:"Ю",Yacute:"Ý",Ycirc:"Ŷ",Ycy:"Ы",Yfr:"𝔜",Yopf:"𝕐",Yscr:"𝒴",Yuml:"Ÿ",ZHcy:"Ж",Zacute:"Ź",Zcaron:"Ž",Zcy:"З",Zdot:"Ż",ZeroWidthSpace:"​",Zeta:"Ζ",Zfr:"ℨ",Zopf:"ℤ",Zscr:"𝒵",aacute:"á",abreve:"ă",ac:"∾",acE:"∾̳",acd:"∿",acirc:"â",acute:"´",acy:"а",aelig:"æ",af:"⁡",afr:"𝔞",agrave:"à",alefsym:"ℵ",aleph:"ℵ",alpha:"α",amacr:"ā",amalg:"⨿",amp:"&",and:"∧",andand:"⩕",andd:"⩜",andslope:"⩘",andv:"⩚",ang:"∠",ange:"⦤",angle:"∠",angmsd:"∡",angmsdaa:"⦨",angmsdab:"⦩",angmsdac:"⦪",angmsdad:"⦫",angmsdae:"⦬",angmsdaf:"⦭",angmsdag:"⦮",angmsdah:"⦯",angrt:"∟",angrtvb:"⊾",angrtvbd:"⦝",angsph:"∢",angst:"Å",angzarr:"⍼",aogon:"ą",aopf:"𝕒",ap:"≈",apE:"⩰",apacir:"⩯",ape:"≊",apid:"≋",apos:"'",approx:"≈",approxeq:"≊",aring:"å",ascr:"𝒶",ast:"*",asymp:"≈",asympeq:"≍",atilde:"ã",auml:"ä",awconint:"∳",awint:"⨑",bNot:"⫭",backcong:"≌",backepsilon:"϶",backprime:"‵",backsim:"∽",backsimeq:"⋍",barvee:"⊽",barwed:"⌅",barwedge:"⌅",bbrk:"⎵",bbrktbrk:"⎶",bcong:"≌",bcy:"б",bdquo:"„",becaus:"∵",because:"∵",bemptyv:"⦰",bepsi:"϶",bernou:"ℬ",beta:"β",beth:"ℶ",between:"≬",bfr:"𝔟",bigcap:"⋂",bigcirc:"◯",bigcup:"⋃",bigodot:"⨀",bigoplus:"⨁",bigotimes:"⨂",bigsqcup:"⨆",bigstar:"★",bigtriangledown:"▽",bigtriangleup:"△",biguplus:"⨄",bigvee:"⋁",bigwedge:"⋀",bkarow:"⤍",blacklozenge:"⧫",blacksquare:"▪",blacktriangle:"▴",blacktriangledown:"▾",blacktriangleleft:"◂",blacktriangleright:"▸",blank:"␣",blk12:"▒",blk14:"░",blk34:"▓",block:"█",bne:"=⃥",bnequiv:"≡⃥",bnot:"⌐",bopf:"𝕓",bot:"⊥",bottom:"⊥",bowtie:"⋈",boxDL:"╗",boxDR:"╔",boxDl:"╖",boxDr:"╓",boxH:"═",boxHD:"╦",boxHU:"╩",boxHd:"╤",boxHu:"╧",boxUL:"╝",boxUR:"╚",boxUl:"╜",boxUr:"╙",boxV:"║",boxVH:"╬",boxVL:"╣",boxVR:"╠",boxVh:"╫",boxVl:"╢",boxVr:"╟",boxbox:"⧉",boxdL:"╕",boxdR:"╒",boxdl:"┐",boxdr:"┌",boxh:"─",boxhD:"╥",boxhU:"╨",boxhd:"┬",boxhu:"┴",boxminus:"⊟",boxplus:"⊞",boxtimes:"⊠",boxuL:"╛",boxuR:"╘",boxul:"┘",boxur:"└",boxv:"│",boxvH:"╪",boxvL:"╡",boxvR:"╞",boxvh:"┼",boxvl:"┤",boxvr:"├",bprime:"‵",breve:"˘",brvbar:"¦",bscr:"𝒷",bsemi:"⁏",bsim:"∽",bsime:"⋍",bsol:"\\",bsolb:"⧅",bsolhsub:"⟈",bull:"•",bullet:"•",bump:"≎",bumpE:"⪮",bumpe:"≏",bumpeq:"≏",cacute:"ć",cap:"∩",capand:"⩄",capbrcup:"⩉",capcap:"⩋",capcup:"⩇",capdot:"⩀",caps:"∩︀",caret:"⁁",caron:"ˇ",ccaps:"⩍",ccaron:"č",ccedil:"ç",ccirc:"ĉ",ccups:"⩌",ccupssm:"⩐",cdot:"ċ",cedil:"¸",cemptyv:"⦲",cent:"¢",centerdot:"·",cfr:"𝔠",chcy:"ч",check:"✓",checkmark:"✓",chi:"χ",cir:"○",cirE:"⧃",circ:"ˆ",circeq:"≗",circlearrowleft:"↺",circlearrowright:"↻",circledR:"®",circledS:"Ⓢ",circledast:"⊛",circledcirc:"⊚",circleddash:"⊝",cire:"≗",cirfnint:"⨐",cirmid:"⫯",cirscir:"⧂",clubs:"♣",clubsuit:"♣",colon:":",colone:"≔",coloneq:"≔",comma:",",commat:"@",comp:"∁",compfn:"∘",complement:"∁",complexes:"ℂ",cong:"≅",congdot:"⩭",conint:"∮",copf:"𝕔",coprod:"∐",copy:"©",copysr:"℗",crarr:"↵",cross:"✗",cscr:"𝒸",csub:"⫏",csube:"⫑",csup:"⫐",csupe:"⫒",ctdot:"⋯",cudarrl:"⤸",cudarrr:"⤵",cuepr:"⋞",cuesc:"⋟",cularr:"↶",cularrp:"⤽",cup:"∪",cupbrcap:"⩈",cupcap:"⩆",cupcup:"⩊",cupdot:"⊍",cupor:"⩅",cups:"∪︀",curarr:"↷",curarrm:"⤼",curlyeqprec:"⋞",curlyeqsucc:"⋟",curlyvee:"⋎",curlywedge:"⋏",curren:"¤",curvearrowleft:"↶",curvearrowright:"↷",cuvee:"⋎",cuwed:"⋏",cwconint:"∲",cwint:"∱",cylcty:"⌭",dArr:"⇓",dHar:"⥥",dagger:"†",daleth:"ℸ",darr:"↓",dash:"‐",dashv:"⊣",dbkarow:"⤏",dblac:"˝",dcaron:"ď",dcy:"д",dd:"ⅆ",ddagger:"‡",ddarr:"⇊",ddotseq:"⩷",deg:"°",delta:"δ",demptyv:"⦱",dfisht:"⥿",dfr:"𝔡",dharl:"⇃",dharr:"⇂",diam:"⋄",diamond:"⋄",diamondsuit:"♦",diams:"♦",die:"¨",digamma:"ϝ",disin:"⋲",div:"÷",divide:"÷",divideontimes:"⋇",divonx:"⋇",djcy:"ђ",dlcorn:"⌞",dlcrop:"⌍",dollar:"$",dopf:"𝕕",dot:"˙",doteq:"≐",doteqdot:"≑",dotminus:"∸",dotplus:"∔",dotsquare:"⊡",doublebarwedge:"⌆",downarrow:"↓",downdownarrows:"⇊",downharpoonleft:"⇃",downharpoonright:"⇂",drbkarow:"⤐",drcorn:"⌟",drcrop:"⌌",dscr:"𝒹",dscy:"ѕ",dsol:"⧶",dstrok:"đ",dtdot:"⋱",dtri:"▿",dtrif:"▾",duarr:"⇵",duhar:"⥯",dwangle:"⦦",dzcy:"џ",dzigrarr:"⟿",eDDot:"⩷",eDot:"≑",eacute:"é",easter:"⩮",ecaron:"ě",ecir:"≖",ecirc:"ê",ecolon:"≕",ecy:"э",edot:"ė",ee:"ⅇ",efDot:"≒",efr:"𝔢",eg:"⪚",egrave:"è",egs:"⪖",egsdot:"⪘",el:"⪙",elinters:"⏧",ell:"ℓ",els:"⪕",elsdot:"⪗",emacr:"ē",empty:"∅",emptyset:"∅",emptyv:"∅",emsp13:" ",emsp14:" ",emsp:" ",eng:"ŋ",ensp:" ",eogon:"ę",eopf:"𝕖",epar:"⋕",eparsl:"⧣",eplus:"⩱",epsi:"ε",epsilon:"ε",epsiv:"ϵ",eqcirc:"≖",eqcolon:"≕",eqsim:"≂",eqslantgtr:"⪖",eqslantless:"⪕",equals:"=",equest:"≟",equiv:"≡",equivDD:"⩸",eqvparsl:"⧥",erDot:"≓",erarr:"⥱",escr:"ℯ",esdot:"≐",esim:"≂",eta:"η",eth:"ð",euml:"ë",euro:"€",excl:"!",exist:"∃",expectation:"ℰ",exponentiale:"ⅇ",fallingdotseq:"≒",fcy:"ф",female:"♀",ffilig:"ﬃ",fflig:"ﬀ",ffllig:"ﬄ",ffr:"𝔣",filig:"ﬁ",fjlig:"fj",flat:"♭",fllig:"ﬂ",fltns:"▱",fnof:"ƒ",fopf:"𝕗",forall:"∀",fork:"⋔",forkv:"⫙",fpartint:"⨍",frac12:"½",frac13:"⅓",frac14:"¼",frac15:"⅕",frac16:"⅙",frac18:"⅛",frac23:"⅔",frac25:"⅖",frac34:"¾",frac35:"⅗",frac38:"⅜",frac45:"⅘",frac56:"⅚",frac58:"⅝",frac78:"⅞",frasl:"⁄",frown:"⌢",fscr:"𝒻",gE:"≧",gEl:"⪌",gacute:"ǵ",gamma:"γ",gammad:"ϝ",gap:"⪆",gbreve:"ğ",gcirc:"ĝ",gcy:"г",gdot:"ġ",ge:"≥",gel:"⋛",geq:"≥",geqq:"≧",geqslant:"⩾",ges:"⩾",gescc:"⪩",gesdot:"⪀",gesdoto:"⪂",gesdotol:"⪄",gesl:"⋛︀",gesles:"⪔",gfr:"𝔤",gg:"≫",ggg:"⋙",gimel:"ℷ",gjcy:"ѓ",gl:"≷",glE:"⪒",gla:"⪥",glj:"⪤",gnE:"≩",gnap:"⪊",gnapprox:"⪊",gne:"⪈",gneq:"⪈",gneqq:"≩",gnsim:"⋧",gopf:"𝕘",grave:"`",gscr:"ℊ",gsim:"≳",gsime:"⪎",gsiml:"⪐",gt:">",gtcc:"⪧",gtcir:"⩺",gtdot:"⋗",gtlPar:"⦕",gtquest:"⩼",gtrapprox:"⪆",gtrarr:"⥸",gtrdot:"⋗",gtreqless:"⋛",gtreqqless:"⪌",gtrless:"≷",gtrsim:"≳",gvertneqq:"≩︀",gvnE:"≩︀",hArr:"⇔",hairsp:" ",half:"½",hamilt:"ℋ",hardcy:"ъ",harr:"↔",harrcir:"⥈",harrw:"↭",hbar:"ℏ",hcirc:"ĥ",hearts:"♥",heartsuit:"♥",hellip:"…",hercon:"⊹",hfr:"𝔥",hksearow:"⤥",hkswarow:"⤦",hoarr:"⇿",homtht:"∻",hookleftarrow:"↩",hookrightarrow:"↪",hopf:"𝕙",horbar:"―",hscr:"𝒽",hslash:"ℏ",hstrok:"ħ",hybull:"⁃",hyphen:"‐",iacute:"í",ic:"⁣",icirc:"î",icy:"и",iecy:"е",iexcl:"¡",iff:"⇔",ifr:"𝔦",igrave:"ì",ii:"ⅈ",iiiint:"⨌",iiint:"∭",iinfin:"⧜",iiota:"℩",ijlig:"ĳ",imacr:"ī",image:"ℑ",imagline:"ℐ",imagpart:"ℑ",imath:"ı",imof:"⊷",imped:"Ƶ",in:"∈",incare:"℅",infin:"∞",infintie:"⧝",inodot:"ı",int:"∫",intcal:"⊺",integers:"ℤ",intercal:"⊺",intlarhk:"⨗",intprod:"⨼",iocy:"ё",iogon:"į",iopf:"𝕚",iota:"ι",iprod:"⨼",iquest:"¿",iscr:"𝒾",isin:"∈",isinE:"⋹",isindot:"⋵",isins:"⋴",isinsv:"⋳",isinv:"∈",it:"⁢",itilde:"ĩ",iukcy:"і",iuml:"ï",jcirc:"ĵ",jcy:"й",jfr:"𝔧",jmath:"ȷ",jopf:"𝕛",jscr:"𝒿",jsercy:"ј",jukcy:"є",kappa:"κ",kappav:"ϰ",kcedil:"ķ",kcy:"к",kfr:"𝔨",kgreen:"ĸ",khcy:"х",kjcy:"ќ",kopf:"𝕜",kscr:"𝓀",lAarr:"⇚",lArr:"⇐",lAtail:"⤛",lBarr:"⤎",lE:"≦",lEg:"⪋",lHar:"⥢",lacute:"ĺ",laemptyv:"⦴",lagran:"ℒ",lambda:"λ",lang:"⟨",langd:"⦑",langle:"⟨",lap:"⪅",laquo:"«",larr:"←",larrb:"⇤",larrbfs:"⤟",larrfs:"⤝",larrhk:"↩",larrlp:"↫",larrpl:"⤹",larrsim:"⥳",larrtl:"↢",lat:"⪫",latail:"⤙",late:"⪭",lates:"⪭︀",lbarr:"⤌",lbbrk:"❲",lbrace:"{",lbrack:"[",lbrke:"⦋",lbrksld:"⦏",lbrkslu:"⦍",lcaron:"ľ",lcedil:"ļ",lceil:"⌈",lcub:"{",lcy:"л",ldca:"⤶",ldquo:"“",ldquor:"„",ldrdhar:"⥧",ldrushar:"⥋",ldsh:"↲",le:"≤",leftarrow:"←",leftarrowtail:"↢",leftharpoondown:"↽",leftharpoonup:"↼",leftleftarrows:"⇇",leftrightarrow:"↔",leftrightarrows:"⇆",leftrightharpoons:"⇋",leftrightsquigarrow:"↭",leftthreetimes:"⋋",leg:"⋚",leq:"≤",leqq:"≦",leqslant:"⩽",les:"⩽",lescc:"⪨",lesdot:"⩿",lesdoto:"⪁",lesdotor:"⪃",lesg:"⋚︀",lesges:"⪓",lessapprox:"⪅",lessdot:"⋖",lesseqgtr:"⋚",lesseqqgtr:"⪋",lessgtr:"≶",lesssim:"≲",lfisht:"⥼",lfloor:"⌊",lfr:"𝔩",lg:"≶",lgE:"⪑",lhard:"↽",lharu:"↼",lharul:"⥪",lhblk:"▄",ljcy:"љ",ll:"≪",llarr:"⇇",llcorner:"⌞",llhard:"⥫",lltri:"◺",lmidot:"ŀ",lmoust:"⎰",lmoustache:"⎰",lnE:"≨",lnap:"⪉",lnapprox:"⪉",lne:"⪇",lneq:"⪇",lneqq:"≨",lnsim:"⋦",loang:"⟬",loarr:"⇽",lobrk:"⟦",longleftarrow:"⟵",longleftrightarrow:"⟷",longmapsto:"⟼",longrightarrow:"⟶",looparrowleft:"↫",looparrowright:"↬",lopar:"⦅",lopf:"𝕝",loplus:"⨭",lotimes:"⨴",lowast:"∗",lowbar:"_",loz:"◊",lozenge:"◊",lozf:"⧫",lpar:"(",lparlt:"⦓",lrarr:"⇆",lrcorner:"⌟",lrhar:"⇋",lrhard:"⥭",lrm:"‎",lrtri:"⊿",lsaquo:"‹",lscr:"𝓁",lsh:"↰",lsim:"≲",lsime:"⪍",lsimg:"⪏",lsqb:"[",lsquo:"‘",lsquor:"‚",lstrok:"ł",lt:"<",ltcc:"⪦",ltcir:"⩹",ltdot:"⋖",lthree:"⋋",ltimes:"⋉",ltlarr:"⥶",ltquest:"⩻",ltrPar:"⦖",ltri:"◃",ltrie:"⊴",ltrif:"◂",lurdshar:"⥊",luruhar:"⥦",lvertneqq:"≨︀",lvnE:"≨︀",mDDot:"∺",macr:"¯",male:"♂",malt:"✠",maltese:"✠",map:"↦",mapsto:"↦",mapstodown:"↧",mapstoleft:"↤",mapstoup:"↥",marker:"▮",mcomma:"⨩",mcy:"м",mdash:"—",measuredangle:"∡",mfr:"𝔪",mho:"℧",micro:"µ",mid:"∣",midast:"*",midcir:"⫰",middot:"·",minus:"−",minusb:"⊟",minusd:"∸",minusdu:"⨪",mlcp:"⫛",mldr:"…",mnplus:"∓",models:"⊧",mopf:"𝕞",mp:"∓",mscr:"𝓂",mstpos:"∾",mu:"μ",multimap:"⊸",mumap:"⊸",nGg:"⋙̸",nGt:"≫⃒",nGtv:"≫̸",nLeftarrow:"⇍",nLeftrightarrow:"⇎",nLl:"⋘̸",nLt:"≪⃒",nLtv:"≪̸",nRightarrow:"⇏",nVDash:"⊯",nVdash:"⊮",nabla:"∇",nacute:"ń",nang:"∠⃒",nap:"≉",napE:"⩰̸",napid:"≋̸",napos:"ŉ",napprox:"≉",natur:"♮",natural:"♮",naturals:"ℕ",nbsp:" ",nbump:"≎̸",nbumpe:"≏̸",ncap:"⩃",ncaron:"ň",ncedil:"ņ",ncong:"≇",ncongdot:"⩭̸",ncup:"⩂",ncy:"н",ndash:"–",ne:"≠",neArr:"⇗",nearhk:"⤤",nearr:"↗",nearrow:"↗",nedot:"≐̸",nequiv:"≢",nesear:"⤨",nesim:"≂̸",nexist:"∄",nexists:"∄",nfr:"𝔫",ngE:"≧̸",nge:"≱",ngeq:"≱",ngeqq:"≧̸",ngeqslant:"⩾̸",nges:"⩾̸",ngsim:"≵",ngt:"≯",ngtr:"≯",nhArr:"⇎",nharr:"↮",nhpar:"⫲",ni:"∋",nis:"⋼",nisd:"⋺",niv:"∋",njcy:"њ",nlArr:"⇍",nlE:"≦̸",nlarr:"↚",nldr:"‥",nle:"≰",nleftarrow:"↚",nleftrightarrow:"↮",nleq:"≰",nleqq:"≦̸",nleqslant:"⩽̸",nles:"⩽̸",nless:"≮",nlsim:"≴",nlt:"≮",nltri:"⋪",nltrie:"⋬",nmid:"∤",nopf:"𝕟",not:"¬",notin:"∉",notinE:"⋹̸",notindot:"⋵̸",notinva:"∉",notinvb:"⋷",notinvc:"⋶",notni:"∌",notniva:"∌",notnivb:"⋾",notnivc:"⋽",npar:"∦",nparallel:"∦",nparsl:"⫽⃥",npart:"∂̸",npolint:"⨔",npr:"⊀",nprcue:"⋠",npre:"⪯̸",nprec:"⊀",npreceq:"⪯̸",nrArr:"⇏",nrarr:"↛",nrarrc:"⤳̸",nrarrw:"↝̸",nrightarrow:"↛",nrtri:"⋫",nrtrie:"⋭",nsc:"⊁",nsccue:"⋡",nsce:"⪰̸",nscr:"𝓃",nshortmid:"∤",nshortparallel:"∦",nsim:"≁",nsime:"≄",nsimeq:"≄",nsmid:"∤",nspar:"∦",nsqsube:"⋢",nsqsupe:"⋣",nsub:"⊄",nsubE:"⫅̸",nsube:"⊈",nsubset:"⊂⃒",nsubseteq:"⊈",nsubseteqq:"⫅̸",nsucc:"⊁",nsucceq:"⪰̸",nsup:"⊅",nsupE:"⫆̸",nsupe:"⊉",nsupset:"⊃⃒",nsupseteq:"⊉",nsupseteqq:"⫆̸",ntgl:"≹",ntilde:"ñ",ntlg:"≸",ntriangleleft:"⋪",ntrianglelefteq:"⋬",ntriangleright:"⋫",ntrianglerighteq:"⋭",nu:"ν",num:"#",numero:"№",numsp:" ",nvDash:"⊭",nvHarr:"⤄",nvap:"≍⃒",nvdash:"⊬",nvge:"≥⃒",nvgt:">⃒",nvinfin:"⧞",nvlArr:"⤂",nvle:"≤⃒",nvlt:"<⃒",nvltrie:"⊴⃒",nvrArr:"⤃",nvrtrie:"⊵⃒",nvsim:"∼⃒",nwArr:"⇖",nwarhk:"⤣",nwarr:"↖",nwarrow:"↖",nwnear:"⤧",oS:"Ⓢ",oacute:"ó",oast:"⊛",ocir:"⊚",ocirc:"ô",ocy:"о",odash:"⊝",odblac:"ő",odiv:"⨸",odot:"⊙",odsold:"⦼",oelig:"œ",ofcir:"⦿",ofr:"𝔬",ogon:"˛",ograve:"ò",ogt:"⧁",ohbar:"⦵",ohm:"Ω",oint:"∮",olarr:"↺",olcir:"⦾",olcross:"⦻",oline:"‾",olt:"⧀",omacr:"ō",omega:"ω",omicron:"ο",omid:"⦶",ominus:"⊖",oopf:"𝕠",opar:"⦷",operp:"⦹",oplus:"⊕",or:"∨",orarr:"↻",ord:"⩝",order:"ℴ",orderof:"ℴ",ordf:"ª",ordm:"º",origof:"⊶",oror:"⩖",orslope:"⩗",orv:"⩛",oscr:"ℴ",oslash:"ø",osol:"⊘",otilde:"õ",otimes:"⊗",otimesas:"⨶",ouml:"ö",ovbar:"⌽",par:"∥",para:"¶",parallel:"∥",parsim:"⫳",parsl:"⫽",part:"∂",pcy:"п",percnt:"%",period:".",permil:"‰",perp:"⊥",pertenk:"‱",pfr:"𝔭",phi:"φ",phiv:"ϕ",phmmat:"ℳ",phone:"☎",pi:"π",pitchfork:"⋔",piv:"ϖ",planck:"ℏ",planckh:"ℎ",plankv:"ℏ",plus:"+",plusacir:"⨣",plusb:"⊞",pluscir:"⨢",plusdo:"∔",plusdu:"⨥",pluse:"⩲",plusmn:"±",plussim:"⨦",plustwo:"⨧",pm:"±",pointint:"⨕",popf:"𝕡",pound:"£",pr:"≺",prE:"⪳",prap:"⪷",prcue:"≼",pre:"⪯",prec:"≺",precapprox:"⪷",preccurlyeq:"≼",preceq:"⪯",precnapprox:"⪹",precneqq:"⪵",precnsim:"⋨",precsim:"≾",prime:"′",primes:"ℙ",prnE:"⪵",prnap:"⪹",prnsim:"⋨",prod:"∏",profalar:"⌮",profline:"⌒",profsurf:"⌓",prop:"∝",propto:"∝",prsim:"≾",prurel:"⊰",pscr:"𝓅",psi:"ψ",puncsp:" ",qfr:"𝔮",qint:"⨌",qopf:"𝕢",qprime:"⁗",qscr:"𝓆",quaternions:"ℍ",quatint:"⨖",quest:"?",questeq:"≟",quot:'"',rAarr:"⇛",rArr:"⇒",rAtail:"⤜",rBarr:"⤏",rHar:"⥤",race:"∽̱",racute:"ŕ",radic:"√",raemptyv:"⦳",rang:"⟩",rangd:"⦒",range:"⦥",rangle:"⟩",raquo:"»",rarr:"→",rarrap:"⥵",rarrb:"⇥",rarrbfs:"⤠",rarrc:"⤳",rarrfs:"⤞",rarrhk:"↪",rarrlp:"↬",rarrpl:"⥅",rarrsim:"⥴",rarrtl:"↣",rarrw:"↝",ratail:"⤚",ratio:"∶",rationals:"ℚ",rbarr:"⤍",rbbrk:"❳",rbrace:"}",rbrack:"]",rbrke:"⦌",rbrksld:"⦎",rbrkslu:"⦐",rcaron:"ř",rcedil:"ŗ",rceil:"⌉",rcub:"}",rcy:"р",rdca:"⤷",rdldhar:"⥩",rdquo:"”",rdquor:"”",rdsh:"↳",real:"ℜ",realine:"ℛ",realpart:"ℜ",reals:"ℝ",rect:"▭",reg:"®",rfisht:"⥽",rfloor:"⌋",rfr:"𝔯",rhard:"⇁",rharu:"⇀",rharul:"⥬",rho:"ρ",rhov:"ϱ",rightarrow:"→",rightarrowtail:"↣",rightharpoondown:"⇁",rightharpoonup:"⇀",rightleftarrows:"⇄",rightleftharpoons:"⇌",rightrightarrows:"⇉",rightsquigarrow:"↝",rightthreetimes:"⋌",ring:"˚",risingdotseq:"≓",rlarr:"⇄",rlhar:"⇌",rlm:"‏",rmoust:"⎱",rmoustache:"⎱",rnmid:"⫮",roang:"⟭",roarr:"⇾",robrk:"⟧",ropar:"⦆",ropf:"𝕣",roplus:"⨮",rotimes:"⨵",rpar:")",rpargt:"⦔",rppolint:"⨒",rrarr:"⇉",rsaquo:"›",rscr:"𝓇",rsh:"↱",rsqb:"]",rsquo:"’",rsquor:"’",rthree:"⋌",rtimes:"⋊",rtri:"▹",rtrie:"⊵",rtrif:"▸",rtriltri:"⧎",ruluhar:"⥨",rx:"℞",sacute:"ś",sbquo:"‚",sc:"≻",scE:"⪴",scap:"⪸",scaron:"š",sccue:"≽",sce:"⪰",scedil:"ş",scirc:"ŝ",scnE:"⪶",scnap:"⪺",scnsim:"⋩",scpolint:"⨓",scsim:"≿",scy:"с",sdot:"⋅",sdotb:"⊡",sdote:"⩦",seArr:"⇘",searhk:"⤥",searr:"↘",searrow:"↘",sect:"§",semi:";",seswar:"⤩",setminus:"∖",setmn:"∖",sext:"✶",sfr:"𝔰",sfrown:"⌢",sharp:"♯",shchcy:"щ",shcy:"ш",shortmid:"∣",shortparallel:"∥",shy:"­",sigma:"σ",sigmaf:"ς",sigmav:"ς",sim:"∼",simdot:"⩪",sime:"≃",simeq:"≃",simg:"⪞",simgE:"⪠",siml:"⪝",simlE:"⪟",simne:"≆",simplus:"⨤",simrarr:"⥲",slarr:"←",smallsetminus:"∖",smashp:"⨳",smeparsl:"⧤",smid:"∣",smile:"⌣",smt:"⪪",smte:"⪬",smtes:"⪬︀",softcy:"ь",sol:"/",solb:"⧄",solbar:"⌿",sopf:"𝕤",spades:"♠",spadesuit:"♠",spar:"∥",sqcap:"⊓",sqcaps:"⊓︀",sqcup:"⊔",sqcups:"⊔︀",sqsub:"⊏",sqsube:"⊑",sqsubset:"⊏",sqsubseteq:"⊑",sqsup:"⊐",sqsupe:"⊒",sqsupset:"⊐",sqsupseteq:"⊒",squ:"□",square:"□",squarf:"▪",squf:"▪",srarr:"→",sscr:"𝓈",ssetmn:"∖",ssmile:"⌣",sstarf:"⋆",star:"☆",starf:"★",straightepsilon:"ϵ",straightphi:"ϕ",strns:"¯",sub:"⊂",subE:"⫅",subdot:"⪽",sube:"⊆",subedot:"⫃",submult:"⫁",subnE:"⫋",subne:"⊊",subplus:"⪿",subrarr:"⥹",subset:"⊂",subseteq:"⊆",subseteqq:"⫅",subsetneq:"⊊",subsetneqq:"⫋",subsim:"⫇",subsub:"⫕",subsup:"⫓",succ:"≻",succapprox:"⪸",succcurlyeq:"≽",succeq:"⪰",succnapprox:"⪺",succneqq:"⪶",succnsim:"⋩",succsim:"≿",sum:"∑",sung:"♪",sup1:"¹",sup2:"²",sup3:"³",sup:"⊃",supE:"⫆",supdot:"⪾",supdsub:"⫘",supe:"⊇",supedot:"⫄",suphsol:"⟉",suphsub:"⫗",suplarr:"⥻",supmult:"⫂",supnE:"⫌",supne:"⊋",supplus:"⫀",supset:"⊃",supseteq:"⊇",supseteqq:"⫆",supsetneq:"⊋",supsetneqq:"⫌",supsim:"⫈",supsub:"⫔",supsup:"⫖",swArr:"⇙",swarhk:"⤦",swarr:"↙",swarrow:"↙",swnwar:"⤪",szlig:"ß",target:"⌖",tau:"τ",tbrk:"⎴",tcaron:"ť",tcedil:"ţ",tcy:"т",tdot:"⃛",telrec:"⌕",tfr:"𝔱",there4:"∴",therefore:"∴",theta:"θ",thetasym:"ϑ",thetav:"ϑ",thickapprox:"≈",thicksim:"∼",thinsp:" ",thkap:"≈",thksim:"∼",thorn:"þ",tilde:"˜",times:"×",timesb:"⊠",timesbar:"⨱",timesd:"⨰",tint:"∭",toea:"⤨",top:"⊤",topbot:"⌶",topcir:"⫱",topf:"𝕥",topfork:"⫚",tosa:"⤩",tprime:"‴",trade:"™",triangle:"▵",triangledown:"▿",triangleleft:"◃",trianglelefteq:"⊴",triangleq:"≜",triangleright:"▹",trianglerighteq:"⊵",tridot:"◬",trie:"≜",triminus:"⨺",triplus:"⨹",trisb:"⧍",tritime:"⨻",trpezium:"⏢",tscr:"𝓉",tscy:"ц",tshcy:"ћ",tstrok:"ŧ",twixt:"≬",twoheadleftarrow:"↞",twoheadrightarrow:"↠",uArr:"⇑",uHar:"⥣",uacute:"ú",uarr:"↑",ubrcy:"ў",ubreve:"ŭ",ucirc:"û",ucy:"у",udarr:"⇅",udblac:"ű",udhar:"⥮",ufisht:"⥾",ufr:"𝔲",ugrave:"ù",uharl:"↿",uharr:"↾",uhblk:"▀",ulcorn:"⌜",ulcorner:"⌜",ulcrop:"⌏",ultri:"◸",umacr:"ū",uml:"¨",uogon:"ų",uopf:"𝕦",uparrow:"↑",updownarrow:"↕",upharpoonleft:"↿",upharpoonright:"↾",uplus:"⊎",upsi:"υ",upsih:"ϒ",upsilon:"υ",upuparrows:"⇈",urcorn:"⌝",urcorner:"⌝",urcrop:"⌎",uring:"ů",urtri:"◹",uscr:"𝓊",utdot:"⋰",utilde:"ũ",utri:"▵",utrif:"▴",uuarr:"⇈",uuml:"ü",uwangle:"⦧",vArr:"⇕",vBar:"⫨",vBarv:"⫩",vDash:"⊨",vangrt:"⦜",varepsilon:"ϵ",varkappa:"ϰ",varnothing:"∅",varphi:"ϕ",varpi:"ϖ",varpropto:"∝",varr:"↕",varrho:"ϱ",varsigma:"ς",varsubsetneq:"⊊︀",varsubsetneqq:"⫋︀",varsupsetneq:"⊋︀",varsupsetneqq:"⫌︀",vartheta:"ϑ",vartriangleleft:"⊲",vartriangleright:"⊳",vcy:"в",vdash:"⊢",vee:"∨",veebar:"⊻",veeeq:"≚",vellip:"⋮",verbar:"|",vert:"|",vfr:"𝔳",vltri:"⊲",vnsub:"⊂⃒",vnsup:"⊃⃒",vopf:"𝕧",vprop:"∝",vrtri:"⊳",vscr:"𝓋",vsubnE:"⫋︀",vsubne:"⊊︀",vsupnE:"⫌︀",vsupne:"⊋︀",vzigzag:"⦚",wcirc:"ŵ",wedbar:"⩟",wedge:"∧",wedgeq:"≙",weierp:"℘",wfr:"𝔴",wopf:"𝕨",wp:"℘",wr:"≀",wreath:"≀",wscr:"𝓌",xcap:"⋂",xcirc:"◯",xcup:"⋃",xdtri:"▽",xfr:"𝔵",xhArr:"⟺",xharr:"⟷",xi:"ξ",xlArr:"⟸",xlarr:"⟵",xmap:"⟼",xnis:"⋻",xodot:"⨀",xopf:"𝕩",xoplus:"⨁",xotime:"⨂",xrArr:"⟹",xrarr:"⟶",xscr:"𝓍",xsqcup:"⨆",xuplus:"⨄",xutri:"△",xvee:"⋁",xwedge:"⋀",yacute:"ý",yacy:"я",ycirc:"ŷ",ycy:"ы",yen:"¥",yfr:"𝔶",yicy:"ї",yopf:"𝕪",yscr:"𝓎",yucy:"ю",yuml:"ÿ",zacute:"ź",zcaron:"ž",zcy:"з",zdot:"ż",zeetrf:"ℨ",zeta:"ζ",zfr:"𝔷",zhcy:"ж",zigrarr:"⇝",zopf:"𝕫",zscr:"𝓏",zwj:"‍",zwnj:"‌"},re={0:65533,128:8364,130:8218,131:402,132:8222,133:8230,134:8224,135:8225,136:710,137:8240,138:352,139:8249,140:338,142:381,145:8216,146:8217,147:8220,148:8221,149:8226,150:8211,151:8212,152:732,153:8482,154:353,155:8250,156:339,158:382,159:376};function ne(e){return e.replace(/&(?:[a-zA-Z]+|#[xX][\da-fA-F]+|#\d+);/g,(e=>{if("#"===e.charAt(1)){const t=e.charAt(2);return function(e){if(e>=55296&&e<=57343||e>1114111)return"�";return String.fromCodePoint(X(re,e)??e)}("X"===t||"x"===t?parseInt(e.slice(3),16):parseInt(e.slice(2),10))}return X(te,e.slice(1,-1))??e}))}function oe(e,t){return e.startIndex=e.tokenIndex=e.index,e.startColumn=e.tokenColumn=e.column,e.startLine=e.tokenLine=e.line,e.setToken(8192&l[e.currentChar]?function(e){const t=e.currentChar;let r=n(e);const o=e.index;for(;r!==t;)e.index>=e.end&&e.report(16),r=n(e);r!==t&&e.report(16);e.tokenValue=e.source.slice(o,e.index),n(e),e.options.raw&&(e.tokenRaw=e.source.slice(e.tokenIndex,e.index));return 134283267}(e):ee(e,t,0)),e.getToken()}function ae(e){if(e.startIndex=e.tokenIndex=e.index,e.startColumn=e.tokenColumn=e.column,e.startLine=e.tokenLine=e.line,e.index>=e.end)return void e.setToken(1048576);if(60===e.currentChar)return n(e),void e.setToken(8456256);if(123===e.currentChar)return n(e),void e.setToken(2162700);let t=0;for(;e.index<e.end;){const r=l[e.source.charCodeAt(e.index)];if(1024&r?(t|=5,i(e)):2048&r?(a(e,t),t=-5&t|1):n(e),16384&l[e.currentChar])break}e.tokenIndex===e.index&&e.report(0);const r=e.source.slice(e.tokenIndex,e.index);e.options.raw&&(e.tokenRaw=r),e.tokenValue=ne(r),e.setToken(137)}function ie(e){if(!(143360&~e.getToken())){const{index:t}=e;let r=e.currentChar;for(;32770&l[r];)r=n(e);e.tokenValue+=e.source.slice(t,e.index),e.setToken(208897,!0)}return e.getToken()}class se{parser;type;parent;scopeError;variableBindings=new Map;constructor(e,t=2,r){this.parser=e,this.type=t,this.parent=r}createChildScope(e){return new se(this.parser,e,this)}addVarOrBlock(e,t,r,n){4&r?this.addVarName(e,t,r):this.addBlockName(e,t,r,n),64&n&&this.parser.declareUnboundVariable(t)}addVarName(e,t,r){const{parser:n}=this;let o=this;for(;o&&!(128&o.type);){const{variableBindings:a}=o,i=a.get(t);i&&248&i&&(!n.options.webcompat||1&e||!(128&r&&68&i||128&i&&68&r))&&n.report(145,t),o===this&&i&&1&i&&1&r&&o.recordScopeError(145,t),i&&(256&i||512&i&&!n.options.webcompat)&&n.report(145,t),o.variableBindings.set(t,r),o=o.parent}}hasVariable(e){return this.variableBindings.has(e)}addBlockName(e,t,r,n){const{parser:o}=this,a=this.variableBindings.get(t);!a||2&a||(1&r?this.recordScopeError(145,t):o.options.webcompat&&!(1&e)&&2&n&&64===a&&64===r||o.report(145,t)),64&this.type&&this.parent?.hasVariable(t)&&!(2&this.parent.variableBindings.get(t))&&o.report(145,t),512&this.type&&a&&!(2&a)&&1&r&&this.recordScopeError(145,t),32&this.type&&768&this.parent.variableBindings.get(t)&&o.report(159,t),this.variableBindings.set(t,r)}recordScopeError(e,...t){this.scopeError={type:e,params:t,start:this.parser.tokenStart,end:this.parser.currentLocation}}reportScopeError(){const{scopeError:e}=this;if(e)throw new N(e.start,e.end,e.type,...e.params)}}function ce(e,t,r){const n=e.createScope().createChildScope(512);return n.addBlockName(t,r,1,0),n}class le{parser;parent;refs=Object.create(null);privateIdentifiers=new Map;constructor(e,t){this.parser=e,this.parent=t}addPrivateIdentifier(e,t){const{privateIdentifiers:r}=this;let n=800&t;768&n||(n|=768);const o=r.get(e);this.hasPrivateIdentifier(e)&&((32&o)!=(32&n)||o&n&768)&&this.parser.report(146,e),r.set(e,this.hasPrivateIdentifier(e)?o|n:n)}addPrivateIdentifierRef(e){this.refs[e]??=[],this.refs[e].push(this.parser.tokenStart)}isPrivateIdentifierDefined(e){return this.hasPrivateIdentifier(e)||Boolean(this.parent?.isPrivateIdentifierDefined(e))}validatePrivateIdentifierRefs(){for(const e in this.refs)if(!this.isPrivateIdentifierDefined(e)){const{index:t,line:r,column:n}=this.refs[e][0];throw new N({index:t,line:r,column:n},{index:t+e.length,line:r,column:n+e.length},4,e)}}hasPrivateIdentifier(e){return this.privateIdentifiers.has(e)}}class ue{source;options;lastOnToken=null;token=1048576;flags=0;index=0;line=1;column=0;startIndex=0;end=0;tokenIndex=0;startColumn=0;tokenColumn=0;tokenLine=1;startLine=1;tokenValue="";tokenRaw="";tokenRegExp=void 0;currentChar=0;exportedNames=new Set;exportedBindings=new Set;assignable=1;destructible=0;leadingDecorators={decorators:[]};constructor(e,t={}){this.source=e,this.options=t,this.end=e.length,this.currentChar=e.charCodeAt(0)}getToken(){return this.token}setToken(e,t=!1){this.token=e;const{onToken:r}=this.options;if(r)if(1048576!==e){const n={start:{line:this.tokenLine,column:this.tokenColumn},end:{line:this.line,column:this.column}};!t&&this.lastOnToken&&r(...this.lastOnToken),this.lastOnToken=[c(e),this.tokenIndex,this.index,n]}else this.lastOnToken&&(r(...this.lastOnToken),this.lastOnToken=null);return e}get tokenStart(){return{index:this.tokenIndex,line:this.tokenLine,column:this.tokenColumn}}get currentLocation(){return{index:this.index,line:this.line,column:this.column}}finishNode(e,t,r){if(this.options.ranges){e.start=t.index;const n=r?r.index:this.startIndex;e.end=n,e.range=[t.index,n]}return this.options.loc&&(e.loc={start:{line:t.line,column:t.column},end:r?{line:r.line,column:r.column}:{line:this.startLine,column:this.startColumn}},this.options.source&&(e.loc.source=this.options.source)),e}addBindingToExports(e){this.exportedBindings.add(e)}declareUnboundVariable(e){const{exportedNames:t}=this;t.has(e)&&this.report(147,e),t.add(e)}report(e,...t){throw new N(this.tokenStart,this.currentLocation,e,...t)}createScopeIfLexical(e,t){if(this.options.lexical)return this.createScope(e,t)}createScope(e,t){return new se(this,e,t)}createPrivateScopeIfLexical(e){if(this.options.lexical)return new le(this,e)}}function pe(e,t={},r=0){const o=function(e){const t={...e};return t.onComment&&(t.onComment=Array.isArray(t.onComment)?function(e,t){return function(r,n,o,a,i){const s={type:r,value:n};t.ranges&&(s.start=o,s.end=a,s.range=[o,a]),t.loc&&(s.loc=i),e.push(s)}}(t.onComment,t):t.onComment),t.onToken&&(t.onToken=Array.isArray(t.onToken)?function(e,t){return function(r,n,o,a){const i={token:r};t.ranges&&(i.start=n,i.end=o,i.range=[n,o]),t.loc&&(i.loc=a),e.push(i)}}(t.onToken,t):t.onToken),t}(t);o.module&&(r|=3),o.globalReturn&&(r|=4096),o.impliedStrict&&(r|=1);const a=new ue(e,o);!function(e){const{source:t}=e;35===e.currentChar&&33===t.charCodeAt(e.index+1)&&(n(e),n(e),h(e,t,0,4,e.tokenStart))}(a);const i=a.createScopeIfLexical();let s=[],c="script";if(2&r){if(c="module",s=function(e,t,r){Q(e,32|t);const n=[];for(;134283267===e.getToken();){const{tokenStart:r}=e,o=e.getToken();n.push(Te(e,t,rt(e,t),o,r))}for(;1048576!==e.getToken();)n.push(de(e,t,r));return n}(a,8|r,i),i)for(const e of a.exportedBindings)i.hasVariable(e)||a.report(148,e)}else s=function(e,t,r){Q(e,262176|t);const n=[];for(;134283267===e.getToken();){const{index:r,tokenValue:o,tokenStart:a,tokenIndex:i}=e,s=e.getToken(),c=rt(e,t);if(R(e,r,i,o)){if(t|=1,64&e.flags)throw new N(e.tokenStart,e.currentLocation,9);if(4096&e.flags)throw new N(e.tokenStart,e.currentLocation,15)}n.push(Te(e,t,c,s,a))}for(;1048576!==e.getToken();)n.push(ge(e,t,r,void 0,4,{}));return n}(a,8|r,i);return a.finishNode({type:"Program",sourceType:c,body:s},{index:0,line:1,column:0},a.currentLocation)}function de(e,t,r){let n;switch(132===e.getToken()&&Object.assign(e.leadingDecorators,{start:e.tokenStart,decorators:yt(e,t,void 0)}),e.getToken()){case 20564:n=function(e,t,r){const n=e.leadingDecorators.decorators.length?e.leadingDecorators.start:e.tokenStart;Q(e,32|t);const o=[];let a=null,i=null,s=[];if(U(e,32|t,20561)){switch(e.getToken()){case 86104:a=nt(e,t,r,void 0,4,1,1,0,e.tokenStart);break;case 132:case 86094:a=Tt(e,t,r,void 0,1);break;case 209005:{const{tokenStart:n}=e;a=tt(e,t);const{flags:o}=e;1&o||(86104===e.getToken()?a=nt(e,t,r,void 0,4,1,1,1,n):67174411===e.getToken()?(a=bt(e,t,void 0,a,1,1,0,o,n),a=je(e,t,void 0,a,0,0,n),a=Re(e,t,void 0,0,0,n,a)):143360&e.getToken()&&(r&&(r=ce(e,t,e.tokenValue)),a=tt(e,t),a=ft(e,t,r,void 0,[a],1,n)));break}default:a=Ie(e,t,void 0,1,0,e.tokenStart),D(e,32|t)}return r&&e.declareUnboundVariable("default"),e.finishNode({type:"ExportDefaultDeclaration",declaration:a},n)}switch(e.getToken()){case 8391476:{Q(e,t);let o=null;U(e,t,77932)&&(r&&e.declareUnboundVariable(e.tokenValue),o=$e(e,t)),P(e,t,209011),134283267!==e.getToken()&&e.report(105,"Export"),i=rt(e,t);const a={type:"ExportAllDeclaration",source:i,exported:o,attributes:ze(e,t)};return D(e,32|t),e.finishNode(a,n)}case 2162700:{Q(e,t);const n=[],a=[];let c=0;for(;143360&e.getToken()||134283267===e.getToken();){const{tokenStart:i,tokenValue:s}=e,l=$e(e,t);let u;"Literal"===l.type&&(c=1),77932===e.getToken()?(Q(e,t),143360&e.getToken()||134283267===e.getToken()||e.report(106),r&&(n.push(e.tokenValue),a.push(s)),u=$e(e,t)):(r&&(n.push(e.tokenValue),a.push(e.tokenValue)),u=l),o.push(e.finishNode({type:"ExportSpecifier",local:l,exported:u},i)),1074790415!==e.getToken()&&P(e,t,18)}P(e,t,1074790415),U(e,t,209011)?(134283267!==e.getToken()&&e.report(105,"Export"),i=rt(e,t),s=ze(e,t),r&&n.forEach((t=>e.declareUnboundVariable(t)))):(c&&e.report(172),r&&(n.forEach((t=>e.declareUnboundVariable(t))),a.forEach((t=>e.addBindingToExports(t))))),D(e,32|t);break}case 132:case 86094:a=Tt(e,t,r,void 0,2);break;case 86104:a=nt(e,t,r,void 0,4,1,2,0,e.tokenStart);break;case 241737:a=we(e,t,r,void 0,8,64);break;case 86090:a=we(e,t,r,void 0,16,64);break;case 86088:a=Se(e,t,r,void 0,64);break;case 209005:{const{tokenStart:n}=e;if(Q(e,t),!(1&e.flags)&&86104===e.getToken()){a=nt(e,t,r,void 0,4,1,2,1,n);break}}default:e.report(30,I[255&e.getToken()])}const c={type:"ExportNamedDeclaration",declaration:a,specifiers:o,source:i,attributes:s};return e.finishNode(c,n)}(e,t,r);break;case 86106:n=function(e,t,r){const n=e.tokenStart;Q(e,t);let o=null;const{tokenStart:a}=e;let i=[];if(134283267===e.getToken())o=rt(e,t);else{if(143360&e.getToken()){const n=qe(e,t,r);if(i=[e.finishNode({type:"ImportDefaultSpecifier",local:n},a)],U(e,t,18))switch(e.getToken()){case 8391476:i.push(Ee(e,t,r));break;case 2162700:Ne(e,t,r,i);break;default:e.report(107)}}else switch(e.getToken()){case 8391476:i=[Ee(e,t,r)];break;case 2162700:Ne(e,t,r,i);break;case 67174411:return Ae(e,t,void 0,n);case 67108877:return Le(e,t,n);default:e.report(30,I[255&e.getToken()])}o=function(e,t){P(e,t,209011),134283267!==e.getToken()&&e.report(105,"Import");return rt(e,t)}(e,t)}const s=ze(e,t),c={type:"ImportDeclaration",specifiers:i,source:o,attributes:s};return D(e,32|t),e.finishNode(c,n)}(e,t,r);break;default:n=ge(e,t,r,void 0,4,{})}return e.leadingDecorators?.decorators.length&&e.report(170),n}function ge(e,t,r,n,o,a){const i=e.tokenStart;switch(e.getToken()){case 86104:return nt(e,t,r,n,o,1,0,0,i);case 132:case 86094:return Tt(e,t,r,n,0);case 86090:return we(e,t,r,n,16,0);case 241737:return function(e,t,r,n,o){const{tokenValue:a,tokenStart:i}=e,s=e.getToken();let c=tt(e,t);if(2240512&e.getToken()){const o=ve(e,t,r,n,8,0);return D(e,32|t),e.finishNode({type:"VariableDeclaration",kind:"let",declarations:o},i)}e.assignable=1,1&t&&e.report(85);if(21===e.getToken())return me(e,t,r,n,o,{},a,c,s,0,i);if(10===e.getToken()){let r;e.options.lexical&&(r=ce(e,t,a)),e.flags=128^(128|e.flags),c=ft(e,t,r,n,[c],0,i)}else c=je(e,t,n,c,0,0,i),c=Re(e,t,n,0,0,i,c);18===e.getToken()&&(c=Ve(e,t,n,0,i,c));return he(e,t,c,i)}(e,t,r,n,o);case 20564:e.report(103,"export");case 86106:switch(Q(e,t),e.getToken()){case 67174411:return Ae(e,t,n,i);case 67108877:return Le(e,t,i);default:e.report(103,"import")}case 209005:return be(e,t,r,n,o,a,1);default:return fe(e,t,r,n,o,a,1)}}function fe(e,t,r,n,o,a,i){switch(e.getToken()){case 86088:return Se(e,t,r,n,0);case 20572:return function(e,t,r){4096&t||e.report(92);const n=e.tokenStart;Q(e,32|t);const o=1&e.flags||1048576&e.getToken()?null:De(e,t,r,0,1,e.tokenStart);return D(e,32|t),e.finishNode({type:"ReturnStatement",argument:o},n)}(e,t,n);case 20569:return function(e,t,r,n,o){const a=e.tokenStart;Q(e,t),P(e,32|t,67174411),e.assignable=1;const i=De(e,t,n,0,1,e.tokenStart);P(e,32|t,16);const s=ye(e,t,r,n,o);let c=null;20563===e.getToken()&&(Q(e,32|t),c=ye(e,t,r,n,o));return e.finishNode({type:"IfStatement",test:i,consequent:s,alternate:c},a)}(e,t,r,n,a);case 20567:return function(e,t,r,n,o){const a=e.tokenStart;Q(e,t);const i=((2048&t)>0||(2&t)>0&&(8&t)>0)&&U(e,t,209006);P(e,32|t,67174411),r=r?.createChildScope(1);let s,c=null,l=null,u=0,p=null,d=86088===e.getToken()||241737===e.getToken()||86090===e.getToken();const{tokenStart:g}=e,f=e.getToken();if(d)241737===f?(p=tt(e,t),2240512&e.getToken()?(8673330===e.getToken()?1&t&&e.report(67):p=e.finishNode({type:"VariableDeclaration",kind:"let",declarations:ve(e,131072|t,r,n,8,32)},g),e.assignable=1):1&t?e.report(67):(d=!1,e.assignable=1,p=je(e,t,n,p,0,0,g),471156===e.getToken()&&e.report(115))):(Q(e,t),p=e.finishNode(86088===f?{type:"VariableDeclaration",kind:"var",declarations:ve(e,131072|t,r,n,4,32)}:{type:"VariableDeclaration",kind:"const",declarations:ve(e,131072|t,r,n,16,32)},g),e.assignable=1);else if(1074790417===f)i&&e.report(82);else if(2097152&~f)p=Ge(e,131072|t,n,1,0,1);else{const r=e.tokenStart;p=2162700===f?lt(e,t,void 0,n,1,0,0,2,32):at(e,t,void 0,n,1,0,0,2,32),u=e.destructible,64&u&&e.report(63),e.assignable=16&u?2:1,p=je(e,131072|t,n,p,0,0,r)}if(!(262144&~e.getToken())){if(471156===e.getToken()){2&e.assignable&&e.report(80,i?"await":"of"),O(e,p),Q(e,32|t),s=Ie(e,t,n,1,0,e.tokenStart),P(e,32|t,16);const c=xe(e,t,r,n,o);return e.finishNode({type:"ForOfStatement",left:p,right:s,body:c,await:i},a)}2&e.assignable&&e.report(80,"in"),O(e,p),Q(e,32|t),i&&e.report(82),s=De(e,t,n,0,1,e.tokenStart),P(e,32|t,16);const c=xe(e,t,r,n,o);return e.finishNode({type:"ForInStatement",body:c,left:p,right:s},a)}i&&e.report(82);d||(8&u&&1077936155!==e.getToken()&&e.report(80,"loop"),p=Re(e,131072|t,n,0,0,g,p));18===e.getToken()&&(p=Ve(e,t,n,0,g,p));P(e,32|t,1074790417),1074790417!==e.getToken()&&(c=De(e,t,n,0,1,e.tokenStart));P(e,32|t,1074790417),16!==e.getToken()&&(l=De(e,t,n,0,1,e.tokenStart));P(e,32|t,16);const k=xe(e,t,r,n,o);return e.finishNode({type:"ForStatement",init:p,test:c,update:l,body:k},a)}(e,t,r,n,a);case 20562:return function(e,t,r,n,o){const a=e.tokenStart;Q(e,32|t);const i=xe(e,t,r,n,o);P(e,t,20578),P(e,32|t,67174411);const s=De(e,t,n,0,1,e.tokenStart);return P(e,32|t,16),U(e,32|t,1074790417),e.finishNode({type:"DoWhileStatement",body:i,test:s},a)}(e,t,r,n,a);case 20578:return function(e,t,r,n,o){const a=e.tokenStart;Q(e,t),P(e,32|t,67174411);const i=De(e,t,n,0,1,e.tokenStart);P(e,32|t,16);const s=xe(e,t,r,n,o);return e.finishNode({type:"WhileStatement",test:i,body:s},a)}(e,t,r,n,a);case 86110:return function(e,t,r,n,o){const a=e.tokenStart;Q(e,t),P(e,32|t,67174411);const i=De(e,t,n,0,1,e.tokenStart);P(e,t,16),P(e,t,2162700);const s=[];let c=0;r=r?.createChildScope(8);for(;1074790415!==e.getToken();){const{tokenStart:a}=e;let i=null;const l=[];for(U(e,32|t,20556)?i=De(e,t,n,0,1,e.tokenStart):(P(e,32|t,20561),c&&e.report(89),c=1),P(e,32|t,21);20556!==e.getToken()&&1074790415!==e.getToken()&&20561!==e.getToken();)l.push(ge(e,4|t,r,n,2,{$:o}));s.push(e.finishNode({type:"SwitchCase",test:i,consequent:l},a))}return P(e,32|t,1074790415),e.finishNode({type:"SwitchStatement",discriminant:i,cases:s},a)}(e,t,r,n,a);case 1074790417:return function(e,t){const r=e.tokenStart;return Q(e,32|t),e.finishNode({type:"EmptyStatement"},r)}(e,t);case 2162700:return ke(e,t,r?.createChildScope(),n,a,e.tokenStart);case 86112:return function(e,t,r){const n=e.tokenStart;Q(e,32|t),1&e.flags&&e.report(90);const o=De(e,t,r,0,1,e.tokenStart);return D(e,32|t),e.finishNode({type:"ThrowStatement",argument:o},n)}(e,t,n);case 20555:return function(e,t,r){const n=e.tokenStart;Q(e,32|t);let o=null;if(!(1&e.flags)&&143360&e.getToken()){const{tokenValue:n}=e;o=tt(e,32|t),J(e,r,n,0)||e.report(138,n)}else 132&t||e.report(69);return D(e,32|t),e.finishNode({type:"BreakStatement",label:o},n)}(e,t,a);case 20559:return function(e,t,r){128&t||e.report(68);const n=e.tokenStart;Q(e,t);let o=null;if(!(1&e.flags)&&143360&e.getToken()){const{tokenValue:n}=e;o=tt(e,32|t),J(e,r,n,1)||e.report(138,n)}return D(e,32|t),e.finishNode({type:"ContinueStatement",label:o},n)}(e,t,a);case 20577:return function(e,t,r,n,o){const a=e.tokenStart;Q(e,32|t);const i=r?.createChildScope(16),s=ke(e,t,i,n,{$:o}),{tokenStart:c}=e,l=U(e,32|t,20557)?function(e,t,r,n,o,a){let i=null,s=r;U(e,t,67174411)&&(r=r?.createChildScope(4),i=qt(e,t,r,n,2097152&~e.getToken()?512:256,0),18===e.getToken()?e.report(86):1077936155===e.getToken()&&e.report(87),P(e,32|t,16));s=r?.createChildScope(32);const c=ke(e,t,s,n,{$:o});return e.finishNode({type:"CatchClause",param:i,body:c},a)}(e,t,r,n,o,c):null;let u=null;if(20566===e.getToken()){Q(e,32|t);const a=r?.createChildScope(4);u=ke(e,t,a,n,{$:o})}l||u||e.report(88);return e.finishNode({type:"TryStatement",block:s,handler:l,finalizer:u},a)}(e,t,r,n,a);case 20579:return function(e,t,r,n,o){const a=e.tokenStart;Q(e,t),1&t&&e.report(91);P(e,32|t,67174411);const i=De(e,t,n,0,1,e.tokenStart);P(e,32|t,16);const s=fe(e,t,r,n,2,o,0);return e.finishNode({type:"WithStatement",object:i,body:s},a)}(e,t,r,n,a);case 20560:return function(e,t){const r=e.tokenStart;return Q(e,32|t),D(e,32|t),e.finishNode({type:"DebuggerStatement"},r)}(e,t);case 209005:return be(e,t,r,n,o,a,0);case 20557:e.report(162);case 20566:e.report(163);case 86104:e.report(1&t?76:e.options.webcompat?77:78);case 86094:e.report(79);default:return function(e,t,r,n,o,a,i){const{tokenValue:s,tokenStart:c}=e,l=e.getToken();let u;if(241737===l)u=tt(e,t),1&t&&e.report(85),69271571===e.getToken()&&e.report(84);else u=Je(e,t,n,2,0,1,0,1,e.tokenStart);if(143360&l&&21===e.getToken())return me(e,t,r,n,o,a,s,u,l,i,c);u=je(e,t,n,u,0,0,c),u=Re(e,t,n,0,0,c,u),18===e.getToken()&&(u=Ve(e,t,n,0,c,u));return he(e,t,u,c)}(e,t,r,n,o,a,i)}}function ke(e,t,r,n,o,a=e.tokenStart,i="BlockStatement"){const s=[];for(P(e,32|t,2162700);1074790415!==e.getToken();)s.push(ge(e,t,r,n,2,{$:o}));return P(e,32|t,1074790415),e.finishNode({type:i,body:s},a)}function he(e,t,r,n){return D(e,32|t),e.finishNode({type:"ExpressionStatement",expression:r},n)}function me(e,t,r,n,o,a,i,s,c,l,u){G(e,t,0,c,1),function(e,t,r){let n=t;for(;n;)n["$"+r]&&e.report(136,r),n=n.$;t["$"+r]=1}(e,a,i),Q(e,32|t);const p=!l||1&t||!e.options.webcompat||86104!==e.getToken()?fe(e,t,r,n,o,a,l):nt(e,t,r?.createChildScope(),n,o,0,0,0,e.tokenStart);return e.finishNode({type:"LabeledStatement",label:s,body:p},u)}function be(e,t,r,n,o,a,i){const{tokenValue:s,tokenStart:c}=e,l=e.getToken();let u=tt(e,t);if(21===e.getToken())return me(e,t,r,n,o,a,s,u,l,1,c);const p=1&e.flags;if(!p){if(86104===e.getToken())return i||e.report(123),nt(e,t,r,n,o,1,0,1,c);if(H(t,e.getToken()))return u=mt(e,t,n,1,c),18===e.getToken()&&(u=Ve(e,t,n,0,c,u)),he(e,t,u,c)}return 67174411===e.getToken()?u=bt(e,t,n,u,1,1,0,p,c):(10===e.getToken()&&(z(e,t,l),36864&~l||(e.flags|=256),u=dt(e,2048|t,n,e.tokenValue,u,0,1,0,c)),e.assignable=1),u=je(e,t,n,u,0,0,c),u=Re(e,t,n,0,0,c,u),e.assignable=1,18===e.getToken()&&(u=Ve(e,t,n,0,c,u)),he(e,t,u,c)}function Te(e,t,r,n,o){const a=e.startIndex;1074790417!==n&&(e.assignable=2,r=je(e,t,void 0,r,0,0,o),1074790417!==e.getToken()&&(r=Re(e,t,void 0,0,0,o,r),18===e.getToken()&&(r=Ve(e,t,void 0,0,o,r))),D(e,32|t));const i={type:"ExpressionStatement",expression:r};return"Literal"===r.type&&"string"==typeof r.value&&(i.directive=e.source.slice(o.index+1,a-1)),e.finishNode(i,o)}function ye(e,t,r,n,o){const{tokenStart:a}=e;return 1&t||!e.options.webcompat||86104!==e.getToken()?fe(e,t,r,n,0,{$:o},0):nt(e,t,r?.createChildScope(),n,0,0,0,0,a)}function xe(e,t,r,n,o){return fe(e,131072^(131072|t)|128,r,n,0,{loop:1,$:o},0)}function we(e,t,r,n,o,a){const i=e.tokenStart;Q(e,t);const s=ve(e,t,r,n,o,a);return D(e,32|t),e.finishNode({type:"VariableDeclaration",kind:8&o?"let":"const",declarations:s},i)}function Se(e,t,r,n,o){const a=e.tokenStart;Q(e,t);const i=ve(e,t,r,n,4,o);return D(e,32|t),e.finishNode({type:"VariableDeclaration",kind:"var",declarations:i},a)}function ve(e,t,r,n,o,a){let i=1;const s=[Ce(e,t,r,n,o,a)];for(;U(e,t,18);)i++,s.push(Ce(e,t,r,n,o,a));return i>1&&32&a&&262144&e.getToken()&&e.report(61,I[255&e.getToken()]),s}function Ce(e,t,r,n,o,a){const{tokenStart:i}=e,s=e.getToken();let c=null;const l=qt(e,t,r,n,o,a);if(1077936155===e.getToken()){if(Q(e,32|t),c=Ie(e,t,n,1,0,e.tokenStart),(32&a||!(2097152&s))&&(471156===e.getToken()||8673330===e.getToken()&&(2097152&s||!(4&o)||1&t)))throw new N(i,e.currentLocation,60,471156===e.getToken()?"of":"in")}else(16&o||(2097152&s)>0)&&262144&~e.getToken()&&e.report(59,16&o?"const":"destructuring");return e.finishNode({type:"VariableDeclarator",id:l,init:c},i)}function qe(e,t,r){return H(t,e.getToken())||e.report(118),537079808&~e.getToken()||e.report(119),r?.addBlockName(t,e.tokenValue,8,0),tt(e,t)}function Ee(e,t,r){const{tokenStart:n}=e;if(Q(e,t),P(e,t,77932),!(134217728&~e.getToken()))throw new N(n,e.currentLocation,30,I[255&e.getToken()]);return e.finishNode({type:"ImportNamespaceSpecifier",local:qe(e,t,r)},n)}function Ne(e,t,r,n){for(Q(e,t);143360&e.getToken()||134283267===e.getToken();){let{tokenValue:o,tokenStart:a}=e;const i=e.getToken(),s=$e(e,t);let c;U(e,t,77932)?(134217728&~e.getToken()&&18!==e.getToken()?G(e,t,16,e.getToken(),0):e.report(106),o=e.tokenValue,c=tt(e,t)):"Identifier"===s.type?(G(e,t,16,i,0),c=s):e.report(25,I[108]),r?.addBlockName(t,o,8,0),n.push(e.finishNode({type:"ImportSpecifier",local:c,imported:s},a)),1074790415!==e.getToken()&&P(e,t,18)}return P(e,t,1074790415),n}function Le(e,t,r){let n=Me(e,t,e.finishNode({type:"Identifier",name:"import"},r),r);return n=je(e,t,void 0,n,0,0,r),n=Re(e,t,void 0,0,0,r,n),18===e.getToken()&&(n=Ve(e,t,void 0,0,r,n)),he(e,t,n,r)}function Ae(e,t,r,n){let o=He(e,t,r,0,n);return o=je(e,t,r,o,0,0,n),18===e.getToken()&&(o=Ve(e,t,r,0,n,o)),he(e,t,o,n)}function Ie(e,t,r,n,o,a){let i=Je(e,t,r,2,0,n,o,1,a);return i=je(e,t,r,i,o,0,a),Re(e,t,r,o,0,a,i)}function Ve(e,t,r,n,o,a){const i=[a];for(;U(e,32|t,18);)i.push(Ie(e,t,r,1,n,e.tokenStart));return e.finishNode({type:"SequenceExpression",expressions:i},o)}function De(e,t,r,n,o,a){const i=Ie(e,t,r,o,n,a);return 18===e.getToken()?Ve(e,t,r,n,a,i):i}function Re(e,t,r,n,o,a,i){const s=e.getToken();if(!(4194304&~s)){2&e.assignable&&e.report(26),(!o&&1077936155===s&&"ArrayExpression"===i.type||"ObjectExpression"===i.type)&&O(e,i),Q(e,32|t);const c=Ie(e,t,r,1,n,e.tokenStart);return e.assignable=2,e.finishNode(o?{type:"AssignmentPattern",left:i,right:c}:{type:"AssignmentExpression",left:i,operator:I[255&s],right:c},a)}return 8388608&~s||(i=Pe(e,t,r,n,a,4,s,i)),U(e,32|t,22)&&(i=Ue(e,t,r,i,a)),i}function Be(e,t,r,n,o,a,i){const s=e.getToken();Q(e,32|t);const c=Ie(e,t,r,1,n,e.tokenStart);return i=e.finishNode(o?{type:"AssignmentPattern",left:i,right:c}:{type:"AssignmentExpression",left:i,operator:I[255&s],right:c},a),e.assignable=2,i}function Ue(e,t,r,n,o){const a=Ie(e,131072^(131072|t),r,1,0,e.tokenStart);P(e,32|t,21),e.assignable=1;const i=Ie(e,t,r,1,0,e.tokenStart);return e.assignable=2,e.finishNode({type:"ConditionalExpression",test:n,consequent:a,alternate:i},o)}function Pe(e,t,r,n,o,a,i,s){const c=8673330&-((131072&t)>0);let l,u;for(e.assignable=2;8388608&e.getToken()&&(l=e.getToken(),u=3840&l,(524288&l&&268435456&i||524288&i&&268435456&l)&&e.report(165),!(u+((8391735===l)<<8)-((c===l)<<12)<=a));)Q(e,32|t),s=e.finishNode({type:524288&l||268435456&l?"LogicalExpression":"BinaryExpression",left:s,right:Pe(e,t,r,n,e.tokenStart,u,l,Ge(e,t,r,0,n,1)),operator:I[255&l]},o);return 1077936155===e.getToken()&&e.report(26),s}function Oe(e,t,r,n,o,a,i){const{tokenStart:s}=e;P(e,32|t,2162700);const c=[];if(1074790415!==e.getToken()){for(;134283267===e.getToken();){const{index:r,tokenStart:n,tokenIndex:o,tokenValue:a}=e,s=e.getToken(),l=rt(e,t);if(R(e,r,o,a)){if(t|=1,128&e.flags)throw new N(n,e.currentLocation,66);if(64&e.flags)throw new N(n,e.currentLocation,9);if(4096&e.flags)throw new N(n,e.currentLocation,15);i?.reportScopeError()}c.push(Te(e,t,l,s,n))}1&t&&(a&&(537079808&~a||e.report(119),36864&~a||e.report(40)),512&e.flags&&e.report(119),256&e.flags&&e.report(118))}for(e.flags=4928^(4928|e.flags),e.destructible=256^(256|e.destructible);1074790415!==e.getToken();)c.push(ge(e,t,r,n,4,{}));return P(e,24&o?32|t:t,1074790415),e.flags&=-4289,1077936155===e.getToken()&&e.report(26),e.finishNode({type:"BlockStatement",body:c},s)}function Ge(e,t,r,n,o,a){const i=e.tokenStart;return je(e,t,r,Je(e,t,r,2,0,n,o,a,i),o,0,i)}function je(e,t,r,n,o,a,i){if(33619968&~e.getToken()||1&e.flags){if(!(67108864&~e.getToken())){switch(t=131072^(131072|t),e.getToken()){case 67108877:{Q(e,8^(262152|t)),16&t&&130===e.getToken()&&"super"===e.tokenValue&&e.report(173),e.assignable=1;const o=Fe(e,64|t,r);n=e.finishNode({type:"MemberExpression",object:n,computed:!1,property:o,optional:!1},i);break}case 69271571:{let a=!1;2048&~e.flags||(a=!0,e.flags=2048^(2048|e.flags)),Q(e,32|t);const{tokenStart:s}=e,c=De(e,t,r,o,1,s);P(e,t,20),e.assignable=1,n=e.finishNode({type:"MemberExpression",object:n,computed:!0,property:c,optional:!1},i),a&&(e.flags|=2048);break}case 67174411:{if(!(1024&~e.flags))return e.flags=1024^(1024|e.flags),n;let a=!1;2048&~e.flags||(a=!0,e.flags=2048^(2048|e.flags));const s=et(e,t,r,o);e.assignable=2,n=e.finishNode({type:"CallExpression",callee:n,arguments:s,optional:!1},i),a&&(e.flags|=2048);break}case 67108990:Q(e,8^(262152|t)),e.flags|=2048,e.assignable=2,n=function(e,t,r,n,o){let a,i=!1;69271571!==e.getToken()&&67174411!==e.getToken()||2048&~e.flags||(i=!0,e.flags=2048^(2048|e.flags));if(69271571===e.getToken()){Q(e,32|t);const{tokenStart:i}=e,s=De(e,t,r,0,1,i);P(e,t,20),e.assignable=2,a=e.finishNode({type:"MemberExpression",object:n,computed:!0,optional:!0,property:s},o)}else if(67174411===e.getToken()){const i=et(e,t,r,0);e.assignable=2,a=e.finishNode({type:"CallExpression",callee:n,arguments:i,optional:!0},o)}else{const i=Fe(e,t,r);e.assignable=2,a=e.finishNode({type:"MemberExpression",object:n,computed:!1,optional:!0,property:i},o)}i&&(e.flags|=2048);return a}(e,t,r,n,i);break;default:2048&~e.flags||e.report(166),e.assignable=2,n=e.finishNode({type:"TaggedTemplateExpression",tag:n,quasi:67174408===e.getToken()?Ke(e,64|t,r):Ze(e,t)},i)}n=je(e,t,r,n,0,1,i)}}else n=function(e,t,r,n){2&e.assignable&&e.report(55);const o=e.getToken();return Q(e,t),e.assignable=2,e.finishNode({type:"UpdateExpression",argument:r,operator:I[255&o],prefix:!1},n)}(e,t,n,i);return 0!==a||2048&~e.flags||(e.flags=2048^(2048|e.flags),n=e.finishNode({type:"ChainExpression",expression:n},i)),n}function Fe(e,t,r){return 143360&e.getToken()||-2147483528===e.getToken()||-2147483527===e.getToken()||130===e.getToken()||e.report(160),130===e.getToken()?vt(e,t,r,0):tt(e,t)}function Je(e,t,r,n,o,a,i,s,c){if(!(143360&~e.getToken())){switch(e.getToken()){case 209006:return function(e,t,r,n,o,a){o&&(e.destructible|=128),524288&t&&e.report(177);const i=pt(e,t,r);if("ArrowFunctionExpression"===i.type||!(65536&e.getToken())){if(2048&t)throw new N(a,{index:e.startIndex,line:e.startLine,column:e.startColumn},176);if(2&t)throw new N(a,{index:e.startIndex,line:e.startLine,column:e.startColumn},110);if(8192&t&&2048&t)throw new N(a,{index:e.startIndex,line:e.startLine,column:e.startColumn},110);return i}if(8192&t)throw new N(a,{index:e.startIndex,line:e.startLine,column:e.startColumn},31);if(2048&t||2&t&&8&t){if(n)throw new N(a,{index:e.startIndex,line:e.startLine,column:e.startColumn},0);const o=Ge(e,t,r,0,0,1);return 8391735===e.getToken()&&e.report(33),e.assignable=2,e.finishNode({type:"AwaitExpression",argument:o},a)}if(2&t)throw new N(a,{index:e.startIndex,line:e.startLine,column:e.startColumn},98);return i}(e,t,r,o,i,c);case 241771:return function(e,t,r,n,o,a){if(n&&(e.destructible|=256),1024&t){Q(e,32|t),8192&t&&e.report(32),o||e.report(26),22===e.getToken()&&e.report(124);let n=null,i=!1;return 1&e.flags?8391476===e.getToken()&&e.report(30,I[255&e.getToken()]):(i=U(e,32|t,8391476),(77824&e.getToken()||i)&&(n=Ie(e,t,r,1,0,e.tokenStart))),e.assignable=2,e.finishNode({type:"YieldExpression",argument:n,delegate:i},a)}return 1&t&&e.report(97,"yield"),pt(e,t,r)}(e,t,r,i,a,c);case 209005:return function(e,t,r,n,o,a,i,s){const c=e.getToken(),l=tt(e,t),{flags:u}=e;if(!(1&u)){if(86104===e.getToken())return ot(e,t,r,1,n,s);if(H(t,e.getToken()))return o||e.report(0),36864&~e.getToken()||(e.flags|=256),mt(e,t,r,a,s)}return i||67174411!==e.getToken()?10===e.getToken()?(z(e,t,c),i&&e.report(51),36864&~c||(e.flags|=256),dt(e,t,r,e.tokenValue,l,i,a,0,s)):(e.assignable=1,l):bt(e,t,r,l,a,1,0,u,s)}(e,t,r,i,s,a,o,c)}const{tokenValue:l}=e,u=e.getToken(),p=tt(e,64|t);return 10===e.getToken()?(s||e.report(0),z(e,t,u),36864&~u||(e.flags|=256),dt(e,t,r,l,p,o,a,0,c)):(!(16&t)||32768&t||8192&t||"arguments"!==e.tokenValue||e.report(130),73==(255&u)&&(1&t&&e.report(113),24&n&&e.report(100)),e.assignable=1&t&&!(537079808&~u)?2:1,p)}if(!(134217728&~e.getToken()))return rt(e,t);switch(e.getToken()){case 33619993:case 33619994:return function(e,t,r,n,o,a){n&&e.report(56),o||e.report(0);const i=e.getToken();Q(e,32|t);const s=Ge(e,t,r,0,0,1);return 2&e.assignable&&e.report(55),e.assignable=2,e.finishNode({type:"UpdateExpression",argument:s,operator:I[255&i],prefix:!0},a)}(e,t,r,o,s,c);case 16863276:case 16842798:case 16842799:case 25233968:case 25233969:case 16863275:case 16863277:return function(e,t,r,n,o){n||e.report(0);const{tokenStart:a}=e,i=e.getToken();Q(e,32|t);const s=Ge(e,t,r,0,o,1);var c;return 8391735===e.getToken()&&e.report(33),1&t&&16863276===i&&("Identifier"===s.type?e.report(121):(c=s).property&&"PrivateIdentifier"===c.property.type&&e.report(127)),e.assignable=2,e.finishNode({type:"UnaryExpression",operator:I[255&i],argument:s,prefix:!0},a)}(e,t,r,s,i);case 86104:return ot(e,t,r,0,i,c);case 2162700:return function(e,t,r,n,o){const a=lt(e,t,void 0,r,n,o,0,2,0);64&e.destructible&&e.report(63);8&e.destructible&&e.report(62);return a}(e,t,r,a?0:1,i);case 69271571:return function(e,t,r,n,o){const a=at(e,t,void 0,r,n,o,0,2,0);64&e.destructible&&e.report(63);8&e.destructible&&e.report(62);return a}(e,t,r,a?0:1,i);case 67174411:return function(e,t,r,n,o,a,i){e.flags=128^(128|e.flags);const s=e.tokenStart;Q(e,262176|t);const c=e.createScopeIfLexical()?.createChildScope(512);if(t=131072^(131072|t),U(e,t,16))return gt(e,t,c,r,[],n,0,i);let l,u=0;e.destructible&=-385;let p=[],d=0,g=0,f=0;const k=e.tokenStart;e.assignable=1;for(;16!==e.getToken();){const{tokenStart:n}=e,i=e.getToken();if(143360&i)c?.addBlockName(t,e.tokenValue,1,0),537079808&~i?36864&~i||(f=1):g=1,l=Je(e,t,r,o,0,1,1,1,n),16===e.getToken()||18===e.getToken()?2&e.assignable&&(u|=16,g=1):(1077936155===e.getToken()?g=1:u|=16,l=je(e,t,r,l,1,0,n),16!==e.getToken()&&18!==e.getToken()&&(l=Re(e,t,r,1,0,n,l)));else{if(2097152&~i){if(14===i){l=st(e,t,c,r,16,o,a,0,1,0),16&e.destructible&&e.report(74),g=1,!d||16!==e.getToken()&&18!==e.getToken()||p.push(l),u|=8;break}if(u|=16,l=Ie(e,t,r,1,1,n),!d||16!==e.getToken()&&18!==e.getToken()||p.push(l),18===e.getToken()&&(d||(d=1,p=[l])),d){for(;U(e,32|t,18);)p.push(Ie(e,t,r,1,1,e.tokenStart));e.assignable=2,l=e.finishNode({type:"SequenceExpression",expressions:p},k)}return P(e,t,16),e.destructible=u,e.options.preserveParens?e.finishNode({type:"ParenthesizedExpression",expression:l},s):l}l=2162700===i?lt(e,262144|t,c,r,0,1,0,o,a):at(e,262144|t,c,r,0,1,0,o,a),u|=e.destructible,g=1,e.assignable=2,16!==e.getToken()&&18!==e.getToken()&&(8&u&&e.report(122),l=je(e,t,r,l,0,0,n),u|=16,16!==e.getToken()&&18!==e.getToken()&&(l=Re(e,t,r,0,0,n,l)))}if(!d||16!==e.getToken()&&18!==e.getToken()||p.push(l),!U(e,32|t,18))break;if(d||(d=1,p=[l]),16===e.getToken()){u|=8;break}}d&&(e.assignable=2,l=e.finishNode({type:"SequenceExpression",expressions:p},k));P(e,t,16),16&u&&8&u&&e.report(151);if(u|=256&e.destructible?256:128&e.destructible?128:0,10===e.getToken())return 48&u&&e.report(49),2050&t&&128&u&&e.report(31),1025&t&&256&u&&e.report(32),g&&(e.flags|=128),f&&(e.flags|=256),gt(e,t,c,r,d?p:[l],n,0,i);64&u&&e.report(63);8&u&&e.report(144);return e.destructible=256^(256|e.destructible)|u,e.options.preserveParens?e.finishNode({type:"ParenthesizedExpression",expression:l},s):l}(e,64|t,r,a,1,0,c);case 86021:case 86022:case 86023:return function(e,t){const r=e.tokenStart,n=I[255&e.getToken()],o=86023===e.getToken()?null:"true"===n;return Q(e,t),e.assignable=2,e.finishNode(e.options.raw?{type:"Literal",value:o,raw:n}:{type:"Literal",value:o},r)}(e,t);case 86111:return function(e,t){const{tokenStart:r}=e;return Q(e,t),e.assignable=2,e.finishNode({type:"ThisExpression"},r)}(e,t);case 65540:return function(e,t){const{tokenRaw:r,tokenRegExp:n,tokenValue:o,tokenStart:a}=e;Q(e,t),e.assignable=2;const i={type:"Literal",value:o,regex:n};e.options.raw&&(i.raw=r);return e.finishNode(i,a)}(e,t);case 132:case 86094:return function(e,t,r,n,o){let a=null,i=null;const s=yt(e,t,r);t=16384^(16385|t),Q(e,t),4096&e.getToken()&&20565!==e.getToken()&&(F(e,t,e.getToken())&&e.report(118),537079808&~e.getToken()||e.report(119),a=tt(e,t));let c=t;U(e,32|t,20565)?(i=Ge(e,t,r,0,n,0),c|=512):c=512^(512|c);const l=wt(e,c,t,void 0,r,2,0,n);return e.assignable=2,e.finishNode({type:"ClassExpression",id:a,superClass:i,body:l,...e.options.next?{decorators:s}:null},o)}(e,t,r,i,c);case 86109:return function(e,t){const{tokenStart:r}=e;switch(Q(e,t),e.getToken()){case 67108990:e.report(167);case 67174411:512&t||e.report(28),e.assignable=2;break;case 69271571:case 67108877:256&t||e.report(29),e.assignable=1;break;default:e.report(30,"super")}return e.finishNode({type:"Super"},r)}(e,t);case 67174409:return Ze(e,t);case 67174408:return Ke(e,t,r);case 86107:return function(e,t,r,n){const{tokenStart:o}=e,a=tt(e,32|t),{tokenStart:i}=e;if(U(e,t,67108877)){if(65536&t&&209029===e.getToken())return e.assignable=2,function(e,t,r,n){const o=tt(e,t);return e.finishNode({type:"MetaProperty",meta:r,property:o},n)}(e,t,a,o);e.report(94)}e.assignable=2,16842752&~e.getToken()||e.report(65,I[255&e.getToken()]);const s=Je(e,t,r,2,1,0,n,1,i);t=131072^(131072|t),67108990===e.getToken()&&e.report(168);const c=ht(e,t,r,s,n,i);return e.assignable=2,e.finishNode({type:"NewExpression",callee:c,arguments:67174411===e.getToken()?et(e,t,r,n):[]},o)}(e,t,r,i);case 134283388:return Ye(e,t);case 130:return vt(e,t,r,0);case 86106:return function(e,t,r,n,o,a){let i=tt(e,t);if(67108877===e.getToken())return Me(e,t,i,a);n&&e.report(142);return i=He(e,t,r,o,a),e.assignable=2,je(e,t,r,i,o,0,a)}(e,t,r,o,i,c);case 8456256:if(e.options.jsx)return Nt(e,t,r,0,e.tokenStart);default:if(H(t,e.getToken()))return pt(e,t,r);e.report(30,I[255&e.getToken()])}}function Me(e,t,r,n){2&t||e.report(169),Q(e,t);const o=e.getToken();return 209030!==o&&"meta"!==e.tokenValue?e.report(174):-2147483648&o&&e.report(175),e.assignable=2,e.finishNode({type:"MetaProperty",meta:r,property:tt(e,t)},n)}function He(e,t,r,n,o){P(e,32|t,67174411),14===e.getToken()&&e.report(143);const a=Ie(e,t,r,1,n,e.tokenStart);let i=null;if(18===e.getToken()){if(P(e,t,18),16!==e.getToken()){i=Ie(e,131072^(131072|t),r,1,n,e.tokenStart)}U(e,t,18)}const s={type:"ImportExpression",source:a,options:i};return P(e,t,16),e.finishNode(s,o)}function ze(e,t){if(!U(e,t,20579))return[];P(e,t,2162700);const r=[],n=new Set;for(;1074790415!==e.getToken();){const o=e.tokenStart,a=_e(e,t);P(e,t,21);const i=Xe(e,t),s="Literal"===a.type?a.value:a.name;n.has(s)&&e.report(145,`${s}`),n.add(s),r.push(e.finishNode({type:"ImportAttribute",key:a,value:i},o)),1074790415!==e.getToken()&&P(e,t,18)}return P(e,t,1074790415),r}function Xe(e,t){if(134283267===e.getToken())return rt(e,t);e.report(30,I[255&e.getToken()])}function _e(e,t){return 134283267===e.getToken()?rt(e,t):143360&e.getToken()?tt(e,t):void e.report(30,I[255&e.getToken()])}function $e(e,t){return 134283267===e.getToken()?(function(e,t){const r=t.length;for(let n=0;n<r;n++){const o=t.charCodeAt(n);55296==(64512&o)&&(o>56319||++n>=r||56320!=(64512&t.charCodeAt(n)))&&e.report(171,JSON.stringify(t.charAt(n--)))}}(e,e.tokenValue),rt(e,t)):143360&e.getToken()?tt(e,t):void e.report(30,I[255&e.getToken()])}function Ye(e,t){const{tokenRaw:r,tokenValue:n,tokenStart:o}=e;Q(e,t),e.assignable=2;const a={type:"Literal",value:n,bigint:String(n)};return e.options.raw&&(a.raw=r),e.finishNode(a,o)}function Ze(e,t){e.assignable=2;const{tokenValue:r,tokenRaw:n,tokenStart:o}=e;P(e,t,67174409);const a=[We(e,r,n,o,!0)];return e.finishNode({type:"TemplateLiteral",expressions:[],quasis:a},o)}function Ke(e,t,r){t=131072^(131072|t);const{tokenValue:n,tokenRaw:o,tokenStart:a}=e;P(e,-65&t|32,67174408);const i=[We(e,n,o,a,!1)],s=[De(e,-65&t,r,0,1,e.tokenStart)];for(1074790415!==e.getToken()&&e.report(83);67174409!==e.setToken(q(e,t),!0);){const{tokenValue:n,tokenRaw:o,tokenStart:a}=e;P(e,-65&t|32,67174408),i.push(We(e,n,o,a,!1)),s.push(De(e,t,r,0,1,e.tokenStart)),1074790415!==e.getToken()&&e.report(83)}{const{tokenValue:r,tokenRaw:n,tokenStart:o}=e;P(e,t,67174409),i.push(We(e,r,n,o,!0))}return e.finishNode({type:"TemplateLiteral",expressions:s,quasis:i},a)}function We(e,t,r,n,o){const a=e.finishNode({type:"TemplateElement",value:{cooked:t,raw:r},tail:o},n),i=o?1:2;return e.options.ranges&&(a.start+=1,a.range[0]+=1,a.end-=i,a.range[1]-=i),e.options.loc&&(a.loc.start.column+=1,a.loc.end.column-=i),a}function Qe(e,t,r){const n=e.tokenStart;P(e,32|(t=131072^(131072|t)),14);const o=Ie(e,t,r,1,0,e.tokenStart);return e.assignable=1,e.finishNode({type:"SpreadElement",argument:o},n)}function et(e,t,r,n){Q(e,32|t);const o=[];if(16===e.getToken())return Q(e,64|t),o;for(;16!==e.getToken()&&(14===e.getToken()?o.push(Qe(e,t,r)):o.push(Ie(e,t,r,1,n,e.tokenStart)),18===e.getToken())&&(Q(e,32|t),16!==e.getToken()););return P(e,64|t,16),o}function tt(e,t){const{tokenValue:r,tokenStart:n}=e,o="await"===r&&!(-2147483648&e.getToken());return Q(e,t|(o?32:0)),e.finishNode({type:"Identifier",name:r},n)}function rt(e,t){const{tokenValue:r,tokenRaw:n,tokenStart:o}=e;return 134283388===e.getToken()?Ye(e,t):(Q(e,t),e.assignable=2,e.finishNode(e.options.raw?{type:"Literal",value:r,raw:n}:{type:"Literal",value:r},o))}function nt(e,t,r,n,o,a,i,s,c){Q(e,32|t);const l=a?B(e,t,8391476):0;let u,p=null,d=r?e.createScope():void 0;if(67174411===e.getToken())1&i||e.report(39,"Function");else{const n=!(4&o)||8&t&&2&t?64|(s?1024:0)|(l?1024:0):4;j(e,t,e.getToken()),r&&(4&n?r.addVarName(t,e.tokenValue,n):r.addBlockName(t,e.tokenValue,n,o),d=d?.createChildScope(128),i&&2&i&&e.declareUnboundVariable(e.tokenValue)),u=e.getToken(),143360&e.getToken()?p=tt(e,t):e.report(30,I[255&e.getToken()])}{const e=28416;t=(t|e)^e|65536|(s?2048:0)|(l?1024:0)|(l?0:262144)}d=d?.createChildScope(256);const g=kt(e,-524289&t|8192,d,n,0,1),f=524428,k=Oe(e,36864|(t|f)^f,d?.createChildScope(64),n,8,u,d);return e.finishNode({type:"FunctionDeclaration",id:p,params:g,body:k,async:1===s,generator:1===l},c)}function ot(e,t,r,n,o,a){Q(e,32|t);const i=B(e,t,8391476),s=(n?2048:0)|(i?1024:0);let c,l=null,u=e.createScopeIfLexical();const p=552704;143360&e.getToken()&&(j(e,(t|p)^p|s,e.getToken()),u=u?.createChildScope(128),c=e.getToken(),l=tt(e,t)),t=(t|p)^p|65536|s|(i?0:262144),u=u?.createChildScope(256);const d=kt(e,-524289&t|8192,u,r,o,1),g=Oe(e,36864|-131229&t,u?.createChildScope(64),r,0,c,u);return e.assignable=2,e.finishNode({type:"FunctionExpression",id:l,params:d,body:g,async:1===n,generator:1===i},a)}function at(e,t,r,n,o,a,i,s,c){const{tokenStart:l}=e;Q(e,32|t);const u=[];let p=0;for(t=131072^(131072|t);20!==e.getToken();)if(U(e,32|t,18))u.push(null);else{let o;const{tokenStart:l,tokenValue:d}=e,g=e.getToken();if(143360&g)if(o=Je(e,t,n,s,0,1,a,1,l),1077936155===e.getToken()){2&e.assignable&&e.report(26),Q(e,32|t),r?.addVarOrBlock(t,d,s,c);const u=Ie(e,t,n,1,a,e.tokenStart);o=e.finishNode(i?{type:"AssignmentPattern",left:o,right:u}:{type:"AssignmentExpression",operator:"=",left:o,right:u},l),p|=256&e.destructible?256:128&e.destructible?128:0}else 18===e.getToken()||20===e.getToken()?(2&e.assignable?p|=16:r?.addVarOrBlock(t,d,s,c),p|=256&e.destructible?256:128&e.destructible?128:0):(p|=1&s?32:2&s?0:16,o=je(e,t,n,o,a,0,l),18!==e.getToken()&&20!==e.getToken()?(1077936155!==e.getToken()&&(p|=16),o=Re(e,t,n,a,i,l,o)):1077936155!==e.getToken()&&(p|=2&e.assignable?16:32));else 2097152&g?(o=2162700===e.getToken()?lt(e,t,r,n,0,a,i,s,c):at(e,t,r,n,0,a,i,s,c),p|=e.destructible,e.assignable=16&e.destructible?2:1,18===e.getToken()||20===e.getToken()?2&e.assignable&&(p|=16):8&e.destructible?e.report(71):(o=je(e,t,n,o,a,0,l),p=2&e.assignable?16:0,18!==e.getToken()&&20!==e.getToken()?o=Re(e,t,n,a,i,l,o):1077936155!==e.getToken()&&(p|=2&e.assignable?16:32))):14===g?(o=st(e,t,r,n,20,s,c,0,a,i),p|=e.destructible,18!==e.getToken()&&20!==e.getToken()&&e.report(30,I[255&e.getToken()])):(o=Ge(e,t,n,1,0,1),18!==e.getToken()&&20!==e.getToken()?(o=Re(e,t,n,a,i,l,o),3&s||67174411!==g||(p|=16)):2&e.assignable?p|=16:67174411===g&&(p|=1&e.assignable&&3&s?32:16));if(u.push(o),!U(e,32|t,18))break;if(20===e.getToken())break}P(e,t,20);const d=e.finishNode({type:i?"ArrayPattern":"ArrayExpression",elements:u},l);return!o&&4194304&e.getToken()?it(e,t,n,p,a,i,l,d):(e.destructible=p,d)}function it(e,t,r,n,o,a,i,s){1077936155!==e.getToken()&&e.report(26),Q(e,32|t),16&n&&e.report(26),a||O(e,s);const{tokenStart:c}=e,l=Ie(e,t,r,1,o,c);return e.destructible=72^(72|n)|(128&e.destructible?128:0)|(256&e.destructible?256:0),e.finishNode(a?{type:"AssignmentPattern",left:s,right:l}:{type:"AssignmentExpression",left:s,operator:"=",right:l},i)}function st(e,t,r,n,o,a,i,s,c,l){const{tokenStart:u}=e;Q(e,32|t);let p=null,d=0;const{tokenValue:g,tokenStart:f}=e;let k=e.getToken();if(143360&k)e.assignable=1,p=Je(e,t,n,a,0,1,c,1,f),k=e.getToken(),p=je(e,t,n,p,c,0,f),18!==e.getToken()&&e.getToken()!==o&&(2&e.assignable&&1077936155===e.getToken()&&e.report(71),d|=16,p=Re(e,t,n,c,l,f,p)),2&e.assignable?d|=16:k===o||18===k?r?.addVarOrBlock(t,g,a,i):d|=32,d|=128&e.destructible?128:0;else if(k===o)e.report(41);else{if(!(2097152&k)){d|=32,p=Ge(e,t,n,1,c,1);const{tokenStart:r}=e,a=e.getToken();return 1077936155===a?(2&e.assignable&&e.report(26),p=Re(e,t,n,c,l,r,p),d|=16):(18===a?d|=16:a!==o&&(p=Re(e,t,n,c,l,r,p)),d|=1&e.assignable?32:16),e.destructible=d,e.getToken()!==o&&18!==e.getToken()&&e.report(161),e.finishNode({type:l?"RestElement":"SpreadElement",argument:p},u)}p=2162700===e.getToken()?lt(e,t,r,n,1,c,l,a,i):at(e,t,r,n,1,c,l,a,i),k=e.getToken(),1077936155!==k&&k!==o&&18!==k?(8&e.destructible&&e.report(71),p=je(e,t,n,p,c,0,f),d|=2&e.assignable?16:0,4194304&~e.getToken()?(8388608&~e.getToken()||(p=Pe(e,t,n,1,f,4,k,p)),U(e,32|t,22)&&(p=Ue(e,t,n,p,f)),d|=2&e.assignable?16:32):(1077936155!==e.getToken()&&(d|=16),p=Re(e,t,n,c,l,f,p))):d|=1074790415===o&&1077936155!==k?16:e.destructible}if(e.getToken()!==o)if(1&a&&(d|=s?16:32),U(e,32|t,1077936155)){16&d&&e.report(26),O(e,p);const r=Ie(e,t,n,1,c,e.tokenStart);p=e.finishNode(l?{type:"AssignmentPattern",left:p,right:r}:{type:"AssignmentExpression",left:p,operator:"=",right:r},f),d=16}else d|=16;return e.destructible=d,e.finishNode({type:l?"RestElement":"SpreadElement",argument:p},u)}function ct(e,t,r,n,o,a){const i=11264|(64&n?0:16896);t=98560|((t|i)^i|(8&n?1024:0)|(16&n?2048:0)|(64&n?16384:0));let s=e.createScopeIfLexical(256);const c=function(e,t,r,n,o,a,i){P(e,t,67174411);const s=[];if(e.flags=128^(128|e.flags),16===e.getToken())return 512&o&&e.report(37,"Setter","one",""),Q(e,t),s;256&o&&e.report(37,"Getter","no","s");512&o&&14===e.getToken()&&e.report(38);t=131072^(131072|t);let c=0,l=0;for(;18!==e.getToken();){let u=null;const{tokenStart:p}=e;if(143360&e.getToken()?(1&t||(36864&~e.getToken()||(e.flags|=256),537079808&~e.getToken()||(e.flags|=512)),u=Et(e,t,r,1|o,0)):(2162700===e.getToken()?u=lt(e,t,r,n,1,i,1,a,0):69271571===e.getToken()?u=at(e,t,r,n,1,i,1,a,0):14===e.getToken()&&(u=st(e,t,r,n,16,a,0,0,i,1)),l=1,48&e.destructible&&e.report(50)),1077936155===e.getToken()){Q(e,32|t),l=1;const r=Ie(e,t,n,1,0,e.tokenStart);u=e.finishNode({type:"AssignmentPattern",left:u,right:r},p)}if(c++,s.push(u),!U(e,t,18))break;if(16===e.getToken())break}512&o&&1!==c&&e.report(37,"Setter","one","");r?.reportScopeError(),l&&(e.flags|=128);return P(e,t,16),s}(e,-524289&t|8192,s,r,n,1,o);s=s?.createChildScope(64);const l=Oe(e,36864|-655373&t,s,r,0,void 0,s?.parent);return e.finishNode({type:"FunctionExpression",params:c,body:l,async:(16&n)>0,generator:(8&n)>0,id:null},a)}function lt(e,t,r,n,o,a,i,s,c){const{tokenStart:l}=e;Q(e,t);const u=[];let p=0,d=0;for(t=131072^(131072|t);1074790415!==e.getToken();){const{tokenValue:o,tokenStart:l}=e,g=e.getToken();if(14===g)u.push(st(e,t,r,n,1074790415,s,c,0,a,i));else{let f,k=0,h=null;if(143360&e.getToken()||-2147483528===e.getToken()||-2147483527===e.getToken())if(-2147483527===e.getToken()&&(p|=16),h=tt(e,t),18===e.getToken()||1074790415===e.getToken()||1077936155===e.getToken())if(k|=4,1&t&&!(537079808&~g)?p|=16:G(e,t,s,g,0),r?.addVarOrBlock(t,o,s,c),U(e,32|t,1077936155)){p|=8;const r=Ie(e,t,n,1,a,e.tokenStart);p|=256&e.destructible?256:128&e.destructible?128:0,f=e.finishNode({type:"AssignmentPattern",left:e.options.uniqueKeyInPattern?Object.assign({},h):h,right:r},l)}else p|=(209006===g?128:0)|(-2147483528===g?16:0),f=e.options.uniqueKeyInPattern?Object.assign({},h):h;else if(U(e,32|t,21)){const{tokenStart:l}=e;if("__proto__"===o&&d++,143360&e.getToken()){const o=e.getToken(),u=e.tokenValue;f=Je(e,t,n,s,0,1,a,1,l);const d=e.getToken();f=je(e,t,n,f,a,0,l),18===e.getToken()||1074790415===e.getToken()?1077936155===d||1074790415===d||18===d?(p|=128&e.destructible?128:0,2&e.assignable?p|=16:143360&~o||r?.addVarOrBlock(t,u,s,c)):p|=1&e.assignable?32:16:4194304&~e.getToken()?(p|=16,8388608&~e.getToken()||(f=Pe(e,t,n,1,l,4,d,f)),U(e,32|t,22)&&(f=Ue(e,t,n,f,l))):(2&e.assignable?p|=16:1077936155!==d?p|=32:r?.addVarOrBlock(t,u,s,c),f=Re(e,t,n,a,i,l,f))}else 2097152&~e.getToken()?(f=Ge(e,t,n,1,a,1),p|=1&e.assignable?32:16,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(p|=16):(f=je(e,t,n,f,a,0,l),p=2&e.assignable?16:0,18!==e.getToken()&&1074790415!==g&&(1077936155!==e.getToken()&&(p|=16),f=Re(e,t,n,a,i,l,f)))):(f=69271571===e.getToken()?at(e,t,r,n,0,a,i,s,c):lt(e,t,r,n,0,a,i,s,c),p=e.destructible,e.assignable=16&p?2:1,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(p|=16):8&e.destructible?e.report(71):(f=je(e,t,n,f,a,0,l),p=2&e.assignable?16:0,4194304&~e.getToken()?(8388608&~e.getToken()||(f=Pe(e,t,n,1,l,4,g,f)),U(e,32|t,22)&&(f=Ue(e,t,n,f,l)),p|=2&e.assignable?16:32):f=Be(e,t,n,a,i,l,f)))}else 69271571===e.getToken()?(p|=16,209005===g&&(k|=16),k|=2|(209008===g?256:209009===g?512:1),h=ut(e,t,n,a),p|=e.assignable,f=ct(e,t,n,k,a,e.tokenStart)):143360&e.getToken()?(p|=16,-2147483528===g&&e.report(95),209005===g?(1&e.flags&&e.report(132),k|=17):209008===g?k|=256:209009===g?k|=512:e.report(0),h=tt(e,t),f=ct(e,t,n,k,a,e.tokenStart)):67174411===e.getToken()?(p|=16,k|=1,f=ct(e,t,n,k,a,e.tokenStart)):8391476===e.getToken()?(p|=16,209008===g?e.report(42):209009===g?e.report(43):209005!==g&&e.report(30,I[52]),Q(e,t),k|=9|(209005===g?16:0),143360&e.getToken()?h=tt(e,t):134217728&~e.getToken()?69271571===e.getToken()?(k|=2,h=ut(e,t,n,a),p|=e.assignable):e.report(30,I[255&e.getToken()]):h=rt(e,t),f=ct(e,t,n,k,a,e.tokenStart)):134217728&~e.getToken()?e.report(133):(209005===g&&(k|=16),k|=209008===g?256:209009===g?512:1,p|=16,h=rt(e,t),f=ct(e,t,n,k,a,e.tokenStart));else if(134217728&~e.getToken())if(69271571===e.getToken())if(h=ut(e,t,n,a),p|=256&e.destructible?256:0,k|=2,21===e.getToken()){Q(e,32|t);const{tokenStart:o,tokenValue:l}=e,u=e.getToken();if(143360&e.getToken()){f=Je(e,t,n,s,0,1,a,1,o);const d=e.getToken();f=je(e,t,n,f,a,0,o),4194304&~e.getToken()?18===e.getToken()||1074790415===e.getToken()?1077936155===d||1074790415===d||18===d?2&e.assignable?p|=16:143360&~u||r?.addVarOrBlock(t,l,s,c):p|=1&e.assignable?32:16:(p|=16,f=Re(e,t,n,a,i,o,f)):(p|=2&e.assignable?16:1077936155===d?0:32,f=Be(e,t,n,a,i,o,f))}else 2097152&~e.getToken()?(f=Ge(e,t,n,1,0,1),p|=1&e.assignable?32:16,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(p|=16):(f=je(e,t,n,f,a,0,o),p=1&e.assignable?0:16,18!==e.getToken()&&1074790415!==e.getToken()&&(1077936155!==e.getToken()&&(p|=16),f=Re(e,t,n,a,i,o,f)))):(f=69271571===e.getToken()?at(e,t,r,n,0,a,i,s,c):lt(e,t,r,n,0,a,i,s,c),p=e.destructible,e.assignable=16&p?2:1,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(p|=16):8&p?e.report(62):(f=je(e,t,n,f,a,0,o),p=2&e.assignable?16|p:0,4194304&~e.getToken()?(8388608&~e.getToken()||(f=Pe(e,t,n,1,o,4,g,f)),U(e,32|t,22)&&(f=Ue(e,t,n,f,o)),p|=2&e.assignable?16:32):(1077936155!==e.getToken()&&(p|=16),f=Be(e,t,n,a,i,o,f))))}else 67174411===e.getToken()?(k|=1,f=ct(e,t,n,k,a,e.tokenStart),p=16):e.report(44);else if(8391476===g)if(P(e,32|t,8391476),k|=8,143360&e.getToken()){const r=e.getToken();if(h=tt(e,t),k|=1,67174411!==e.getToken())throw new N(e.tokenStart,e.currentLocation,209005===r?46:209008===r||209009===e.getToken()?45:47,I[255&r]);p|=16,f=ct(e,t,n,k,a,e.tokenStart)}else 134217728&~e.getToken()?69271571===e.getToken()?(p|=16,k|=3,h=ut(e,t,n,a),f=ct(e,t,n,k,a,e.tokenStart)):e.report(126):(p|=16,h=rt(e,t),k|=1,f=ct(e,t,n,k,a,e.tokenStart));else e.report(30,I[255&g]);else if(h=rt(e,t),21===e.getToken()){P(e,32|t,21);const{tokenStart:l}=e;if("__proto__"===o&&d++,143360&e.getToken()){f=Je(e,t,n,s,0,1,a,1,l);const{tokenValue:o}=e,u=e.getToken();f=je(e,t,n,f,a,0,l),18===e.getToken()||1074790415===e.getToken()?1077936155===u||1074790415===u||18===u?2&e.assignable?p|=16:r?.addVarOrBlock(t,o,s,c):p|=1&e.assignable?32:16:1077936155===e.getToken()?(2&e.assignable&&(p|=16),f=Re(e,t,n,a,i,l,f)):(p|=16,f=Re(e,t,n,a,i,l,f))}else 2097152&~e.getToken()?(f=Ge(e,t,n,1,0,1),p|=1&e.assignable?32:16,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(p|=16):(f=je(e,t,n,f,a,0,l),p=1&e.assignable?0:16,18!==e.getToken()&&1074790415!==e.getToken()&&(1077936155!==e.getToken()&&(p|=16),f=Re(e,t,n,a,i,l,f)))):(f=69271571===e.getToken()?at(e,t,r,n,0,a,i,s,c):lt(e,t,r,n,0,a,i,s,c),p=e.destructible,e.assignable=16&p?2:1,18===e.getToken()||1074790415===e.getToken()?2&e.assignable&&(p|=16):8&~e.destructible&&(f=je(e,t,n,f,a,0,l),p=2&e.assignable?16:0,4194304&~e.getToken()?(8388608&~e.getToken()||(f=Pe(e,t,n,1,l,4,g,f)),U(e,32|t,22)&&(f=Ue(e,t,n,f,l)),p|=2&e.assignable?16:32):f=Be(e,t,n,a,i,l,f)))}else 67174411===e.getToken()?(k|=1,f=ct(e,t,n,k,a,e.tokenStart),p=16|e.assignable):e.report(134);p|=128&e.destructible?128:0,e.destructible=p,u.push(e.finishNode({type:"Property",key:h,value:f,kind:768&k?512&k?"set":"get":"init",computed:(2&k)>0,method:(1&k)>0,shorthand:(4&k)>0},l))}if(p|=e.destructible,18!==e.getToken())break;Q(e,t)}P(e,t,1074790415),d>1&&(p|=64);const g=e.finishNode({type:i?"ObjectPattern":"ObjectExpression",properties:u},l);return!o&&4194304&e.getToken()?it(e,t,n,p,a,i,l,g):(e.destructible=p,g)}function ut(e,t,r,n){Q(e,32|t);const o=Ie(e,131072^(131072|t),r,1,n,e.tokenStart);return P(e,t,20),o}function pt(e,t,r){const{tokenStart:n}=e,{tokenValue:o}=e;let a=0,i=0;537079808&~e.getToken()?36864&~e.getToken()||(i=1):a=1;const s=tt(e,t);if(e.assignable=1,10===e.getToken()){const c=e.options.lexical?ce(e,t,o):void 0;return a&&(e.flags|=128),i&&(e.flags|=256),ft(e,t,c,r,[s],0,n)}return s}function dt(e,t,r,n,o,a,i,s,c){i||e.report(57),a&&e.report(51),e.flags&=-129;return ft(e,t,e.options.lexical?ce(e,t,n):void 0,r,[o],s,c)}function gt(e,t,r,n,o,a,i,s){a||e.report(57);for(let t=0;t<o.length;++t)O(e,o[t]);return ft(e,t,r,n,o,i,s)}function ft(e,t,r,n,o,a,i){1&e.flags&&e.report(48),P(e,32|t,10);const s=535552;t=(t|s)^s|(a?2048:0);const c=2162700!==e.getToken();let l;if(r?.reportScopeError(),c)e.flags=4928^(4928|e.flags),l=Ie(e,t,n,1,0,e.tokenStart);else{r=r?.createChildScope(64);const o=131084;switch(l=Oe(e,(t|o)^o|4096,r,n,16,void 0,void 0),e.getToken()){case 69271571:1&e.flags||e.report(116);break;case 67108877:case 67174409:case 22:e.report(117);case 67174411:1&e.flags||e.report(116),e.flags|=1024}8388608&~e.getToken()||1&e.flags||e.report(30,I[255&e.getToken()]),33619968&~e.getToken()||e.report(125)}return e.assignable=2,e.finishNode({type:"ArrowFunctionExpression",params:o,body:l,async:1===a,expression:c,generator:!1},i)}function kt(e,t,r,n,o,a){P(e,t,67174411),e.flags=128^(128|e.flags);const i=[];if(U(e,t,16))return i;t=131072^(131072|t);let s=0;for(;18!==e.getToken();){let c;const{tokenStart:l}=e,u=e.getToken();if(143360&u?(1&t||(36864&~u||(e.flags|=256),537079808&~u||(e.flags|=512)),c=Et(e,t,r,1|a,0)):(2162700===u?c=lt(e,t,r,n,1,o,1,a,0):69271571===u?c=at(e,t,r,n,1,o,1,a,0):14===u?c=st(e,t,r,n,16,a,0,0,o,1):e.report(30,I[255&u]),s=1,48&e.destructible&&e.report(50)),1077936155===e.getToken()){Q(e,32|t),s=1;const r=Ie(e,t,n,1,o,e.tokenStart);c=e.finishNode({type:"AssignmentPattern",left:c,right:r},l)}if(i.push(c),!U(e,t,18))break;if(16===e.getToken())break}return s&&(e.flags|=128),(s||1&t)&&r?.reportScopeError(),P(e,t,16),i}function ht(e,t,r,n,o,a){const i=e.getToken();if(67108864&i){if(67108877===i){Q(e,262144|t),e.assignable=1;const o=Fe(e,t,r);return ht(e,t,r,e.finishNode({type:"MemberExpression",object:n,computed:!1,property:o,optional:!1},a),0,a)}if(69271571===i){Q(e,32|t);const{tokenStart:i}=e,s=De(e,t,r,o,1,i);return P(e,t,20),e.assignable=1,ht(e,t,r,e.finishNode({type:"MemberExpression",object:n,computed:!0,property:s,optional:!1},a),0,a)}if(67174408===i||67174409===i)return e.assignable=2,ht(e,t,r,e.finishNode({type:"TaggedTemplateExpression",tag:n,quasi:67174408===e.getToken()?Ke(e,64|t,r):Ze(e,64|t)},a),0,a)}return n}function mt(e,t,r,n,o){return 209006===e.getToken()&&e.report(31),1025&t&&241771===e.getToken()&&e.report(32),z(e,t,e.getToken()),36864&~e.getToken()||(e.flags|=256),dt(e,-524289&t|2048,r,e.tokenValue,tt(e,t),0,n,1,o)}function bt(e,t,r,n,o,a,i,s,c){Q(e,32|t);const l=e.createScopeIfLexical()?.createChildScope(512);if(U(e,t=131072^(131072|t),16))return 10===e.getToken()?(1&s&&e.report(48),gt(e,t,l,r,[],o,1,c)):e.finishNode({type:"CallExpression",callee:n,arguments:[],optional:!1},c);let u=0,p=null,d=0;e.destructible=384^(384|e.destructible);const g=[];for(;16!==e.getToken();){const{tokenStart:o}=e,s=e.getToken();if(143360&s)l?.addBlockName(t,e.tokenValue,a,0),537079808&~s?36864&~s||(e.flags|=256):e.flags|=512,p=Je(e,t,r,a,0,1,1,1,o),16===e.getToken()||18===e.getToken()?2&e.assignable&&(u|=16,d=1):(1077936155===e.getToken()?d=1:u|=16,p=je(e,t,r,p,1,0,o),16!==e.getToken()&&18!==e.getToken()&&(p=Re(e,t,r,1,0,o,p)));else if(2097152&s)p=2162700===s?lt(e,t,l,r,0,1,0,a,i):at(e,t,l,r,0,1,0,a,i),u|=e.destructible,d=1,16!==e.getToken()&&18!==e.getToken()&&(8&u&&e.report(122),p=je(e,t,r,p,0,0,o),u|=16,8388608&~e.getToken()||(p=Pe(e,t,r,1,c,4,s,p)),U(e,32|t,22)&&(p=Ue(e,t,r,p,c)));else{if(14!==s){for(p=Ie(e,t,r,1,0,o),u=e.assignable,g.push(p);U(e,32|t,18);)g.push(Ie(e,t,r,1,0,o));return u|=e.assignable,P(e,t,16),e.destructible=16|u,e.assignable=2,e.finishNode({type:"CallExpression",callee:n,arguments:g,optional:!1},c)}p=st(e,t,l,r,16,a,i,1,1,0),u|=(16===e.getToken()?0:16)|e.destructible,d=1}if(g.push(p),!U(e,32|t,18))break}return P(e,t,16),u|=256&e.destructible?256:128&e.destructible?128:0,10===e.getToken()?(48&u&&e.report(27),(1&e.flags||1&s)&&e.report(48),128&u&&e.report(31),1025&t&&256&u&&e.report(32),d&&(e.flags|=128),gt(e,2048|t,l,r,g,o,1,c)):(64&u&&e.report(63),8&u&&e.report(62),e.assignable=2,e.finishNode({type:"CallExpression",callee:n,arguments:g,optional:!1},c))}function Tt(e,t,r,n,o){let a,i;e.leadingDecorators.decorators.length?(132===e.getToken()&&e.report(30,"@"),a=e.leadingDecorators.start,i=[...e.leadingDecorators.decorators],e.leadingDecorators.decorators.length=0):(a=e.tokenStart,i=yt(e,t,n)),Q(e,t=16384^(16385|t));let s=null,c=null;const{tokenValue:l}=e;4096&e.getToken()&&20565!==e.getToken()?(F(e,t,e.getToken())&&e.report(118),537079808&~e.getToken()||e.report(119),r&&(r.addBlockName(t,l,32,0),o&&2&o&&e.declareUnboundVariable(l)),s=tt(e,t)):1&o||e.report(39,"Class");let u=t;U(e,32|t,20565)?(c=Ge(e,t,n,0,0,0),u|=512):u=512^(512|u);const p=wt(e,u,t,r,n,2,8,0);return e.finishNode({type:"ClassDeclaration",id:s,superClass:c,body:p,...e.options.next?{decorators:i}:null},a)}function yt(e,t,r){const n=[];if(e.options.next)for(;132===e.getToken();)n.push(xt(e,t,r));return n}function xt(e,t,r){const n=e.tokenStart;Q(e,32|t);let o=Je(e,t,r,2,0,1,0,1,n);return o=je(e,t,r,o,0,0,e.tokenStart),e.finishNode({type:"Decorator",expression:o},n)}function wt(e,t,r,n,o,a,i,s){const{tokenStart:c}=e,l=e.createPrivateScopeIfLexical(o);P(e,32|t,2162700);const u=655360;t=(t|u)^u;const p=32&e.flags;e.flags=32^(32|e.flags);const d=[];for(;1074790415!==e.getToken();){const o=e.tokenStart,i=yt(e,t,l);i.length>0&&"constructor"===e.tokenValue&&e.report(109),1074790415===e.getToken()&&e.report(108),U(e,t,1074790417)?i.length>0&&e.report(120):d.push(St(e,t,n,l,r,a,i,0,s,i.length>0?o:e.tokenStart))}return P(e,8&i?32|t:t,1074790415),l?.validatePrivateIdentifierRefs(),e.flags=-33&e.flags|p,e.finishNode({type:"ClassBody",body:d},c)}function St(e,t,r,n,o,a,i,s,c,l){let u=s?32:0,p=null;const d=e.getToken();if(176128&d||-2147483528===d)switch(p=tt(e,t),d){case 36970:if(!s&&67174411!==e.getToken()&&1048576&~e.getToken()&&1077936155!==e.getToken())return St(e,t,r,n,o,a,i,1,c,l);break;case 209005:if(67174411!==e.getToken()&&!(1&e.flags)){if(!(1073741824&~e.getToken()))return Ct(e,t,n,p,u,i,l);u|=16|(B(e,t,8391476)?8:0)}break;case 209008:if(67174411!==e.getToken()){if(!(1073741824&~e.getToken()))return Ct(e,t,n,p,u,i,l);u|=256}break;case 209009:if(67174411!==e.getToken()){if(!(1073741824&~e.getToken()))return Ct(e,t,n,p,u,i,l);u|=512}break;case 12402:if(67174411!==e.getToken()&&!(1&e.flags)){if(!(1073741824&~e.getToken()))return Ct(e,t,n,p,u,i,l);e.options.next&&(u|=1024)}}else if(69271571===d)u|=2,p=ut(e,o,n,c);else if(134217728&~d)if(8391476===d)u|=8,Q(e,t);else if(130===e.getToken())u|=8192,p=vt(e,16|t,n,768);else if(1073741824&~e.getToken()){if(s&&2162700===d)return function(e,t,r,n,o){return r=r?.createChildScope(),ke(e,t=592128|5764^(5764|t),r,n,{},o,"StaticBlock")}(e,16|t,r,n,l);-2147483527===d?(p=tt(e,t),67174411!==e.getToken()&&e.report(30,I[255&e.getToken()])):e.report(30,I[255&e.getToken()])}else u|=128;else p=rt(e,t);if(1816&u&&(143360&e.getToken()||-2147483528===e.getToken()||-2147483527===e.getToken()?p=tt(e,t):134217728&~e.getToken()?69271571===e.getToken()?(u|=2,p=ut(e,t,n,0)):130===e.getToken()?(u|=8192,p=vt(e,t,n,u)):e.report(135):p=rt(e,t)),2&u||("constructor"===e.tokenValue?(1073741824&~e.getToken()?32&u||67174411!==e.getToken()||(920&u?e.report(53,"accessor"):512&t||(32&e.flags?e.report(54):e.flags|=32)):e.report(129),u|=64):!(8192&u)&&32&u&&"prototype"===e.tokenValue&&e.report(52)),1024&u||67174411!==e.getToken()&&!(768&u))return Ct(e,t,n,p,u,i,l);const g=ct(e,16|t,n,u,c,e.tokenStart);return e.finishNode({type:"MethodDefinition",kind:!(32&u)&&64&u?"constructor":256&u?"get":512&u?"set":"method",static:(32&u)>0,computed:(2&u)>0,key:p,value:g,...e.options.next?{decorators:i}:null},l)}function vt(e,t,r,n){const{tokenStart:o}=e;Q(e,t);const{tokenValue:a}=e;return"constructor"===a&&e.report(128),e.options.lexical&&(r||e.report(4,a),n?r.addPrivateIdentifier(a,n):r.addPrivateIdentifierRef(a)),Q(e,t),e.finishNode({type:"PrivateIdentifier",name:a},o)}function Ct(e,t,r,n,o,a,i){let s=null;if(8&o&&e.report(0),1077936155===e.getToken()){Q(e,32|t);const{tokenStart:n}=e;537079927===e.getToken()&&e.report(119);const a=11264|(64&o?0:16896);s=Je(e,16|(t=65792|((t|a)^a|(8&o?1024:0)|(16&o?2048:0)|(64&o?16384:0))),r,2,0,1,0,1,n),!(1073741824&~e.getToken())&&4194304&~e.getToken()||(s=je(e,16|t,r,s,0,0,n),s=Re(e,16|t,r,0,0,n,s))}return D(e,t),e.finishNode({type:1024&o?"AccessorProperty":"PropertyDefinition",key:n,value:s,static:(32&o)>0,computed:(2&o)>0,...e.options.next?{decorators:a}:null},i)}function qt(e,t,r,n,o,a){if(143360&e.getToken()||!(1&t)&&-2147483527===e.getToken())return Et(e,t,r,o,a);2097152&~e.getToken()&&e.report(30,I[255&e.getToken()]);const i=69271571===e.getToken()?at(e,t,r,n,1,0,1,o,a):lt(e,t,r,n,1,0,1,o,a);return 16&e.destructible&&e.report(50),32&e.destructible&&e.report(50),i}function Et(e,t,r,n,o){const a=e.getToken();1&t&&(537079808&~a?36864&~a&&-2147483527!==a||e.report(118):e.report(119)),20480&~a||e.report(102),241771===a&&(1024&t&&e.report(32),2&t&&e.report(111)),73==(255&a)&&24&n&&e.report(100),209006===a&&(2048&t&&e.report(176),2&t&&e.report(110));const{tokenValue:i,tokenStart:s}=e;return Q(e,t),r?.addVarOrBlock(t,i,n,o),e.finishNode({type:"Identifier",name:i},s)}function Nt(e,t,r,n,o){if(n||P(e,t,8456256),8390721===e.getToken()){const a=function(e,t){return ae(e),e.finishNode({type:"JSXOpeningFragment"},t)}(e,o),[i,s]=function(e,t,r,n){const o=[];for(;;){const a=At(e,t,r,n);if("JSXClosingFragment"===a.type)return[o,a];o.push(a)}}(e,t,r,n);return e.finishNode({type:"JSXFragment",openingFragment:a,children:i,closingFragment:s},o)}8457014===e.getToken()&&e.report(30,I[255&e.getToken()]);let a=null,i=[];const s=function(e,t,r,n,o){143360&~e.getToken()&&4096&~e.getToken()&&e.report(0);const a=Vt(e,t),i=function(e,t,r){const n=[];for(;8457014!==e.getToken()&&8390721!==e.getToken()&&1048576!==e.getToken();)n.push(Rt(e,t,r));return n}(e,t,r),s=8457014===e.getToken();s&&P(e,t,8457014);8390721!==e.getToken()&&e.report(25,I[65]);n||!s?ae(e):Q(e,t);return e.finishNode({type:"JSXOpeningElement",name:a,attributes:i,selfClosing:s},o)}(e,t,r,n,o);if(!s.selfClosing){[i,a]=function(e,t,r,n){const o=[];for(;;){const a=Lt(e,t,r,n);if("JSXClosingElement"===a.type)return[o,a];o.push(a)}}(e,t,r,n);const o=M(a.name);M(s.name)!==o&&e.report(155,o)}return e.finishNode({type:"JSXElement",children:i,openingElement:s,closingElement:a},o)}function Lt(e,t,r,n){if(137===e.getToken())return It(e,t);if(2162700===e.getToken())return Ut(e,t,r,1,0);if(8456256===e.getToken()){const{tokenStart:o}=e;return Q(e,t),8457014===e.getToken()?function(e,t,r,n){P(e,t,8457014);const o=Vt(e,t);return 8390721!==e.getToken()&&e.report(25,I[65]),r?ae(e):Q(e,t),e.finishNode({type:"JSXClosingElement",name:o},n)}(e,t,n,o):Nt(e,t,r,1,o)}e.report(0)}function At(e,t,r,n){if(137===e.getToken())return It(e,t);if(2162700===e.getToken())return Ut(e,t,r,1,0);if(8456256===e.getToken()){const{tokenStart:o}=e;return Q(e,t),8457014===e.getToken()?function(e,t,r,n){return P(e,t,8457014),8390721!==e.getToken()&&e.report(25,I[65]),r?ae(e):Q(e,t),e.finishNode({type:"JSXClosingFragment"},n)}(e,t,n,o):Nt(e,t,r,1,o)}e.report(0)}function It(e,t){const r=e.tokenStart;Q(e,t);const n={type:"JSXText",value:e.tokenValue};return e.options.raw&&(n.raw=e.tokenRaw),e.finishNode(n,r)}function Vt(e,t){const{tokenStart:r}=e;ie(e);let n=Pt(e,t);if(21===e.getToken())return Bt(e,t,n,r);for(;U(e,t,67108877);)ie(e),n=Dt(e,t,n,r);return n}function Dt(e,t,r,n){const o=Pt(e,t);return e.finishNode({type:"JSXMemberExpression",object:r,property:o},n)}function Rt(e,t,r){const{tokenStart:n}=e;if(2162700===e.getToken())return function(e,t,r){const n=e.tokenStart;Q(e,t),P(e,t,14);const o=Ie(e,t,r,1,0,e.tokenStart);return P(e,t,1074790415),e.finishNode({type:"JSXSpreadAttribute",argument:o},n)}(e,t,r);ie(e);let o=null,a=Pt(e,t);if(21===e.getToken()&&(a=Bt(e,t,a,n)),1077936155===e.getToken()){switch(oe(e,t)){case 134283267:o=rt(e,t);break;case 8456256:o=Nt(e,t,r,0,e.tokenStart);break;case 2162700:o=Ut(e,t,r,0,1);break;default:e.report(154)}}return e.finishNode({type:"JSXAttribute",value:o,name:a},n)}function Bt(e,t,r,n){P(e,t,21);const o=Pt(e,t);return e.finishNode({type:"JSXNamespacedName",namespace:r,name:o},n)}function Ut(e,t,r,n,o){const{tokenStart:a}=e;Q(e,32|t);const{tokenStart:i}=e;if(14===e.getToken())return function(e,t,r,n){P(e,t,14);const o=Ie(e,t,r,1,0,e.tokenStart);return P(e,t,1074790415),e.finishNode({type:"JSXSpreadChild",expression:o},n)}(e,t,r,a);let s=null;return 1074790415===e.getToken()?(o&&e.report(157),s=function(e,t){return e.finishNode({type:"JSXEmptyExpression"},t,e.tokenStart)}(e,{index:e.startIndex,line:e.startLine,column:e.startColumn})):s=Ie(e,t,r,1,0,i),1074790415!==e.getToken()&&e.report(25,I[15]),n?ae(e):Q(e,t),e.finishNode({type:"JSXExpressionContainer",expression:s},a)}function Pt(e,t){const r=e.tokenStart;143360&e.getToken()||e.report(30,I[255&e.getToken()]);const{tokenValue:n}=e;return Q(e,t),e.finishNode({type:"JSXIdentifier",name:n},r)}e.parse=function(e,t){return pe(e,t)},e.parseModule=function(e,t){return pe(e,t,3)},e.parseScript=function(e,t){return pe(e,t)},e.version="6.1.4"}));

},{}],6:[function(require,module,exports){
module.exports={
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
          "https://github.com/advisories/GHSA-rmxg-73gg-4p98",
          "https://github.com/jquery/jquery/issues/2432",
          "https://nvd.nist.gov/vuln/detail/CVE-2015-9251"
        ]
      },
      {
        "atOrAbove": "1.8.0",
        "below": "2.2.0",
        "cwe": [
          "CWE-79"
        ],
        "severity": "medium",
        "identifiers": {
          "summary": "parseHTML() executes scripts in event handlers",
          "issue": "11974"
        },
        "info": [
          "http://research.insecurelabs.org/jquery/test/",
          "https://bugs.jquery.com/ticket/11974"
        ]
      },
      {
        "below": "2.999.999",
        "excludes": [
          "1.12.4-aem"
        ],
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
        "excludes": [
          "1.12.4-aem"
        ],
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
          "https://github.com/advisories/GHSA-rmxg-73gg-4p98",
          "https://github.com/jquery/jquery/issues/2432",
          "https://nvd.nist.gov/vuln/detail/CVE-2015-9251"
        ]
      },
      {
        "atOrAbove": "2.2.2",
        "below": "3.0.0",
        "cwe": [
          "CWE-79"
        ],
        "severity": "medium",
        "identifiers": {
          "summary": "parseHTML() executes scripts in event handlers",
          "issue": "11974"
        },
        "info": [
          "http://research.insecurelabs.org/jquery/test/",
          "https://bugs.jquery.com/ticket/11974"
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
      },
      {
        "atOrAbove": "0",
        "below": "999.999.999",
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
        "atOrAbove": "0",
        "below": "1.16.5",
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
        "atOrAbove": "1.3.1",
        "below": "1.8.4",
        "cwe": [
          "CWE-791"
        ],
        "severity": "medium",
        "identifiers": {
          "summary": "AngularJS Incomplete Filtering of Special Elements vulnerability",
          "CVE": [
            "CVE-2025-2336"
          ],
          "githubID": "GHSA-4p4w-6hg8-63wx"
        },
        "info": [
          "https://github.com/advisories/GHSA-4p4w-6hg8-63wx",
          "https://nvd.nist.gov/vuln/detail/CVE-2025-2336",
          "https://codepen.io/herodevs/pen/bNGYaXx/412a3a4218387479898912f60c269c6c",
          "https://github.com/angular/angular.js",
          "https://www.herodevs.com/vulnerability-directory/cve-2025-2336"
        ]
      },
      {
        "atOrAbove": "1.7.0",
        "below": "1.8.8",
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
      },
      {
        "atOrAbove": "0",
        "below": "1.9.8",
        "cwe": [
          "CWE-791"
        ],
        "severity": "medium",
        "identifiers": {
          "summary": "AngularJS Incomplete Filtering of Special Elements vulnerability",
          "CVE": [
            "CVE-2025-2336"
          ],
          "githubID": "GHSA-4p4w-6hg8-63wx"
        },
        "info": [
          "https://github.com/advisories/GHSA-4p4w-6hg8-63wx",
          "https://nvd.nist.gov/vuln/detail/CVE-2025-2336",
          "https://codepen.io/herodevs/pen/bNGYaXx/412a3a4218387479898912f60c269c6c",
          "https://github.com/angular/angular.js",
          "https://www.herodevs.com/vulnerability-directory/cve-2025-2336"
        ]
      },
      {
        "atOrAbove": "0",
        "below": "1.9.9",
        "cwe": [
          "CWE-1333"
        ],
        "severity": "medium",
        "identifiers": {
          "summary": "AngularJS Regular expression Denial of Service (ReDoS)",
          "CVE": [
            "CVE-2025-4690"
          ],
          "githubID": "GHSA-hfff-63hg-f47j"
        },
        "info": [
          "https://github.com/advisories/GHSA-hfff-63hg-f47j",
          "https://nvd.nist.gov/vuln/detail/CVE-2025-4690",
          "https://codepen.io/herodevs/pen/RNNEPzP/751b91eab7730dff277523f3d50e4b77",
          "https://github.com/angular/angular.js",
          "https://www.herodevs.com/vulnerability-directory/cve-2025-4690"
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
        "below": "999.999.999",
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
        "/\\*[\\*\\s]+(?:@license )?AngularJS(?: NES)? v(§§version§§)",
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
        "return[\\s]+ReactSharedInternals.[a-zA-Z].useHostTransitionStatus\\(\\)[;]?[\\s]*\\}[;,][\\s]*exports.version[\\s]*=[\\s]*\"(§§version§§)\""
      ],
      "ast": [
        "//ObjectExpression/Property[/:key/:name == \"reconcilerVersion\"]/$$:value/:value",
        "//ObjectExpression[       /Property[/:key/:name == \"rendererPackageName\" && /:value/:value == \"react-dom\"]     ]/Property[/:key/:name == \"version\"]/:value/:value",
        "//SequenceExpression[             /AssignmentExpression/:left[/:object/:name == \"exports\" && /:property/:name == \"__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE\"]          ]/AssignmentExpression[             /:left/:object/:name == \"exports\" && /:left/:property/:name == \"version\"         ]/:right/:value",
        "/ExpressionStatement/AssignmentExpression[   /MemberExpression/:property/:name == \"version\" &&   /MemberExpression     [/:$object ==          ../../../ExpressionStatement/AssignmentExpression/MemberExpression[           /:property/:name == \"__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE\"         ]/$:object ||       /Identifier[         /:name == \"exports\" && ../../../../ExpressionStatement/AssignmentExpression/MemberExpression[           /:property/:name == \"__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE\"         ]/Identifier/:name == \"exports\"       ]     ]     ]/$$:right/:value"
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
        "atOrAbove": "2.3.0",
        "below": "3.4.0",
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
        "atOrAbove": "2.3.0",
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
        "atOrAbove": "1.4.0",
        "below": "3.4.2",
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
        "atOrAbove": "3.4.1",
        "below": "3.4.2",
        "severity": "medium",
        "cwe": [
          "CWE-79"
        ],
        "identifiers": {
          "summary": "Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting') vulnerability in Bootstrap allows Cross-Site Scripting (XSS). This issue affects Bootstrap version 3.4.1. At time of publication, there is no publicly available patched version.",
          "githubID": "GHSA-q58r-hwc8-rm9j",
          "CVE": [
            "CVE-2025-1647"
          ]
        },
        "info": [
          "https://lists.debian.org/debian-lts-announce/2025/06/msg00001.html",
          "https://www.herodevs.com/vulnerability-directory/cve-2025-1647"
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
      },
      {
        "atOrAbove": "44.2.0",
        "below": "45.2.2",
        "severity": "low",
        "cwe": [
          "CWE-79"
        ],
        "identifiers": {
          "summary": "### Impact\nA Cross-Site Scripting (XSS) vulnerability has been discovered in the CKEditor 5 clipboard package. This vulnerability could be triggered by a specific user action, leading to unauthorized JavaScript code execution, if the attacker managed to insert a malicious content into the editor, which might happen with a very specific editor configuration.\n\nThis vulnerability affects **only** installations where the editor configuration meets one of the following criteria:\n- [HTML embed plugin](https://ckeditor.com/docs/ckeditor5/latest/features/html/html-embed.html) is enabled\n- Custom plugin introducing editable element which implements view [`RawElement`](https://ckeditor.com/docs/ckeditor5/latest/api/module_engine_view_rawelement-ViewRawElement.html) is enabled\n\n### Patches\nThe problem has been recognized and patched. The fix will be available in version 46.0.3 (and above), and explicitly in version 45.2.2.\n\n### For more information\nEmail us at [security@cksource.com](mailto:security@cksource.com) if you have any questions or comments about this advisory.",
          "githubID": "GHSA-x9gp-vjh6-3wv6",
          "CVE": [
            "CVE-2025-58064"
          ]
        },
        "info": [
          "https://github.com/ckeditor/ckeditor5/security/advisories/GHSA-x9gp-vjh6-3wv6",
          "https://github.com/ckeditor/ckeditor5/commit/b210e90c6cf84e662ef6c7daf93a92355a961bf2"
        ]
      },
      {
        "atOrAbove": "46.0.0",
        "below": "46.0.3",
        "severity": "low",
        "cwe": [
          "CWE-79"
        ],
        "identifiers": {
          "summary": "### Impact\nA Cross-Site Scripting (XSS) vulnerability has been discovered in the CKEditor 5 clipboard package. This vulnerability could be triggered by a specific user action, leading to unauthorized JavaScript code execution, if the attacker managed to insert a malicious content into the editor, which might happen with a very specific editor configuration.\n\nThis vulnerability affects **only** installations where the editor configuration meets one of the following criteria:\n- [HTML embed plugin](https://ckeditor.com/docs/ckeditor5/latest/features/html/html-embed.html) is enabled\n- Custom plugin introducing editable element which implements view [`RawElement`](https://ckeditor.com/docs/ckeditor5/latest/api/module_engine_view_rawelement-ViewRawElement.html) is enabled\n\n### Patches\nThe problem has been recognized and patched. The fix will be available in version 46.0.3 (and above), and explicitly in version 45.2.2.\n\n### For more information\nEmail us at [security@cksource.com](mailto:security@cksource.com) if you have any questions or comments about this advisory.",
          "githubID": "GHSA-x9gp-vjh6-3wv6",
          "CVE": [
            "CVE-2025-58064"
          ]
        },
        "info": [
          "https://github.com/ckeditor/ckeditor5/security/advisories/GHSA-x9gp-vjh6-3wv6",
          "https://github.com/ckeditor/ckeditor5/commit/b210e90c6cf84e662ef6c7daf93a92355a961bf2"
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
        "atOrAbove": "0",
        "below": "0.30.2",
        "severity": "high",
        "cwe": [
          "CWE-770"
        ],
        "identifiers": {
          "summary": "## Summary\n\nWhen Axios runs on Node.js and is given a URL with the `data:` scheme, it does not perform HTTP. Instead, its Node http adapter decodes the entire payload into memory (`Buffer`/`Blob`) and returns a synthetic 200 response.\nThis path ignores `maxContentLength` / `maxBodyLength` (which only protect HTTP responses), so an attacker can supply a very large `data:` URI and cause the process to allocate unbounded memory and crash (DoS), even if the caller requested `responseType: 'stream'`.",
          "githubID": "GHSA-4hjh-wcwx-xvwj",
          "CVE": [
            "CVE-2025-58754"
          ]
        },
        "info": [
          "https://github.com/axios/axios/security/advisories/GHSA-4hjh-wcwx-xvwj",
          "https://github.com/axios/axios/pull/7011",
          "https://github.com/axios/axios/commit/945435fc51467303768202250debb8d4ae892593",
          "https://github.com/axios/axios/releases/tag/v1.12.0"
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
      },
      {
        "atOrAbove": "1.0.0",
        "below": "1.12.0",
        "severity": "high",
        "cwe": [
          "CWE-770"
        ],
        "identifiers": {
          "summary": "## Summary\n\nWhen Axios runs on Node.js and is given a URL with the `data:` scheme, it does not perform HTTP. Instead, its Node http adapter decodes the entire payload into memory (`Buffer`/`Blob`) and returns a synthetic 200 response.\nThis path ignores `maxContentLength` / `maxBodyLength` (which only protect HTTP responses), so an attacker can supply a very large `data:` URI and cause the process to allocate unbounded memory and crash (DoS), even if the caller requested `responseType: 'stream'`.",
          "githubID": "GHSA-4hjh-wcwx-xvwj",
          "CVE": [
            "CVE-2025-58754"
          ]
        },
        "info": [
          "https://github.com/axios/axios/security/advisories/GHSA-4hjh-wcwx-xvwj",
          "https://github.com/axios/axios/pull/7011",
          "https://github.com/axios/axios/commit/945435fc51467303768202250debb8d4ae892593",
          "https://github.com/axios/axios/releases/tag/v1.12.0"
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
        "atOrAbove": "0.9.9",
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
          "CWE-285",
          "CWE-863"
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
          "CWE-285",
          "CWE-863"
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
          "CWE-285",
          "CWE-863"
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
        "atOrAbove": "0.9.9",
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
          "CWE-285",
          "CWE-863"
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
        "atOrAbove": "0.9.9",
        "below": "14.2.31",
        "severity": "medium",
        "cwe": [
          "CWE-524"
        ],
        "identifiers": {
          "summary": "A vulnerability in Next.js Image Optimization has been fixed in v15.4.5 and v14.2.31. When images returned from API routes vary based on request headers (such as `Cookie` or `Authorization`), these responses could be incorrectly cached and served to unauthorized users due to a cache key confusion bug.\n\nAll users are encouraged to upgrade if they use API routes to serve images that depend on request headers and have image optimization enabled.\n\nMore details at [Vercel Changelog](https://vercel.com/changelog/cve-2025-57752)",
          "githubID": "GHSA-g5qg-72qw-gw5v",
          "CVE": [
            "CVE-2025-57752"
          ]
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-g5qg-72qw-gw5v",
          "https://github.com/vercel/next.js/pull/82114",
          "https://github.com/vercel/next.js/commit/6b12c60c61ee80cb0443ccd20de82ca9b4422ddd",
          "https://vercel.com/changelog/cve-2025-57752"
        ]
      },
      {
        "atOrAbove": "0.9.9",
        "below": "14.2.31",
        "severity": "medium",
        "cwe": [
          "CWE-20"
        ],
        "identifiers": {
          "summary": "A vulnerability in **Next.js Image Optimization** has been fixed in **v15.4.5** and **v14.2.31**. The issue allowed attacker-controlled external image sources to trigger file downloads with arbitrary content and filenames under specific configurations. This behavior could be abused for phishing or malicious file delivery.\n\nAll users relying on `images.domains` or `images.remotePatterns` are encouraged to upgrade and verify that external image sources are strictly validated.\n\nMore details at [Vercel Changelog](https://vercel.com/changelog/cve-2025-55173)",
          "githubID": "GHSA-xv57-4mr9-wg8v",
          "CVE": [
            "CVE-2025-55173"
          ]
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-xv57-4mr9-wg8v",
          "https://github.com/vercel/next.js/commit/6b12c60c61ee80cb0443ccd20de82ca9b4422ddd",
          "https://vercel.com/changelog/cve-2025-55173",
          "http://vercel.com/changelog/cve-2025-55173"
        ]
      },
      {
        "atOrAbove": "0.9.9",
        "below": "14.2.32",
        "severity": "medium",
        "cwe": [
          "CWE-918"
        ],
        "identifiers": {
          "summary": "A vulnerability in **Next.js Middleware** has been fixed in **v14.2.32** and **v15.4.7**. The issue occurred when request headers were directly passed into `NextResponse.next()`. In self-hosted applications, this could allow Server-Side Request Forgery (SSRF) if certain sensitive headers from the incoming request were reflected back into the response.\n\nAll users implementing custom middleware logic in self-hosted environments are strongly encouraged to upgrade and verify correct usage of the `next()` function.\n\nMore details at [Vercel Changelog](https://vercel.com/changelog/cve-2025-57822)",
          "githubID": "GHSA-4342-x723-ch2f",
          "CVE": [
            "CVE-2025-57822"
          ]
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-4342-x723-ch2f",
          "https://github.com/vercel/next.js/commit/9c9aaed5bb9338ef31b0517ccf0ab4414f2093d8",
          "https://vercel.com/changelog/cve-2025-57822"
        ]
      },
      {
        "atOrAbove": "13.3.0",
        "below": "14.2.34",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "13.3.1-canary.0",
        "below": "14.2.35",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
        ]
      },
      {
        "atOrAbove": "14.3.0-canary.77",
        "below": "15.0.5",
        "severity": "critical",
        "cwe": [
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages<sup>1</sup> for versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182). \n\nFixed in:\nReact: 19.0.1, 19.1.2, 19.2.1\nNext.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7\n\nThe vulnerability also affects experimental canary releases starting with 14.3.0-canary.77. Users on any of the 14.3 canary builds should either downgrade to a 14.x stable release or 14.3.0-canary.76.\n\nAll users of stable 15.x or 16.x Next.js versions should upgrade to a patched, stable version immediately.\n\n<sup>1</sup> The affected React packages are:\n- react-server-dom-parcel\n- react-server-dom-turbopack\n- react-server-dom-webpack",
          "githubID": "GHSA-9qr9-h5gf-34mp"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp"
        ]
      },
      {
        "atOrAbove": "15.0.0-canary.0",
        "below": "15.0.6",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "15.0.0-canary.0",
        "below": "15.0.6",
        "severity": "medium",
        "cwe": [
          "CWE-1395",
          "CWE-497",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55183](https://www.cve.org/CVERecord?id=CVE-2025-55183).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that can return the compiled source code of [Server Functions](https://react.dev/reference/rsc/server-functions). This could reveal business logic, but would not expose secrets unless they were hardcoded directly into [Server Function](https://react.dev/reference/rsc/server-functions) code.",
          "githubID": "GHSA-w37m-7fhw-fmv9"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-w37m-7fhw-fmv9",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55183"
        ]
      },
      {
        "atOrAbove": "15.0.6",
        "below": "15.0.7",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
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
        "atOrAbove": "15.1.0-canary.0",
        "below": "15.1.9",
        "severity": "critical",
        "cwe": [
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages<sup>1</sup> for versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182). \n\nFixed in:\nReact: 19.0.1, 19.1.2, 19.2.1\nNext.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7\n\nThe vulnerability also affects experimental canary releases starting with 14.3.0-canary.77. Users on any of the 14.3 canary builds should either downgrade to a 14.x stable release or 14.3.0-canary.76.\n\nAll users of stable 15.x or 16.x Next.js versions should upgrade to a patched, stable version immediately.\n\n<sup>1</sup> The affected React packages are:\n- react-server-dom-parcel\n- react-server-dom-turbopack\n- react-server-dom-webpack",
          "githubID": "GHSA-9qr9-h5gf-34mp"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp"
        ]
      },
      {
        "atOrAbove": "15.1.1-canary.0",
        "below": "15.1.10",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "15.1.1-canary.0",
        "below": "15.1.10",
        "severity": "medium",
        "cwe": [
          "CWE-1395",
          "CWE-497",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55183](https://www.cve.org/CVERecord?id=CVE-2025-55183).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that can return the compiled source code of [Server Functions](https://react.dev/reference/rsc/server-functions). This could reveal business logic, but would not expose secrets unless they were hardcoded directly into [Server Function](https://react.dev/reference/rsc/server-functions) code.",
          "githubID": "GHSA-w37m-7fhw-fmv9"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-w37m-7fhw-fmv9",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55183"
        ]
      },
      {
        "atOrAbove": "15.1.10",
        "below": "15.1.11",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
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
          "CWE-285",
          "CWE-863"
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
        "atOrAbove": "15.2.0-canary.0",
        "below": "15.2.6",
        "severity": "critical",
        "cwe": [
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages<sup>1</sup> for versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182). \n\nFixed in:\nReact: 19.0.1, 19.1.2, 19.2.1\nNext.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7\n\nThe vulnerability also affects experimental canary releases starting with 14.3.0-canary.77. Users on any of the 14.3 canary builds should either downgrade to a 14.x stable release or 14.3.0-canary.76.\n\nAll users of stable 15.x or 16.x Next.js versions should upgrade to a patched, stable version immediately.\n\n<sup>1</sup> The affected React packages are:\n- react-server-dom-parcel\n- react-server-dom-turbopack\n- react-server-dom-webpack",
          "githubID": "GHSA-9qr9-h5gf-34mp"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp"
        ]
      },
      {
        "atOrAbove": "15.2.0-canary.0",
        "below": "15.2.7",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "15.2.0-canary.0",
        "below": "15.2.7",
        "severity": "medium",
        "cwe": [
          "CWE-1395",
          "CWE-497",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55183](https://www.cve.org/CVERecord?id=CVE-2025-55183).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that can return the compiled source code of [Server Functions](https://react.dev/reference/rsc/server-functions). This could reveal business logic, but would not expose secrets unless they were hardcoded directly into [Server Function](https://react.dev/reference/rsc/server-functions) code.",
          "githubID": "GHSA-w37m-7fhw-fmv9"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-w37m-7fhw-fmv9",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55183"
        ]
      },
      {
        "atOrAbove": "15.2.7",
        "below": "15.2.8",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
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
      },
      {
        "atOrAbove": "15.3.0-canary.0",
        "below": "15.3.6",
        "severity": "critical",
        "cwe": [
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages<sup>1</sup> for versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182). \n\nFixed in:\nReact: 19.0.1, 19.1.2, 19.2.1\nNext.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7\n\nThe vulnerability also affects experimental canary releases starting with 14.3.0-canary.77. Users on any of the 14.3 canary builds should either downgrade to a 14.x stable release or 14.3.0-canary.76.\n\nAll users of stable 15.x or 16.x Next.js versions should upgrade to a patched, stable version immediately.\n\n<sup>1</sup> The affected React packages are:\n- react-server-dom-parcel\n- react-server-dom-turbopack\n- react-server-dom-webpack",
          "githubID": "GHSA-9qr9-h5gf-34mp"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp"
        ]
      },
      {
        "atOrAbove": "15.3.0-canary.0",
        "below": "15.3.7",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "15.3.0-canary.0",
        "below": "15.3.7",
        "severity": "medium",
        "cwe": [
          "CWE-1395",
          "CWE-497",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55183](https://www.cve.org/CVERecord?id=CVE-2025-55183).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that can return the compiled source code of [Server Functions](https://react.dev/reference/rsc/server-functions). This could reveal business logic, but would not expose secrets unless they were hardcoded directly into [Server Function](https://react.dev/reference/rsc/server-functions) code.",
          "githubID": "GHSA-w37m-7fhw-fmv9"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-w37m-7fhw-fmv9",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55183"
        ]
      },
      {
        "atOrAbove": "15.3.7",
        "below": "15.3.8",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
        ]
      },
      {
        "atOrAbove": "15.0.0",
        "below": "15.4.5",
        "severity": "medium",
        "cwe": [
          "CWE-524"
        ],
        "identifiers": {
          "summary": "A vulnerability in Next.js Image Optimization has been fixed in v15.4.5 and v14.2.31. When images returned from API routes vary based on request headers (such as `Cookie` or `Authorization`), these responses could be incorrectly cached and served to unauthorized users due to a cache key confusion bug.\n\nAll users are encouraged to upgrade if they use API routes to serve images that depend on request headers and have image optimization enabled.\n\nMore details at [Vercel Changelog](https://vercel.com/changelog/cve-2025-57752)",
          "githubID": "GHSA-g5qg-72qw-gw5v",
          "CVE": [
            "CVE-2025-57752"
          ]
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-g5qg-72qw-gw5v",
          "https://github.com/vercel/next.js/pull/82114",
          "https://github.com/vercel/next.js/commit/6b12c60c61ee80cb0443ccd20de82ca9b4422ddd",
          "https://vercel.com/changelog/cve-2025-57752"
        ]
      },
      {
        "atOrAbove": "15.0.0",
        "below": "15.4.5",
        "severity": "medium",
        "cwe": [
          "CWE-20"
        ],
        "identifiers": {
          "summary": "A vulnerability in **Next.js Image Optimization** has been fixed in **v15.4.5** and **v14.2.31**. The issue allowed attacker-controlled external image sources to trigger file downloads with arbitrary content and filenames under specific configurations. This behavior could be abused for phishing or malicious file delivery.\n\nAll users relying on `images.domains` or `images.remotePatterns` are encouraged to upgrade and verify that external image sources are strictly validated.\n\nMore details at [Vercel Changelog](https://vercel.com/changelog/cve-2025-55173)",
          "githubID": "GHSA-xv57-4mr9-wg8v",
          "CVE": [
            "CVE-2025-55173"
          ]
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-xv57-4mr9-wg8v",
          "https://github.com/vercel/next.js/commit/6b12c60c61ee80cb0443ccd20de82ca9b4422ddd",
          "https://vercel.com/changelog/cve-2025-55173",
          "http://vercel.com/changelog/cve-2025-55173"
        ]
      },
      {
        "atOrAbove": "15.0.0-canary.0",
        "below": "15.4.7",
        "severity": "medium",
        "cwe": [
          "CWE-918"
        ],
        "identifiers": {
          "summary": "A vulnerability in **Next.js Middleware** has been fixed in **v14.2.32** and **v15.4.7**. The issue occurred when request headers were directly passed into `NextResponse.next()`. In self-hosted applications, this could allow Server-Side Request Forgery (SSRF) if certain sensitive headers from the incoming request were reflected back into the response.\n\nAll users implementing custom middleware logic in self-hosted environments are strongly encouraged to upgrade and verify correct usage of the `next()` function.\n\nMore details at [Vercel Changelog](https://vercel.com/changelog/cve-2025-57822)",
          "githubID": "GHSA-4342-x723-ch2f",
          "CVE": [
            "CVE-2025-57822"
          ]
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-4342-x723-ch2f",
          "https://github.com/vercel/next.js/commit/9c9aaed5bb9338ef31b0517ccf0ab4414f2093d8",
          "https://vercel.com/changelog/cve-2025-57822"
        ]
      },
      {
        "atOrAbove": "15.4.0-canary.0",
        "below": "15.4.8",
        "severity": "critical",
        "cwe": [
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages<sup>1</sup> for versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182). \n\nFixed in:\nReact: 19.0.1, 19.1.2, 19.2.1\nNext.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7\n\nThe vulnerability also affects experimental canary releases starting with 14.3.0-canary.77. Users on any of the 14.3 canary builds should either downgrade to a 14.x stable release or 14.3.0-canary.76.\n\nAll users of stable 15.x or 16.x Next.js versions should upgrade to a patched, stable version immediately.\n\n<sup>1</sup> The affected React packages are:\n- react-server-dom-parcel\n- react-server-dom-turbopack\n- react-server-dom-webpack",
          "githubID": "GHSA-9qr9-h5gf-34mp"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp"
        ]
      },
      {
        "atOrAbove": "15.4.0-canary.0",
        "below": "15.4.9",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "15.4.0-canary.0",
        "below": "15.4.9",
        "severity": "medium",
        "cwe": [
          "CWE-1395",
          "CWE-497",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55183](https://www.cve.org/CVERecord?id=CVE-2025-55183).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that can return the compiled source code of [Server Functions](https://react.dev/reference/rsc/server-functions). This could reveal business logic, but would not expose secrets unless they were hardcoded directly into [Server Function](https://react.dev/reference/rsc/server-functions) code.",
          "githubID": "GHSA-w37m-7fhw-fmv9"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-w37m-7fhw-fmv9",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55183"
        ]
      },
      {
        "atOrAbove": "15.4.9",
        "below": "15.4.10",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
        ]
      },
      {
        "atOrAbove": "15.5.0-canary.0",
        "below": "15.5.7",
        "severity": "critical",
        "cwe": [
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages<sup>1</sup> for versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182). \n\nFixed in:\nReact: 19.0.1, 19.1.2, 19.2.1\nNext.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7\n\nThe vulnerability also affects experimental canary releases starting with 14.3.0-canary.77. Users on any of the 14.3 canary builds should either downgrade to a 14.x stable release or 14.3.0-canary.76.\n\nAll users of stable 15.x or 16.x Next.js versions should upgrade to a patched, stable version immediately.\n\n<sup>1</sup> The affected React packages are:\n- react-server-dom-parcel\n- react-server-dom-turbopack\n- react-server-dom-webpack",
          "githubID": "GHSA-9qr9-h5gf-34mp"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp"
        ]
      },
      {
        "atOrAbove": "15.5.1-canary.0",
        "below": "15.5.8",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "15.5.1-canary.0",
        "below": "15.5.8",
        "severity": "medium",
        "cwe": [
          "CWE-1395",
          "CWE-497",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55183](https://www.cve.org/CVERecord?id=CVE-2025-55183).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that can return the compiled source code of [Server Functions](https://react.dev/reference/rsc/server-functions). This could reveal business logic, but would not expose secrets unless they were hardcoded directly into [Server Function](https://react.dev/reference/rsc/server-functions) code.",
          "githubID": "GHSA-w37m-7fhw-fmv9"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-w37m-7fhw-fmv9",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55183"
        ]
      },
      {
        "atOrAbove": "15.5.8",
        "below": "15.5.9",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
        ]
      },
      {
        "atOrAbove": "15.6.0-canary.0",
        "below": "15.6.0-canary.59",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "15.6.0-canary.0",
        "below": "15.6.0-canary.59",
        "severity": "medium",
        "cwe": [
          "CWE-1395",
          "CWE-497",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55183](https://www.cve.org/CVERecord?id=CVE-2025-55183).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that can return the compiled source code of [Server Functions](https://react.dev/reference/rsc/server-functions). This could reveal business logic, but would not expose secrets unless they were hardcoded directly into [Server Function](https://react.dev/reference/rsc/server-functions) code.",
          "githubID": "GHSA-w37m-7fhw-fmv9"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-w37m-7fhw-fmv9",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55183"
        ]
      },
      {
        "atOrAbove": "15.6.0-canary.59",
        "below": "15.6.0-canary.60",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
        ]
      },
      {
        "atOrAbove": "16.0.0-canary.0",
        "below": "16.0.7",
        "severity": "critical",
        "cwe": [
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages<sup>1</sup> for versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182). \n\nFixed in:\nReact: 19.0.1, 19.1.2, 19.2.1\nNext.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7\n\nThe vulnerability also affects experimental canary releases starting with 14.3.0-canary.77. Users on any of the 14.3 canary builds should either downgrade to a 14.x stable release or 14.3.0-canary.76.\n\nAll users of stable 15.x or 16.x Next.js versions should upgrade to a patched, stable version immediately.\n\n<sup>1</sup> The affected React packages are:\n- react-server-dom-parcel\n- react-server-dom-turbopack\n- react-server-dom-webpack",
          "githubID": "GHSA-9qr9-h5gf-34mp"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp"
        ]
      },
      {
        "atOrAbove": "16.0.0-beta.0",
        "below": "16.0.9",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "16.0.0-beta.0",
        "below": "16.0.9",
        "severity": "medium",
        "cwe": [
          "CWE-1395",
          "CWE-497",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55183](https://www.cve.org/CVERecord?id=CVE-2025-55183).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that can return the compiled source code of [Server Functions](https://react.dev/reference/rsc/server-functions). This could reveal business logic, but would not expose secrets unless they were hardcoded directly into [Server Function](https://react.dev/reference/rsc/server-functions) code.",
          "githubID": "GHSA-w37m-7fhw-fmv9"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-w37m-7fhw-fmv9",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55183"
        ]
      },
      {
        "atOrAbove": "16.0.9",
        "below": "16.0.10",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
        ]
      },
      {
        "atOrAbove": "16.1.0-canary.0",
        "below": "16.1.0-canary.17",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55184](https://www.cve.org/CVERecord?id=CVE-2025-55184).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that, when deserialized, can cause the server process to hang and consume CPU. This can result in denial of service in unpatched environments.",
          "githubID": "GHSA-mwv6-3258-q52c"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-mwv6-3258-q52c",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184"
        ]
      },
      {
        "atOrAbove": "16.1.0-canary.0",
        "below": "16.1.0-canary.17",
        "severity": "medium",
        "cwe": [
          "CWE-1395",
          "CWE-497",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "A vulnerability affects certain React packages for versions 19.0.0, 19.0.1, 19.1.0, 19.1.1, 19.1.2, 19.2.0, and 19.2.1 and frameworks that use the affected packages, including Next.js 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-55183](https://www.cve.org/CVERecord?id=CVE-2025-55183).\n\nA malicious HTTP request can be crafted and sent to any App Router endpoint that can return the compiled source code of [Server Functions](https://react.dev/reference/rsc/server-functions). This could reveal business logic, but would not expose secrets unless they were hardcoded directly into [Server Function](https://react.dev/reference/rsc/server-functions) code.",
          "githubID": "GHSA-w37m-7fhw-fmv9"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-w37m-7fhw-fmv9",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://www.cve.org/CVERecord?id=CVE-2025-55183"
        ]
      },
      {
        "atOrAbove": "16.1.0-canary.17",
        "below": "16.1.0-canary.19",
        "severity": "high",
        "cwe": [
          "CWE-1395",
          "CWE-400",
          "CWE-502"
        ],
        "identifiers": {
          "summary": "It was found that the fix addressing [CVE-2025-55184](https://github.com/advisories/GHSA-2m3v-v2m8-q956) in React Server Components was incomplete and did not fully prevent denial-of-service attacks in all payload types. This affects React package versions 19.0.2, 19.1.3, and 19.2.2 and frameworks that use the affected packages, including Next.js 13.x, 14.x, 15.x and 16.x using the App Router. The issue is tracked upstream as [CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779).\n\nA malicious HTTP request can be crafted and sent to any Server Function endpoint that, when deserialized, can enter an infinite loop within the React Server Components runtime. This can cause the server process to hang and consume CPU, resulting in denial of service in unpatched environments.",
          "githubID": "GHSA-5j59-xgg2-r9c4"
        },
        "info": [
          "https://github.com/vercel/next.js/security/advisories/GHSA-5j59-xgg2-r9c4",
          "https://nextjs.org/blog/security-update-2025-12-11",
          "https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components",
          "https://www.cve.org/CVERecord?id=CVE-2025-55184",
          "https://www.facebook.com/security/advisories/cve-2025-67779"
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
        "atOrAbove": "4.7.0",
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
      },
      {
        "atOrAbove": "4.0.0",
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
        "atOrAbove": "0.7.30",
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
}
},{}]},{},[1])(1)
});
