exports.queries = {
  "bootstrap": [
    /*
      5.x unminified — BlockStatement has both class BaseComponent and var DATA_KEY... = 'bs.alert'
        const VERSION = '5.3.8';
        class BaseComponent extends Config { ... }
        const DATA_KEY$a = 'bs.alert';
    */
    `//BlockStatement[
      /ClassDeclaration[/:id/:name == "BaseComponent"] &&
      /VariableDeclaration/VariableDeclarator[/:init/:value == "bs.alert"]
    ]/VariableDeclaration/VariableDeclarator[/:id/:name == "VERSION"]/:init/:value`,
    /*
      5.x minified (5.2.3+) — BaseComponent class body has VERSION getter, DATA_KEY getter
      (TemplateLiteral bs.${this.NAME}), and EVENT_KEY getter (TemplateLiteral .${this.DATA_KEY})
    */
    `//ClassBody[
      /MethodDefinition[/:kind == "get" && /:key/:name == "DATA_KEY"]//TemplateLiteral &&
      /MethodDefinition[/:kind == "get" && /:key/:name == "EVENT_KEY"]//TemplateLiteral
    ]/MethodDefinition[/:kind == "get" && /:key/:name == "VERSION"]//ReturnStatement//Literal/:value`,
    /*
      5.0.0 minified — VERSION getter and DATA_KEY getter in different classes (base vs Alert),
      but in the same BlockStatement (factory body)
        class B { static get VERSION(){return"5.0.0"} }
        class $ extends B { static get DATA_KEY(){return"bs.alert"} }
    */
    `//BlockStatement[
      //ClassBody/MethodDefinition[/:kind == "get" && /:key/:name == "DATA_KEY"]//Literal[/:value == "bs.alert"]
    ]//ClassBody/MethodDefinition[/:kind == "get" && /:key/:name == "VERSION"]//ReturnStatement//Literal/:value`,
    /*
      4.x min+unmin — Babel _createClass descriptor {key:"VERSION", get:function(){return...}}
      anchored by "bs.alert" literal (VariableDeclarator in unmin, Data_KEY getter body in min).
      $$: resolves identifier binding in unmin (return VERSION → '4.x.x') and returns the
      inline Literal directly in minified (return "4.x.x").
    */
    `//BlockStatement[
      //Literal[/:value == "bs.alert"]
    ]//ObjectExpression[
      /Property[/:key/:name == "key" && /:value/:value == "VERSION"]
    ]/Property[/:key/:name == "get"]//ReturnStatement/$$:argument/:value`,
  ],
  "jquery-migrate": [
    /* 
      function(x) {
        x.migrateVersion = "x.y.z";
        ...
      }
    */
    `//FunctionExpression[
      /:params ==
      //AssignmentExpression/MemberExpression[
        /:property/:name == "migrateVersion"
      ]/$:object
    ]//AssignmentExpression[
      /MemberExpression/:property/:name == "migrateVersion"
    ]/$$:right/:value`,
  ],
  jquery: [
    /* 
    x.fn = x.prototype = {
      jquery: "x.y.z",
      ...
    }
  */
    `//AssignmentExpression[/:left/:property/:name == 'fn']
      /AssignmentExpression[/:left/:property/:name=='prototype' && /:left/$:object == ../:left/$:object]
      /ObjectExpression/:properties[/:key/:name == 'jquery']/$$:value/:value
    `,
  ],
  handlebars: [
    /*  
    x.HandlebarsEnvironment = ...;
    x.VERSION = "x.y.z";
  */
    `//FunctionExpression/BlockStatement[
      /ExpressionStatement//AssignmentExpression[
        /:left/:property/:name == 'HandlebarsEnvironment'
      ]/:left/$:object ==
      /ExpressionStatement/AssignmentExpression[
        /:left/:property/:name == 'VERSION'
      ]/:left/$:object
    ]
    /ExpressionStatement/AssignmentExpression[
      /:left/:property/:name == 'VERSION'
    ]/$$:right/:value`,
    /*
    (function(){var a={};window.Handlebars=a,a.VERSION="1.0.beta.2"
    */
    `
      //SequenceExpression[
        /AssignmentExpression[
          /:left/:property/:name == 'Handlebars' && 
          /:left/:object/:name == 'window'
        ]
      ]/AssignmentExpression[/:left/:property/:name == 'VERSION']/:right/:value
    `,
  ],
  "jquery-ui": [
    /*
    function (x) {
      x.ui.version = "x.y.z";
    }*/
    `//AssignmentExpression[
        /MemberExpression[
          /MemberExpression[
            /$:object == ../../../../../../:params ||
            /$:object == ../../../../../:params
          ]/:property/:name == "ui"
        ]/:property/:name == "version"
      ]/:right/:value`,
    `//CallExpression[
        /:callee/:property/:name == "extend" && 
        /:arguments/:property/:name == "ui"
      ]/:arguments/Property[
        /:key/:name == "version"
      ]/:value/:value`,
    `
      //AssignmentExpression[

        /:left/:property/:name == "ui" &&
        /:left/$:object == ../../../:params
      ]/:right/Property[
        /:key/:name == "version"
      ]/:value/:value
      `,
  ],
  "jquery.prettyPhoto": [
    /*
    (function($) {
	    $.prettyPhoto = {version: '3.1.6'};
  */
    `//AssignmentExpression[
      /:left/:property/:name == "prettyPhoto"
    ]/:right/:properties[
      /:key/:name == "version"
    ]/:value/:value`,
  ],
  ember: [
    /*
    Ember.VERSION="0.9.7"
    */
    `//AssignmentExpression[
      /:left/:object/:name == "Ember" &&
      /:left/:property/:name == "VERSION"
    ]/:right/:value`,
    /*
    r("ember/version",["exports"],function(e){"use strict";Object.defineProperty(e,"__esModule",{value:!0}),e.default=void 0;e.default="4.6.0"})
    */
    `//CallExpression[
      /Literal/:value == "ember/version"
    ]/FunctionExpression/BlockStatement/ExpressionStatement/AssignmentExpression[
      /:left/:property/:name == "default" || /:left/:property/:value == "default"
    ]/:right/:value`,
    `//SequenceExpression[
      /AssignmentExpression[
        /:left/:property/:name == "toString" &&
        /:right//ReturnStatement/:argument/:value == "Ember"
      ]
    ]/AssignmentExpression[
      /MemberExpression/:property/:name == "VERSION"
    ]/:right/:value`,
    /*
    ember 6.x: version Literal co-declared with an ember-specific module export
    6.0.x sibling: Object.defineProperty({...WireFormatDebugger...},...) — glimmer wire-format class
    6.7.x sibling: Object.defineProperty({...isLowLevelRegister...},...) — glimmer-vm register check
    */
    `//VariableDeclaration[
      //Property/:key/:name == "WireFormatDebugger" ||
      //Property/:key/:name == "isLowLevelRegister"
    ]/VariableDeclarator[/:init/:type == "Literal"]/:init/:value`,
  ],
  vue: [
    `//VariableDeclarator[
      /:id/:name == "Vue"
    ]/CallExpression/FunctionExpression/BlockStatement/ReturnStatement/SequenceExpression/AssignmentExpression[
      /:left/:property/:name == "version"
    ]/$:right/:init/:value
    `,
    `//CallExpression[
      /:callee//:left/:property/:name == "Vue"
    ]/:arguments//AssignmentExpression[
      /:left/:property/:name == "version"
    ]/$$:right/:value`,
    `//AssignmentExpression[
      /:left/:object/:name == "Vue" &&
      /:left/:property/:name == "version"
    ]/:right/:value`,
  ],
  DOMPurify: [
    /*
    All versions (minified): DOMPurify.version = "x.y.z" inside UMD factory
    2.x/3.0.x: var DOMPurify = function DOMPurify(root){...}
    3.1.x+:    const DOMPurify = root => createDOMPurify(root)
    */
    `//CallExpression[
      /:callee//:left/:property/:name == "DOMPurify"
    ]/:arguments//AssignmentExpression[
      /:left/:property/:name == "version"
    ]/:right/:value`,
    /*
    Turbopack/bundled: if (o.version = "x.y.z", o.removed = [], ...)
      return o.isSupported = false, o;
    Anchored by o.removed (test) + o.isSupported (consequent) on same object
    */
    `//IfStatement[
      /:test//AssignmentExpression[/:left/:property/:name == "removed"]/:left/$:object ==
      /:consequent//AssignmentExpression[/:left/:property/:name == "isSupported"]/:left/$:object
    ]/:test//AssignmentExpression[/:left/:property/:name == "version"]/$$:right/:value`,
  ],
  "ua-parser-js": [
    `//SequenceExpression[
      /AssignmentExpression[
        /:left/:property/:name == "VERSION"
      ]/:left/$:object == //AssignmentExpression[
        /:left/:property/:name == "UAParser"
      ]/$:right
    ]/AssignmentExpression[
      /:left/:property/:name == "VERSION"
    ]/$$:right/:value`,
    `//IfStatement[
      /SequenceExpression/AssignmentExpression[
        /:left/:property/:name == "VERSION"
      ]/:left/$:object ==
      /:consequent//AssignmentExpression[
        /:left/:property/:name == "UAParser"
      ]/$:right
    ]/SequenceExpression/AssignmentExpression[
      /:left/:property/:name == "VERSION"
    ]/$$:right/:value`,
    `//BlockStatement[
      /ExpressionStatement
        /AssignmentExpression[
            /:left/:property/:name == "VERSION"
          ]/:left/$:object ==
        //AssignmentExpression[
          /:left/:property/:name == "UAParser"
        ]/$:right
    ]/ExpressionStatement/AssignmentExpression[
      /:left/:property/:name == "VERSION"
    ]/$$:right/:value`,
  ],
  dojo: [
    `//BlockStatement/ExpressionStatement/AssignmentExpression[
      /:left/:property/:name == "version" && 
      /:left[
        /:object/:name == "dojo" ||
        /:$object/:init/:properties/:key/:name == "dojox"
      ]
    ]/ObjectExpression[
      /Property/:key/:name == "major" ||
      /Property/:key/:name == "minor" ||
      /Property/:key/:name == "patch"
    ]/fn:concat(
      /Property[/:key/:name == "major"]/:value/:value, ".",
      /Property[/:key/:name == "minor"]/:value/:value, ".",
      /Property[/:key/:name == "patch"]/:value/:value
    )`,
  ],
  angularjs: [
    /* {angularVersion:"1.7.5"} */
    `//ObjectExpression[
      /Property/:key/:name == "angularVersion"
    ]/:properties/$$:value/:value`,
    /*
      { 'version': version, 'bootstrap': bootstrap, 'injector': injector }
    */
    `//ObjectExpression[
      /Property/:key[/:name == "version" || /:value == "version"] && 
      /Property/:key[/:name == "bind" || /:value == "bind"] &&
      /Property/:key[/:name == "injector" || /:value == "injector"]
    ]/Property[/:key/:name == "version" || /:key/:value == "version"]/$:value/ObjectExpression/Property[
      /:key/:name == "full"
    ]/:value/:value`,
    `//ObjectExpression[
      /Property/:key[/:name == "version" || /:value == "version"] &&
      /Property/:key[/:name == "bind" || /:value == "bind"] &&
      /Property/:key[/:name == "injector" || /:value == "injector"]
    ]/Property[/:key/:name == "version" || /:key/:value == "version"]/:value/Property[
      /:key/:name == "full"
    ]/:value/:value`,
  ],
  "@angular/core": [
    `//ExportNamedDeclaration[
      /ExportSpecifier/:exported[
        /:name == "NgModuleFactory" || 
        /:name == "ɵBrowserDomAdapter"
      ]
    ]/ExportSpecifier[
      /:exported/:name == "VERSION"
    ]/:$local/:init/:arguments/:value`,

    `//CallExpression/ArrayExpression[/Literal/:value == "ng-version"]/MemberExpression[
      /:property/:name == "full"
    ]/:$object/:init/:arguments/:value`,
    `//CallExpression/ArrayExpression[/Literal/:value == "ng-version"]/:1/:value`,
    /*
      UMD/ES5 bundles (v2–v12) call setAttribute directly rather than via an array:
        renderer.setAttribute(el, 'ng-version', VERSION.full)
      where var VERSION = new Version('4.4.7')
    */
    `//CallExpression[/Literal/:value == "ng-version"]/MemberExpression[
      /:property/:name == "full"
    ]/:$object/:init/:arguments/:value`,
    /*
      v20+ moved VERSION into a shared chunk that re-exports it alongside
      Angular-specific internals:
        const VERSION = new Version('20.3.25'); export { ..., VERSION, XSS_SECURITY_URL, ZONELESS_ENABLED, ... }
    */
    `//ExportNamedDeclaration[
      /ExportSpecifier/:exported[
        /:name == "XSS_SECURITY_URL" ||
        /:name == "ZONELESS_ENABLED"
      ]
    ]/ExportSpecifier[
      /:exported/:name == "VERSION"
    ]/:$local/:init/:arguments/:value`,
  ],
  "react-dom": [
    `//ObjectExpression/Property[/:key/:name == "reconcilerVersion"]/$$:value/:value`,
    /* {findFiberByHostInstance:_w,bundleType:0,version:"17.0.2",rendererPackageName:"react-dom"} */
    `//ObjectExpression[
      /Property[/:key/:name == "rendererPackageName" && /:value/:value == "react-dom"]
    ]/Property[/:key/:name == "version"]/:value/:value`,
    `//SequenceExpression[
            /AssignmentExpression/:left[/:object/:name == "exports" && /:property/:name == "__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE"] 
        ]/AssignmentExpression[
            /:left/:object/:name == "exports" && /:left/:property/:name == "version"
        ]/:right/:value`,
        `/ExpressionStatement/AssignmentExpression[
  /MemberExpression/:property/:name == "version" &&
  /MemberExpression
    [/:$object == 
        ../../../ExpressionStatement/AssignmentExpression/MemberExpression[
          /:property/:name == "__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE"
        ]/$:object ||
      /Identifier[
        /:name == "exports" && ../../../../ExpressionStatement/AssignmentExpression/MemberExpression[
          /:property/:name == "__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE"
        ]/Identifier/:name == "exports"
      ]
    ]
    ]/$$:right/:value`
  ],
  react: [
    `//CallExpression[
      /FunctionExpression//MemberExpression/:property/:name == "React"
    ]/FunctionExpression/BlockStatement/ExpressionStatement/AssignmentExpression[
      /:left/:property/:name == "version"
    ]/$$:right/:value`,
    `//BlockStatement[
      /ExpressionStatement/AssignmentExpression/MemberExpression[/:property/:name == "__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED"]/$:object ==
      /ExpressionStatement/AssignmentExpression/MemberExpression[/:property/:name == "version"]/$:object
    ]/ExpressionStatement/AssignmentExpression[/MemberExpression/:property/:name == "version"]/$$:right/:value`,
    `/ExpressionStatement/AssignmentExpression[
        /MemberExpression/:property/:name == "version" &&
        /MemberExpression/:$object == 
        ../../ExpressionStatement/AssignmentExpression/MemberExpression[
          /:property/:name == "__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED"
        ]/$:object
    ]/$$:right/:value`,
  ],
  "moment.js": [
    /*
    _.version = '2.30.1';
    _.isMoment = function
    */
    `//SequenceExpression[
      /AssignmentExpression[
        /:left/:property/:name == "isMoment"
      ]/:left/$:object == 
      /AssignmentExpression[
        /:left/:property/:name == "version"
      ]/:left/$:object
    ]/AssignmentExpression[
      /:left/:property/:name == "version"
    ]/$$:right/:value`,

    `//BlockStatement[
        //AssignmentExpression[/:left/:property/:name == "moment"]/:$right ==
        /*/SequenceExpression/AssignmentExpression[/:left/:property/:name == "version"]/:left/$:object
      ]/*/SequenceExpression/AssignmentExpression[/:left/:property/:name == "version"]/:$right/:init/:value`,
  ],
  "mustache.js": [
    /*
    mustache.name = "mustache.js";
    mustache.version = "2.1.0";  (2.x – 3.x pattern)
    */
    `//BlockStatement[
      /ExpressionStatement/AssignmentExpression[
        /:left/:object/:name == "mustache" &&
        /:left/:property/:name == "name"
      ]
    ]/ExpressionStatement/AssignmentExpression[
      /:left/:property/:name == "version"
    ]/:right/:value`,
    /*
    var mustache = { name: "mustache.js", version: "4.0.1", ... }  (4.x pattern)
    */
    `//ObjectExpression[
      /Property[/:key/:name == "name"]/:value/:value == "mustache.js"
    ]/Property[/:key/:name == "version"]/:value/:value`,
  ],
  nextjs: [
    `//BlockStatement[
      /ExpressionStatement/AssignmentExpression/:left/:property/:name == "version" &&
      /ExpressionStatement/AssignmentExpression/:left[
        /:property/:name == "__NEXT_DATA__" &&
        /:object/:name == "window"
      ]
    ]/ExpressionStatement/AssignmentExpression[/:left/:property/:name == "version"]/:$$right/:value`,
    `//AssignmentExpression[
      /:left/:object/:name == "window" &&
      /:left/:property/:name == "next"
    ]/ObjectExpression/:properties[/:key/:name == "version"]/:value/:value`,
  ],
  axios: [
    `//AssignmentExpression[
      /:left/:object/:name == "axios" &&
      /:left/:property/:name == "VERSION"
    ]/$$:right/:value`,
    `//SequenceExpression[
      /AssignmentExpression[
        /:left/:property/:name == "AxiosError"
      ]/:left/$:object ==
      /AssignmentExpression[
        /:left/:property/:name == "VERSION"
      ]/:left/$:object
    ]/AssignmentExpression[
      /:left/:property/:name == "VERSION"
    ]/$$:right/:value`,
  ],
  knockout: [
    `//ExpressionStatement/SequenceExpression[
          /AssignmentExpression[/:left/:property/:name == "options" && /ObjectExpression/:properties/:key/:name == "foreachHidesDestroyed" ]
        ]/AssignmentExpression[/:left/:property/:name == "version"]/:right/:value`,
    `//BlockStatement[
          /ExpressionStatement/AssignmentExpression[
            /:left/:property/:name == "options"  &&
            /ObjectExpression/:properties/:key[
                /:name == "foreachHidesDestroyed" ||
                /:value == "foreachHidesDestroyed"
            ]
          ]
        ]/ExpressionStatement/AssignmentExpression[/:left/:property/:name == "version"]/:right/:value`,
    `//BlockStatement[
          /ExpressionStatement/CallExpression/:arguments/:value == "isWriteableObservable"
        ]/ExpressionStatement/AssignmentExpression[/:left/:property/:name == "version"]/:right/:value`
  ],
  "ckeditor5": [
    /*
      const v = "1.2.3"; ...; x.CKEDITOR_VERSION = v   (newer)
      x.CKEDITOR_VERSION = "1.2.3"                      (older)
    */
    `//AssignmentExpression[
      /:left/:property/:name == "CKEDITOR_VERSION"
    ]/$$:right/:value`,
  ],
  "ckeditor": [
    /*
      window.CKEDITOR = (..., {
        timestamp: "...", version: "4.x.y", revision: "...",
        basePath: function() { var a = window.CKEDITOR_BASEPATH || ""; ... }
      })
    */
    `//ObjectExpression[
      /Property[/:key/:name == "revision"] &&
      /Property[/:key/:name == "basePath"]//Identifier[/:name == "CKEDITOR_BASEPATH"]
    ]/Property[/:key/:name == "version"]/:value/:value`,
  ],
  "highlightjs": [
    `//VariableDeclarator[/:id/:name == "hljs"]//AssignmentExpression[/MemberExpression/:property/:name=="versionString"]/:right/:value`
  ],
  "echarts" : [
    `//SequenceExpression[/AssignmentExpression/:left/:property/:name == "disConnect"]/AssignmentExpression[//:left/:property/:name == "version"]/:right/:value`,
    `//BlockStatement[/FunctionDeclaration/:id/:name == "createRegisterEventWithLowercaseECharts"]/VariableDeclaration/:declarations[/:id/:name == "version"]/:init/:value`,
  ],
  "zrender" : [
    `//SequenceExpression[/AssignmentExpression/:left/:property/:name == "showDebugDirtyRect"]/AssignmentExpression[//:left/:property/:name == "version"]/:right/:value`,
    `//BlockStatement[/FunctionDeclaration/:id/:name == "registerPainter" && /FunctionDeclaration/:id/:name == "getWheelDeltaMayPolyfill"]/VariableDeclaration/VariableDeclarator[/:id/:name == "version"]/Literal/:value`
  ],
  "d3" : [
    `//BlockStatement[
      /ExpressionStatement/AssignmentExpression/:left/:property/:name == "curveCatmullRomClosed" &&
      /ExpressionStatement/AssignmentExpression/:left/:property/:name == "thresholdFreedmanDiaconis"
    ]/ExpressionStatement/AssignmentExpression[ /:left/:property/:name == "version" ]/$$:right/:value`,
    `//BlockStatement/ExpressionStatement/SequenceExpression[
      /AssignmentExpression/:left/:property/:name == "thresholdFreedmanDiaconis" &&
      /AssignmentExpression/:left/:property/:name == "thresholdSturges" &&
      /AssignmentExpression/:left/:property/:name == "thresholdScott"
    ]/AssignmentExpression[ /:left/:property/:name == "version" ]/$$:right/:value`
  ],
  "tinyMCE": [
    /*
      EditorManager = {
        majorVersion: '8', minorVersion: '1.2',
        setup() { ... window.tinyMCEPreInit ... }
      }
    */
    `//ObjectExpression[
      /Property[/:key/:name == "majorVersion"] &&
      /Property[/:key/:name == "setup"]//MemberExpression[/:property/:name == "tinyMCEPreInit"]
    ]/fn:concat(
      /Property[/:key/:name == "majorVersion"]/:value/:value,
      ".",
      /Property[/:key/:name == "minorVersion"]/:value/:value
    )`,
  ]
};
