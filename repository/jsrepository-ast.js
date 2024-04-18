exports.queries = {
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
    `//CallExpression[
      /:callee//:left/:property/:name == "DOMPurify"
    ]/:arguments//AssignmentExpression[
      /:left/:property/:name == "version" &&
      /:left/$:object/:init/:type == "FunctionExpression"
    ]/:right/:value`,
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
  ],
  "react-dom": [
    `//ObjectExpression/Property[/:key/:name == "reconcilerVersion"]/$$:value/:value`,
    /* {findFiberByHostInstance:_w,bundleType:0,version:"17.0.2",rendererPackageName:"react-dom"} */
    `//ObjectExpression[
      /Property[/:key/:name == "rendererPackageName" && /:value/:value == "react-dom"]
    ]/Property[/:key/:name == "version"]/:value/:value`,
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
};
