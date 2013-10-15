Submitting to the repositories
------------------------------

Please always run validate before creating a pull request


### jsrepository.json
Lists vulnerable javascript libraries. §§version§§ is a placeholder for a regex capturing versions with numbers + alpha/beta/rc1 etc.

	"retire-example": {  //user friendly name of library
		"vulnerabilities" : [ //List of vulnerable versions and links to more info
			{ "atOrAbove" : "0.0.1", "below" : "0.0.2", "info" : [ "http://github.com/eoftedal/retire.js/" ] }
		],
		"extractors" : {  //how do we find out which library and version this is
			"filename"		: [ "retire-example-(§§version§§)(.min)?\\.js" ],	//regexes for filenames and uris
			"filecontent"	: [ "/\\*! Retire-example v(§§version§§)" ],		//regexes for content within file
			"hashes"		: { "07f8b94c8d601a24a1914a1a92bec0e4fafda964" : "0.0.1" } //Hashes for specific versions (can be omitted)
		}
	},

### npmrepository.json
Lists vulnerable node modules (npms)

	"retire-example": { //actual name of module
		"vulnerabilities" : [ //List of vulnerable version and link to more info
			{ "atOrAbove": "0.0.1", "below" : "0.0.2", "info" : [ "http://github.com/eoftedal/retire.js/" ] }
		]
	},