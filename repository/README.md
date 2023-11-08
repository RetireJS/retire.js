## Submitting to the repository

Do **not** submit to npmrepository.json (deprecated).

Do **not** make changes directly to jsrepository.json (old format). Make changes in jsrepository-master.json, and run convertToOldFormat to update (jsrepository.json).

Please always run validate before creating a pull request.

### jsrepository-master.json

Lists vulnerable javascript libraries. §§version§§ is a placeholder for a regex capturing versions with numbers + alpha/beta/rc1 etc.

```
		"retire-example": {  //user friendly name of library
			"vulnerabilities" : [ //List of vulnerable versions and links to more info
				{
					"ranges" : [
						{
							"atOrAbove" : "0.0.1",
							"below" : "0.0.2",
						}
					],
					"severity": "high",
					"cwe": ["CWE-79"],
					"summary" : "vulnerable to xss"
					"identifiers" : {
						"CVE" : [ "CVE-2000-0000" ],
						"githubID": "GHSA-1234-1234-1234"
					}
					"info" : [ "http://github.com/eoftedal/retire.js/" ]
				}
			],
			"extractors" : {  //how do we find out which library and version this is
				"filename"		: [ "retire-example-(§§version§§)(.min)?\\.js" ],	//regexes for filenames and uris
				"filecontent"	: [ "/\\*! Retire-example v(§§version§§)" ],		//regexes for content within file
				"hashes"		: { "07f8b94c8d601a24a1914a1a92bec0e4fafda964" : "0.0.1" } //Hashes for specific versions (can be omitted)
			}
		},
```

- Must contain:
  - Severity (align with CVE or GHSA if possible)
  - CWE
  - At least one identifier which is either `CVE`, `githubID`, `pr` or `issue` (see file for examples).
- Ranges are the vulnerable ranges.
  - If no lower bound is known, then drop atOrAbove.
  - If no upper bound is known then insert "999.0.0".
