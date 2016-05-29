(function (data, document) {
    
    function init() {
        
        var list = document.getElementById('list');
        
        data.forEach(function(library) {
                
            list.appendChild(UI.createLibrary(library));
        });
    }
    
    var UI = (function () {
        
        return {
            createLibrary: createLibrary,
        };
        
        function createLibrary (library) {
            
            var element = document.createElement('li');
            element.className = 'retire-library'; 
            element.innerHTML = '<em>' + library.file + '</em>';
            
            var results = document.createElement('ul'),
                resultsFragment = document.createDocumentFragment();
                
            results.className = 'retire-results';
            
            library.results.forEach(function (result) {
                 
                 resultsFragment.appendChild(createResult(result));
            });
            
            results.appendChild(resultsFragment);
            element.appendChild(results);
            
            return element;
        }
        
        function createResult (result) {
            
            var element = document.createElement('li');
            element.className = 'retire-result';
            element.innerHTML = '<div class="retire-resultInfo"><strong>' + result.component + ' ' + result.version + '</strong> has known vulnerabilities</div>';
            
            var vulnerabilities = document.createElement('ul'),
                fragment = document.createDocumentFragment();
            
            vulnerabilities.className = 'retire-vulnerabilities';
            
            result.vulnerabilities.forEach(function (vulnerability) {
                 
                 fragment.appendChild(createVulnerability(vulnerability));
            });
            
            vulnerabilities.appendChild(fragment);
            element.appendChild(vulnerabilities);
            
            return element;
        }
        
        function createVulnerability (vulnerability) {
            
            var element = document.createElement('li');
            element.className = 'retire-vulnerability';
            
            var elementHTML = '', i = 0;
            for (propery in vulnerability.identifiers) {
                
                if (i > 0) elementHTML += ' - ';
                elementHTML += vulnerability.identifiers[propery];
                i++;
            }
            
            elementHTML += ' <span class="retire-label retire-' + vulnerability.severity + '">' + vulnerability.severity + '</span>';
            element.innerHTML = elementHTML;
            
            var info = document.createElement('div');
            info.className = 'retire-info';
            
            var infoHTML = '';
            vulnerability.info.forEach(function (value, i) {
                 
                 if (i > 0) infoHTML += ', ';
                 infoHTML += '<a href="' + value + '">' + value + '</a>';
            });
            
            info.innerHTML = infoHTML;
            
            element.appendChild(info);
            return element;      
        }
        
    })();
    
    init();
    
})(retireJSON, document);