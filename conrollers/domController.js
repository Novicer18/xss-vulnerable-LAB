/**
 * DOM-Based XSS Controller
 * Handles DOM XSS vulnerabilities and client-side injections
 */

class DomController {
    
    /**
     * Main DOM XSS page
     */
    static async getDomPage(req, res) {
        res.render('dom', {
            title: 'DOM-Based XSS Challenge',
            difficulty: 'Hard',
            description: 'Client-side JavaScript processes user input and writes it to DOM without sanitization.',
            hints: [
                'Check URL fragments (after #)',
                'Look for innerHTML, outerHTML usage',
                'Find document.write() calls',
                'Check eval(), setTimeout() with user input',
                'Test JavaScript URLs and event handlers',
                'Examine JSONP endpoints'
            ],
            currentPage: 'dom'
        });
    }
    
    /**
     * Vulnerable JSONP endpoint
     */
    static async vulnerableJsonp(req, res) {
        const callback = req.query.callback || 'callback';
        const dataParam = req.query.data || '{}';
        
        // Intentionally vulnerable: no validation of callback name
        let data;
        try {
            // Vulnerable: using eval with user input
            data = eval(`(${dataParam})`);
        } catch (e) {
            data = { error: 'Invalid data parameter' };
        }
        
        const response = {
            status: 'success',
            message: 'JSONP endpoint response',
            userData: data,
            timestamp: new Date().toISOString(),
            debug: {
                callback: callback,
                rawData: dataParam
            }
        };
        
        res.set('Content-Type', 'application/javascript');
        // Intentionally vulnerable: callback parameter directly used
        res.send(`${callback}(${JSON.stringify(response)})`);
    }
    
    /**
     * Vulnerable redirect endpoint
     */
    static async vulnerableRedirect(req, res) {
        const url = req.query.url || '/dom';
        const delay = parseInt(req.query.delay) || 0;
        
        // Intentionally vulnerable: user input in redirect
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting...</title>
            <link rel="stylesheet" href="/css/styles.css">
            <style>
                .redirect-info {
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 20px;
                    border-radius: 5px;
                    margin: 20px 0;
                }
                .vulnerable-url {
                    color: #e74c3c;
                    font-family: monospace;
                    background: #f8f9fa;
                    padding: 10px;
                    border-radius: 3px;
                    word-break: break-all;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔄 Redirect Page</h1>
                
                <div class="redirect-info">
                    <p>You will be redirected to:</p>
                    <div class="vulnerable-url">${url}</div>
                    <p>Delay: ${delay}ms</p>
                </div>
                
                <script>
                    // Intentionally vulnerable: user input in window.location
                    setTimeout(function() {
                        window.location = "${url}";
                    }, ${delay});
                    
                    // Alternative vulnerable redirect methods
                    var redirectMethods = [
                        "window.location = '${url}'",
                        "window.location.href = '${url}'",
                        "window.location.replace('${url}')",
                        "window.open('${url}')"
                    ];
                    
                    console.log("Available redirect methods:", redirectMethods);
                </script>
                
                <div class="warning">
                    <h4>⚠️ Security Warning:</h4>
                    <p>This endpoint accepts any URL, including <code>javascript:</code> URLs.</p>
                    <p>Try: <code>/dom/redirect?url=javascript:alert(document.cookie)</code></p>
                </div>
                
                <a href="/dom" class="btn">← Back to Challenge</a>
            </div>
        </body>
        </html>
        `;
        
        res.send(html);
    }
    
    /**
     * Vulnerable fragment handler page
     */
    static async fragmentHandler(req, res) {
        // Note: The actual vulnerability is in client-side JavaScript
        // This just serves the vulnerable page
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Fragment Handler - DOM XSS</title>
            <link rel="stylesheet" href="/css/styles.css">
        </head>
        <body>
            <div class="container">
                <h1># Fragment Handler</h1>
                <p>This page processes URL fragments client-side.</p>
                
                <div id="fragmentContent" class="result-box">
                    <p>Fragment content will appear here after page load.</p>
                </div>
                
                <div class="examples">
                    <h3>Try these URLs:</h3>
                    <ul>
                        <li><code>/dom/fragment#welcome</code></li>
                        <li><code>/dom/fragment#&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
                        <li><code>/dom/fragment#&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                    </ul>
                </div>
                
                <!-- Vulnerable JavaScript -->
                <script>
                    // Intentionally vulnerable fragment handling
                    window.addEventListener('load', function() {
                        var fragment = window.location.hash.substring(1);
                        if (fragment) {
                            var contentDiv = document.getElementById('fragmentContent');
                            // UNSAFE: direct innerHTML assignment
                            contentDiv.innerHTML = \`
                                <div class="fragment-display">
                                    <h3>Fragment Content:</h3>
                                    <div class="content">\${fragment}</div>
                                    <p class="meta">Processed at: \${new Date().toLocaleTimeString()}</p>
                                </div>
                            \`;
                        }
                    });
                    
                    // Additional vulnerability: using fragment in document.write
                    function debugFragment() {
                        var frag = window.location.hash.substring(1);
                        if (frag && frag.includes('debug')) {
                            document.write('<p>Debug mode: ' + frag + '</p>');
                        }
                    }
                    
                    // More vulnerabilities: eval with fragment data
                    function processCommand() {
                        var cmd = window.location.hash.substring(1);
                        if (cmd.startsWith('cmd:')) {
                            var command = cmd.substring(4);
                            try {
                                // DANGEROUS: eval with user input
                                var result = eval(command);
                                console.log('Command result:', result);
                            } catch (e) {
                                console.error('Command failed:', e);
                            }
                        }
                    }
                </script>
                
                <a href="/dom" class="btn">← Back to Challenge</a>
            </div>
        </body>
        </html>
        `;
        
        res.send(html);
    }
    
    /**
     * Vulnerable search API
     */
    static async vulnerableSearchApi(req, res) {
        const query = req.query.q || '';
        const format = req.query.format || 'html';
        
        const results = [
            { id: 1, title: `Result for: ${query}`, snippet: `This result contains information about ${query}` },
            { id: 2, title: `Related to ${query}`, snippet: `More data related to your search for ${query}` },
            { id: 3, title: `${query} Analysis`, snippet: `Detailed analysis of ${query} topic` }
        ];
        
        if (format === 'json') {
            // JSON response that might be parsed unsafely
            res.json({
                query: query,
                results: results,
                total: results.length,
                timestamp: new Date().toISOString(),
                warning: 'This endpoint returns unsanitized user input in JSON'
            });
        } else {
            // HTML response with vulnerabilities
            const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Search Results</title>
                <link rel="stylesheet" href="/css/styles.css">
            </head>
            <body>
                <div class="container">
                    <h1>🔍 Search Results</h1>
                    <p>Query: <strong>${query}</strong></p>
                    
                    <div id="searchResults">
                        ${results.map(result => `
                            <div class="result-item">
                                <h3>${result.title}</h3>
                                <p>${result.snippet}</p>
                                <small>ID: ${result.id}</small>
                            </div>
                        `).join('')}
                    </div>
                    
                    <script>
                        // Vulnerable: using query in JavaScript
                        var searchQuery = "${query}";
                        document.title = "Results for: " + searchQuery;
                        
                        // Another vulnerability
                        if (searchQuery.includes('<script>')) {
                            console.warn('Potential XSS in search query');
                        }
                    </script>
                    
                    <a href="/dom" class="btn">← Back to Challenge</a>
                </div>
            </body>
            </html>
            `;
            
            res.send(html);
        }
    }
    
    /**
     * Dynamic script loader endpoint
     */
    static async dynamicScriptLoader(req, res) {
        const scriptUrl = req.query.src || '';
        const callback = req.query.callback || '';
        
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dynamic Script Loader</title>
            <link rel="stylesheet" href="/css/styles.css">
        </head>
        <body>
            <div class="container">
                <h1>📦 Dynamic Script Loader</h1>
                <p>Load external scripts dynamically.</p>
                
                <div class="loader-controls">
                    <form id="scriptForm">
                        <div class="form-group">
                            <label for="scriptSrc">Script URL:</label>
                            <input type="text" id="scriptSrc" name="src" 
                                   value="${scriptUrl || 'https://code.jquery.com/jquery-3.6.0.min.js'}" 
                                   class="form-control">
                        </div>
                        <div class="form-group">
                            <label for="scriptCallback">Callback Function:</label>
                            <input type="text" id="scriptCallback" name="callback" 
                                   value="${callback}" 
                                   class="form-control" 
                                   placeholder="Optional callback function name">
                        </div>
                        <button type="button" onclick="loadScript()" class="btn btn-primary">
                            Load Script
                        </button>
                    </form>
                </div>
                
                <div id="scriptOutput" class="result-box">
                    <p>Script output will appear here.</p>
                </div>
                
                <!-- Vulnerable JavaScript -->
                <script>
                    function loadScript() {
                        var src = document.getElementById('scriptSrc').value;
                        var callback = document.getElementById('scriptCallback').value;
                        
                        if (!src) {
                            alert('Please enter a script URL');
                            return;
                        }
                        
                        var output = document.getElementById('scriptOutput');
                        output.innerHTML = '<p>Loading script: ' + src + '</p>';
                        
                        // Intentionally vulnerable: creating script element with user-controlled src
                        var script = document.createElement('script');
                        script.src = src;
                        
                        if (callback) {
                            // Vulnerable: using user input as function name
                            window[callback] = function() {
                                output.innerHTML += '<p>Callback ' + callback + ' executed!</p>';
                            };
                            script.onload = window[callback];
                        }
                        
                        script.onload = function() {
                            output.innerHTML += '<p class="success">✅ Script loaded successfully!</p>';
                        };
                        
                        script.onerror = function() {
                            output.innerHTML += '<p class="error">❌ Failed to load script</p>';
                        };
                        
                        document.head.appendChild(script);
                    }
                    
                    // Auto-load if URL parameters provided
                    window.addEventListener('load', function() {
                        ${scriptUrl ? 'loadScript();' : ''}
                    });
                </script>
                
                <div class="warning">
                    <h4>⚠️ Extreme Danger:</h4>
                    <p>This endpoint allows loading ANY script from ANY domain.</p>
                    <p>An attacker could load malicious scripts that steal cookies, redirect users, or deface the page.</p>
                </div>
                
                <a href="/dom" class="btn">← Back to Challenge</a>
            </div>
        </body>
        </html>
        `;
        
        res.send(html);
    }
}

module.exports = DomController;