/**
 * Reflected XSS Controller
 * Contains intentionally vulnerable reflected XSS endpoints
 */

class ReflectedController {
    
    /**
     * Main reflected XSS page
     */
    static async getReflectedPage(req, res) {
        const { name, search } = req.query;
        
        // Intentionally vulnerable - no output encoding in template
        res.render('reflected', {
            title: 'Reflected XSS Challenge',
            name: name || '',
            search: search || '',
            difficulty: 'Easy',
            description: 'User input is directly reflected in the HTML response without proper encoding.',
            hints: [
                'Try <script>alert("XSS")</script> in search parameter',
                'Try <img src=x onerror=alert(1)> in name parameter',
                'Use JavaScript URLs: javascript:alert(document.cookie)',
                'Test with <svg onload=alert(1)>'
            ],
            currentPage: 'reflected'
        });
    }
    
    /**
     * Vulnerable search endpoint - reflected XSS
     */
    static async vulnerableSearch(req, res) {
        const query = req.query.q || '';
        
        // Intentionally vulnerable: direct insertion into HTML
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Search Results - Reflected XSS</title>
            <link rel="stylesheet" href="/css/styles.css">
            <style>
                body {
                    padding: 20px;
                    font-family: Arial, sans-serif;
                }
                .result {
                    background: #f5f5f5;
                    padding: 20px;
                    margin: 20px 0;
                    border-radius: 5px;
                }
                .vulnerable-output {
                    color: #d63031;
                    font-weight: bold;
                    margin: 10px 0;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 Search Results</h1>
                <p>You searched for: <span class="vulnerable-output">${query}</span></p>
                <div class="result">
                    <h3>Search Query Analysis:</h3>
                    <p>Query: <strong>${query}</strong></p>
                    <p>Length: ${query.length} characters</p>
                    <p>URL Encoded: ${encodeURIComponent(query)}</p>
                </div>
                
                <div class="warning">
                    <h4>⚠️ Vulnerability Note:</h4>
                    <p>This page reflects user input directly without sanitization.</p>
                    <p>Raw HTML generated: <code>&lt;span class="vulnerable-output"&gt;${query}&lt;/span&gt;</code></p>
                </div>
                
                <a href="/reflected" class="btn">← Back to Challenge</a>
            </div>
        </body>
        </html>
        `;
        
        res.send(html);
    }
    
    /**
     * Vulnerable user profile endpoint
     */
    static async vulnerableProfile(req, res) {
        const username = req.query.user || 'Guest';
        const userId = req.query.id || '12345';
        
        // Intentionally vulnerable: multiple XSS sinks
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>User Profile - ${username}</title>
            <link rel="stylesheet" href="/css/styles.css">
        </head>
        <body>
            <div class="container">
                <h1>👤 User Profile</h1>
                
                <!-- Vulnerable: Direct insertion in title -->
                <h2>Welcome, ${username}!</h2>
                
                <div class="profile-card">
                    <div class="profile-info">
                        <p><strong>User ID:</strong> ${userId}</p>
                        <p><strong>Username:</strong> ${username}</p>
                        <p><strong>Joined:</strong> ${new Date().toLocaleDateString()}</p>
                    </div>
                    
                    <div class="profile-bio">
                        <h3>Bio:</h3>
                        <p id="userBio">${username}'s profile page. Customize this text!</p>
                    </div>
                </div>
                
                <!-- Vulnerable JavaScript -->
                <script>
                    // Intentionally vulnerable: user input in JavaScript string
                    var userMessage = "Hello, ${username}!";
                    document.getElementById('userBio').innerHTML = userMessage;
                    
                    // Another vulnerability: using eval with user input
                    var userParam = "${userId}";
                    if (userParam.includes('alert')) {
                        console.log("Potential XSS detected in user ID");
                    }
                </script>
                
                <div class="vulnerability-hint">
                    <h4>🎯 XSS Test Points:</h4>
                    <ul>
                        <li><code>user</code> parameter in page title</li>
                        <li><code>user</code> parameter in H2 tag</li>
                        <li><code>user</code> parameter in JavaScript string</li>
                        <li><code>id</code> parameter in JavaScript</li>
                    </ul>
                </div>
                
                <a href="/reflected" class="btn">← Back to Challenge</a>
            </div>
        </body>
        </html>
        `;
        
        res.send(html);
    }
    
    /**
     * Vulnerable API endpoint with JSON response
     */
    static async vulnerableApi(req, res) {
        const { user, action, data } = req.query;
        
        // Intentionally vulnerable: JSON response that might be parsed unsafely
        const response = {
            status: 'success',
            timestamp: new Date().toISOString(),
            user: user || 'anonymous',
            action: action || 'none',
            data: data || '',
            message: `Welcome ${user || 'anonymous'}! Your action "${action || 'none'}" was processed.`,
            debug: {
                rawQuery: req.query,
                userAgent: req.get('User-Agent'),
                ip: req.ip
            }
        };
        
        // Also vulnerable: callback parameter for JSONP
        const callback = req.query.callback;
        if (callback) {
            res.set('Content-Type', 'application/javascript');
            // Intentionally vulnerable JSONP
            res.send(`${callback}(${JSON.stringify(response)})`);
        } else {
            res.json(response);
        }
    }
    
    /**
     * Vulnerable error message endpoint
     */
    static async vulnerableError(req, res) {
        const errorMsg = req.query.msg || 'Unknown error occurred';
        const errorCode = req.query.code || '500';
        
        // Intentionally vulnerable: error messages with user input
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error ${errorCode}</title>
            <link rel="stylesheet" href="/css/styles.css">
        </head>
        <body>
            <div class="container">
                <div class="error-header">
                    <h1>⚠️ Error ${errorCode}</h1>
                    <p class="error-message">${errorMsg}</p>
                </div>
                
                <div class="error-details">
                    <h3>Error Details:</h3>
                    <p><strong>Message:</strong> ${errorMsg}</p>
                    <p><strong>Code:</strong> ${errorCode}</p>
                    <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
                </div>
                
                <div class="hint">
                    <h4>💡 XSS Hint:</h4>
                    <p>Error messages often reflect user input. Try:</p>
                    <code>/reflected/error?msg=&lt;script&gt;alert(1)&lt;/script&gt;</code>
                </div>
                
                <a href="/reflected" class="btn">← Back to Challenge</a>
            </div>
        </body>
        </html>
        `;
        
        res.status(parseInt(errorCode) || 500).send(html);
    }
}

module.exports = ReflectedController;