/**
 * Stored XSS Controller
 * Handles stored XSS vulnerabilities with database interaction
 */

class StoredController {
    
    /**
     * Get all comments (vulnerable display)
     */
    static async getCommentsPage(req, res) {
        try {
            const pool = req.app.locals.pool;
            const [comments] = await pool.execute(
                'SELECT * FROM comments ORDER BY created_at DESC'
            );
            
            // Also get stats for admin panel
            const [stats] = await pool.execute(
                `SELECT 
                    COUNT(*) as total,
                    SUM(is_admin) as admin_comments,
                    COUNT(DISTINCT username) as unique_users
                 FROM comments`
            );
            
            res.render('stored', {
                title: 'Stored XSS Challenge',
                comments: comments,
                stats: stats[0] || {},
                difficulty: 'Medium',
                description: 'User input is stored in database and displayed to other users without sanitization.',
                hints: [
                    'Post a comment with <script>alert("XSS")</script>',
                    'Try event handlers: onmouseover, onload, onerror',
                    'Use <img src=x onerror=alert(document.cookie)>',
                    'Test SVG payloads: <svg onload=alert(1)>',
                    'Try cookie stealing payloads'
                ],
                currentPage: 'stored'
            });
        } catch (error) {
            console.error('Error loading comments:', error);
            res.status(500).render('error', {
                title: 'Database Error',
                message: 'Failed to load comments from database'
            });
        }
    }
    
    /**
     * Submit a new comment (vulnerable storage)
     */
    static async submitComment(req, res) {
        try {
            const { username, comment } = req.body;
            const pool = req.app.locals.pool;
            
            if (!comment || comment.trim().length === 0) {
                return res.redirect('/stored?error=empty');
            }
            
            // Intentionally NOT sanitizing input before storage
            const [result] = await pool.execute(
                `INSERT INTO comments (username, content, ip_address, user_agent, created_at) 
                 VALUES (?, ?, ?, ?, NOW())`,
                [
                    username || 'Anonymous',
                    comment,
                    req.ip,
                    req.get('User-Agent')
                ]
            );
            
            // Log the XSS attempt
            await pool.execute(
                `INSERT INTO logs (module, action, payload, ip_address, user_agent) 
                 VALUES (?, ?, ?, ?, ?)`,
                [
                    'stored',
                    'comment_posted',
                    comment.substring(0, 500), // Limit payload length
                    req.ip,
                    req.get('User-Agent')
                ]
            );
            
            res.redirect('/stored');
            
        } catch (error) {
            console.error('Error submitting comment:', error);
            res.redirect('/stored?error=server');
        }
    }
    
    /**
     * Admin view showing raw comments
     */
    static async getAdminView(req, res) {
        try {
            const pool = req.app.locals.pool;
            const [comments] = await pool.execute(
                'SELECT * FROM comments ORDER BY created_at DESC'
            );
            
            // Also get XSS detection logs
            const [logs] = await pool.execute(
                `SELECT * FROM logs 
                 WHERE module = 'stored' 
                 ORDER BY created_at DESC 
                 LIMIT 50`
            );
            
            res.render('stored-admin', {
                title: 'Admin View - Raw Comments',
                comments: comments,
                logs: logs,
                showRaw: true,
                currentPage: 'stored'
            });
            
        } catch (error) {
            console.error('Error loading admin view:', error);
            res.status(500).send('Database error');
        }
    }
    
    /**
     * Delete a comment (no authentication - intentional)
     */
    static async deleteComment(req, res) {
        try {
            const { id } = req.params;
            const pool = req.app.locals.pool;
            
            // Intentionally no authentication check
            await pool.execute('DELETE FROM comments WHERE id = ?', [id]);
            
            // Log the deletion
            await pool.execute(
                `INSERT INTO logs (module, action, payload, ip_address) 
                 VALUES (?, ?, ?, ?)`,
                ['stored', 'comment_deleted', `Comment ID: ${id}`, req.ip]
            );
            
            res.redirect('/stored');
            
        } catch (error) {
            console.error('Error deleting comment:', error);
            res.redirect('/stored?error=delete');
        }
    }
    
    /**
     * Preview comment before posting (vulnerable)
     */
    static async previewComment(req, res) {
        const { username, comment } = req.query;
        
        // Intentionally vulnerable preview
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Comment Preview</title>
            <link rel="stylesheet" href="/css/styles.css">
        </head>
        <body>
            <div class="container">
                <h1>👁️ Comment Preview</h1>
                <div class="preview-warning">
                    <p><strong>⚠️ Warning:</strong> This preview shows exactly how your comment will appear to other users.</p>
                    <p>Any HTML/JavaScript you enter will be executed!</p>
                </div>
                
                <div class="comment-preview">
                    <div class="comment-header">
                        <strong>${username || 'Anonymous'}</strong>
                        <span>Preview at ${new Date().toLocaleTimeString()}</span>
                    </div>
                    <div class="comment-body">
                        <!-- INTENTIONALLY VULNERABLE -->
                        ${comment || 'No comment provided'}
                    </div>
                </div>
                
                <div class="raw-preview">
                    <h4>Raw HTML that will be stored:</h4>
                    <pre><code>${comment || ''}</code></pre>
                </div>
                
                <form action="/stored/comment" method="POST" style="margin-top: 20px;">
                    <input type="hidden" name="username" value="${username || ''}">
                    <input type="hidden" name="comment" value="${comment || ''}">
                    <button type="submit" class="btn btn-primary">Post Comment</button>
                    <a href="/stored" class="btn">Cancel</a>
                </form>
            </div>
        </body>
        </html>
        `;
        
        res.send(html);
    }
    
    /**
     * Get comment stats API
     */
    static async getStats(req, res) {
        try {
            const pool = req.app.locals.pool;
            
            const [stats] = await pool.execute(`
                SELECT 
                    COUNT(*) as total_comments,
                    COUNT(DISTINCT username) as unique_users,
                    COUNT(CASE WHEN content LIKE '%<script>%' THEN 1 END) as script_tags,
                    COUNT(CASE WHEN content LIKE '%onerror=%' THEN 1 END) as event_handlers,
                    COUNT(CASE WHEN content LIKE '%javascript:%' THEN 1 END) as js_urls,
                    MAX(created_at) as latest_comment
                FROM comments
            `);
            
            const [recentXSS] = await pool.execute(`
                SELECT * FROM logs 
                WHERE module = 'stored' 
                AND (payload LIKE '%<script>%' OR payload LIKE '%onerror=%')
                ORDER BY created_at DESC 
                LIMIT 10
            `);
            
            res.json({
                success: true,
                stats: stats[0],
                recent_xss_attempts: recentXSS,
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }
}

module.exports = StoredController;