/**
 * Comment Model
 * Handles database operations for comments (intentionally vulnerable)
 */

const mysql = require('mysql2/promise');

class CommentModel {
    
    /**
     * Initialize database connection
     */
    static async initPool(pool) {
        this.pool = pool;
        
        // Create table if not exists
        await this.createTable();
    }
    
    /**
     * Create comments table
     */
    static async createTable() {
        try {
            await this.pool.execute(`
                CREATE TABLE IF NOT EXISTS comments (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    username VARCHAR(255) NOT NULL DEFAULT 'Anonymous',
                    content TEXT NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    is_admin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_created_at (created_at),
                    INDEX idx_username (username)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            `);
            
            console.log('Comments table created/verified');
            
            // Seed initial data
            await this.seedInitialComments();
            
        } catch (error) {
            console.error('Error creating comments table:', error);
            throw error;
        }
    }
    
    /**
     * Seed initial comments
     */
    static async seedInitialComments() {
        try {
            const [existing] = await this.pool.execute(
                'SELECT COUNT(*) as count FROM comments WHERE is_admin = TRUE'
            );
            
            if (existing[0].count === 0) {
                const initialComments = [
                    {
                        username: 'System',
                        content: 'Welcome to the Stored XSS Challenge! This comment system is intentionally vulnerable. Try posting a comment with XSS payloads.',
                        is_admin: true
                    },
                    {
                        username: 'Alice',
                        content: 'Test comment: <script>alert("Basic XSS")</script>',
                        is_admin: false
                    },
                    {
                        username: 'Bob',
                        content: 'Another test: <img src="x" onerror="alert(\'XSS via image\')">',
                        is_admin: false
                    },
                    {
                        username: 'Admin',
                        content: '⚠️ <strong>Warning:</strong> All comments are displayed without sanitization. This is for training purposes only!',
                        is_admin: true
                    }
                ];
                
                for (const comment of initialComments) {
                    await this.pool.execute(
                        'INSERT INTO comments (username, content, is_admin) VALUES (?, ?, ?)',
                        [comment.username, comment.content, comment.is_admin]
                    );
                }
                
                console.log('Initial comments seeded');
            }
        } catch (error) {
            console.error('Error seeding comments:', error);
        }
    }
    
    /**
     * Get all comments (unsafe - no sanitization)
     */
    static async getAllComments(limit = 100, offset = 0) {
        try {
            const [rows] = await this.pool.execute(
                'SELECT * FROM comments ORDER BY created_at DESC LIMIT ? OFFSET ?',
                [limit, offset]
            );
            return rows;
        } catch (error) {
            console.error('Error fetching comments:', error);
            throw error;
        }
    }
    
    /**
     * Get comment by ID
     */
    static async getCommentById(id) {
        try {
            const [rows] = await this.pool.execute(
                'SELECT * FROM comments WHERE id = ?',
                [id]
            );
            return rows[0] || null;
        } catch (error) {
            console.error('Error fetching comment by ID:', error);
            throw error;
        }
    }
    
    /**
     * Create a new comment (intentionally no sanitization)
     */
    static async createComment(commentData) {
        try {
            const { username, content, ip_address, user_agent } = commentData;
            
            const [result] = await this.pool.execute(
                `INSERT INTO comments (username, content, ip_address, user_agent, created_at) 
                 VALUES (?, ?, ?, ?, NOW())`,
                [
                    username || 'Anonymous',
                    content,
                    ip_address || null,
                    user_agent || null
                ]
            );
            
            return {
                id: result.insertId,
                username: username || 'Anonymous',
                content: content,
                created_at: new Date()
            };
            
        } catch (error) {
            console.error('Error creating comment:', error);
            throw error;
        }
    }
    
    /**
     * Update comment (vulnerable to XSS)
     */
    static async updateComment(id, commentData) {
        try {
            const { content } = commentData;
            
            // Intentionally no sanitization
            await this.pool.execute(
                'UPDATE comments SET content = ? WHERE id = ?',
                [content, id]
            );
            
            return await this.getCommentById(id);
            
        } catch (error) {
            console.error('Error updating comment:', error);
            throw error;
        }
    }
    
    /**
     * Delete comment
     */
    static async deleteComment(id) {
        try {
            await this.pool.execute(
                'DELETE FROM comments WHERE id = ?',
                [id]
            );
            return true;
        } catch (error) {
            console.error('Error deleting comment:', error);
            throw error;
        }
    }
    
    /**
     * Search comments (vulnerable to SQL injection for training)
     */
    static async searchComments(keyword) {
        try {
            // Intentionally vulnerable SQL query for training
            const query = `SELECT * FROM comments WHERE content LIKE '%${keyword}%' OR username LIKE '%${keyword}%' ORDER BY created_at DESC`;
            
            const [rows] = await this.pool.query(query);
            return rows;
            
        } catch (error) {
            console.error('Error searching comments:', error);
            throw error;
        }
    }
    
    /**
     * Get comment statistics
     */
    static async getStatistics() {
        try {
            const [stats] = await this.pool.execute(`
                SELECT 
                    COUNT(*) as total,
                    COUNT(DISTINCT username) as unique_users,
                    AVG(LENGTH(content)) as avg_length,
                    MAX(created_at) as latest,
                    MIN(created_at) as earliest,
                    COUNT(CASE WHEN content LIKE '%<script>%' THEN 1 END) as script_tags,
                    COUNT(CASE WHEN content LIKE '%onload=%' THEN 1 END) as onload_handlers,
                    COUNT(CASE WHEN content LIKE '%onerror=%' THEN 1 END) as onerror_handlers,
                    COUNT(CASE WHEN content LIKE '%javascript:%' THEN 1 END) as js_urls
                FROM comments
            `);
            
            const [recentActivity] = await this.pool.execute(`
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as count,
                    GROUP_CONCAT(DISTINCT username) as users
                FROM comments 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            `);
            
            return {
                overall: stats[0],
                recent_activity: recentActivity
            };
            
        } catch (error) {
            console.error('Error getting statistics:', error);
            throw error;
        }
    }
    
    /**
     * Reset comments to initial state
     */
    static async resetComments() {
        try {
            // Delete all non-admin comments
            await this.pool.execute('DELETE FROM comments WHERE is_admin = FALSE');
            
            // Add some test comments
            const testComments = [
                {
                    username: 'TestUser1',
                    content: 'New session started. Try <script>alert("XSS")</script>',
                    is_admin: false
                },
                {
                    username: 'TestUser2',
                    content: 'Test: <img src=x onerror=alert(1)>',
                    is_admin: false
                },
                {
                    username: 'TestUser3',
                    content: 'SVG test: <svg onload=alert("SVG XSS")></svg>',
                    is_admin: false
                }
            ];
            
            for (const comment of testComments) {
                await this.pool.execute(
                    'INSERT INTO comments (username, content, is_admin) VALUES (?, ?, ?)',
                    [comment.username, comment.content, comment.is_admin]
                );
            }
            
            return {
                success: true,
                message: 'Comments reset successfully',
                test_comments_added: testComments.length
            };
            
        } catch (error) {
            console.error('Error resetting comments:', error);
            throw error;
        }
    }
    
    /**
     * Check for potential XSS in comments
     */
    static async detectXSSPatterns() {
        try {
            const [patterns] = await this.pool.execute(`
                SELECT 
                    id,
                    username,
                    SUBSTRING(content, 1, 100) as preview,
                    CASE 
                        WHEN content LIKE '%<script>%' THEN 'script_tag'
                        WHEN content LIKE '%onerror=%' THEN 'onerror_handler'
                        WHEN content LIKE '%onload=%' THEN 'onload_handler'
                        WHEN content LIKE '%onmouseover=%' THEN 'mouseover_handler'
                        WHEN content LIKE '%javascript:%' THEN 'javascript_url'
                        WHEN content LIKE '%eval(%' THEN 'eval_call'
                        WHEN content LIKE '%innerHTML%' THEN 'innerhtml_usage'
                        ELSE 'other'
                    END as xss_type,
                    created_at
                FROM comments 
                WHERE content REGEXP '<script|onerror=|onload=|onmouseover=|javascript:|eval\\(|innerHTML'
                ORDER BY created_at DESC
                LIMIT 50
            `);
            
            return patterns;
            
        } catch (error) {
            console.error('Error detecting XSS patterns:', error);
            throw error;
        }
    }
}

module.exports = CommentModel;