/**
 * Log Model
 * Tracks user activity and XSS attempts
 */

class LogModel {
    
    /**
     * Initialize database connection
     */
    static async initPool(pool) {
        this.pool = pool;
        await this.createTable();
    }
    
    /**
     * Create logs table
     */
    static async createTable() {
        try {
            await this.pool.execute(`
                CREATE TABLE IF NOT EXISTS logs (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    module VARCHAR(50) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    payload TEXT,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    session_id VARCHAR(100),
                    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_module (module),
                    INDEX idx_action (action),
                    INDEX idx_severity (severity),
                    INDEX idx_created_at (created_at),
                    INDEX idx_ip (ip_address)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            `);
            
            console.log('Logs table created/verified');
            
        } catch (error) {
            console.error('Error creating logs table:', error);
            throw error;
        }
    }
    
    /**
     * Log an activity
     */
    static async logActivity(logData) {
        try {
            const {
                module,
                action,
                payload = '',
                ip_address = '',
                user_agent = '',
                session_id = '',
                severity = 'low'
            } = logData;
            
            // Intentionally store payload without sanitization for analysis
            const [result] = await this.pool.execute(
                `INSERT INTO logs (module, action, payload, ip_address, user_agent, session_id, severity, created_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
                [module, action, payload, ip_address, user_agent, session_id, severity]
            );
            
            return result.insertId;
            
        } catch (error) {
            console.error('Error logging activity:', error);
            // Don't throw error for logging failures
            return null;
        }
    }
    
    /**
     * Log XSS attempt
     */
    static async logXSSAttempt(attemptData) {
        try {
            const {
                module,
                payload,
                ip_address = '',
                user_agent = '',
                triggered = false,
                notes = ''
            } = attemptData;
            
            // Analyze payload for severity
            let severity = 'low';
            if (payload.includes('document.cookie') || payload.includes('localStorage')) {
                severity = 'critical';
            } else if (payload.includes('alert') || payload.includes('prompt')) {
                severity = 'medium';
            } else if (payload.includes('<script>') || payload.includes('onerror=')) {
                severity = 'high';
            }
            
            const action = triggered ? 'xss_triggered' : 'xss_attempted';
            const fullPayload = notes ? `${payload} | Notes: ${notes}` : payload;
            
            return await this.logActivity({
                module,
                action,
                payload: fullPayload,
                ip_address,
                user_agent,
                severity
            });
            
        } catch (error) {
            console.error('Error logging XSS attempt:', error);
            return null;
        }
    }
    
    /**
     * Get logs with filters
     */
    static async getLogs(filters = {}) {
        try {
            const {
                module = null,
                action = null,
                severity = null,
                startDate = null,
                endDate = null,
                limit = 100,
                offset = 0
            } = filters;
            
            let query = 'SELECT * FROM logs WHERE 1=1';
            const params = [];
            
            if (module) {
                query += ' AND module = ?';
                params.push(module);
            }
            
            if (action) {
                query += ' AND action = ?';
                params.push(action);
            }
            
            if (severity) {
                query += ' AND severity = ?';
                params.push(severity);
            }
            
            if (startDate) {
                query += ' AND created_at >= ?';
                params.push(startDate);
            }
            
            if (endDate) {
                query += ' AND created_at <= ?';
                params.push(endDate);
            }
            
            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
            params.push(limit, offset);
            
            const [rows] = await this.pool.execute(query, params);
            return rows;
            
        } catch (error) {
            console.error('Error fetching logs:', error);
            throw error;
        }
    }
    
    /**
     * Get log statistics
     */
    static async getLogStatistics() {
        try {
            const [overallStats] = await this.pool.execute(`
                SELECT 
                    COUNT(*) as total,
                    COUNT(DISTINCT module) as modules,
                    COUNT(DISTINCT ip_address) as unique_ips,
                    MIN(created_at) as first_log,
                    MAX(created_at) as last_log
                FROM logs
            `);
            
            const [moduleStats] = await this.pool.execute(`
                SELECT 
                    module,
                    COUNT(*) as count,
                    COUNT(CASE WHEN action LIKE '%xss%' THEN 1 END) as xss_count,
                    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count
                FROM logs 
                GROUP BY module 
                ORDER BY count DESC
            `);
            
            const [severityStats] = await this.pool.execute(`
                SELECT 
                    severity,
                    COUNT(*) as count,
                    COUNT(DISTINCT ip_address) as unique_ips
                FROM logs 
                GROUP BY severity 
                ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low')
            `);
            
            const [recentXSS] = await this.pool.execute(`
                SELECT 
                    id,
                    module,
                    action,
                    SUBSTRING(payload, 1, 200) as payload_preview,
                    ip_address,
                    created_at
                FROM logs 
                WHERE action LIKE '%xss%' 
                ORDER BY created_at DESC 
                LIMIT 10
            `);
            
            return {
                overall: overallStats[0],
                by_module: moduleStats,
                by_severity: severityStats,
                recent_xss: recentXSS
            };
            
        } catch (error) {
            console.error('Error getting log statistics:', error);
            throw error;
        }
    }
    
    /**
     * Clear logs
     */
    static async clearLogs(module = null) {
        try {
            if (module) {
                await this.pool.execute('DELETE FROM logs WHERE module = ?', [module]);
                return { success: true, message: `Logs cleared for module: ${module}` };
            } else {
                await this.pool.execute('DELETE FROM logs');
                return { success: true, message: 'All logs cleared' };
            }
        } catch (error) {
            console.error('Error clearing logs:', error);
            throw error;
        }
    }
    
    /**
     * Export logs to CSV format
     */
    static async exportLogs(format = 'csv') {
        try {
            const [logs] = await this.pool.execute(`
                SELECT 
                    id,
                    module,
                    action,
                    payload,
                    ip_address,
                    user_agent,
                    severity,
                    created_at
                FROM logs 
                ORDER BY created_at DESC
            `);
            
            if (format === 'csv') {
                // Convert to CSV
                const headers = ['ID', 'Module', 'Action', 'Payload', 'IP Address', 'User Agent', 'Severity', 'Timestamp'];
                const csvRows = logs.map(log => [
                    log.id,
                    `"${log.module}"`,
                    `"${log.action}"`,
                    `"${log.payload ? log.payload.replace(/"/g, '""') : ''}"`,
                    `"${log.ip_address}"`,
                    `"${log.user_agent ? log.user_agent.replace(/"/g, '""') : ''}"`,
                    `"${log.severity}"`,
                    `"${log.created_at}"`
                ]);
                
                const csvContent = [
                    headers.join(','),
                    ...csvRows.map(row => row.join(','))
                ].join('\n');
                
                return csvContent;
                
            } else {
                // Return as JSON
                return logs;
            }
            
        } catch (error) {
            console.error('Error exporting logs:', error);
            throw error;
        }
    }
    
    /**
     * Detect suspicious patterns in logs
     */
    static async detectSuspiciousActivity() {
        try {
            const [suspicious] = await this.pool.execute(`
                SELECT 
                    ip_address,
                    COUNT(*) as request_count,
                    COUNT(DISTINCT module) as modules_accessed,
                    GROUP_CONCAT(DISTINCT module ORDER BY module) as modules_list,
                    MAX(created_at) as last_request,
                    MIN(created_at) as first_request,
                    SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END) as high_severity_count
                FROM logs 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                GROUP BY ip_address 
                HAVING request_count > 50 OR high_severity_count > 5
                ORDER BY high_severity_count DESC, request_count DESC
            `);
            
            const [xssPatterns] = await this.pool.execute(`
                SELECT 
                    payload,
                    COUNT(*) as occurrence_count,
                    COUNT(DISTINCT ip_address) as unique_ips,
                    GROUP_CONCAT(DISTINCT module) as modules,
                    MAX(created_at) as last_seen
                FROM logs 
                WHERE action LIKE '%xss%' 
                AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY payload 
                HAVING occurrence_count > 1
                ORDER BY occurrence_count DESC
                LIMIT 20
            `);
            
            return {
                suspicious_ips: suspicious,
                common_xss_payloads: xssPatterns
            };
            
        } catch (error) {
            console.error('Error detecting suspicious activity:', error);
            throw error;
        }
    }
}

module.exports = LogModel;