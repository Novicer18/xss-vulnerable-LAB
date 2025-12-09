require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');

// Database connection
const mysql = require('mysql2/promise');
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'xssuser',
    password: process.env.DB_PASSWORD || 'xsspassword',
    database: process.env.DB_NAME || 'xss_lab',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

const app = express();
const PORT = process.env.PORT || 3000;

// Create logs directory
if (!fs.existsSync('logs')) {
    fs.mkdirSync('logs');
}

// Session store
const sessionStore = new MySQLStore(dbConfig);

// Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Disabled for XSS training
    crossOriginEmbedderPolicy: false
}));

app.use(morgan('combined', {
    stream: fs.createWriteStream(path.join(__dirname, 'logs', 'access.log'), { flags: 'a' })
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
    key: 'session_cookie_name',
    secret: process.env.SESSION_SECRET || 'xss-training-secret-key',
    store: sessionStore,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Database connection pool
const pool = mysql.createPool(dbConfig);

// Make pool available to routes
app.locals.pool = pool;

// Logging middleware
app.use(async (req, res, next) => {
    const logData = {
        module: req.path.split('/')[1] || 'home',
        action: req.method,
        payload: JSON.stringify(req.query || req.body || {}),
        ip_address: req.ip,
        user_agent: req.get('User-Agent')
    };
    
    try {
        await pool.execute(
            'INSERT INTO logs (module, action, payload, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
            [logData.module, logData.action, logData.payload, logData.ip_address, logData.user_agent]
        );
    } catch (err) {
        console.error('Logging error:', err);
    }
    
    next();
});

// Routes
const reflectedRouter = require('./routes/reflected');
const storedRouter = require('./routes/stored');
const domRouter = require('./routes/dom');

// Initialize models
const CommentModel = require('./models/comment');
const LogModel = require('./models/log');

// Make models available to app
app.locals.CommentModel = CommentModel;
app.locals.LogModel = LogModel;

// // Initialize models with DB pool
// CommentModel.initPool(pool);
// LogModel.initPool(pool);

app.use('/reflected', reflectedRouter);
app.use('/stored', storedRouter);
app.use('/dom', domRouter);

// Home route
app.get('/', (req, res) => {
    res.render('dashboard', { 
        title: 'XSS Training Lab',
        modules: [
            { name: 'Reflected XSS', path: '/reflected', difficulty: 'Easy', description: 'Input is immediately reflected in response' },
            { name: 'Stored XSS', path: '/stored', difficulty: 'Medium', description: 'Input is stored and displayed to other users' },
            { name: 'DOM-Based XSS', path: '/dom', difficulty: 'Hard', description: 'Client-side JavaScript manipulates DOM unsafely' }
        ]
    });
});

// Admin panel (optional)
app.get('/admin', async (req, res) => {
    try {
        const [logs] = await pool.execute('SELECT * FROM logs ORDER BY created_at DESC LIMIT 100');
        const [comments] = await pool.execute('SELECT * FROM comments ORDER BY created_at DESC');
        
        res.render('admin', {
            title: 'Admin Panel',
            logs: logs,
            comments: comments,
            totalLogs: logs.length,
            totalComments: comments.length
        });
    } catch (error) {
        res.status(500).send('Error loading admin panel');
    }
});

// Reset endpoints (for training)
app.post('/api/reset/comments', async (req, res) => {
    try {
        await pool.execute('DELETE FROM comments WHERE is_admin = FALSE');
        await pool.execute(`
            INSERT INTO comments (username, content, is_admin) 
            VALUES (?, ?, ?), (?, ?, ?)
        `, [
            'System', 'Comments have been reset. Try stored XSS attacks!', true,
            'Alice', 'New session started. Try <script>alert(1)</script>', false
        ]);
        
        res.json({ success: true, message: 'Comments reset successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/reset/logs', async (req, res) => {
    try {
        await pool.execute('DELETE FROM logs');
        res.json({ success: true, message: 'Logs cleared' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API for DOM XSS
app.get('/api/search', (req, res) => {
    const query = req.query.q || '';
    // Intentionally vulnerable - no output encoding
    res.json({ 
        success: true, 
        query: query,
        results: [`Search result for: ${query}`],
        message: 'Search completed'
    });
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// // Start server
// app.listen(PORT, () => {
//     console.log(`XSS Training Lab running on http://localhost:${PORT}`);
//     console.log(`MySQL Database: ${dbConfig.host}:${dbConfig.port}/${dbConfig.database}`);
// });

// Initialize models with pool
app.listen(PORT, async () => {
    console.log(`XSS Training Lab running on http://localhost:${PORT}`);
    console.log(`MySQL Database: ${dbConfig.host}:${dbConfig.port}/${dbConfig.database}`);
    
    try {
        // Initialize models
        await CommentModel.initPool(pool);
        await LogModel.initPool(pool);
        console.log('Models initialized successfully');
    } catch (error) {
        console.error('Error initializing models:', error);
    }
});
    