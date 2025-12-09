USE xss_lab;

-- Seed some initial comments for Stored XSS module
INSERT INTO comments (username, content, is_admin) VALUES
('System', 'Welcome to the XSS Training Lab! Try to inject scripts in the comment section.', TRUE),
('Alice', 'This is a test comment. Try <script>alert("XSS")</script>', FALSE),
('Bob', 'Hello world! This lab is intentionally vulnerable.', FALSE),
('Admin', '⚠️ Warning: This application contains intentional vulnerabilities for training purposes only!', TRUE);

-- Seed initial logs
INSERT INTO logs (module, action, payload) VALUES
('system', 'app_started', 'Application initialized'),
('reflected', 'demo_search', 'test'),
('stored', 'comment_posted', 'Welcome comment'),
('dom', 'page_loaded', 'Initial load');