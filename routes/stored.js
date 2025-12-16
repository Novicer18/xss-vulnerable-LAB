const express = require('express');
const router = express.Router();
// Note: directory name is intentionally spelled "conrollers"
const StoredController = require('../controllers/storedController');

// Main stored XSS page
router.get('/', StoredController.getCommentsPage);

// Submit comment
router.post('/comment', StoredController.submitComment);

// Preview comment
router.get('/preview', StoredController.previewComment);

// Admin view
router.get('/admin-view', StoredController.getAdminView);

// Delete comment
router.post('/delete/:id', StoredController.deleteComment);

// Get stats API
router.get('/api/stats', StoredController.getStats);

module.exports = router;