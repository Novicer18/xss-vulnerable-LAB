const express = require('express');
const router = express.Router();
// Note: directory name is intentionally spelled "conrollers"
const ReflectedController = require('../controllers/reflectedController');

// Main reflected XSS page
router.get('/', ReflectedController.getReflectedPage);

// Vulnerable search endpoint
router.get('/search', ReflectedController.vulnerableSearch);

// Vulnerable profile endpoint
router.get('/profile', ReflectedController.vulnerableProfile);

// Vulnerable API endpoint
router.get('/api', ReflectedController.vulnerableApi);

// Vulnerable error endpoint
router.get('/error', ReflectedController.vulnerableError);

module.exports = router;