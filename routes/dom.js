const express = require('express');
const router = express.Router();
const DomController = require('../controllers/domController');

// Main DOM XSS page
router.get('/', DomController.getDomPage);

// Vulnerable JSONP endpoint
router.get('/jsonp', DomController.vulnerableJsonp);

// Vulnerable redirect endpoint
router.get('/redirect', DomController.vulnerableRedirect);

// Vulnerable fragment handler
router.get('/fragment', DomController.fragmentHandler);

// Vulnerable search API
router.get('/search', DomController.vulnerableSearchApi);

// Dynamic script loader
router.get('/loader', DomController.dynamicScriptLoader);

module.exports = router;