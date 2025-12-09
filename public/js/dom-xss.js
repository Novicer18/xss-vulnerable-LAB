// DOM XSS Module - Intentionally Vulnerable JavaScript

// Vulnerability 1: Unsafe fragment handling
window.addEventListener('load', function() {
    // UNSAFE: Directly inserting fragment into innerHTML
    const fragment = window.location.hash.substring(1);
    if (fragment) {
        const output = document.getElementById('fragmentOutput');
        if (output) {
            output.innerHTML = `
                <div class="alert alert-info">
                    <strong>Fragment content:</strong>
                    <div class="fragment-content">${fragment}</div>
                </div>
            `;
        }
    }
    
    // Also vulnerable: using fragment in document.write
    if (fragment.includes('debug')) {
        document.write(`<p>Debug mode: ${fragment}</p>`);
    }
});

// Vulnerability 2: Unsafe search functionality
function performSearch() {
    const searchInput = document.getElementById('domSearch');
    const searchTerm = searchInput.value;
    const resultsDiv = document.getElementById('searchResults');
    
    if (!searchTerm.trim()) {
        resultsDiv.innerHTML = '<p class="text-gray">Please enter a search term</p>';
        return;
    }
    
    // UNSAFE: Direct innerHTML assignment with user input
    resultsDiv.innerHTML = `
        <div class="search-results">
            <h4>Search Results for "${searchTerm}"</h4>
            <div class="results-list">
                <p>1. Result related to: ${searchTerm}</p>
                <p>2. Another result for: ${searchTerm}</p>
                <p>3. More results about: ${searchTerm}</p>
            </div>
            <p class="search-meta">Search completed at ${new Date().toLocaleTimeString()}</p>
        </div>
    `;
    
    // UNSAFE: Using eval with user input (hidden vulnerability)
    try {
        if (searchTerm.startsWith('calc:')) {
            const expression = searchTerm.substring(5);
            // DANGEROUS: eval with user input
            const result = eval(expression);
            resultsDiv.innerHTML += `<p>Calculation result: ${result}</p>`;
        }
    } catch (e) {
        // Silently fail
    }
}

// Vulnerability 3: Unsafe redirect
function unsafeRedirect() {
    const urlInput = document.getElementById('redirectUrl');
    const url = urlInput.value.trim();
    
    if (!url) {
        alert('Please enter a URL');
        return;
    }
    
    // UNSAFE: Direct assignment to location with user input
    // This allows javascript: URLs
    window.location = url;
}

// Vulnerability 4: Dynamic script injection
function loadDynamicScript() {
    const scriptSource = document.getElementById('scriptSource').value.trim();
    
    if (!scriptSource) {
        alert('Please enter a script URL');
        return;
    }
    
    // UNSAFE: Creating script element with user-controlled source
    const script = document.createElement('script');
    script.src = scriptSource;
    script.onload = function() {
        alert('Script loaded successfully!');
    };
    script.onerror = function() {
        alert('Failed to load script');
    };
    
    document.head.appendChild(script);
}

// Vulnerability 5: Unsafe setTimeout with user input
function scheduleMessage() {
    const message = prompt('Enter a message to display after 2 seconds:');
    if (message) {
        // UNSAFE: Using user input in setTimeout string
        setTimeout(`alert("Scheduled: ${message}")`, 2000);
    }
}

// Vulnerability 6: Unsafe JSON parsing
function parseUserData() {
    const jsonInput = prompt('Enter JSON data:');
    if (jsonInput) {
        try {
            // UNSAFE: Direct eval instead of JSON.parse
            const data = eval('(' + jsonInput + ')');
            alert('Data parsed: ' + JSON.stringify(data));
        } catch (e) {
            alert('Invalid JSON');
        }
    }
}

// Helper functions
function setSearch(payload) {
    document.getElementById('domSearch').value = payload;
}

// Expose functions globally (for testing)
window.performSearch = performSearch;
window.unsafeRedirect = unsafeRedirect;
window.loadDynamicScript = loadDynamicScript;
window.scheduleMessage = scheduleMessage;
window.parseUserData = parseUserData;
window.setSearch = setSearch;

// Add some global variables that could be accessed by XSS
window.userSettings = {
    theme: 'light',
    language: 'en',
    sessionId: Math.random().toString(36).substr(2, 9)
};

// Cookie simulation
document.cookie = "training_session=abc123; path=/";
document.cookie = "user_preferences=theme=light; path=/";

console.warn('This JavaScript file contains intentional DOM XSS vulnerabilities for training purposes.');