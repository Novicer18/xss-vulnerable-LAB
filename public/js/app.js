// Global application JavaScript

// Reset comments function
async function resetComments() {
    if (confirm('Reset all comments to initial state?')) {
        try {
            const response = await fetch('/api/reset/comments', {
                method: 'POST'
            });
            const data = await response.json();
            if (data.success) {
                alert('Comments reset successfully!');
                location.reload();
            }
        } catch (error) {
            alert('Error resetting comments');
        }
    }
}

// Clear logs function
async function clearLogs() {
    if (confirm('Clear all activity logs?')) {
        try {
            const response = await fetch('/api/reset/logs', {
                method: 'POST'
            });
            const data = await response.json();
            if (data.success) {
                alert('Logs cleared successfully!');
                location.reload();
            }
        } catch (error) {
            alert('Error clearing logs');
        }
    }
}

// Copy to clipboard function
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard!');
    }).catch(err => {
        console.error('Copy failed:', err);
    });
}

// Toggle code visibility
function toggleCode(elementId) {
    const element = document.getElementById(elementId);
    if (element.style.display === 'none') {
        element.style.display = 'block';
    } else {
        element.style.display = 'none';
    }
}

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    // Add copy buttons to code blocks
    document.querySelectorAll('pre code').forEach((block) => {
        const button = document.createElement('button');
        button.className = 'btn btn-sm btn-outline copy-btn';
        button.innerHTML = '<i class="fas fa-copy"></i> Copy';
        button.style.position = 'absolute';
        button.style.top = '0.5rem';
        button.style.right = '0.5rem';
        
        const pre = block.parentElement;
        pre.style.position = 'relative';
        pre.appendChild(button);
        
        button.addEventListener('click', () => {
            copyToClipboard(block.textContent);
        });
    });
    
    // Auto-expand textareas
    const textareas = document.querySelectorAll('textarea');
    textareas.forEach(textarea => {
        textarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    });
});