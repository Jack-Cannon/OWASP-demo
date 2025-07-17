// Global state for secure mode toggle
let secureMode = false;
let csrfToken = null;

document.addEventListener('DOMContentLoaded', () => {
    // Initialize secure mode from localStorage if available
    initializeSecureMode();
    
    // Set up event listeners for navigation buttons
    document.querySelectorAll('nav button').forEach(button => {
        button.addEventListener('click', () => {
            const sectionId = button.getAttribute('onclick').match(/showSection\('([^']+)'\)/)[1];
            showSection(sectionId);
        });
    });
    
    // Show the first section by default
    showSection('xss-section');
    
    // Load initial XSS comments
    loadXSSComments();
    
    // Update BAC login status on load
    updateBACLoginStatus();
    
    // Set up event listeners for file upload buttons
    document.getElementById('vulnerableUploadBtn')?.addEventListener('click', uploadVulnerable);
    document.getElementById('secureUploadBtn')?.addEventListener('click', uploadSecure);
    document.getElementById('listFilesBtn')?.addEventListener('click', listUploadedFiles);
    
    // Set up CSRF demo buttons
    document.getElementById('csrfCheckBalanceBtn')?.addEventListener('click', csrfCheckBalance);
    document.getElementById('csrfTransferBtn')?.addEventListener('click', csrfTransferMoney);
    document.getElementById('csrfAttackBtn')?.addEventListener('click', simulateCsrfAttack);
});

// Initialize secure mode from localStorage if available
function initializeSecureMode() {
    const savedMode = localStorage.getItem('secureMode');
    if (savedMode === 'true') {
        secureMode = true;
        document.getElementById('secureToggle').checked = true;
    }
    updateSecureModeUI();
}

// Toggle between secure and vulnerable modes
function toggleSecureMode() {
    secureMode = document.getElementById('secureToggle').checked;
    localStorage.setItem('secureMode', secureMode);
    updateSecureModeUI();
    
    // Refresh current views to reflect the new mode
    refreshCurrentView();
}

// Update UI to reflect current secure mode
function updateSecureModeUI() {
    const modeIndicator = document.getElementById('currentModeIndicator');
    if (secureMode) {
        modeIndicator.textContent = 'SECURE MODE';
        modeIndicator.className = 'mode-secure';
    } else {
        modeIndicator.textContent = 'VULNERABLE MODE';
        modeIndicator.className = 'mode-vulnerable';
    }
    
    // Update UI to show secure/vulnerable indicators
    updateSecurityIndicators();
};

// Refresh the current view based on active section
function refreshCurrentView() {
    // Get the currently active section
    const activeSection = document.querySelector('.demo-section.active');
    if (!activeSection) return;
    
    const sectionId = activeSection.id;
    
    // Refresh content based on active section
    switch (sectionId) {
        case 'xss-section':
            loadXSSComments();
            break;
        case 'injection-section':
            // Just clear the results, no need to re-search
            document.getElementById('injectionResultsDisplay').innerHTML = '';
            break;
        case 'bac-section':
            // Refresh user profile and admin panel if they were loaded
            const profileDisplay = document.getElementById('bacUserProfileDisplay');
            const adminDisplay = document.getElementById('bacAdminPanelDisplay');
            if (profileDisplay && profileDisplay.innerHTML !== 'No profile loaded.') {
                bacGetUserProfile();
            }
            if (adminDisplay && adminDisplay.innerHTML !== 'No admin data loaded.') {
                bacAccessAdminPanel();
            }
            break;
        case 'csrf-section':
            // Refresh balance if logged in
            if (currentBACUser) {
                csrfCheckBalance();
            }
            break;
        case 'upload-section':
            // Refresh uploaded files list
            listUploadedFiles();
            break;
    }
}

// Update UI to show secure/vulnerable indicators
function updateSecurityIndicators() {
    document.querySelectorAll('.security-indicator').forEach(indicator => {
        if (secureMode) {
            indicator.textContent = '🔒 SECURE';
            indicator.className = 'security-indicator secure';
        } else {
            indicator.textContent = '⚠️ VULNERABLE';
            indicator.className = 'security-indicator vulnerable';
        }
    });
}

function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.demo-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Show the selected section
    const selectedSection = document.getElementById(sectionId);
    if (selectedSection) {
        selectedSection.classList.add('active');
        
        // Load section-specific content
        switch (sectionId) {
            case 'xss-section':
                loadXSSComments();
                break;
            case 'bac-section':
                updateBACLoginStatus();
                break;
            case 'csrf-section':
                if (currentBACUser) {
                    csrfCheckBalance();
                }
                break;
            case 'upload-section':
                listUploadedFiles();
                break;
        }
        
        // Update navigation highlighting
        document.querySelectorAll('nav button').forEach((button, index) => {
            // Match the button index with the section order
            if (button.textContent.includes(selectedSection.querySelector('h2').textContent)) {
                button.classList.add('active');
            } else {
                button.classList.remove('active');
            }
        });
    }
}

// --- XSS Demonstration Functions ---

async function addXSSComment() {
    const commentInput = document.getElementById('xssCommentInput');
    const comment = commentInput.value;
    if (!comment) {
        alert('Please enter a comment.');
        return;
    }

    try {
        // Use secure or vulnerable endpoint based on mode
        const endpoint = secureMode ? '/api/injection/xss/add-comment-secure' : '/api/injection/xss/add-comment';
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ comment })
        });
        const data = await response.json();
        console.log(data.message);
        commentInput.value = ''; // Clear input
        loadXSSComments(); // Refresh comments display
    } catch (error) {
        console.error('Error adding comment:', error);
        alert('Failed to add comment.');
    }
}

async function loadXSSComments() {
    const commentsDisplay = document.getElementById('xssCommentsDisplay');
    commentsDisplay.innerHTML = ''; // Clear current display

    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator ' + (secureMode ? 'secure' : 'vulnerable');
    securityIndicator.textContent = secureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
    commentsDisplay.appendChild(securityIndicator);

    try {
        // Use secure or vulnerable endpoint based on mode
        const endpoint = secureMode ? '/api/injection/xss/get-comments-secure' : '/api/injection/xss/get-comments';
        const response = await fetch(endpoint);
        const comments = await response.json();

        if (comments.length === 0) {
            const noComments = document.createElement('div');
            noComments.textContent = 'No comments yet.';
            commentsDisplay.appendChild(noComments);
            return;
        }

        if (secureMode) {
            // SECURE: Display sanitized comments
            comments.forEach(comment => {
                const commentDiv = document.createElement('div');
                commentDiv.className = 'comment-item';
                commentDiv.innerHTML = comment; // Content is already sanitized on the server
                commentsDisplay.appendChild(commentDiv);
            });
        } else {
            // VULNERABLE: For demonstration purposes, we'll use a different approach
            // that allows script execution to show the XSS vulnerability
            
            // Create a container for all comments
            const commentsContainer = document.createElement('div');
            
            // Join all comments with a separator
            const allComments = comments.join('<hr>');
            
            // Use document.write in a controlled way to demonstrate XSS
            // This is ONLY for demonstration purposes and should NEVER be used in real applications
            const iframe = document.createElement('iframe');
            iframe.style.width = '100%';
            iframe.style.border = '1px solid #ddd';
            iframe.style.borderRadius = '4px';
            iframe.style.minHeight = '200px';
            commentsDisplay.appendChild(iframe);
            
            // Write the comments to the iframe document
            // This allows script execution for demonstration purposes
            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
            iframeDoc.open();
            iframeDoc.write(`
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; padding: 10px; }
                        .comment-item { padding: 8px; margin-bottom: 8px; background-color: #f9f9f9; }
                        .vulnerability-warning { color: red; font-weight: bold; margin-top: 10px; }
                    </style>
                </head>
                <body>
                    <div class="vulnerability-warning">⚠️ VULNERABLE: Scripts can execute in this context!</div>
                    <div class="comments-container">${allComments}</div>
                </body>
                </html>
            `);
            iframeDoc.close();
        }
    } catch (error) {
        console.error('Error loading comments:', error);
        const errorMsg = document.createElement('div');
        errorMsg.textContent = 'Failed to load comments.';
        commentsDisplay.appendChild(errorMsg);
    }
}

async function clearXSSComments() {
    if (confirm('Are you sure you want to clear all comments?')) {
        try {
            // Use the server endpoint to clear comments
            await fetch('/api/injection/xss/clear-comments', { method: 'POST' });
            alert('All comments have been cleared.');
            // Reload comments to show empty state
            loadXSSComments();
        } catch (error) {
            console.error('Error clearing comments:', error);
            alert('Failed to clear comments. Server error.');
        }
    }
}

// Command Injection Simulation
async function simulateCommandInjection() {
    const filenameInput = document.getElementById('commandInjectionInput');
    const filename = filenameInput.value;
    const resultDisplay = document.getElementById('commandInjectionDisplay');
    resultDisplay.innerHTML = ''; // Clear previous results
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator ' + (secureMode ? 'secure' : 'vulnerable');
    securityIndicator.textContent = secureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
    resultDisplay.appendChild(securityIndicator);
    
    if (!filename) {
        const message = document.createElement('div');
        message.textContent = 'Please enter a filename to read.';
        resultDisplay.appendChild(message);
        return;
    }
    
    try {
        // Use secure or vulnerable endpoint based on mode
        const endpoint = secureMode ? 
            `/api/injection/command-secure?filename=${encodeURIComponent(filename)}` : 
            `/api/injection/command?filename=${encodeURIComponent(filename)}`;
            
        const response = await fetch(endpoint);
        const data = await response.json();
        
        if (response.ok) {
            // Create result container
            const resultContainer = document.createElement('div');
            resultContainer.className = 'command-result';
            
            // If injection was detected in vulnerable mode
            if (!secureMode && data.vulnerable) {
                const warningDiv = document.createElement('div');
                warningDiv.className = 'injection-alert';
                warningDiv.innerHTML = `
                    <strong>COMMAND INJECTION DETECTED!</strong><br>
                    Simulated command: <code>${data.simulatedCommand}</code><br>
                    <p>${data.explanation}</p>
                `;
                resultContainer.appendChild(warningDiv);
            } else {
                // Normal response
                const contentDiv = document.createElement('div');
                contentDiv.innerHTML = `<p>${data.content}</p>`;
                if (data.note) {
                    const noteDiv = document.createElement('div');
                    noteDiv.className = secureMode ? 'security-note' : 'note';
                    noteDiv.textContent = data.note;
                    contentDiv.appendChild(noteDiv);
                }
                resultContainer.appendChild(contentDiv);
            }
            
            resultDisplay.appendChild(resultContainer);
        } else {
            const errorMsg = document.createElement('div');
            errorMsg.className = 'error-message';
            errorMsg.textContent = data.message || 'Error executing command';
            resultDisplay.appendChild(errorMsg);
        }
    } catch (error) {
        console.error('Error in command injection simulation:', error);
        const errorMsg = document.createElement('div');
        errorMsg.className = 'error-message';
        errorMsg.textContent = 'Failed to execute command.';
        resultDisplay.appendChild(errorMsg);
    }
}


// --- Injection Demonstration Functions ---

async function searchInjectionUser() {
    const usernameInput = document.getElementById('injectionUsernameInput');
    const username = usernameInput.value;
    const resultsDisplay = document.getElementById('injectionResultsDisplay');
    resultsDisplay.innerHTML = ''; // Clear previous results

    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator ' + (secureMode ? 'secure' : 'vulnerable');
    securityIndicator.textContent = secureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
    resultsDisplay.appendChild(securityIndicator);

    if (!username) {
        const message = document.createElement('div');
        message.textContent = 'Please enter a username to search.';
        resultsDisplay.appendChild(message);
        return;
    }

    try {
        // Use secure or vulnerable endpoint based on mode
        const endpoint = secureMode ? 
            `/api/injection/search-user-secure?username=${encodeURIComponent(username)}` : 
            `/api/injection/search-user?username=${encodeURIComponent(username)}`;
            
        const response = await fetch(endpoint);
        const users = await response.json();

        if (response.ok) {
            if (users.length === 0) {
                const message = document.createElement('div');
                message.textContent = 'No users found.';
                resultsDisplay.appendChild(message);
            } else {
                const userList = document.createElement('ul');
                users.forEach(user => {
                    const listItem = document.createElement('li');
                    listItem.textContent = `ID: ${user.id}, Username: ${user.username}, Email: ${user.email}`;
                    userList.appendChild(listItem);
                });
                resultsDisplay.appendChild(userList);
                
                // Add explanation if injection was detected
                if (!secureMode && users.length > 1 && username.includes("'")) {
                    const injectionAlert = document.createElement('div');
                    injectionAlert.className = 'injection-alert';
                    injectionAlert.innerHTML = `<strong>SQL Injection Detected!</strong> Your input bypassed the WHERE clause and returned all users.`;
                    resultsDisplay.appendChild(injectionAlert);
                }
            }
        } else {
            const errorMsg = document.createElement('div');
            errorMsg.textContent = `Error: ${users.message || response.statusText}`;
            resultsDisplay.appendChild(errorMsg);
        }

    } catch (error) {
        console.error('Error searching user:', error);
        const errorMsg = document.createElement('div');
        errorMsg.textContent = 'Failed to perform search.';
        resultsDisplay.appendChild(errorMsg);
    }
}

// --- Broken Access Control Demonstration Functions ---

let currentBACUser = null;

async function updateBACLoginStatus() {
    const statusSpan = document.getElementById('bacCurrentUser');
    try {
        const response = await fetch('/api/current-user');
        currentBACUser = await response.json();
        if (currentBACUser) {
            statusSpan.textContent = `${currentBACUser.username} (ID: ${currentBACUser.id}, Role: ${currentBACUser.role})`;
            // Store CSRF token if available
            if (currentBACUser.csrfToken) {
                csrfToken = currentBACUser.csrfToken;
            }
        } else {
            statusSpan.textContent = 'Not logged in';
            csrfToken = null;
        }
    } catch (error) {
        console.error('Error fetching current user:', error);
        statusSpan.textContent = 'Error fetching status';
    }
}

async function bacLogin() {
    const usernameInput = document.getElementById('bacUsername');
    const passwordInput = document.getElementById('bacPassword');
    const username = usernameInput.value;
    const password = passwordInput.value;

    try {
        const response = await fetch('/api/bac/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        if (data.success) {
            alert(data.message);
            usernameInput.value = '';
            passwordInput.value = '';
            // Store CSRF token if available
            if (data.csrfToken) {
                csrfToken = data.csrfToken;
            }
        } else {
            alert(`Login failed: ${data.message}`);
        }
        updateBACLoginStatus();
    } catch (error) {
        console.error('Login error:', error);
        alert('An error occurred during login.');
    }
}

async function bacLogout() {
    try {
        const response = await fetch('/api/bac/logout', { method: 'POST' });
        const data = await response.json();
        alert(data.message);
        updateBACLoginStatus();
        document.getElementById('bacUserProfileDisplay').innerHTML = 'No profile loaded.';
        document.getElementById('bacAdminPanelDisplay').innerHTML = 'No admin data loaded.';
        csrfToken = null;
    } catch (error) {
        console.error('Logout error:', error);
        alert('An error occurred during logout.');
    }
}

async function bacGetUserProfile() {
    const userIdInput = document.getElementById('bacUserIdInput');
    const userId = userIdInput.value;
    console.log('[DEBUG] Frontend - Requesting user profile with ID:', userId);
    console.log('[DEBUG] Frontend - Current BAC user:', currentBACUser);
    console.log('[DEBUG] Frontend - Secure mode:', secureMode);
    
    const profileDisplay = document.getElementById('bacUserProfileDisplay');
    profileDisplay.innerHTML = '';

    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator ' + (secureMode ? 'secure' : 'vulnerable');
    securityIndicator.textContent = secureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
    profileDisplay.appendChild(securityIndicator);

    if (!userId) {
        const message = document.createElement('div');
        message.textContent = 'Please enter a User ID.';
        profileDisplay.appendChild(message);
        return;
    }

    if (!currentBACUser) {
        const message = document.createElement('div');
        message.textContent = 'Please log in first.';
        profileDisplay.appendChild(message);
        return;
    }

    try {
        // Use secure or vulnerable endpoint based on mode
        const endpoint = secureMode ? 
            `/api/bac/user-profile-secure/${userId}` : 
            `/api/bac/user-profile/${userId}`;
        
        console.log('[DEBUG] Frontend - Calling endpoint:', endpoint);
        const response = await fetch(endpoint);
        console.log('[DEBUG] Frontend - Response status:', response.status);
        const data = await response.json();
        console.log('[DEBUG] Frontend - Response data:', data);

        if (response.ok) {
            const profileInfo = document.createElement('div');
            profileInfo.innerHTML = `
                <p><strong>User ID:</strong> ${data.id}</p>
                <p><strong>Username:</strong> ${data.username}</p>
                <p><strong>Email:</strong> ${data.email}</p>
            `;
            profileDisplay.appendChild(profileInfo);
            
            // Add vulnerability warning if in vulnerable mode and accessing another user's profile
            if (!secureMode && currentBACUser && currentBACUser.id != userId && currentBACUser.role !== 'admin') {
                const warning = document.createElement('p');
                warning.className = 'vulnerability-warning';
                warning.innerHTML = '<strong>VULNERABLE: IDOR</strong> - You should not be able to view this profile if not authorized!';
                profileDisplay.appendChild(warning);
            }
        } else {
            const errorMsg = document.createElement('div');
            errorMsg.className = 'error-message';
            errorMsg.textContent = `Error: ${data.message || response.statusText}`;
            profileDisplay.appendChild(errorMsg);
            
            if (secureMode) {
                const securityNote = document.createElement('div');
                securityNote.className = 'security-note';
                securityNote.innerHTML = '<strong>SECURE:</strong> Access properly denied by authorization check.';
                profileDisplay.appendChild(securityNote);
            }
        }
    } catch (error) {
        console.error('Error fetching user profile:', error);
        const errorMsg = document.createElement('div');
        errorMsg.className = 'error-message';
        errorMsg.textContent = 'Failed to fetch user profile.';
        profileDisplay.appendChild(errorMsg);
    }
}

async function bacAccessAdminPanel() {
    const adminDisplay = document.getElementById('bacAdminPanelDisplay');
    adminDisplay.innerHTML = '';

    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator ' + (secureMode ? 'secure' : 'vulnerable');
    securityIndicator.textContent = secureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
    adminDisplay.appendChild(securityIndicator);

    if (!currentBACUser) {
        const message = document.createElement('div');
        message.textContent = 'Please log in first.';
        adminDisplay.appendChild(message);
        return;
    }

    try {
        // Use secure or vulnerable endpoint based on mode
        const endpoint = secureMode ? '/api/bac/admin-data-secure' : '/api/bac/admin-data';
        const response = await fetch(endpoint);
        const data = await response.json();

        if (response.ok) {
            const adminInfo = document.createElement('div');
            adminInfo.innerHTML = `
                <p><strong>Message:</strong> ${data.message}</p>
                <p><strong>Secret Data:</strong> ${data.secret_data}</p>
                <p><strong>User Count:</strong> ${data.user_count}</p>
            `;
            adminDisplay.appendChild(adminInfo);
            
            // Add vulnerability warning if in vulnerable mode and not admin
            if (!secureMode && currentBACUser && currentBACUser.role !== 'admin') {
                const warning = document.createElement('p');
                warning.className = 'vulnerability-warning';
                warning.innerHTML = '<strong>VULNERABLE: Role Bypass</strong> - You should not be able to view this if not an admin!';
                adminDisplay.appendChild(warning);
            }
        } else {
            const errorMsg = document.createElement('div');
            errorMsg.className = 'error-message';
            errorMsg.textContent = `Error: ${data.message || response.statusText}`;
            adminDisplay.appendChild(errorMsg);
            
            if (secureMode) {
                const securityNote = document.createElement('div');
                securityNote.className = 'security-note';
                securityNote.innerHTML = '<strong>SECURE:</strong> Access properly denied by role check.';
                adminDisplay.appendChild(securityNote);
            }
        }
    } catch (error) {
        console.error('Error accessing admin panel:', error);
        const errorMsg = document.createElement('div');
        errorMsg.className = 'error-message';
        errorMsg.textContent = 'Failed to access admin panel.';
        adminDisplay.appendChild(errorMsg);
    }
}

// --- CSRF Demonstration Functions ---

async function csrfCheckBalance() {
    const balanceDisplay = document.getElementById('csrfBalanceDisplay');
    balanceDisplay.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator ' + (secureMode ? 'secure' : 'vulnerable');
    securityIndicator.textContent = secureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
    balanceDisplay.appendChild(securityIndicator);
    
    if (!currentBACUser) {
        const message = document.createElement('div');
        message.textContent = 'Please log in first.';
        balanceDisplay.appendChild(message);
        return;
    }
    
    try {
        const response = await fetch('/api/bac/balance');
        const data = await response.json();
        
        if (response.ok) {
            const balanceInfo = document.createElement('div');
            balanceInfo.innerHTML = `
                <p><strong>Current Balance:</strong> $${data.balance}</p>
            `;
            balanceDisplay.appendChild(balanceInfo);
        } else {
            const errorMsg = document.createElement('div');
            errorMsg.className = 'error-message';
            errorMsg.textContent = `Error: ${data.message || response.statusText}`;
            balanceDisplay.appendChild(errorMsg);
        }
    } catch (error) {
        console.error('Error checking balance:', error);
        const errorMsg = document.createElement('div');
        errorMsg.className = 'error-message';
        errorMsg.textContent = 'Failed to check balance.';
        balanceDisplay.appendChild(errorMsg);
    }
}

async function csrfTransferMoney() {
    const recipientInput = document.getElementById('csrfRecipient');
    const amountInput = document.getElementById('csrfAmount');
    const transferResult = document.getElementById('csrfTransferResult');
    transferResult.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator ' + (secureMode ? 'secure' : 'vulnerable');
    securityIndicator.textContent = secureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
    transferResult.appendChild(securityIndicator);
    
    const to = recipientInput.value;
    const amount = amountInput.value;
    
    if (!to || !amount) {
        const message = document.createElement('div');
        message.textContent = 'Please enter both recipient and amount.';
        transferResult.appendChild(message);
        return;
    }
    
    if (!currentBACUser) {
        const message = document.createElement('div');
        message.textContent = 'Please log in first.';
        transferResult.appendChild(message);
        return;
    }
    
    try {
        // Use secure or vulnerable endpoint based on mode
        const endpoint = secureMode ? '/api/bac/transfer-secure' : '/api/bac/transfer';
        const requestBody = secureMode ? 
            { to, amount, csrfToken } : 
            { to, amount };
            
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            const resultInfo = document.createElement('div');
            resultInfo.innerHTML = `
                <p><strong>Transfer Result:</strong> ${data.message}</p>
                <p><strong>New Balance:</strong> $${data.newBalance}</p>
            `;
            transferResult.appendChild(resultInfo);
            
            // Update CSRF token if secure mode and token was refreshed
            if (secureMode && data.csrfToken) {
                csrfToken = data.csrfToken;
            }
            
            // Clear inputs
            recipientInput.value = '';
            amountInput.value = '';
        } else {
            const errorMsg = document.createElement('div');
            errorMsg.className = 'error-message';
            errorMsg.textContent = `Error: ${data.message || response.statusText}`;
            transferResult.appendChild(errorMsg);
        }
    } catch (error) {
        console.error('Error transferring money:', error);
        const errorMsg = document.createElement('div');
        errorMsg.className = 'error-message';
        errorMsg.textContent = 'Failed to transfer money.';
        transferResult.appendChild(errorMsg);
    }
}

async function simulateCsrfAttack() {
    if (!currentBACUser) {
        alert('Please log in first to demonstrate the CSRF attack.');
        return;
    }
    
    if (secureMode) {
        alert('CSRF attack prevented! In secure mode, the CSRF token is required and the attacker does not have access to it.');
        return;
    }
    
    try {
        // Simulate a malicious request without CSRF token
        const response = await fetch('/api/bac/transfer', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                to: 'admin',
                amount: 100
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert(`CSRF Attack Successful! ${data.message}\nYour new balance: $${data.newBalance}\n\nThis demonstrates how an attacker can make your browser send requests without your knowledge or consent.`);
            // Refresh balance display
            csrfCheckBalance();
        } else {
            alert(`CSRF Attack Failed: ${data.message}`);
        }
    } catch (error) {
        console.error('Error in CSRF attack simulation:', error);
        alert('CSRF Attack simulation failed due to an error.');
    }
}

// --- Cryptographic Failures Demonstration Functions ---

async function storePasswordInsecure() {
    const username = document.getElementById('cryptoUsername').value;
    const password = document.getElementById('cryptoPassword').value;
    const resultDisplay = document.getElementById('cryptoResult');
    
    if (!username || !password) {
        resultDisplay.innerHTML = '<div class="error-message">Username and password are required</div>';
        return;
    }
    
    try {
        const response = await fetch('/api/crypto/store-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            resultDisplay.innerHTML = `
                <p><strong>${data.message}</strong></p>
                <p class="vulnerability-warning">${data.warning}</p>
            `;
        } else {
            resultDisplay.innerHTML = `<div class="error-message">${data.message}</div>`;
        }
    } catch (error) {
        console.error('Error storing password:', error);
        resultDisplay.innerHTML = '<div class="error-message">Failed to store password</div>';
    }
}

async function storePasswordSecure() {
    const username = document.getElementById('cryptoUsername').value;
    const password = document.getElementById('cryptoPassword').value;
    const resultDisplay = document.getElementById('cryptoResult');
    
    if (!username || !password) {
        resultDisplay.innerHTML = '<div class="error-message">Username and password are required</div>';
        return;
    }
    
    try {
        const response = await fetch('/api/crypto/store-password-secure', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            resultDisplay.innerHTML = `
                <p><strong>${data.message}</strong></p>
                <p class="security-note">${data.note}</p>
            `;
        } else {
            resultDisplay.innerHTML = `<div class="error-message">${data.message}</div>`;
        }
    } catch (error) {
        console.error('Error storing password securely:', error);
        resultDisplay.innerHTML = '<div class="error-message">Failed to store password</div>';
    }
}

async function showStoredPasswords() {
    const passwordsDisplay = document.getElementById('storedPasswordsDisplay');
    
    try {
        const response = await fetch('/api/crypto/stored-passwords');
        const data = await response.json();
        
        if (response.ok) {
            let html = '<h4>Insecure Storage:</h4><div class="password-list">';
            
            // Display insecure passwords
            data.insecurePasswords.forEach(user => {
                html += `
                    <div class="password-item">
                        <div><strong>Username:</strong> ${user.username}</div>
                        <div><strong>Password:</strong> ${user.password}</div>
                        <div class="vulnerability-warning">${user.warning}</div>
                    </div>
                `;
            });
            
            html += '</div><h4>Secure Storage:</h4><div class="password-list">';
            
            // Display secure passwords
            data.securePasswords.forEach(user => {
                html += `
                    <div class="password-item">
                        <div><strong>Username:</strong> ${user.username}</div>
                        <div><strong>Password Hash:</strong> ${user.passwordHash}</div>
                        <div class="security-note">${user.note}</div>
                    </div>
                `;
            });
            
            html += '</div>';
            passwordsDisplay.innerHTML = html;
        } else {
            passwordsDisplay.innerHTML = `<div class="error-message">${data.message}</div>`;
        }
    } catch (error) {
        console.error('Error fetching stored passwords:', error);
        passwordsDisplay.innerHTML = '<div class="error-message">Failed to fetch stored passwords</div>';
    }
}

// --- File Upload Demonstration Functions ---

async function uploadVulnerable() {
    const fileInput = document.getElementById('vulnerableFileInput');
    const resultDisplay = document.getElementById('vulnerableUploadResult');
    resultDisplay.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator vulnerable';
    securityIndicator.textContent = '⚠️ VULNERABLE';
    resultDisplay.appendChild(securityIndicator);
    
    if (!fileInput.files || fileInput.files.length === 0) {
        const message = document.createElement('div');
        message.textContent = 'Please select a file to upload.';
        resultDisplay.appendChild(message);
        return;
    }
    
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/upload/vulnerable', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            const resultInfo = document.createElement('div');
            resultInfo.innerHTML = `
                <p><strong>Upload Result:</strong> ${data.message}</p>
                <p><strong>File Name:</strong> ${data.file.originalname}</p>
                <p><strong>File Type:</strong> ${data.file.mimetype}</p>
                <p><strong>File Size:</strong> ${formatFileSize(data.file.size)}</p>
                <p class="vulnerability-note">No validation was performed on this file upload. Any file type could be uploaded, including potentially malicious files.</p>
            `;
            resultDisplay.appendChild(resultInfo);
            
            // Clear file input
            fileInput.value = '';
        } else {
            const errorMsg = document.createElement('div');
            errorMsg.className = 'error-message';
            errorMsg.textContent = `Error: ${data.message || response.statusText}`;
            resultDisplay.appendChild(errorMsg);
        }
    } catch (error) {
        console.error('Error uploading file:', error);
        const errorMsg = document.createElement('div');
        errorMsg.className = 'error-message';
        errorMsg.textContent = 'Failed to upload file.';
        resultDisplay.appendChild(errorMsg);
    }
}

async function uploadSecure() {
    const fileInput = document.getElementById('secureFileInput');
    const resultDisplay = document.getElementById('secureUploadResult');
    resultDisplay.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator secure';
    securityIndicator.textContent = '🔒 SECURE';
    resultDisplay.appendChild(securityIndicator);
    
    if (!fileInput.files || fileInput.files.length === 0) {
        const message = document.createElement('div');
        message.textContent = 'Please select a file to upload.';
        resultDisplay.appendChild(message);
        return;
    }
    
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/upload/secure', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            const resultInfo = document.createElement('div');
            resultInfo.innerHTML = `
                <p><strong>Upload Result:</strong> ${data.message}</p>
                <p><strong>File Name:</strong> ${data.file.originalname}</p>
                <p><strong>File Type:</strong> ${data.file.mimetype}</p>
                <p><strong>File Size:</strong> ${formatFileSize(data.file.size)}</p>
                <p class="security-note">This upload was validated for file type (images only) and size (max 5MB).</p>
            `;
            resultDisplay.appendChild(resultInfo);
            
            // Clear file input
            fileInput.value = '';
        } else {
            const errorMsg = document.createElement('div');
            errorMsg.className = 'error-message';
            errorMsg.textContent = `Error: ${data.message || response.statusText}`;
            resultDisplay.appendChild(errorMsg);
        }
    } catch (error) {
        console.error('Error uploading file:', error);
        const errorMsg = document.createElement('div');
        errorMsg.className = 'error-message';
        errorMsg.textContent = 'Failed to upload file.';
        resultDisplay.appendChild(errorMsg);
    }
}

async function listUploadedFiles() {
    const filesListDisplay = document.getElementById('uploadedFilesList');
    filesListDisplay.innerHTML = '';
    
    try {
        const response = await fetch('/api/upload/upload/files');
        const files = await response.json();
        
        if (files.length === 0) {
            const message = document.createElement('div');
            message.textContent = 'No files have been uploaded yet.';
            filesListDisplay.appendChild(message);
            return;
        }
        
        const filesList = document.createElement('ul');
        files.forEach(file => {
            const listItem = document.createElement('li');
            listItem.innerHTML = `
                <strong>${file.originalname}</strong> (${file.mimetype}) - ${formatFileSize(file.size)}
            `;
            filesList.appendChild(listItem);
        });
        filesListDisplay.appendChild(filesList);
    } catch (error) {
        console.error('Error listing files:', error);
        const errorMsg = document.createElement('div');
        errorMsg.className = 'error-message';
        errorMsg.textContent = 'Failed to list uploaded files.';
        filesListDisplay.appendChild(errorMsg);
    }
}

// Helper function to format file size
function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' bytes';
    else if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    else return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

// --- Insecure Design Functions ---

// Store applied discounts for the current session
let appliedDiscounts = [];
let sessionId = 'user-' + Math.random().toString(36).substring(2, 10);

async function applyDiscount() {
    const discountInput = document.getElementById('discountCode');
    const discountCode = discountInput.value.trim();
    const checkoutResult = document.getElementById('checkoutResult');
    
    if (!discountCode) {
        checkoutResult.innerHTML = '<div class="error-message">Please enter a discount code</div>';
        return;
    }
    
    try {
        // Use secure or vulnerable endpoint based on mode
        const endpoint = secureMode ? '/api/design/apply-discount-secure' : '/api/design/apply-discount';
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: discountCode,
                sessionId: sessionId
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Add security indicator
            checkoutResult.innerHTML = '';
            const securityIndicator = document.createElement('div');
            securityIndicator.className = 'security-indicator ' + (secureMode ? 'secure' : 'vulnerable');
            securityIndicator.textContent = secureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
            checkoutResult.appendChild(securityIndicator);
            
            // Add discount message
            const messageDiv = document.createElement('div');
            messageDiv.textContent = data.message;
            checkoutResult.appendChild(messageDiv);
            
            // Add warning or note if present
            if (data.warning) {
                const warningDiv = document.createElement('div');
                warningDiv.className = 'warning';
                warningDiv.textContent = data.warning;
                checkoutResult.appendChild(warningDiv);
            }
            
            if (data.note) {
                const noteDiv = document.createElement('div');
                noteDiv.className = 'security-note';
                noteDiv.textContent = data.note;
                checkoutResult.appendChild(noteDiv);
            }
            
            // Store the discount for later use
            if (!secureMode) {
                appliedDiscounts.push(data.discount);
                
                // Show stacked discounts in vulnerable mode
                const stackedDiv = document.createElement('div');
                const totalDiscount = appliedDiscounts.reduce((sum, discount) => sum + discount, 0);
                stackedDiv.innerHTML = `<p>Total discount: <strong>${totalDiscount}%</strong></p>`;
                
                if (totalDiscount > 50) {
                    stackedDiv.innerHTML += '<p class="warning">Vulnerability: Multiple discounts stacked!</p>';
                }
                
                checkoutResult.appendChild(stackedDiv);
            }
            
            // Clear the input
            discountInput.value = '';
        } else {
            checkoutResult.innerHTML = `<div class="error-message">${data.message}</div>`;
        }
    } catch (error) {
        console.error('Error applying discount:', error);
        checkoutResult.innerHTML = '<div class="error-message">Failed to apply discount. Server error.</div>';
    }
}

async function checkout() {
    const checkoutResult = document.getElementById('checkoutResult');
    
    try {
        // Use secure or vulnerable endpoint based on mode
        const endpoint = secureMode ? '/api/design/checkout-secure' : '/api/design/checkout';
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cart: { product: 'Security Training Course', price: 100 },
                discounts: appliedDiscounts,
                discountCode: appliedDiscounts.length > 0 ? 'APPLIED' : null,
                sessionId: sessionId
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Add security indicator
            checkoutResult.innerHTML = '';
            const securityIndicator = document.createElement('div');
            securityIndicator.className = 'security-indicator ' + (secureMode ? 'secure' : 'vulnerable');
            securityIndicator.textContent = secureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
            checkoutResult.appendChild(securityIndicator);
            
            // Create checkout summary
            const summaryDiv = document.createElement('div');
            summaryDiv.className = 'checkout-summary';
            summaryDiv.innerHTML = `
                <h4>Checkout Summary</h4>
                <p>Original Price: $${data.originalPrice.toFixed(2)}</p>
                <p>Discount: ${data.discountPercentage}% ($${data.discountAmount})</p>
                <p><strong>Final Price: $${data.finalPrice}</strong></p>
            `;
            
            checkoutResult.appendChild(summaryDiv);
            
            // Add warning or note if present
            if (data.warning) {
                const warningDiv = document.createElement('div');
                warningDiv.className = 'warning';
                warningDiv.textContent = data.warning;
                checkoutResult.appendChild(warningDiv);
            }
            
            if (data.note) {
                const noteDiv = document.createElement('div');
                noteDiv.className = 'security-note';
                noteDiv.textContent = data.note;
                checkoutResult.appendChild(noteDiv);
            }
            
            // Reset discounts after checkout
            appliedDiscounts = [];
        } else {
            checkoutResult.innerHTML = `<div class="error-message">${data.message}</div>`;
        }
    } catch (error) {
        console.error('Error during checkout:', error);
        checkoutResult.innerHTML = '<div class="error-message">Failed to complete checkout. Server error.</div>';
    }
}

// --- Security Misconfiguration Functions ---

async function getServerInfo() {
    const serverInfoDisplay = document.getElementById('serverInfoDisplay');
    serverInfoDisplay.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator vulnerable';
    securityIndicator.textContent = '⚠️ VULNERABLE';
    serverInfoDisplay.appendChild(securityIndicator);
    
    try {
        const response = await fetch('/api/misconfig/server-info');
        const data = await response.json();
        
        if (response.ok) {
            const serverInfo = data.serverInfo;
            const infoDiv = document.createElement('div');
            infoDiv.className = 'server-info';
            
            // Create a formatted display of server information
            let infoHtml = '<h4>Server Information:</h4>';
            infoHtml += `<p><strong>Server:</strong> ${serverInfo.server}</p>`;
            infoHtml += `<p><strong>PHP Version:</strong> ${serverInfo.phpVersion}</p>`;
            infoHtml += `<p><strong>OS Version:</strong> ${serverInfo.osVersion}</p>`;
            infoHtml += `<p><strong>Database:</strong> ${serverInfo.databaseVersion}</p>`;
            
            infoHtml += '<p><strong>Modules:</strong></p><ul>';
            serverInfo.modules.forEach(module => {
                infoHtml += `<li>${module}</li>`;
            });
            infoHtml += '</ul>';
            
            infoHtml += '<p><strong>Paths:</strong></p>';
            infoHtml += `<p>Document Root: ${serverInfo.paths.documentRoot}</p>`;
            infoHtml += `<p>Config File: ${serverInfo.paths.configFile}</p>`;
            infoHtml += `<p>Logs Directory: ${serverInfo.paths.logsDirectory}</p>`;
            
            infoDiv.innerHTML = infoHtml;
            serverInfoDisplay.appendChild(infoDiv);
            
            // Add warning
            if (data.warning) {
                const warningDiv = document.createElement('div');
                warningDiv.className = 'warning';
                warningDiv.textContent = data.warning;
                serverInfoDisplay.appendChild(warningDiv);
            }
        } else {
            serverInfoDisplay.innerHTML += `<div class="error-message">${data.message || 'Failed to get server info'}</div>`;
        }
    } catch (error) {
        console.error('Error getting server info:', error);
        serverInfoDisplay.innerHTML += '<div class="error-message">Failed to get server information</div>';
    }
}

async function getServerInfoSecure() {
    const serverInfoDisplay = document.getElementById('serverInfoDisplay');
    serverInfoDisplay.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator secure';
    securityIndicator.textContent = '🔒 SECURE';
    serverInfoDisplay.appendChild(securityIndicator);
    
    try {
        const response = await fetch('/api/misconfig/server-info-secure');
        const data = await response.json();
        
        if (response.ok) {
            const messageDiv = document.createElement('div');
            messageDiv.textContent = data.message;
            serverInfoDisplay.appendChild(messageDiv);
            
            // Add security note
            if (data.note) {
                const noteDiv = document.createElement('div');
                noteDiv.className = 'security-note';
                noteDiv.textContent = data.note;
                serverInfoDisplay.appendChild(noteDiv);
            }
        } else {
            serverInfoDisplay.innerHTML += `<div class="error-message">${data.message || 'Failed to get server info'}</div>`;
        }
    } catch (error) {
        console.error('Error getting server info:', error);
        serverInfoDisplay.innerHTML += '<div class="error-message">Failed to get server information</div>';
    }
}

async function triggerError() {
    const errorDisplay = document.getElementById('errorDisplay');
    errorDisplay.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator vulnerable';
    securityIndicator.textContent = '⚠️ VULNERABLE';
    errorDisplay.appendChild(securityIndicator);
    
    try {
        const response = await fetch('/api/misconfig/error');
        const data = await response.json();
        
        if (!response.ok) {
            // Display the detailed error information
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-details';
            
            let errorHtml = '<h4>Error Details:</h4>';
            errorHtml += `<p><strong>Message:</strong> ${data.error}</p>`;
            errorHtml += '<p><strong>Stack Trace:</strong></p>';
            errorHtml += `<pre>${data.stack}</pre>`;
            
            errorDiv.innerHTML = errorHtml;
            errorDisplay.appendChild(errorDiv);
            
            // Add warning
            if (data.warning) {
                const warningDiv = document.createElement('div');
                warningDiv.className = 'warning';
                warningDiv.textContent = data.warning;
                errorDisplay.appendChild(warningDiv);
            }
        }
    } catch (error) {
        console.error('Error triggering error:', error);
        errorDisplay.innerHTML += '<div class="error-message">Failed to trigger error</div>';
    }
}

async function triggerErrorSecure() {
    const errorDisplay = document.getElementById('errorDisplay');
    errorDisplay.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator secure';
    securityIndicator.textContent = '🔒 SECURE';
    errorDisplay.appendChild(securityIndicator);
    
    try {
        const response = await fetch('/api/misconfig/error-secure');
        const data = await response.json();
        
        if (!response.ok) {
            // Display the generic error information
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-details';
            
            let errorHtml = '<h4>Error Information:</h4>';
            errorHtml += `<p><strong>Message:</strong> ${data.message}</p>`;
            if (data.requestId) {
                errorHtml += `<p><strong>Request ID:</strong> ${data.requestId}</p>`;
                errorHtml += '<p>This ID can be used by administrators to locate the detailed error in server logs.</p>';
            }
            
            errorDiv.innerHTML = errorHtml;
            errorDisplay.appendChild(errorDiv);
            
            // Add security note
            if (data.note) {
                const noteDiv = document.createElement('div');
                noteDiv.className = 'security-note';
                noteDiv.textContent = data.note;
                errorDisplay.appendChild(noteDiv);
            }
        }
    } catch (error) {
        console.error('Error triggering secure error:', error);
        errorDisplay.innerHTML += '<div class="error-message">An error occurred, but details are hidden for security</div>';
    }
}

// --- Security Misconfiguration Authentication Functions ---

async function loginInsecure() {
    const username = document.getElementById('authUsername').value;
    const password = document.getElementById('authPassword').value;
    const authResult = document.getElementById('authResult');
    
    // Clear previous results
    authResult.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator vulnerable';
    securityIndicator.textContent = '⚠️ VULNERABLE';
    authResult.appendChild(securityIndicator);
    
    try {
        const response = await fetch('/api/misconfig/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Login successful
            const successDiv = document.createElement('div');
            successDiv.className = 'success-message';
            successDiv.textContent = `Logged in as: ${data.username}`;
            authResult.appendChild(successDiv);
            
            // Add role information if available
            if (data.role) {
                const roleDiv = document.createElement('div');
                roleDiv.textContent = `Role: ${data.role}`;
                authResult.appendChild(roleDiv);
            }
            
            // Add warning about default credentials
            if (data.warning) {
                const warningDiv = document.createElement('div');
                warningDiv.className = 'warning';
                warningDiv.textContent = data.warning;
                authResult.appendChild(warningDiv);
            }
        } else {
            // Login failed
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-message';
            errorDiv.textContent = data.message || 'Login failed';
            authResult.appendChild(errorDiv);
        }
    } catch (error) {
        console.error('Error during insecure login:', error);
        authResult.innerHTML += '<div class="error-message">An error occurred during login</div>';
    }
}

async function loginSecure() {
    const username = document.getElementById('authUsername').value;
    const password = document.getElementById('authPassword').value;
    const authResult = document.getElementById('authResult');
    
    // Clear previous results
    authResult.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator secure';
    securityIndicator.textContent = '🔒 SECURE';
    authResult.appendChild(securityIndicator);
    
    try {
        const response = await fetch('/api/misconfig/login-secure', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Login successful
            const successDiv = document.createElement('div');
            successDiv.className = 'success-message';
            successDiv.textContent = `Logged in as: ${data.username}`;
            authResult.appendChild(successDiv);
            
            // Add role information if available
            if (data.role) {
                const roleDiv = document.createElement('div');
                roleDiv.textContent = `Role: ${data.role}`;
                authResult.appendChild(roleDiv);
            }
            
            // Add security note
            if (data.note) {
                const noteDiv = document.createElement('div');
                noteDiv.className = 'security-note';
                noteDiv.textContent = data.note;
                authResult.appendChild(noteDiv);
            }
        } else {
            // Login failed
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-message';
            errorDiv.textContent = data.message || 'Login failed';
            authResult.appendChild(errorDiv);
        }
    } catch (error) {
        console.error('Error during secure login:', error);
        authResult.innerHTML += '<div class="error-message">An error occurred during login</div>';
    }
}

// --- Authentication Failures Functions ---

async function resetPasswordInsecure() {
    const email = document.getElementById('resetEmail').value;
    const resetResult = document.getElementById('resetResult');
    
    // Clear previous results
    resetResult.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator vulnerable';
    securityIndicator.textContent = '⚠️ VULNERABLE';
    resetResult.appendChild(securityIndicator);
    
    if (!email) {
        resetResult.innerHTML += '<div class="error-message">Please enter an email address</div>';
        return;
    }
    
    // Simulate loading
    const loadingDiv = document.createElement('div');
    loadingDiv.textContent = 'Processing request...';
    resetResult.appendChild(loadingDiv);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Remove loading message
    resetResult.removeChild(loadingDiv);
    
    // --- VULNERABLE LOGIC: No rate limiting, no verification, predictable tokens ---
    const successDiv = document.createElement('div');
    successDiv.className = 'success-message';
    successDiv.textContent = `Password reset link sent to ${email}`;
    resetResult.appendChild(successDiv);
    
    // Show the vulnerable implementation details
    const detailsDiv = document.createElement('div');
    detailsDiv.className = 'vulnerability-details';
    
    // Generate a simple predictable token (vulnerable)
    const timestamp = Date.now();
    const simpleToken = `reset_${email.split('@')[0]}_${timestamp}`;
    
    detailsDiv.innerHTML = `
        <h4>Vulnerability Details:</h4>
        <p><strong>Issues:</strong></p>
        <ul>
            <li>No rate limiting (could be used for user enumeration)</li>
            <li>No verification that email exists in system</li>
            <li>Predictable reset token: <code>${simpleToken}</code></li>
            <li>No expiration time for reset token</li>
        </ul>
        <p><strong>Impact:</strong> Attackers can enumerate users, guess tokens, or brute force the reset functionality</p>
    `;
    resetResult.appendChild(detailsDiv);
    
    // Add warning
    const warningDiv = document.createElement('div');
    warningDiv.className = 'warning';
    warningDiv.textContent = 'VULNERABLE: Weak password reset implementation';
    resetResult.appendChild(warningDiv);
}

async function resetPasswordSecure() {
    const email = document.getElementById('resetEmail').value;
    const resetResult = document.getElementById('resetResult');
    
    // Clear previous results
    resetResult.innerHTML = '';
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator secure';
    securityIndicator.textContent = '🔒 SECURE';
    resetResult.appendChild(securityIndicator);
    
    if (!email) {
        resetResult.innerHTML += '<div class="error-message">Please enter an email address</div>';
        return;
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        resetResult.innerHTML += '<div class="error-message">Please enter a valid email address</div>';
        return;
    }
    
    // Simulate loading
    const loadingDiv = document.createElement('div');
    loadingDiv.textContent = 'Processing request...';
    resetResult.appendChild(loadingDiv);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Remove loading message
    resetResult.removeChild(loadingDiv);
    
    // --- SECURE LOGIC: Generic response regardless of email existence ---
    const successDiv = document.createElement('div');
    successDiv.className = 'success-message';
    successDiv.textContent = 'If your email exists in our system, you will receive password reset instructions';
    resetResult.appendChild(successDiv);
    
    // Show the secure implementation details
    const detailsDiv = document.createElement('div');
    detailsDiv.className = 'security-details';
    
    // Generate a secure random token (not displayed to user in real implementation)
    const secureToken = Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    
    detailsDiv.innerHTML = `
        <h4>Security Measures:</h4>
        <ul>
            <li>Rate limiting implemented (max 3 attempts per hour)</li>
            <li>Generic response prevents user enumeration</li>
            <li>Cryptographically secure token generation</li>
            <li>Token expires after 15 minutes</li>
            <li>One-time use tokens</li>
        </ul>
    `;
    resetResult.appendChild(detailsDiv);
    
    // Add security note
    const noteDiv = document.createElement('div');
    noteDiv.className = 'security-note';
    noteDiv.textContent = 'SECURE: Strong password reset implementation with anti-enumeration measures';
    resetResult.appendChild(noteDiv);
}

// --- Vulnerable and Outdated Components Functions ---

async function scanDependencies() {
    const dependencyScanResult = document.getElementById('dependencyScanResult');
    dependencyScanResult.innerHTML = '';
    
    // Toggle between secure and vulnerable mode
    const isSecureMode = secureMode;
    
    // Add security indicator
    const securityIndicator = document.createElement('div');
    securityIndicator.className = 'security-indicator ' + (isSecureMode ? 'secure' : 'vulnerable');
    securityIndicator.textContent = isSecureMode ? '🔒 SECURE' : '⚠️ VULNERABLE';
    dependencyScanResult.appendChild(securityIndicator);
    
    // Simulate loading
    const loadingDiv = document.createElement('div');
    loadingDiv.textContent = 'Scanning dependencies...';
    dependencyScanResult.appendChild(loadingDiv);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Remove loading message
    dependencyScanResult.removeChild(loadingDiv);
    
    // Create results container
    const resultsDiv = document.createElement('div');
    resultsDiv.className = 'dependency-results';
    
    if (isSecureMode) {
        // Secure mode - up-to-date dependencies
        resultsDiv.innerHTML = `
            <h4>Dependency Scan Results</h4>
            <p>All dependencies are up-to-date and secure.</p>
            
            <div class="dependency-list">
                <div class="dependency-item secure">
                    <span class="name">express</span>
                    <span class="version">4.18.2</span>
                    <span class="status">✅ Current</span>
                </div>
                <div class="dependency-item secure">
                    <span class="name">bcrypt</span>
                    <span class="version">5.1.1</span>
                    <span class="status">✅ Current</span>
                </div>
                <div class="dependency-item secure">
                    <span class="name">jsonwebtoken</span>
                    <span class="version">9.0.2</span>
                    <span class="status">✅ Current</span>
                </div>
                <div class="dependency-item secure">
                    <span class="name">helmet</span>
                    <span class="version">7.0.0</span>
                    <span class="status">✅ Current</span>
                </div>
                <div class="dependency-item secure">
                    <span class="name">multer</span>
                    <span class="version">1.4.5-lts.1</span>
                    <span class="status">✅ Current</span>
                </div>
            </div>
            
            <div class="security-note">
                <p>SECURE: All dependencies are regularly updated and monitored for vulnerabilities.</p>
                <p>Security scanning is performed automatically with each build.</p>
            </div>
        `;
    } else {
        // Vulnerable mode - outdated dependencies with vulnerabilities
        resultsDiv.innerHTML = `
            <h4>Dependency Scan Results</h4>
            <p class="warning">⚠️ Multiple vulnerable dependencies detected!</p>
            
            <div class="dependency-list">
                <div class="dependency-item vulnerable">
                    <span class="name">express</span>
                    <span class="version">4.16.1</span>
                    <span class="status">❌ Outdated</span>
                    <div class="vulnerability">
                        <strong>CVE-2022-24999:</strong> Vulnerable to denial of service attacks.
                    </div>
                </div>
                <div class="dependency-item vulnerable">
                    <span class="name">bcrypt</span>
                    <span class="version">3.0.6</span>
                    <span class="status">❌ Outdated</span>
                    <div class="vulnerability">
                        <strong>CVE-2020-7689:</strong> Timing attack vulnerability in password comparison.
                    </div>
                </div>
                <div class="dependency-item vulnerable">
                    <span class="name">jsonwebtoken</span>
                    <span class="version">8.3.0</span>
                    <span class="status">❌ Outdated</span>
                    <div class="vulnerability">
                        <strong>CVE-2022-23529:</strong> Vulnerability allowing attackers to bypass verification.
                    </div>
                </div>
                <div class="dependency-item vulnerable">
                    <span class="name">node-fetch</span>
                    <span class="version">2.6.0</span>
                    <span class="status">❌ Outdated</span>
                    <div class="vulnerability">
                        <strong>CVE-2022-0235:</strong> Exposure to ReDoS (Regular Expression Denial of Service).
                    </div>
                </div>
                <div class="dependency-item vulnerable">
                    <span class="name">lodash</span>
                    <span class="version">4.17.15</span>
                    <span class="status">❌ Outdated</span>
                    <div class="vulnerability">
                        <strong>CVE-2021-23337:</strong> Prototype pollution vulnerability.
                    </div>
                </div>
            </div>
            
            <div class="warning">
                <p>VULNERABLE: Multiple outdated dependencies with known security vulnerabilities.</p>
                <p>These vulnerabilities could allow attackers to:</p>
                <ul>
                    <li>Execute denial of service attacks</li>
                    <li>Bypass authentication</li>
                    <li>Access sensitive information</li>
                    <li>Execute arbitrary code</li>
                </ul>
            </div>
        `;
    }
    
    dependencyScanResult.appendChild(resultsDiv);
}
