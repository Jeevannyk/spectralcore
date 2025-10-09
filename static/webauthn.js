// WebAuthn utility functions for SecurePass

// Convert base64url to ArrayBuffer
function base64urlToArrayBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Convert ArrayBuffer to base64url
function arrayBufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Register a new user with WebAuthn
async function registerUser(name, email) {
    try {
        console.log('Starting registration for:', email);
        
        // Step 1: Get registration options from server
        const beginResponse = await fetch('/api/register/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, email })
        });
        
        if (!beginResponse.ok) {
            const error = await beginResponse.json();
            throw new Error(error.error || 'Failed to begin registration');
        }
        
        const options = await beginResponse.json();
        console.log('Registration options received:', options);
        
        // Step 2: Convert base64url strings to ArrayBuffers
        const publicKeyCredentialCreationOptions = {
            ...options.publicKey,
            challenge: base64urlToArrayBuffer(options.publicKey.challenge),
            user: {
                ...options.publicKey.user,
                id: base64urlToArrayBuffer(options.publicKey.user.id)
            },
            excludeCredentials: options.publicKey.excludeCredentials?.map(cred => ({
                ...cred,
                id: base64urlToArrayBuffer(cred.id)
            })) || []
        };
        
        console.log('Converted options for WebAuthn API:', publicKeyCredentialCreationOptions);
        
        // Step 3: Create credential using WebAuthn API (this triggers biometric prompt)
        console.log('Calling navigator.credentials.create - biometric prompt should appear now...');
        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        });
        
        if (!credential) {
            throw new Error('Failed to create credential - user may have cancelled biometric authentication');
        }
        
        console.log('Credential created successfully:', credential);
        
        // Step 4: Convert ArrayBuffers back to base64url for transmission
        const credentialData = {
            id: credential.id,
            rawId: arrayBufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
                clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON)
            }
        };
        
        console.log('Sending credential to server:', credentialData);
        
        // Step 5: Send credential to server for verification
        const completeResponse = await fetch('/api/register/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(credentialData)
        });
        
        if (!completeResponse.ok) {
            const error = await completeResponse.json();
            throw new Error(error.error || 'Failed to complete registration');
        }
        
        const result = await completeResponse.json();
        console.log('Registration completed:', result);
        return { success: result.verified };
        
    } catch (error) {
        console.error('Registration error:', error);
        
        // Provide more user-friendly error messages
        let userMessage = error.message;
        if (error.name === 'NotSupportedError') {
            userMessage = 'WebAuthn is not supported on this device or browser. Please use a modern browser with biometric authentication support.';
        } else if (error.name === 'NotAllowedError') {
            userMessage = 'Biometric authentication was cancelled or failed. Please try again and complete the biometric verification.';
        } else if (error.name === 'SecurityError') {
            userMessage = 'Security error occurred. Please ensure you are using HTTPS or localhost.';
        } else if (error.name === 'AbortError') {
            userMessage = 'Registration was cancelled. Please try again.';
        }
        
        return { success: false, error: userMessage };
    }
}

// Login user with WebAuthn
async function loginUser(email) {
    try {
        console.log('Starting login for:', email);
        
        // Step 1: Get authentication options from server
        const beginResponse = await fetch('/api/login/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email })
        });
        
        if (!beginResponse.ok) {
            const error = await beginResponse.json();
            throw new Error(error.error || 'Failed to begin login');
        }
        
        const options = await beginResponse.json();
        console.log('Login options received:', options);
        
        // Step 2: Convert base64url strings to ArrayBuffers
        const publicKeyCredentialRequestOptions = {
            ...options.publicKey,
            challenge: base64urlToArrayBuffer(options.publicKey.challenge),
            allowCredentials: options.publicKey.allowCredentials?.map(cred => ({
                ...cred,
                id: base64urlToArrayBuffer(cred.id)
            })) || []
        };
        
        console.log('Converted options for WebAuthn API:', publicKeyCredentialRequestOptions);
        
        // Step 3: Get assertion using WebAuthn API (this triggers biometric prompt)
        console.log('Calling navigator.credentials.get - biometric prompt should appear now...');
        const assertion = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions
        });
        
        if (!assertion) {
            throw new Error('Failed to get assertion - user may have cancelled biometric authentication');
        }
        
        console.log('Assertion created successfully:', assertion);
        
        // Step 4: Convert ArrayBuffers back to base64url for transmission
        const assertionData = {
            id: assertion.id,
            rawId: arrayBufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: arrayBufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: arrayBufferToBase64url(assertion.response.clientDataJSON),
                signature: arrayBufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? arrayBufferToBase64url(assertion.response.userHandle) : null
            }
        };
        
        console.log('Sending assertion to server:', assertionData);
        
        // Step 5: Send assertion to server for verification
        const completeResponse = await fetch('/api/login/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(assertionData)
        });
        
        if (!completeResponse.ok) {
            const error = await completeResponse.json();
            throw new Error(error.error || 'Failed to complete login');
        }
        
        const result = await completeResponse.json();
        console.log('Login completed:', result);
        return { success: result.verified };
        
    } catch (error) {
        console.error('Login error:', error);
        
        // Provide more user-friendly error messages
        let userMessage = error.message;
        if (error.name === 'NotSupportedError') {
            userMessage = 'WebAuthn is not supported on this device or browser. Please use a modern browser with biometric authentication support.';
        } else if (error.name === 'NotAllowedError') {
            userMessage = 'Biometric authentication was cancelled or failed. Please try again and complete the biometric verification.';
        } else if (error.name === 'SecurityError') {
            userMessage = 'Security error occurred. Please ensure you are using HTTPS or localhost.';
        } else if (error.name === 'AbortError') {
            userMessage = 'Login was cancelled. Please try again.';
        }
        
        return { success: false, error: userMessage };
    }
}

// Check WebAuthn support
function isWebAuthnSupported() {
    return window.PublicKeyCredential && 
           navigator.credentials && 
           navigator.credentials.create && 
           navigator.credentials.get;
}

// Check if biometric authentication is available
async function checkBiometricSupport() {
    if (!isWebAuthnSupported()) {
        return false;
    }
    
    try {
        // Check if the device supports user verification (biometrics)
        const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        console.log('Biometric authentication available:', available);
        return available;
    } catch (error) {
        console.error('Error checking biometric support:', error);
        return false;
    }
}

// Initialize WebAuthn check on page load
document.addEventListener('DOMContentLoaded', async function() {
    console.log('Checking WebAuthn and biometric support...');
    
    if (!isWebAuthnSupported()) {
        const statusDiv = document.getElementById('status');
        if (statusDiv) {
            statusDiv.textContent = 'WebAuthn is not supported in this browser. Please use a modern browser with biometric authentication support.';
            statusDiv.className = 'status-message error';
        }
        
        // Disable form buttons
        const buttons = document.querySelectorAll('button[type="submit"]');
        buttons.forEach(btn => {
            btn.disabled = true;
            btn.textContent = 'WebAuthn Not Supported';
        });
        return;
    }
    
    // Check biometric support
    const biometricAvailable = await checkBiometricSupport();
    if (!biometricAvailable) {
        const statusDiv = document.getElementById('status');
        if (statusDiv) {
            statusDiv.textContent = 'Biometric authentication is not available on this device. Please ensure you have set up Windows Hello, Touch ID, Face ID, or another biometric method.';
            statusDiv.className = 'status-message error';
        }
    } else {
        console.log('WebAuthn and biometric authentication are both supported!');
    }
});