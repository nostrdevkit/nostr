let isPolling = false;

// Per-session token, replaced by the server when the script is served
const PROXY_TOKEN = "__NIP07_PROXY_TOKEN__";

async function pollForRequests() {
    if (isPolling) return;
    isPolling = true;

    try {
        const response = await fetch(`/api/pending?token=${PROXY_TOKEN}`);
        const data = await response.json();

        console.log('Polled for requests, got:', data);

        // Process any new requests
        if (data.requests && data.requests.length > 0) {
            console.log(`Processing ${data.requests.length} requests`);
            for (const request of data.requests) {
                await handleNip07Request(request);
            }
        }
    } catch (error) {
        console.error('Polling error:', error);
        updateStatus('Error: ' + error.message, 'error');
    }

    isPolling = false;
}

async function handleNip07Request(request) {
    console.log('Handling request:', request);

    try {
        let result;

        if (!window.nostr) {
            throw new Error('NIP-07 extension not available');
        }

        switch (request.method) {
            case 'get_public_key':
                console.log('Calling nostr.getPublicKey()');
                result = await window.nostr.getPublicKey();
                console.log('Got public key:', result);
                break;

            case 'sign_event':
                console.log('Calling nostr.signEvent() with:', request.params);
                result = await window.nostr.signEvent(request.params);
                console.log('Got signed event:', result);
                break;

            case 'nip04_encrypt':
                console.log('Calling nostr.nip04.encrypt()');
                result = await window.nostr.nip04.encrypt(
                    request.params.public_key,
                    request.params.content
                );
                break;

            case 'nip04_decrypt':
                console.log('Calling nostr.nip04.decrypt()');
                result = await window.nostr.nip04.decrypt(
                    request.params.public_key,
                    request.params.content
                );
                break;

            case 'nip44_encrypt':
                console.log('Calling nostr.nip44.encrypt()');
                result = await window.nostr.nip44.encrypt(
                    request.params.public_key,
                    request.params.content
                );
                break;

            case 'nip44_decrypt':
                console.log('Calling nostr.nip44.decrypt()');
                result = await window.nostr.nip44.decrypt(
                    request.params.public_key,
                    request.params.content
                );
                break;


            default:
                throw new Error(`Unknown method: ${request.method}`);
        }

        // Send response back to server
        const responsePayload = {
            id: request.id,
            result: result,
            error: null
        };

        console.log('Sending response:', responsePayload);

        await fetch(`/api/response?token=${PROXY_TOKEN}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(responsePayload)
        });

        console.log('Response sent successfully');
        updateStatus('Request processed successfully', 'connected');

    } catch (error) {
        console.error('Error handling request:', error);

        // Send error response back to server
        const errorPayload = {
            id: request.id,
            result: null,
            error: error.message
        };

        console.log('Sending error response:', errorPayload);

        await fetch(`/api/response?token=${PROXY_TOKEN}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(errorPayload)
        });

        updateStatus('Error: ' + error.message, 'error');
    }
}

function updateStatus(message, status) {
    const statusEl = document.getElementById('nip07-proxy-status');
    if (statusEl) {
        statusEl.textContent = message;
        statusEl.style = status === "connected" ?
            "color: green; font-weight: bold;" :
            "color: red; font-weight: bold;";
    }
}

// Start polling when page loads
window.addEventListener('load', () => {
    console.log('NIP-07 Proxy loaded');

    // Check if NIP-07 extension is available
    if (window.nostr) {
        console.log('NIP-07 extension detected');
        updateStatus('Connected to NIP-07 extension - Ready', 'connected');
    } else {
        console.log('NIP-07 extension not found');
        updateStatus('NIP-07 extension not found', 'error');
    }

    // Start polling every 500 ms
    setInterval(pollForRequests, 500);
});
