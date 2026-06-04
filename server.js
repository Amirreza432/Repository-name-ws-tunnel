const http = require('http');
const WebSocket = require('ws');
const net = require('net');

const PORT = 8080;
const XOR_KEY = 75;

function xorDecode(encoded) {
    return encoded.map(v => String.fromCharCode(v ^ XOR_KEY)).join('');
}

const encodedKey = [41,121,127,46,121,114,122,127,102,126,47,42,114,102,127,41,124,126,102,115,125,125,125,102,42,121,124,124,127,114,122,45,115,115,45,47];
const AUTH_KEY = xorDecode(encodedKey).replace(/-/g, '').toLowerCase();

const AUTH_HEADER_NAME = xorDecode([30,59,44,57,42,47,46]);
const AUTH_HEADER_VALUE = xorDecode([60,46,41,56,36,40,32,46,63]);

const server = http.createServer((req, res) => {
    const authHeader = (req.headers[AUTH_HEADER_NAME] || '').toLowerCase();
    if (authHeader !== AUTH_HEADER_VALUE) {
        res.writeHead(200);
        res.end('');
        return;
    }
    res.writeHead(200);
    res.end('Tunnel running\n');
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
    console.log('New WebSocket connection');
    let handshakeDone = false;
    let tcpSocket = null;
    let pendingData = [];

    ws.on('message', async (data) => {
        if (!handshakeDone && data.length >= 19) {
            const tokenBytes = data.slice(1, 17);
            const tokenHex = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, '0')).join('');

            if (tokenHex !== AUTH_KEY) {
                ws.close(1008, 'Invalid auth');
                return;
            }

            const addrLen = data[17];
            let pos = 18 + addrLen + 1;
            const port = (data[pos] << 8) | data[pos + 1];
            pos += 2;

            const addrType = data[pos++];
            let targetHost = '';

            if (addrType === 1) {
                targetHost = data.slice(pos, pos + 4).join('.');
                pos += 4;
            } else if (addrType === 2) {
                const domainLen = data[pos++];
                targetHost = data.slice(pos, pos + domainLen).toString();
                pos += domainLen;
            } else if (addrType === 3) {
                const chunks = [];
                for (let i = 0; i < 8; i++) {
                    chunks.push(((data[pos + i * 2] << 8) | data[pos + i * 2 + 1]).toString(16));
                }
                targetHost = chunks.join(':');
                pos += 16;
            } else {
                ws.close(1002);
                return;
            }

            const initialPayload = data.slice(pos);
            handshakeDone = true;

            try {
                tcpSocket = net.createConnection(port, targetHost);
                tcpSocket.on('connect', () => {
                    ws.send(new Uint8Array([0, 0]));
                    if (initialPayload.length) tcpSocket.write(initialPayload);
                    for (const chunk of pendingData) tcpSocket.write(chunk);
                    pendingData = [];
                });
                tcpSocket.on('data', (chunk) => {
                    if (ws.readyState === WebSocket.OPEN) ws.send(chunk);
                });
                tcpSocket.on('error', (err) => {
                    console.error('TCP error:', err);
                    ws.close(1011);
                });
                tcpSocket.on('close', () => ws.close());
            } catch (err) {
                ws.close(1011);
            }
        } else if (handshakeDone && tcpSocket) {
            tcpSocket.write(data);
        } else {
            pendingData.push(data);
        }
    });

    ws.on('close', () => {
        if (tcpSocket) tcpSocket.end();
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`WebSocket tunnel listening on port ${PORT}`);
});
