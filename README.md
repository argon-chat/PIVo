# PIVo

Local agent that lets websites interact with YubiKey PIV via WebSocket on `127.0.0.1`.

## How it works

```
Browser ──WebSocket──► PIVo Agent ──PIV──► YubiKey
```

PIVo runs on localhost and exposes a JSON-RPC API over WebSocket. Websites connect through the `@argon-chat/pivo` TypeScript client. A PIN-based pairing flow ensures only explicitly approved origins can access the key.

## Security

- Binds to `127.0.0.1` only — not reachable from the network
- Origin validation — only paired origins can send commands
- Host header check — DNS rebinding protection
- [Private Network Access](https://wicg.github.io/private-network-access/) headers for Chrome/Edge
- PIN-based pairing — 6-digit code shown in agent console, entered in browser
- Private keys never leave the YubiKey hardware

## Agent (Go)

### Build

```
go build -o pivo.exe ./cmd/pivo
```

### Run

```
pivo.exe
```

The agent tries ports `9283`, `10293`, `14582`, `17383` in order and binds to the first available.

### Flags

| Flag | Description |
|------|-------------|
| `--list-origins` | Show all paired origins |
| `--unpair <origin>` | Remove a paired origin |

### Config

Stored at `%APPDATA%\PIVo\config.json`. Contains the list of paired origins.

## Client library (`@argon-chat/pivo`)

TypeScript client for browser-side integration.

### Install

```
npm install @argon-chat/pivo
```

### Usage

```typescript
import { PivoAgent, PivoError } from "@argon-chat/pivo";

const agent = new PivoAgent();

// Connect (auto-discovers the port)
await agent.connect();

// Pair (first time — shows PIN in agent console)
const status = await agent.pair();
if (status === "pin-required") {
  const pin = prompt("Enter the PIN shown in PIVo agent:");
  await agent.pair(pin);
}

// List smart card readers
const readers = await agent.listReaders();
await agent.selectReader(readers[0].serial);

// List certificates in all PIV slots
const certs = await agent.listCertificates();
// certs["9a"], certs["9c"], certs["9d"], certs["9e"]

// Generate a key pair (on the YubiKey)
const publicKey = await agent.generateKey({
  slot: "9a",
  algorithm: "RSA2048",
  pin: "123456",
});

// Create a CSR (signed on the YubiKey)
const csr = await agent.createCSR({
  slot: "9a",
  subject: { CN: "operator:user@example.com" },
  pin: "123456",
});

// Import a certificate into a slot
await agent.importCertificate({
  slot: "9a",
  certificate: pemString,
  pin: "123456",
});
```

### Error handling

```typescript
try {
  await agent.generateKey({ slot: "9a" });
} catch (e) {
  if (e instanceof PivoError) {
    if (e.pinRequired) {
      // Management key is PIN-protected, need to provide PIN
    }
    if (e.slotOccupied) {
      // Slot already has a certificate, use force: true to overwrite
    }
  }
}
```

### Error codes

| Code | Constant | Meaning |
|------|----------|---------|
| `4011` | `PivoError.PIN_REQUIRED` | Management key is PIN-protected, provide `pin` parameter |
| `409` | `PivoError.SLOT_OCCUPIED` | Slot already contains a certificate, use `force: true` |
| `400` | — | Invalid parameters |
| `404` | — | No YubiKey selected |
| `500` | — | YubiKey operation failed |

### Events

```typescript
agent.on("connected", (port) => console.log(`Connected on port ${port}`));
agent.on("disconnected", () => console.log("Disconnected"));
agent.on("error", (err) => console.error(err));
```

## API Reference

### Methods (JSON-RPC over WebSocket)

| Method | Description |
|--------|-------------|
| `pair` | Initiate or confirm origin pairing |
| `list-readers` | List connected smart card readers |
| `select-reader` | Select a reader by serial number |
| `list-certificates` | Read certificates from all 4 PIV slots |
| `generate-key` | Generate a key pair on the YubiKey |
| `create-csr` | Create a CSR signed by the YubiKey |
| `import-certificate` | Write a certificate to a PIV slot |

### PIV Slots

| Slot | Purpose |
|------|---------|
| `9a` | Authentication |
| `9c` | Digital Signature |
| `9d` | Key Management |
| `9e` | Card Authentication |

### Supported Algorithms

`RSA1024`, `RSA2048`, `RSA3072`, `RSA4096`, `EC256`, `EC384`, `Ed25519`

## Requirements

- Windows
- YubiKey with PIV support
- Chrome or Edge (Private Network Access)

## License

GPL-3
