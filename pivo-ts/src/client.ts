import type {
  Algorithm,
  CertificateMap,
  PivoEvents,
  ReaderInfo,
  RpcError,
  Slot,
  SubjectParams,
} from "./types.js";

const PORTS = [9283, 10293, 14582, 17383] as const;
const CONNECT_TIMEOUT = 2000;

interface RpcRequest {
  id: number;
  method: string;
  params?: Record<string, unknown>;
}

interface RpcResponse {
  id: number;
  result?: unknown;
  error?: RpcError;
}

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

export class PivoAgent {
  private ws: WebSocket | null = null;
  private msgId = 0;
  private pending = new Map<number, PendingCall>();
  private listeners = new Map<string, Set<(...args: unknown[]) => void>>();
  private _port: number | null = null;

  get port(): number | null {
    return this._port;
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  on<K extends keyof PivoEvents>(event: K, handler: PivoEvents[K]): this {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler as (...args: unknown[]) => void);
    return this;
  }

  off<K extends keyof PivoEvents>(event: K, handler: PivoEvents[K]): this {
    this.listeners.get(event)?.delete(handler as (...args: unknown[]) => void);
    return this;
  }

  private emit(event: string, ...args: unknown[]): void {
    this.listeners.get(event)?.forEach((fn) => fn(...args));
  }

  async connect(): Promise<void> {
    for (const port of PORTS) {
      try {
        await this.tryPort(port);
        this._port = port;
        this.emit("connected", port);
        return;
      } catch {
        continue;
      }
    }
    throw new Error(
      "PIVo agent not found on any port. Is it running?"
    );
  }

  private tryPort(port: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const url = `ws://127.0.0.1:${port}/ws`;
      const socket = new WebSocket(url);

      const timeout = setTimeout(() => {
        socket.close();
        reject(new Error(`timeout on port ${port}`));
      }, CONNECT_TIMEOUT);

      socket.onopen = () => {
        clearTimeout(timeout);
        this.ws = socket;
        this.setupSocket(socket);
        resolve();
      };

      socket.onerror = () => {
        clearTimeout(timeout);
        reject(new Error(`connection refused on port ${port}`));
      };
    });
  }

  private setupSocket(socket: WebSocket): void {
    socket.onmessage = (e: MessageEvent) => {
      const data: RpcResponse = JSON.parse(e.data as string);
      const pending = this.pending.get(data.id);
      if (!pending) return;
      this.pending.delete(data.id);

      if (data.error) {
        pending.reject(new PivoError(data.error.code, data.error.message));
      } else {
        pending.resolve(data.result);
      }
    };

    socket.onclose = () => {
      this.ws = null;
      this._port = null;
      // Reject all pending calls
      for (const [, pending] of this.pending) {
        pending.reject(new Error("connection closed"));
      }
      this.pending.clear();
      this.emit("disconnected");
    };

    socket.onerror = (e) => {
      this.emit("error", new Error(`WebSocket error: ${e}`));
    };
  }

  disconnect(): void {
    this.ws?.close();
    this.ws = null;
    this._port = null;
  }

  private call<T>(method: string, params?: Record<string, unknown>): Promise<T> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error("not connected"));
    }

    const id = ++this.msgId;
    const msg: RpcRequest = { id, method };
    if (params) msg.params = params;

    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      });
      this.ws!.send(JSON.stringify(msg));
    });
  }

  // --- Pairing ---

  async pair(pin?: string): Promise<string> {
    const result = await this.call<{ status: string }>(
      "pair",
      pin ? { pin } : {}
    );
    return result.status;
  }

  // --- Readers ---

  async listReaders(): Promise<ReaderInfo[]> {
    return this.call<ReaderInfo[]>("list-readers");
  }

  async selectReader(serial: number): Promise<void> {
    await this.call<{ status: string }>("select-reader", { serial });
  }

  // --- Certificates ---

  async listCertificates(): Promise<CertificateMap> {
    return this.call<CertificateMap>("list-certificates");
  }

  // --- Key generation ---

  async generateKey(params: {
    slot: Slot;
    algorithm?: Algorithm;
    pin?: string;
    managementKey?: string;
    force?: boolean;
  }): Promise<string> {
    const result = await this.call<{ publicKey: string }>("generate-key", {
      slot: params.slot,
      algorithm: params.algorithm ?? "RSA2048",
      pin: params.pin ?? "",
      managementKey: params.managementKey ?? "",
      force: params.force ?? false,
    });
    return result.publicKey;
  }

  // --- CSR ---

  async createCSR(params: {
    slot: Slot;
    subject: SubjectParams;
    pin?: string;
  }): Promise<string> {
    const result = await this.call<{ csr: string }>("create-csr", {
      slot: params.slot,
      pin: params.pin ?? "",
      subject: params.subject,
    });
    return result.csr;
  }

  // --- Import certificate ---

  async importCertificate(params: {
    slot: Slot;
    certificate: string;
    managementKey?: string;
    pin?: string;
    force?: boolean;
  }): Promise<void> {
    await this.call<{ status: string }>("import-certificate", {
      slot: params.slot,
      certificate: params.certificate,
      managementKey: params.managementKey ?? "",
      pin: params.pin ?? "",
      force: params.force ?? false,
    });
  }
}

export class PivoError extends Error {
  constructor(
    public readonly code: number,
    message: string
  ) {
    super(message);
    this.name = "PivoError";
  }
}
