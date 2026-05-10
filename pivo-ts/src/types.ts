export type Slot = "9a" | "9c" | "9d" | "9e";

export type Algorithm =
  | "RSA1024"
  | "RSA2048"
  | "RSA3072"
  | "RSA4096"
  | "EC256"
  | "EC384"
  | "Ed25519";

export interface ReaderInfo {
  name: string;
  serial: number;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  notAfter: string;
  pem: string;
}

export type CertificateMap = Record<Slot, CertInfo | null>;

export interface SubjectParams {
  CN: string;
  O?: string;
  OU?: string;
}

export interface RpcError {
  code: number;
  message: string;
}

export interface PivoEvents {
  connected: (port: number) => void;
  disconnected: () => void;
  error: (error: Error) => void;
  "pairing-required": (pin: string | null) => void;
}
