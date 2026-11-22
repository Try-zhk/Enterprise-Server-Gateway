# Enterprise Edge Gateway & Operations Studio

A high-performance, asynchronous edge ingress controller and network diagnostics workbench built with Python, epoll event multiplexing, and dynamic service routing.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![Architecture](https://img.shields.io/badge/Arch-x86__64%20%7C%20aarch64-green)](#)

## Key Features

- **High-Throughput Edge Ingress**: Non-blocking asynchronous I/O multiplexer with zero-copy stream forwarding.
- **Dynamic Diagnostics Studio**: Built-in interactive dual-stack DNS resolution, TCP handshake latency probing, and host environment telemetry.
- **DevOps Workbench**: Native browser cryptographic hashing (SHA-256, SHA-512, SHA-1), JSON validation, Base64/URL transformations, and IPv4 CIDR subnet calculation.
- **Enterprise Service Mesh Telemetry**: Full OpenAPI 3.0 specification contract, Prometheus-compatible metrics (`/api/v1/metrics`), and health checks (`/api/v1/health`).
- **Resilient Multi-Runtime Architecture**: Automated native C-extension acceleration with dynamic fallback support.

## Getting Started

### Prerequisites

- Python 3.9+ (Linux, macOS, or Windows)
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Deployment

Run the gateway ingress controller directly:

```bash
python main.py
```

The service binds to the port configured via environment variable (`PORT`, `SERVER_PORT`, or default `8080`) and starts the ingress routing mesh.

### Environment Configuration

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | Listening ingress port | `8080` |
| `WORK_DIR` | Working directory for internal runtime files | `.cache` |
| `WEB_DIR` | Optional directory for custom static website hosting | None |

## API Endpoints

- `GET /` — Operations & Diagnostics Web Console
- `GET /api/v1/health` — Cluster availability and health probe
- `GET /api/v1/metrics` — Prometheus telemetry counter samples
- `GET /api/v1/tools/system` — Real-time host environment telemetry
- `GET /api/v1/tools/probe` — Live network and DNS diagnostic probe
- `GET /openapi.json` — OpenAPI 3.0.3 specification contract

## License

Apache License 2.0. See LICENSE for details.
