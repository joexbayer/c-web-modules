# c-web-modules Examples

This directory contains example modules demonstrating **compute-focused** usage of c-web-modules, such as job-style HTTP triggers and WebSocket streaming. These examples are designed for experimentation and learning purposes. **None of them are production-ready**.

---

## Examples (Highlights)

### 1. **Job Sum (`job_sum.c`)**
A minimal job module that computes sum(1..n) with a JSON payload.  
- **Features**:
  - Reads `{ "n": 100000 }` from payload.
  - Returns `{ "n": ..., "sum": ... }` as job result JSON.
- **Endpoints**:
  - `POST /jobs` – Trigger with `{"module":"job_sum","job":"sum","payload":{"n":100000}}`.
  - `GET /jobs/:uuid` – Returns job status/result.
- **Key Concepts**:
  - Jobs are defined by modules and triggered by name.

---

### 2. **WebSocket Echo (`websocket.c`)**
A basic WebSocket module that echoes messages back to the sender.  
- **Features**:
  - Receives a message and responds with "You: [message]".
- **Endpoints**:
  - `WS /websocket` – Handles WebSocket connections.
- **Key Concepts**:
  - WebSocket communication basics.

---

### 3. **Chat Application (`chat.c`)**
A WebSocket-based chat application that allows multiple users to connect and exchange messages in real time.  
- **Features**:
  - Broadcasts messages to all connected users.
  - Adds/removes users dynamically.
  - Provides a simple HTML chat interface.
- **Endpoints**:
  - `GET /chat` – Serves the chat client page.
  - `WS /chat/ws` – Handles WebSocket connections.
- **Key Concepts**:
  - WebSocket event handling (`on_open`, `on_message`, `on_close`).
  - Multi-user management with thread-safe operations.

---

### 4. **Static File Server (`static.c`)**
Serve local files under `/static/*` with simple content-type detection.  
- **Features**:
  - Basic path safety check against `..`.
  - Content-type based on file extension.
- **Endpoints**:
  - `GET /static/*` – Serves files from the module working directory.
- **Key Concepts**:
  - Simple file IO and response headers.

---

## Other examples
- **Counter (`counter.c`)**: Simple HTML counter with in-memory state.
- **JSON Example (`json.c`)**: Jansson-backed list API with `GET /list` and `POST /json/add`.
