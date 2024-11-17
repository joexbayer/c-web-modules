# c-web-modules Examples

This directory contains example modules demonstrating various features and capabilities of **c-web-modules**, such as routing, WebSocket handling, and using external libraries like SQLite3 and Jansson. These examples are designed for experimentation and learning purposes. **None of them are production-ready**.

---

## Examples

### 1. **Chat Application (`chat.c`)**
A simple WebSocket-based chat application that allows multiple users to connect and exchange messages in real time.  
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

### 2. **Counter Module (`counter.c`)**
A minimal example that tracks a counter and displays it in an HTML page.  
- **Features**:
  - Increments a counter with every request.
- **Endpoints**:
  - `GET /counter` – Displays the current counter value.
- **Key Concepts**:
  - Simple routing and dynamic content generation.

---

### 3. **JSON Example (`json.c`)**
An example showcasing how to use the Jansson library to handle JSON data.  
- **Features**:
  - Maintains a server-side list of items.
  - Allows adding new items via `POST` and retrieving the list as JSON.
- **Endpoints**:
  - `GET /list` – Returns the list in JSON format.
  - `POST /json/add` – Adds a new item to the list.
- **Key Concepts**:
  - Serializing and deserializing JSON.
  - Handling POST data.

---

### 4. **TODO List (`todo.c`)**
A simple TODO list manager with an HTML front-end using Bootstrap.  
- **Features**:
  - Displays a list of tasks.
  - Allows adding tasks via a form.
- **Endpoints**:
  - `GET /` – Serves the TODO list page.
  - `POST /add` – Adds a new task to the list.
- **Key Concepts**:
  - HTML rendering with dynamic content.
  - Handling form submissions and redirects.

---

### 5. **WebSocket Echo (`websocket.c`)**
A basic WebSocket module that echoes messages back to the sender.  
- **Features**:
  - Receives a message and responds with "You: [message]".
- **Endpoints**:
  - `WS /websocket` – Handles WebSocket connections.
- **Key Concepts**:
  - WebSocket communication basics.

---
