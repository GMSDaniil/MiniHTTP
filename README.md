# Distributed Hash Table (DHT) MiniHTTP Server

## Overview

This is the second version of the HTTP server, now incorporating a Distributed Hash Table (DHT) for resource lookup and distribution. This version allows multiple nodes to form a distributed network where each node is responsible for certain resources based on consistent hashing.

## Features

- Supports **GET**, **PUT**, and **DELETE** HTTP methods.
- Uses a **DHT-based lookup mechanism** to distribute resources across nodes.
- Handles resource requests dynamically, forwarding requests when necessary.
- Implements a **lookup and reply system** via UDP to locate responsible nodes.
- Manages a successor and predecessor for routing requests efficiently.

## How It Works

1. **Node Initialization**

   - Each node is assigned a unique ID.
   - It stores references to its predecessor and successor in the network.

2. **Resource Storage & Retrieval**

   - Resources are stored based on hashed URI values.
   - If a node receives a request for a resource it doesn’t own, it forwards the request.

3. **Lookup Mechanism**

   - If a node is not responsible for a resource, it sends a lookup request to its successor.
   - If the lookup reaches the correct node, a reply is sent to the requester.

4. **Handling Replies**

   - Replies are stored to improve routing efficiency.
   - If a responsible node is not yet known, a lookup is initiated.
## Requirements

- **C Compiler**: You will need a C compiler like `gcc` to compile the project.
- **Operating System**: The server is designed to run on Unix-based systems (Linux, macOS). For Windows, modifications to use Winsock are required.
- **Networking Libraries**: The server uses `sys/socket.h`, `netdb.h`, and other networking headers.
  
## Installation

1. Clone the repository:
   ```bash
   git clone -b webserver_v1 https://github.com/username/MiniHTTP.git
   cd MiniHTTP
2. Build the project:
   ```
   cmake -B build -DCMAKE_BUILD_TYPE=Debug
   make -C build
## Use

### Running the Server

```sh
PRED_ID=... PRED_IP=... PRED_PORT=... SUCC_ID=... SUCC_IP=... SUCC_PORT=... ./build/webserver <IP> <PORT> <ID>
```
- `PRED_..`: ID/IP/Port of predecessor node
- `SUCC_..`: ID/IP/Port of successor node
- `<IP>`: The IP address of the node.
- `<PORT>`: The port number the node listens on.
- `<ID>`: The IP address of the node.

## Example Usage

### Starting two Nodes

```sh
PRED_ID=49152 PRED_IP=127.0.0.1 PRED_PORT=2002 SUCC_ID=49152 SUCC_IP=127.0.0.1 SUCC_PORT=2002 ./build/webserver 127.0.0.1 2001 16384
PRED_ID=16384 PRED_IP=127.0.0.1 PRED_PORT=2001 SUCC_ID=16384 SUCC_IP=127.0.0.1 SUCC_PORT=2001 ./build/webserver 127.0.0.1 2002 49152
```

### HTTP Requests

- **Retrieve a resource:**
  ```sh
  curl -i localhost:2002/path-with-unknown-hash
  # Response: HTTP/1.1 503 Service Unavailable
  # Retry-After: 1
  # Content-Length: 0
  ```
- **Store a new resource:**
  ```sh
  curl -i localhost:2002/path-with-unknown-hash
  # Response: HTTP/1.1 303 See Other
  # Location: http://127.0.0.1:2017/path-with-unknown-hash
  # Content-Length: 0
  ```
- **Delete a resource:**
  ```sh
  curl -i localhost:2017/path-with-unknown-hash
  # Response: HTTP/1.1 404 Not Found 
  # Content-Length: 0
  # (Not Found if resource doesn't exists)
  ```
  
## Acknowledgements

- This project was created as an educational exercise to demonstrate HTTP server handling in C.

