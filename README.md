# Simple HTTP Server

This is a simple HTTP server written in C. It supports basic HTTP methods such as `GET`, `POST`, `PUT`, and `DELETE`, and it handles both static and dynamic resources. The server supports creating, reading, and deleting dynamic resources, and it returns appropriate HTTP status codes for different types of requests.

## Features

- **Supports HTTP methods**: `GET`, `POST`, `PUT`, `DELETE`.
- **Static Resources**: Serves basic static files (`/static/foo`, `/static/bar`, `/static/baz`).
- **Dynamic Resources**: Allows clients to add (`PUT`), retrieve (`GET`), and delete (`DELETE`) dynamic resources.
- **Handles HTTP status codes**: Supports `200 OK`, `400 Bad Request`, `404 Not Found`, `501 Not Implemented`, and others.
- **Built-in error handling**: Returns appropriate responses for malformed requests or unsupported actions.
- **Written in C**: Uses basic socket programming to handle client-server communication over TCP/IP.

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
3. Run the server:
   ```
   ./build/webserver <IP-address> <port>

## Example with curl

### Static Resources:
- **Get Static Resource**:
  ```bash
  curl http://localhost:8080/static/foo
  # Expected Response: Foo
  ```

- **Get Static Resource**:
  ```bash
  curl http://localhost:8080/static/bar
  # Expected Response: Bar
  ```

### Dynamic Resources:
- **Create Dynamic Resource**:
  ```bash
  curl -X PUT http://localhost:8080/dynamic/myresource -d "This is dynamic content"
  # Expected Response: HTTP/1.1 201 Created
  ```

- **Get Dynamic Resource**:
  ```bash
  curl http://localhost:8080/dynamic/myresource
  # Expected Response: This is dynamic content
  ```

- **Delete Dynamic Resource**:
  ```bash
  curl -X DELETE http://localhost:8080/dynamic/myresource
  # Expected Response: HTTP/1.1 204 No Content
  ```

## Error Handling

The server performs basic validation and error handling to return appropriate status codes based on the received HTTP request:

1. **Malformed Requests**: If the HTTP request is not valid (e.g., incorrect format or unsupported HTTP method), the server returns a `400 Bad Request` response.
2. **Non-existent Resources**: If a requested resource does not exist, the server responds with `404 Not Found`.
3. **Resource Creation Limits**: If there are too many dynamic resources, attempting to create a new one returns `403 Forbidden`.
4. **Unsupported Methods**: If a request uses an unsupported HTTP method, such as a `PUT` on a static resource, it will return `501 Not Implemented`.

## Acknowledgements

- This project was created as an educational exercise to demonstrate HTTP server handling in C.
