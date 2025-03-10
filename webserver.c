#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

// Buffer to store the last requested URI
static char last_uri[256] = {0};
// Global buffer to store the request body
char global_body[8192] = {0};

typedef struct {
    char path[256];
    char content[8192];
} DynamicResource;

DynamicResource dynamic_resources[100]; 
int resource_count = 0;         

/**
 * Extracts the Content-Length value from the HTTP request headers.
 *
 * @param request The HTTP request as a string.
 * @return The content length as an integer. Returns 0 if not found.
 */
int get_content_length(const char *request) {
    char *request_copy = strdup(request);
    char *content_length_str = strstr(request_copy, "Content-Length:");

    if (content_length_str != NULL) {
        content_length_str += 15;

        // Skip any leading whitespace
        while (*content_length_str == ' ' || *content_length_str == '\t') {
            content_length_str++;
        }

        free(request_copy);
        return atoi(content_length_str);
    }
    free(request_copy);
    return 0;
}

/**
 * Validates the format of an HTTP header line.
 *
 * @param line The header line as a string.
 * @return 1 if valid, 0 otherwise.
 */
int is_valid_header(const char *line) {
    const char *colon = strchr(line, ':');
    if (colon == NULL) return 0;

    // Ensure the key has non-whitespace characters
    for (const char *p = line; p < colon; ++p) {
        if (!isspace((unsigned char)*p)) {
            return 1; // Found a valid key before ':'
        }
    }

    return 0; // No valid key found
}

/**
 * Handles the HTTP request by parsing it and determining the appropriate response.
 *
 * @param request The HTTP request as a string.
 * @param content_length The length of the request body.
 * @return The HTTP status code corresponding to the request handling result.
 */
int handle_request(char *request, int content_length) {
    char *request_copy = strdup(request);
    char *temp = strdup(request);
    char *line = strtok(request_copy, "\r\n"); // Split by CRLF
    if (line == NULL) {
        printf("No Split by CRLF\n");
        return 400;
    }

    char method[10], version[20];
    int num_parsed = sscanf(line, "%s %s %s", method, last_uri, version);
    if (num_parsed != 3){
        printf("Parsed more or less than 3 (method, uri, version)\n");
        return 400;
    }

    // Validate HTTP version
    if (strncmp(version, "HTTP/", 5) != 0){
        printf("Invalid HTTP version\n");
        return 400;
    }

    // Basic method validation
    if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0 &&
        strcmp(method, "PUT") != 0 && strcmp(method, "DELETE") != 0 && strcmp(method, "HEAD") != 0) {
        printf("Invalid method\n");
        return 400;
    }

    // Locate the end of headers
    char *end_of_headers = strstr(request_copy, "\r\n\r\n");
    char *header = strtok(NULL, "\r\n");
    while(header){
        if(header >= end_of_headers) break;
        char* delimiter = strchr(header, ':');
        printf("%s\n",header);
        if(!delimiter){

            printf("Invalid header format\n");
            return 400;
        }

        *delimiter = '\0';
        char* key = header;
        char* value = delimiter + 1;
        while(*value == ' ') value++;


        header = strtok(NULL, "\r\n");
    }

    // Allocate memory for the request body
    char* request_body = malloc(content_length+1);
    char* body_start = strstr(temp, "\r\n\r\n");
    body_start += 4;

    if (content_length > 0) {

        memcpy(request_body, body_start, content_length);
        request_body[content_length] = '\0';

    }
    
    free(request_copy);

    // Handle different HTTP methods
    if (strcmp(method, "GET") == 0) {
        //Handle static resources
        if(strcmp(last_uri, "/static/bar") == 0) return 200;
        else if(strcmp(last_uri, "/static/foo") == 0) return 200;
        else if(strcmp(last_uri, "/static/baz") == 0) return 200;
        //Handle dynamic resources
        if (strncmp(last_uri, "/dynamic/", 9) == 0){
            char *resource = last_uri + 9;
            for (int i = 0; i < resource_count; i++) {
                if (strcmp(dynamic_resources[i].path, resource) == 0) {
                    return 200; // Resource found
                }
            }
        }
        return 404; // Resource not found
    }else if (strcmp(method, "PUT") == 0) {
        if (strncmp(last_uri, "/dynamic/", 9) == 0) {
            char *resource = last_uri + 9;
            for (int i = 0; i < resource_count; i++) {
                if (strcmp(dynamic_resources[i].path, resource) == 0) {
                    return 204; // Resource already exists
                }
            }

            // Add new dynamic resource if limit not reached
            if (resource_count < 50) {
                strncpy(dynamic_resources[resource_count].path, resource, 255);
                dynamic_resources[resource_count].path[255] = '\0';
                strncpy(dynamic_resources[resource_count].content, request_body, 255);
                dynamic_resources[resource_count].content[255] = '\0';
                resource_count++;
                return 201; // Resource created
            }
            return 403; // Maximum resource limit reached
        }
        return 403; // Invalid path
    }else if (strcmp(method, "DELETE") == 0) {
        if (strncmp(last_uri, "/dynamic/", 9) == 0) {
            char *resource = last_uri + 9;

            for (int i = 0; i < resource_count; i++) {
                if (strcmp(dynamic_resources[i].path, resource) == 0) {
                    // Remove resource by shifting the array
                    for (int j = i; j < resource_count - 1; j++) {
                        dynamic_resources[j] = dynamic_resources[j + 1];
                    }
                    resource_count--;
                    return 204; // Resource deleted
                }
            }
            return 404; // Resource not found
        }
        return 403; // Invalid path
    }else{
        return 501; // Not Implemented
    }

}

/**
 * Resolves a hostname and port into a sockaddr_in structure.
 *
 * @param host The IP address or hostname of the server.
 * @param port The port number as a string.
 * @return A sockaddr_in structure containing the resolved IP and port.
 */
static struct sockaddr_in derive_sockaddr(const char* host, const char* port) {
    struct addrinfo hints = {
        .ai_family = AF_INET, // Use IPv4 addresses only.
     };
    struct addrinfo *result_info;

    // Resolve the hostname or IP address to an address structure.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode) {
        fprintf(stderr, "Error␣parsing␣host/port");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in*) result_info->ai_addr);

    freeaddrinfo(result_info);
    return result;
}

int main(int argc, char *argv[])
{
    // Ensure the user provides exactly two arguments: IP-address and port.
    if (argc != 3) {
        printf("Usage: %s <IP-address> <port>\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    const char *port = argv[2];

    // Convert the port string to an integer and validate its range.
    int port_number = atoi(port);
    if (port_number <= 0 || port_number > 65535) 
    {
        printf("Invalid port number. Please provide a value between 1 and 65535.\n");
        return 1;
    }

    struct sockaddr_in server_addr = derive_sockaddr(host, port);

    // Create a TCP socket.
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    // Check if the creation of socket is not successful
    if (sock == -1)
    {
        printf("Socket creation failed with error: %s\n", strerror(errno));
        return 1;
    }

    printf("Socket created\n");

    // Set SO_REUSEADDR option to reuse the address immediately after program termination.
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("Failed to set SO_REUSEADDR");
        close(sock);
        return 1;
    }

    // Bind the socket to the specified address and port.
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("Bind failed: %s\n", strerror(errno));
        close(sock);    // Close socket
        return 1;
    }

    printf("Bind successful on %s:%s\n", host, port);

    // Put the socket into listening mode, allowing up to 10 pending connections.
    if (listen(sock, 10) == -1) 
    {
        printf("Listen failed: %s\n", strerror(errno));
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %s\n", port);

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        // Accept an incoming connection.
        int client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock == -1)
        {
            perror("Accept failed");
            close(sock);
            return 1;
        }
        printf("Accepted connection\n");

        // Request buffer to store incoming HTTP request.
        static char request_buffer[8192] = {0}; 
        static int buffer_length = 0;
        while (1)
        {
            char buffer[8192] = {0};

            // Receive data from the client.
            ssize_t received = recv(client_sock, &buffer, sizeof(buffer) - 1, 0);

            if (received == -1)
            {
                perror("Receive failed");
                break;
            }

            if (received == 0)
            {
                perror("Connection was closed by the client");
                break;
            }

            // Ensure the request does not exceed the buffer size.
            if (buffer_length + received >= sizeof(request_buffer)) {
                fprintf(stderr, "Error: Request too large\n");
                break;
            }

            // Append received data to request_buffer.
            memcpy(request_buffer + buffer_length, buffer, received);
            buffer_length += received;
            request_buffer[buffer_length] = '\0';

            printf("Received data: %s\n", request_buffer);

            // Search for the end of the HTTP headers (double CRLF).
            const char *word = "\r\n\r\n";
            char *result = strstr(request_buffer, word);
            while(result != NULL){
                int payload_len = strlen(result) - strlen(word);
                int content_length = get_content_length(request_buffer);;

                if (payload_len >= content_length)
                {
                    // Allocate memory for the complete HTTP request.
                    char *request = malloc(8192);
                    memcpy(request, request_buffer, result-request_buffer+strlen(word) + content_length);


                    char *body = result + 4; // Pointer at the request-body (if it exists)

                    // Copy the request body into the global buffer.
                    strncpy(global_body, body, sizeof(global_body) - 1);
                    global_body[sizeof(global_body) - 1] = '\0';

                    printf("Checking request\n");
                    int status_code = handle_request(request, content_length);

                    // Prepare the HTTP response based on the status code.
                    char response[16384];
                    if (status_code == 400) {
                        snprintf(response, sizeof(response), "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                    } else if (status_code == 404) {
                        snprintf(response, sizeof(response), "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                    } else if (status_code == 413) {
                        snprintf(response, sizeof(response), "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n");
                    } else if (status_code == 501) {
                        snprintf(response, sizeof(response), "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n");
                    } else if (status_code == 200) {
                        // Handle static and dynamic resource retrieval.
                        if (strncmp(last_uri, "/static/", 8) == 0) {
                            char *resource_name = last_uri + 8;

                            // Creating response-body in relation to the resource
                            if (strcmp(resource_name, "foo") == 0) {
                                snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nFoo");
                            } else if (strcmp(resource_name, "bar") == 0) {
                                snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nBar");
                            } else if (strcmp(resource_name, "baz") == 0) {
                                snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nBaz");
                            } else {
                                snprintf(response, sizeof(response), "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                            }
                        }
                        else if (strncmp(last_uri, "/dynamic/", 9) == 0)
                        {
                            // Form the dynamic response with dynamic content
                            char *resource_name = last_uri + 9;
                            for (int i = 0; i < resource_count; i++)
                            {
                                if (strcmp(dynamic_resources[i].path, resource_name) == 0)
                                {
                                    snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n%s",
                                                strlen(dynamic_resources[i].content), dynamic_resources[i].content);
                                    break;
                                }
                            }
                        }
                    }
                    else if (status_code == 201) {
                        snprintf(response, sizeof(response), "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");
                    }
                    else if (status_code == 403) {
                        snprintf(response, sizeof(response), "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
                    }
                    else if (status_code == 204) {
                        snprintf(response, sizeof(response), "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
                    }
                    else {
                        snprintf(response, sizeof(response), "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
                    }

                    // Send the response
                    int bytes_sent = send(client_sock, response, strlen(response), 0);
                    if (bytes_sent == -1)
                    {
                        perror("Send failed");  // Send failed!
                    }
                    printf("Sent response: %s\n", response);

                    // Clear used data
                    int remaining_length = strlen(body) - content_length;
                    memmove(request_buffer, body + content_length, remaining_length + 1);
                    buffer_length = remaining_length;
                    request_buffer[buffer_length] = '\0';

                    memset(global_body, 0, sizeof(global_body));


                    printf("Remaining data: %s\n", request_buffer);

                    result = strstr(request_buffer, word);
                }else{
                    break;
                }
            }

        }

        close(client_sock);
    }
    close(sock);
    return 0;
}
