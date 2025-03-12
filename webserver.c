#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "data.h"
#include "http.h"
#include "util.h"

// Define maximum limits for resources and reply messages
#define MAX_RESOURCES 100
#define MAX_REPLIES 10

/*
 * Struct representing a node's reply in the network.
 * Used to store responses during a distributed hash table (DHT) lookup.
 */
typedef struct {
    uint16_t id;  
    uint16_t succ_id;  
    char ip[16];    
    uint16_t port;  
} NodeResponse;

// Array to store replies from other nodes and counter for the number of replies
NodeResponse reply_list[MAX_REPLIES];
int reply_count = 0;

/** 
 * Array of static resources (tuples) for HTTP requests.
 * Contains three resources with their associated paths, values, and lengths.
 */
struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof "Foo" - 1},
    {"/static/bar", "Bar", sizeof "Bar" - 1},
    {"/static/baz", "Baz", sizeof "Baz" - 1}};

/** 
 * Struct representing a Node in the distributed network.
 * Contains details of the node, its predecessor, and successor.
 */
typedef struct Node{
    uint16_t id;
    char ip[16];
    int port;
    uint16_t pred_id;
    uint16_t succ_id;
    char pred_ip[16];
    int pred_port;
    char succ_ip[16];
    int succ_port;
} Node;

// Global node representing this server's identity and its network neighbors
Node node;
// Flag indicating whether the distributed hash table (DHT) has been created
bool dht_created = false;

/** 
 * Determines if the current node is responsible for handling a particular hash.
 *
 * @param hash The hash value derived from a resource's URI.
 * @param current_id The ID of the current node's successor.
 * @param pred_id The ID of the current node.
 * @return true if the current node is responsible; false otherwise.
 */
bool is_responsible(uint16_t hash, uint16_t current_id, uint16_t pred_id) {
    return (dht_created && 
            ((current_id > pred_id && hash <= current_id && hash > pred_id) || 
             (current_id < pred_id && (hash <= current_id || hash > pred_id))));
}

/** 
 * Sends a lookup message via UDP to the successor node.
 *
 * @param hash The hash value for which the lookup is performed.
 * @param id The ID of the node performing the lookup.
 * @param ip The IP address (as string) of the requesting node.
 * @param port The port of the requesting node.
 */
void send_lookup(uint16_t hash, uint16_t id, char *ip, uint16_t port) {
    // Create a UDP socket.
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set up the address structure for the successor
    struct sockaddr_in successor_addr;
    memset(&successor_addr, 0, sizeof(successor_addr));
    successor_addr.sin_family = AF_INET;
    successor_addr.sin_port = htons(node.succ_port);
    if (inet_pton(AF_INET, node.succ_ip, &successor_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Prepare the message buffer
    char buffer[11];
    memset(buffer, 0, sizeof(buffer));
    uint32_t ip_bin;
    inet_pton(AF_INET, ip, &ip_bin);
    uint8_t type = 0;  // lookup message
    memcpy(buffer, &type, 1);
    *(uint16_t *)(buffer + 1) = htons(hash);
    *(uint16_t *)(buffer + 3) = htons(id);
    memcpy(buffer + 5, &ip_bin, 4);
    *(uint16_t *)(buffer + 9) = htons(port);

    //Send lookup message
    ssize_t sent = sendto(sock, buffer, sizeof(buffer), 0,
                          (struct sockaddr *)&successor_addr, sizeof(successor_addr));
    if (sent == -1) {
        perror("sendto");
    } else {
        printf("Sent lookup message to successor\n");
    }

    close(sock);
}

/** 
 * Sends a lookup reply via UDP back to a requesting node.
 *
 * @param ip The IP address (as string) of the requesting node.
 * @param port The port number of the requesting node.
 */
void lookup_reply(char *ip, uint16_t port) {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set up the address structure for the recipient
    struct sockaddr_in successor_addr;
    memset(&successor_addr, 0, sizeof(successor_addr));
    successor_addr.sin_family = AF_INET;
    successor_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &successor_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Prepare the reply message
    char buffer[11];
    memset(buffer, 0, sizeof(buffer));
    uint32_t ip_bin;
    inet_pton(AF_INET, node.succ_ip, &ip_bin);
    uint8_t type = 1;  // reply message
    memcpy(buffer, &type, 1);
    *(uint16_t *)(buffer + 1) = htons(node.id);
    *(uint16_t *)(buffer + 3) = htons(node.succ_id);
    memcpy(buffer + 5, &ip_bin, 4);
    *(uint16_t *)(buffer + 9) = htons(node.succ_port);

    //Send reply message
    ssize_t sent = sendto(sock, buffer, sizeof(buffer), 0,
                          (struct sockaddr *)&successor_addr, sizeof(successor_addr));
    if (sent == -1) {
        perror("sendto");
    } else {
        printf("Sent lookup message to successor\n");
    }

    close(sock);
}

/**
 * Processes a received reply message by storing it in the reply list.
 *
 * @param id The ID from the received reply message.
 * @param succ_id The successor ID from the received reply message.
 * @param ip The IP address from the received reply message.
 * @param port The port number from the received reply message.
 */
void process_reply(uint16_t id, uint16_t succ_id, char *ip, uint16_t port) {
    // If there's room, add the reply to the list
    if (reply_count < MAX_REPLIES) {
        reply_list[reply_count].id = id;
        reply_list[reply_count].succ_id = succ_id;
        strcpy(reply_list[reply_count].ip, (char *)ip);
        reply_list[reply_count].port = port;
        reply_count++;
    } else {
        // If the list is full, remove the oldest reply and add the new one
        for (int i = 1; i < MAX_REPLIES; i++) {
            reply_list[i - 1] = reply_list[i];
        }
        reply_list[MAX_REPLIES - 1].id = id;
        reply_list[MAX_REPLIES - 1].succ_id = succ_id;
        strcpy(reply_list[MAX_REPLIES - 1].ip, (char *)ip);
        reply_list[MAX_REPLIES - 1].port = port;
    }
    printf("Received response from node %u at %s:%u\n", id, ip, port);
}

/**
 * Processes an incoming UDP message.
 *
 * @param buffer The message buffer containing the UDP message.
 * @param buffer_length The length of the received message.
 */
void process_udp_message(char *buffer, size_t buffer_length){
    // Check for the expected message size
    if (buffer_length != 11) {
        fprintf(stderr, "Received message has invalid length: %zd\n", buffer_length);
        return;
    }

    // Parse the UDP message
    uint8_t message_type = buffer[0];
    uint16_t hash = ntohs(*(uint16_t *)(buffer + 1));
    uint16_t node_id = ntohs(*(uint16_t *)(buffer + 3));
    struct in_addr ip_addr;
    memcpy(&ip_addr, buffer + 5, sizeof(ip_addr));
    uint16_t port = ntohs(*(uint16_t *)(buffer + 9));

    // Process based on the message type
    if (message_type == 0) { // lookup
        fprintf(stderr, "Processing Lookup message for hash %u\n", hash);
        if (is_responsible(hash, node.succ_id, node.id)) {
            lookup_reply(inet_ntoa(ip_addr), port);
        } else {
            send_lookup(hash, node_id, inet_ntoa(ip_addr), port);
        }
    } else if (message_type == 1) { // reply
        fprintf(stderr, "Processing Reply");
        process_reply(hash, node_id, inet_ntoa(ip_addr), port);
    } else {
        fprintf(stderr, "Unknown message type: %u\n", message_type);
    }
}

/**
 * Sends an HTTP reply to the client based on the received request.
 *
 * @param conn      The file descriptor of the client connection socket.
 * @param request   A pointer to the struct containing the parsed request.
 */
void send_reply(int conn, struct request *request) {
    char buffer[HTTP_MAX_SIZE];
    char *reply = buffer;
    size_t offset = 0;

    // Log request information for debugging
    fprintf(stderr, "Handling %s request for %s (%lu byte payload)\n",
            request->method, request->uri, request->payload_length);

    uint16_t hash = pseudo_hash((unsigned char*)request->uri, strlen(request->uri));

    // Determine if this is a 2-node DHT or a larger network
    bool is_two_node_dht = (node.pred_id == node.succ_id);

    // If this node is not responsible for the hash
    if (dht_created && !is_responsible(hash, node.id, node.pred_id)) {

        if (is_two_node_dht) {
            // 2-node scenario: immediately redirect with 303
            offset = sprintf(
                reply,
                "HTTP/1.1 303 See Other\r\n"
                "Location: http://%s:%d%s\r\n"
                "Content-Length: 0\r\n\r\n",
                node.succ_ip, node.succ_port, request->uri
            );
        }
        else {
            // >=3-node scenario: check if we already know who is responsible
            bool found_responsible = false;
            for (int i = 0; i < reply_count; i++) {
                if (is_responsible(hash, reply_list[i].succ_id, reply_list[i].id)) {
                    found_responsible = true;
                    offset = sprintf(
                        reply,
                        "HTTP/1.1 303 See Other\r\n"
                        "Location: http://%s:%d%s\r\n"
                        "Content-Length: 0\r\n\r\n",
                        reply_list[i].ip, reply_list[i].port, request->uri
                    );
                    break;
                }
            }
            if (!found_responsible) {
                // We do not yet know the responsible node -> 503 + Retry-After
                offset = sprintf(
                    reply,
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Retry-After: 1\r\n"
                    "Content-Length: 0\r\n\r\n"
                );
                // Send a chord lookup so we might learn who is responsible
                send_lookup(hash, node.id, node.ip, node.port);
            }
        }
    }
    else if (strcmp(request->method, "GET") == 0) {
        // Handle GET requests for static resources
        size_t resource_length;
        const char *resource =
            get(request->uri, resources, MAX_RESOURCES, &resource_length);

        if (resource) {
            // If the resource exists, send it with a 200 OK response
            size_t payload_offset = sprintf(
                reply,
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: %lu\r\n\r\n",
                resource_length
            );
            memcpy(reply + payload_offset, resource, resource_length);
            offset = payload_offset + resource_length;
        } else {
            reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            offset = strlen(reply);
        }
    }
    else if (strcmp(request->method, "PUT") == 0) {
        // Handle PUT requests for dynamic resource creation.
        if (set(request->uri, request->payload, request->payload_length,
                resources, MAX_RESOURCES)) {
            reply = "HTTP/1.1 204 No Content\r\n\r\n";
        } else {
            reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
        }
        offset = strlen(reply);
    }
    else if (strcmp(request->method, "DELETE") == 0) {
        // Handle DELETE requests for dynamic resource deletion.
        if (delete(request->uri, resources, MAX_RESOURCES)) {
            reply = "HTTP/1.1 204 No Content\r\n\r\n";
        } else {
            reply = "HTTP/1.1 404 Not Found\r\n\r\n";
        }
        offset = strlen(reply);
    }
    else {
        reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
        offset = strlen(reply);
    }

    if (send(conn, reply, offset, 0) == -1) {
        perror("send");
        close(conn);
    }
    fprintf(stderr, "Sent reply: %s", reply);
}

/**
 * Processes an incoming packet from the client.
 *
 * @param conn The client connection file descriptor.
 * @param buffer The buffer containing the incoming data.
 * @param n The number of bytes in the buffer.
 * @return The number of bytes processed or -1 on error.
 */
size_t process_packet(int conn, char *buffer, size_t n) {
    // Request structure with default values
    struct request request = {
        .method = NULL, .uri = NULL, .payload = NULL, .payload_length = -1
    };

    ssize_t bytes_processed = parse_request(buffer, n, &request);

    if (bytes_processed > 0) {
        send_reply(conn, &request);

        // Check the Connection header to see if the connection should remain open
        const string connection_header = get_header(&request, "Connection");
        if (connection_header && strcmp(connection_header, "close")) {
            return -1;
        }
    }
    else if (bytes_processed == -1) {
        const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(conn, bad_request, strlen(bad_request), 0);
        printf("Received malformed request, terminating connection.\n");
        close(conn);
        return -1;
    }

    return bytes_processed;
}

/**
 * Initializes the connection state for a new client connection.
 *
 * @param state Pointer to the connection state structure.
 * @param sock The client socket file descriptor.
 */
static void connection_setup(struct connection_state *state, int sock) {
    state->sock = sock;
    state->end = state->buffer;
    memset(state->buffer, 0, HTTP_MAX_SIZE);
}

/**
 * Discards processed data from the buffer.
 *
 * @param buffer The original buffer.
 * @param discard Number of bytes to discard.
 * @param keep Number of bytes to retain.
 * @return Pointer to the new beginning of the buffer.
 */
char *buffer_discard(char *buffer, size_t discard, size_t keep) {
    memmove(buffer, buffer + discard, keep);
    memset(buffer + keep, 0, discard);
    return buffer + keep;
}

/**
 * Handles the connection with the client.
 *
 * Reads incoming data from the connection, processes complete HTTP requests,
 * and manages the buffer accordingly.
 *
 * @param state Pointer to the connection state structure.
 * @return true if the connection should remain open; false otherwise.
 */
bool handle_connection(struct connection_state *state) {
    const char *buffer_end = state->buffer + HTTP_MAX_SIZE;
    ssize_t bytes_read = recv(state->sock, state->end, buffer_end - state->end, 0);
    if (bytes_read == -1) {
        perror("recv");
        close(state->sock);
        exit(EXIT_FAILURE);
    } else if (bytes_read == 0) {
        fprintf(stderr, "Zero read");
        return false;
    }

    char *window_start = state->buffer;
    char *window_end = state->end + bytes_read;

    ssize_t bytes_processed = 0;
    // Process packets in the buffer until no complete request remains.
    while ((bytes_processed = process_packet(state->sock, window_start,
                                             window_end - window_start)) > 0) {
        window_start += bytes_processed;
    }
    if (bytes_processed == -1) {
        return false;
    }

    // Discard processed data from the buffer and update the state.
    state->end = buffer_discard(state->buffer,
                                window_start - state->buffer,
                                window_end - window_start);
    return true;
}

/**
 * Resolves a hostname and port into a sockaddr_in structure.
 *
 * @param host The IP address or hostname of the server.
 * @param port The port number as a string.
 * @return A sockaddr_in structure containing the resolved IP and port.
 */
static struct sockaddr_in derive_sockaddr(const char *host, const char *port) {
    struct addrinfo hints = { .ai_family = AF_INET };
    struct addrinfo *result_info;

    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode) {
        fprintf(stderr, "Error parsing host/port");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in result = *((struct sockaddr_in *)result_info->ai_addr);
    freeaddrinfo(result_info);
    return result;
}

/**
 * Sets up a non-blocking TCP socket bound to the specified address.
 *
 * @param addr The sockaddr_in structure containing the address and port.
 * @return The file descriptor for the TCP socket.
 */
static int setup_tcp_socket(struct sockaddr_in addr) {
    const int enable = 1;
    const int backlog = 1;

    // Create a TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set the socket to non-blocking mode
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    // Allow the socket to reuse the address
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Put the socket into listening mode
    if (listen(sock, backlog)) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}

/**
 * Sets up a UDP socket bound to the specified address.
 *
 * @param addr The sockaddr_in structure containing the address and port.
 * @return The file descriptor for the UDP socket.
 */
static int setup_udp_socket(struct sockaddr_in addr) {
    const int enable = 1;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Allow the UDP socket to reuse the address
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind the UDP socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

/**
 * Initializes the server node using environment variables and command-line arguments.
 *
 * Expects environment variables for predecessor and successor details:
 * - PRED_ID, PRED_IP, PRED_PORT, SUCC_ID, SUCC_IP, SUCC_PORT.
 *
 * Additionally, uses command-line arguments for this node's IP and port.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 */
void initialize_server_node(int argc, char **argv){
    // Retrieve predecessor and successor values from environment variables
    const char *pred_id = getenv("PRED_ID");
    const char *pred_ip = getenv("PRED_IP");
    const char *pred_port = getenv("PRED_PORT");
    const char *succ_id = getenv("SUCC_ID");
    const char *succ_ip = getenv("SUCC_IP");
    const char *succ_port = getenv("SUCC_PORT");

    if (!pred_id || !pred_ip || !pred_port || !succ_id || !succ_ip || !succ_port) {
        fprintf(stderr, "Error: Missing required environment variables.\n");
        return;
    }

    // Set predecessor information
    node.pred_id = atoi(pred_id);
    strncpy(node.pred_ip, pred_ip, sizeof(node.pred_ip));
    node.pred_port = atoi(pred_port);
    // Set successor information
    node.succ_id = atoi(succ_id);
    strncpy(node.succ_ip, succ_ip, sizeof(node.succ_ip));
    node.succ_port = atoi(succ_port);

    // Set this node's information using command-line arguments
    node.id = (argc > 3) ? atoi(argv[3]) : 0;
    strncpy(node.ip, argv[1], sizeof(node.ip));
    node.port = atoi(argv[2]);

    // Log the node's configuration
    printf("Node ID: %u (%s:%d)\n", node.id, node.ip, node.port);
    printf("Predecessor: %u (%s:%d)\n", node.pred_id, node.pred_ip, node.pred_port);
    printf("Successor: %u (%s:%d)\n", node.succ_id, node.succ_ip, node.succ_port);

    dht_created = true;
    return;
}

int main(int argc, char **argv) {
    // Require at least two command-line arguments: IP address and port
    if (argc < 3) {
        return EXIT_FAILURE;
    }

    initialize_server_node(argc, argv);

    struct sockaddr_in addr = derive_sockaddr(argv[1], argv[2]);

    int tcp_server_socket = setup_tcp_socket(addr);
    int udp_server_socket = setup_udp_socket(addr);

    // Prepare an array of file descriptors for use with poll()
    struct pollfd sockets[3] = {
        {.fd = tcp_server_socket, .events = POLLIN},
        {.fd = udp_server_socket, .events = POLLIN},
        {.fd = -1, .events = 0}
    };

    // Initialize connection state for managing client data
    struct connection_state state = {0};
    int connection_socket = -1;

    while (true)
    {
        // Wait indefinitely for one or more of the sockets to have incoming data
        int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), -1);
        if (ready == -1)
        {
            perror("poll");
            exit(EXIT_FAILURE);
        }
        // Iterate through the poll file descriptors
        for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i++)
        {
            // Process only those file descriptors that have incoming data
            if (sockets[i].revents != POLLIN) continue;
            

            if (sockets[i].fd == udp_server_socket)
            {
                char buffer[11];
                struct sockaddr_in client_addr;
                socklen_t client_addr_len = sizeof(client_addr);

                ssize_t bytes_received = recvfrom(udp_server_socket, buffer, sizeof(buffer), 0,
                                                (struct sockaddr *)&client_addr, &client_addr_len);
                if (bytes_received == -1) {
                    perror("recvfrom");
                    continue;
                }

                process_udp_message(buffer, bytes_received);
            }
            else if (sockets[i].fd == tcp_server_socket)
            {
                // Accept new TCP connection if no current connection is being handled
                if (sockets[2].fd == -1)
                {
                    connection_socket = accept(tcp_server_socket, NULL, NULL);
                    if (connection_socket == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        perror("accept");
                        exit(EXIT_FAILURE);
                    }

                    sockets[2].fd = connection_socket;
                    sockets[2].events = POLLIN;
                    connection_setup(&state, connection_socket);
                }
            }
            else if (sockets[i].fd == connection_socket)
            {
                // Process data from an established TCP connection
                bool cont = handle_connection(&state);
                if (!cont)
                {
                    close(connection_socket);
                    connection_socket = -1;
                    sockets[2].fd = -1;
                    sockets[2].events = 0;
                }
            }
        }
    }

    return EXIT_SUCCESS;
}
