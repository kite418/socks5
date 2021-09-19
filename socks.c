#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define BAD_METHOD 0X09
#define NO_ACCEPTABLE_METHODS 0xFF
#define SOCKS_VERSION 5

enum supported_methods {
    NO_AUTH_REQUIRED = 0x00,
};

enum supported_aypt {
    IP_V4 = 0x01,
    DOMAIN = 0x03
};

typedef struct initial_request {
    int version;
    int n_methods;
} InitialRequest;

typedef struct socks_command {
    int version;
    int cmd;
    int RSV;
    int ATYP;
    char * DST_ADDR;
    int DST_PORT;
} SocksCommand;

InitialRequest * inital_request() {
    InitialRequest * new_inital_req = malloc(sizeof(struct initial_request));

    new_inital_req->version = -0x01;
    new_inital_req->n_methods = -0x01;

    return new_inital_req;
}

void inital_request_free(InitialRequest * ir) {
    free(ir);
}

SocksCommand * socks_command() {
    SocksCommand * new_socks_cmd = malloc(sizeof(struct socks_command));
    return new_socks_cmd;
}

void socks_command_free(SocksCommand * sc) {
    free(sc);
}

int handle_atyp(int atyp) {
    int dst_addr_len = -1;
    switch (atyp)
    {
    case IP_V4:
        dst_addr_len = 4;
        break;
    default:
        dst_addr_len = 16;
        break;
    }

    return dst_addr_len;
}

void recv_safe(int socket, char buf[], int read_len) {
    int remaining = read_len;
    while (remaining > 0) {
        int n = recv(socket, buf, (size_t) remaining, 0);
        if (n == 0) {
            printf("PEER CLOSED SOCKET\n");
            close(socket);
            exit(0);
        } else if (n == -1) {
            printf("RECV ERROR");
            close(socket);
            exit(0);
        }

        remaining -= n;
    }
}

void send_safe(int socket, char buf[], int send_len) {
    int remaining = send_len;
    while (remaining > 0) {
        int n = send(socket, buf, (size_t) remaining, 0);
        if (n == -1) {
            printf("RECV ERROR");
            close(socket);
            exit(0);
        }

        remaining -= n;
    }
}

void handle_inital_req(InitialRequest * ir, int client_socket) {
    char req[2] = {-0x01, -0x01};
    recv_safe(client_socket, req, sizeof(req));

    ir->version = (int) req[0];
    ir->n_methods = (int) req[1];
}

void recv_methods(int client_socket, int methods[], int n_methods) {
    char method;
    for (int i = 0; i < n_methods; ++i) {
        method = BAD_METHOD; //clear method, with a non-socks method
        recv_safe(client_socket, &method, 1);
        methods[i] = method;
    }
}

int select_method(int methods[], int n_methods) {
    int selected = BAD_METHOD;
    for (int i = 0; i < n_methods; ++i) {
        switch (methods[i])
        {
        case NO_AUTH_REQUIRED:
            selected = NO_AUTH_REQUIRED;
            return selected;
        default:
            selected = BAD_METHOD;
            return selected;
        }
    }

    return selected;
}

void recv_cmd(int client_socket, SocksCommand * s_cmd) {
    char data[4] = {'\0'};
    recv_safe(client_socket, data, sizeof(data));

    s_cmd->version = data[0];
    s_cmd->cmd = data[1];
    s_cmd->RSV = data[2];
    s_cmd->ATYP = data[3];
}

void recv_request(int client_socket, SocksCommand * s_cmd, int dst_addr_len) {
    char * dst_addr = malloc(dst_addr_len + 1);
    recv_safe(client_socket, dst_addr, dst_addr_len);
    dst_addr[dst_addr_len] = '\0';
    printf("%s\n", dst_addr);

    char dst_port[3] = {'\0', '\0', '\0'};
    recv_safe(client_socket, dst_port, 2);
    int port = atoi(dst_port);

    s_cmd->DST_ADDR = dst_addr;
    s_cmd->DST_PORT = port;
}

void print_methods(int methods[], int n_methods) {
    for (int i = 0; i < n_methods; ++i) {
        printf("%i, ", methods[i]);
    }

    printf("\n");
}

void send_method_selection(int client_socket, int version, int method) {
    char msg[2] = {(char) version, (char) method};

    send_safe(client_socket, msg, sizeof(msg));
}

int is_valid_version(int version) {
    return (version == 0x05);
}

void socks_entry(int client_socket) {
    InitialRequest * ir = inital_request();
    handle_inital_req(ir, client_socket);

    //should have versio, nMethods from invitation
    printf("Version Req: 0x%1x, nMethods: 0x%1x\n", ir->version, ir->n_methods);

    if (!is_valid_version(ir->version)) {
        printf("Invalid socks version: 0x%1x\n", ir->version);
        inital_request_free(ir);
        ir = NULL;
        return;
    }

    

    int * methods = malloc(sizeof(int) * ir->n_methods);
    recv_methods(client_socket, methods, ir->n_methods);
    printf("Client requested methods: ");
    print_methods(methods, ir->n_methods);

    //assume we have methods
    int selected_method = select_method(methods, ir->n_methods);
    if (selected_method == BAD_METHOD) {
        printf("All methods unsupported\n");
        send_method_selection(client_socket, SOCKS_VERSION, NO_ACCEPTABLE_METHODS);
        inital_request_free(ir); // dont need this anymore
        ir = NULL;
        return;
    }

    inital_request_free(ir); // dont need this anymore
    ir = NULL;

    printf("Method selected: %i\n", selected_method);
    //tell client, which method we chose
    send_method_selection(client_socket, SOCKS_VERSION, selected_method);

    SocksCommand * s_cmd = malloc(sizeof(struct socks_command));
    recv_cmd(client_socket, s_cmd);
    printf("ATYP: %i\n", s_cmd->ATYP);
    int dst_addr_len = handle_atyp(s_cmd->ATYP);
    
    if (dst_addr_len < 0) {
        printf("Invalid ATYP");
        free(s_cmd);
        s_cmd = NULL;
        return;
    }

    printf("Destination address length: %i\n", dst_addr_len);

    //should be ready to recv dst_addr
    recv_request(client_socket, s_cmd, dst_addr_len);
    printf("Destination address: %s:%i\n", s_cmd->DST_ADDR, s_cmd->DST_PORT);
    for (int i = 0; i < 4; ++i) {
        printf("%hhu ", s_cmd->DST_ADDR[i]);
    }

    printf("\n");
    
    
    return;
}

int main() {


    int server_socket;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(9002);
    server_address.sin_addr.s_addr = INADDR_ANY;

    bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));

    listen(server_socket, 5);

    int client_socket;
    client_socket = accept(server_socket, NULL, NULL);

    socks_entry(client_socket);
    

    close(client_socket);

    return 0;
}

