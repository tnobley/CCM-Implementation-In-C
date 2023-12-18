#include <stdio.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "die.c"
#include "ccm.c"

int main(int argc, char *argv[]) {

    if (argc != 2) // Test for correct number of arguments
        dieWithError("Parameter(s): <Port#>\n");

    int port = atoi(argv[1]);

    // create socket
    int socket_dsc = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in client_addr;

    // initialize server address structure
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // bind to port
    if(bind(socket_dsc, (struct sockaddr*)&server_addr, sizeof(server_addr))<0){
        printf("Couldn't bind to the port\n");
        return -1;
    }

    printf("Done with binding\n");

    // listen for incoming connections
    if(listen(socket_dsc, 1) < 0) {
        printf("Error while listening\n");
        return -1;
    }

    printf("\nListening for incoming connections.....\n");

    // accept connection req and save socket descriptor
    int client_size = sizeof(client_addr);
    int client_sock = accept(socket_dsc, (struct sockaddr*)&client_addr, &client_size);

    // error if invalid socket
    if (client_sock < 0){
        printf("Can't accept\n");
        return -1;
    }

    // setup SCB for receiving transmmissions
    struct SCB* scb = session_setup(client_sock, "12345678", &flip_cipher);

    

    printf("Producer connected at IP: %s and port: %i\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    struct vbuf* adata = vbuf_create();
    struct vbuf* msg = vbuf_create();

    for (;;) {
        recv_msg(adata, msg, scb);
        vbuf_free(adata);
        vbuf_free(msg);
    }

    close(client_sock);
    close(socket_dsc);

}