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

    int socket_dsc = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in consumer_addr;
    consumer_addr.sin_family = AF_INET;
    consumer_addr.sin_port = htons(port);
    consumer_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // initializations
    struct SCB* scb = session_setup(socket_dsc, "12345678", &flip_cipher);
    unsigned long msg_len = 0; // user input length
    unsigned long adata_len = 23;
    char* adata = malloc(adata_len);
    memcpy(adata, "associated data stuff!", adata_len);
    char* msg = malloc(MAX_MSG_LEN);

    connect(socket_dsc, (struct sockaddr*)&consumer_addr, sizeof(consumer_addr));

    for (;;) {

        // reset length for each msg
        msg_len = 0;
        clear_bytes(msg, 0, msg_len);

        // user input
        printf("Consumer Input: ");
        fgets(msg, MAX_MSG_LEN, stdin);

        // quit program
        if (!strcmp(msg, "quit\n"))
            break;

        // count char length for user input
        while (msg[msg_len] != '\0') 
            msg_len++;
        

        int ret = send_msg(msg, msg_len, adata, adata_len, scb);

    }

    close(socket_dsc);

}


