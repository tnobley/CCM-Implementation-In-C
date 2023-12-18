#ifndef CCM
#define CCM

#include <sys/socket.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <endian.h>
#include <limits.h>
#include <stdlib.h>
#include "cipher.c"
#include <arpa/inet.h>

// specify the output style
// 2: binary
// 16: hex
#define PRINT_MODE 16

#define NONCE_LEN 7 // min value of 7
#define TAG_LEN 16
#define CTRL_INFO_LEN 1
#define HEADER_LEN 16
#define BLOCK_LEN 16


#define MAX_MSG_LEN 100000
#define MAX_CCM_LEN 110000

typedef void (*blk_cipher)(char k[16], char* p, char* c);
typedef char blk[16];

struct SCB {

  int socket_fd;
  blk key;
  blk_cipher encrypt_block;

};

struct SCB* session_setup(int socket_fd, blk key, blk_cipher encrypt_block) {

  struct SCB* scb = malloc(sizeof(struct SCB));
  scb->socket_fd = socket_fd;
  scb->encrypt_block = encrypt_block;
  memcpy(scb->key, key, BLOCK_LEN);

  return scb;

}

void clear_bytes(char* data, unsigned long start_index, unsigned long end_index) {

  for (int i = start_index; i < end_index; i++)
    data[i] = (char)0;

}

void session_clear(struct SCB* scb) {

  scb->socket_fd = 0;
  scb->encrypt_block = 0;
  clear_bytes(scb->key, 0, BLOCK_LEN);

}

void session_destroy(struct SCB* scb) {

  session_clear(scb);
  free(scb);

}

struct vbuf {

  char* data;
  unsigned long len;

};


void vbuf_clear(struct vbuf* buffer) {

  clear_bytes(buffer->data, 0, buffer->len);
  buffer->len = 0;

}

void vbuf_free(struct vbuf* buffer) {

  vbuf_clear(buffer);
  free(buffer->data);

}

struct vbuf* vbuf_create() {

  struct vbuf* buffer = malloc(sizeof(struct vbuf));
  vbuf_clear(buffer);
  return buffer;

}

void print_bits(char* data, unsigned long data_len) {

  unsigned char char_to_print;
   
  if (PRINT_MODE == 16) {
    for (unsigned long i = 0; i < data_len; i++)
    {
            printf(" ");
            char_to_print = (unsigned char)data[i];
            printf("%02x", char_to_print);
    }
  }

  else if (PRINT_MODE == 2) {
    for (unsigned long i = 0; i < data_len; i++)
      {
              char_to_print = data[i];

              for (int bit = 0; bit < 8; bit++)
              {
                      printf("%i", (char_to_print & 128) == 128);
                      char_to_print = char_to_print << 1;
              }
              printf(" ");
      }
  }

  printf("\n");

}

void print_data_blocks(char* data_buffer, unsigned long data_len) {

  for (int i = 0; i < data_len; i += 16) {
    unsigned long blk_num = (i / 16);
    printf("B%-3lu = ", blk_num);
    print_bits(&data_buffer[i], 16);
  }

  printf("\n");

}

void xor_blocks(char* b1, char* b2, char* br) {

  for (int i = 0; i < 16; i++)
    br[i] = b1[i] ^ b2[i];

}

unsigned long find_pad_len(unsigned long len) {

  return len + (BLOCK_LEN - (len % BLOCK_LEN));

}

void format_blocks(char* nonce, char* adata, unsigned long pad_adata_len, char* payload, unsigned long payload_len, char* buffer) {

  unsigned long pad_payload_len = find_pad_len(payload_len);
  unsigned long payload_len_hl = be64toh(payload_len);

  // printf("Formatting into %ld blocks...\n", 11111);

  char ctrl_info = 127; // 01 111 111 

  memcpy(buffer, &ctrl_info, 1); // control info
  memcpy(&buffer[1], nonce, NONCE_LEN); // nonce
  memcpy(&buffer[NONCE_LEN+1], (char*)&payload_len_hl, 15-NONCE_LEN); // payload length
  memcpy(&buffer[16], adata, pad_adata_len); // associated data
  memcpy(&buffer[16+pad_adata_len], payload, pad_payload_len); // payload

}


void compute_mac(char* data, unsigned long data_len, struct SCB* scb, char* tag_buffer) {

  // encrypt the first block b0
  (*(scb->encrypt_block))(scb->key, data, tag_buffer);
  printf("B0E         = ");
  print_bits(tag_buffer, BLOCK_LEN);

  // iterate through each block of data
  for (unsigned long i = BLOCK_LEN; i < data_len; i += BLOCK_LEN) {

    unsigned long blk_num = (i / BLOCK_LEN);

    xor_blocks(tag_buffer, &data[i], tag_buffer); // XOR with previous block
    printf("XOR%-3ld      = ", blk_num);
    print_bits(tag_buffer, BLOCK_LEN);
    (*(scb->encrypt_block))(scb->key, tag_buffer, tag_buffer); // encrypt XORed block
    printf("E%-3ld        = ", blk_num);
    print_bits(tag_buffer, BLOCK_LEN);
  }

  printf("\nMAC       = ");
  print_bits(tag_buffer, BLOCK_LEN);

}

int increment_cntr(unsigned char* counter_buffer, unsigned long counter_buffer_len) {

  // add error checking for overflow

  counter_buffer[counter_buffer_len-1] += 1;

  unsigned long i = 0;
  while (counter_buffer[counter_buffer_len-1-i] == 0) {
    i++;
    counter_buffer[counter_buffer_len-1-i] += 1;
  }

}

void generate_cntr_blks(unsigned long counter_buffer_len, char* nonce, char* counter_buffer) {

  char flags = 7; // fixed payload length
  unsigned char* counter = malloc(15-NONCE_LEN);
  clear_bytes(counter, 0, 15-NONCE_LEN);

  // fill buffer with generated blocks
  for (int i = 0; i < counter_buffer_len; i += BLOCK_LEN) {

    memcpy(&counter_buffer[i], &flags, 1); // add flags
    memcpy(&counter_buffer[i+1], nonce, NONCE_LEN); // add nonce
    memcpy(&counter_buffer[i+1+NONCE_LEN], counter, 15-NONCE_LEN); // add ctr
    increment_cntr(counter, 15-NONCE_LEN); // increment ctr

  }

  free(counter);

}


void encrypt_payload(char* payload_buffer, unsigned long payload_buffer_len, char* counters_buffer, char* cipher_buffer, struct SCB* scb) {

  printf("\nCTR Start = ");
  print_bits(counters_buffer, BLOCK_LEN);

  // for each payload block
  for (int i = 0; i < payload_buffer_len; i += BLOCK_LEN) {

    unsigned long blk_num = (i / BLOCK_LEN) + 1;

    (*(scb->encrypt_block))(scb->key, &counters_buffer[i], &counters_buffer[i]); // encrypt the counter block
    printf("CTR E%-3ld    = ", blk_num);
    print_bits(&counters_buffer[i], BLOCK_LEN);
    xor_blocks(&payload_buffer[i], &counters_buffer[i], &cipher_buffer[i]); // xor with unencrypted payload
    printf("CTR XOR%-3ld  = ", blk_num);
    print_bits(&cipher_buffer[i], BLOCK_LEN);
  }

}

void decrypt_payload(char* cipher_buffer, unsigned long cipher_buffer_len, char* counters_buffer, char* payload_buffer, struct SCB* scb) {
  // does the same thing
  encrypt_payload(cipher_buffer, cipher_buffer_len, counters_buffer, payload_buffer, scb);
}


void generate_ccm(char* adata, unsigned long adata_len, char* payload, unsigned long payload_len, char* final_buffer, unsigned long final_buffer_len, struct SCB* scb) {

  // initializing buffer lengths
  unsigned long format_buffer_len = final_buffer_len - TAG_LEN;
  unsigned long format_buffer_blocks = format_buffer_len / BLOCK_LEN;

  unsigned long pad_payload_len = find_pad_len(payload_len);
  unsigned long pad_adata_len = find_pad_len(adata_len);

  // number of assocated_data/payload 128-bit blocks
  unsigned long num_adata_blocks = pad_adata_len / BLOCK_LEN;
  unsigned long num_payload_blocks = pad_payload_len / BLOCK_LEN;

  // generate nonce
  char* nonce = malloc(NONCE_LEN);
  int ret = getrandom(nonce, NONCE_LEN, GRND_RANDOM);
  if (ret != NONCE_LEN)
      perror("getrandom failed!");

  // allocating buffers
  char* format_buffer = malloc(format_buffer_len);  
  char* tag_buffer = malloc(TAG_LEN);
  char* counters_buffer = malloc(pad_payload_len);
  char* cipher_buffer = malloc(pad_payload_len);

  // clear format buffer before using
  clear_bytes(format_buffer, 0, format_buffer_len);

  format_blocks(nonce, adata, pad_adata_len, payload, payload_len, format_buffer); // format into 128-bit blocks

  printf("Nonce: ");
  print_bits(nonce, NONCE_LEN);

  printf("B0:    ");
  print_bits(format_buffer, 16);

  printf("B1:    ");
  print_bits(&format_buffer[16], 16);
  printf("\n\n");

  // payload_buffer loaded with format_buffer data without ctrl-info + nonce

  compute_mac(format_buffer, format_buffer_len, scb, tag_buffer); // compute tag from MAC
  generate_cntr_blks(pad_payload_len, nonce, counters_buffer); // generate counter blocks
  encrypt_payload(payload, pad_payload_len, counters_buffer, cipher_buffer, scb); // encrypt payload XOR counter blocks

  // update buffer to include ctrl-info + nonce + ciphertext + tag (MAC)
  memcpy(final_buffer, format_buffer, 16 + pad_adata_len);
  memcpy(&final_buffer[16 + pad_adata_len], cipher_buffer, pad_payload_len);
  memcpy(&final_buffer[16 + pad_adata_len + pad_payload_len], tag_buffer, TAG_LEN);

  // free memory
  free(format_buffer);
  free(tag_buffer);
  free(counters_buffer);
  free(cipher_buffer);
  free(nonce);
  
}

int send_msg(char* payload, unsigned long payload_len, char* adata, unsigned long adata_len, struct SCB* scb) {

  printf("\n-------------------------------------------------------- Starting CBC-MAC w/ Counter Implementation -------------------------------------------------------\n");

  // add 0 padding to payload
  unsigned long pad_payload_len = find_pad_len(payload_len);
  char* tmp_payload = malloc(pad_payload_len);
  memcpy(tmp_payload, payload, payload_len);
  clear_bytes(tmp_payload, payload_len, pad_payload_len);

  // add length concatenation and 0 padding to associated data
  unsigned long len_pad = 0;
  if (adata_len < 65536) {
    len_pad = 2;
  }
  else if (adata_len < 4294967296) {
    len_pad = 6;
  }
  else {
    len_pad = 10;
  }

  unsigned long pad_adata_len = find_pad_len(adata_len + len_pad);
  char* tmp_adata = malloc(pad_adata_len);
  clear_bytes(tmp_adata, 0, pad_adata_len);
  memcpy(&tmp_adata[len_pad], adata, adata_len);

  unsigned int adata_len_hl = ntohl(adata_len);
  char* adata_len_char = (char*)&adata_len_hl;
  memcpy(tmp_adata, &adata_len_char[2], len_pad); // only works for len < 4 bytes

  if (payload == NULL || adata == NULL) {
    printf("There was an issue while formatting the message... :(");
    return -1;
  }

  // ctrl-info block + associated data + payload + + TAG
  unsigned long data_len = HEADER_LEN + pad_adata_len + pad_payload_len + TAG_LEN; 
  char* data_buffer = malloc(data_len);

  generate_ccm(tmp_adata, adata_len + len_pad, tmp_payload, payload_len, data_buffer, data_len, scb); 

  printf("\n                                                                 Final CCM Message\n");

  
  print_data_blocks(data_buffer, data_len);

  send(scb->socket_fd, data_buffer, data_len, 0);

  printf("\nTotal Length: %lu bytes: [Header-Info, Assoc-Data, Payload, MAC] <--> [16 + %lu + %lu + 16]", data_len, pad_adata_len, pad_payload_len);
    

  printf("\n------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
  printf("\n");

  free(data_buffer);
  free(tmp_adata);
  free(tmp_payload);
}

unsigned long raw_to_payload(char* value) {

  unsigned long* payload_len_ptr = (unsigned long*)value;
  return (htobe64(*payload_len_ptr));

}

unsigned long raw_to_adata(char* value) {

  // update to support all three cases
  unsigned long adata_len = 0;
  unsigned short* adata_sig_ptr = (unsigned short*)value;
  unsigned short adata_sig = htons(*adata_sig_ptr);

  unsigned short len_pad;
  if (adata_sig < (USHRT_MAX - 1)) {
    adata_len = (unsigned long)adata_sig;
    len_pad = 2;
  }
  else if (adata_sig == (USHRT_MAX - 1)) {
    // second most common case
    adata_len = 69;
    len_pad = 6;
  }
  else {
    // super long message
    adata_len = 420;
    len_pad = 10;
  }

  return adata_len + len_pad;

}

bool verify_data(char* data, unsigned long data_len) {

  return false;  

}

int recv_msg(struct vbuf* adata, struct vbuf* payload, struct SCB* scb) {

  char* data_buffer = malloc(MAX_CCM_LEN);
  clear_bytes(data_buffer, 0, MAX_CCM_LEN);
  unsigned long recv_len = 0;
  unsigned long data_len = 0;

  // read ctrl-info, payload len, and adata len
  while (recv_len < 23) {
    recv_len += recv(scb->socket_fd, &data_buffer[recv_len], sizeof(data_buffer), 0);
  }

  printf("\n-------------------------------------------------------- Starting CBC-MAC w/ Counter Implementation -------------------------------------------------------\n");


  // calculate total message length from header information
  unsigned long payload_len = raw_to_payload(&data_buffer[1+NONCE_LEN]);
  unsigned long pad_payload_len = find_pad_len(payload_len);
  unsigned long adata_len = raw_to_adata(&data_buffer[16]);
  unsigned long pad_adata_len = find_pad_len(adata_len);

  data_len = HEADER_LEN + pad_adata_len + pad_payload_len + TAG_LEN;
  
  while (recv_len < data_len) {
    recv_len += recv(scb->socket_fd, &data_buffer[recv_len], sizeof(data_buffer), 0);
  }

  printf("\n                                                              Received CCM Message\n");

  print_data_blocks(data_buffer, data_len);

  char* counters_buffer = malloc(pad_payload_len);
  char* tag_buffer = malloc(TAG_LEN);

  generate_cntr_blks(pad_payload_len, &data_buffer[CTRL_INFO_LEN], counters_buffer);

  decrypt_payload(&data_buffer[HEADER_LEN+pad_adata_len], pad_payload_len, counters_buffer, &data_buffer[HEADER_LEN+pad_adata_len], scb);

  printf("\n\n");

  compute_mac(data_buffer, data_len - TAG_LEN, scb, tag_buffer);

  printf("RECV MAC  = ");
  print_bits(&data_buffer[HEADER_LEN+pad_adata_len+pad_payload_len], 16);

  if (!strncmp(&data_buffer[HEADER_LEN+pad_adata_len+pad_payload_len], tag_buffer, TAG_LEN)) {
    printf("MAC Calculation Match: authenticity and integrity verified! :D\n\n");
  }
  else {
    printf("MAC Calculation Mismatch: This message has been altered! :O\n\n");
    return -1;
  }

  // filling adata buffer
  adata->data = malloc(adata_len);
  memcpy(adata->data, &data_buffer[HEADER_LEN+2], adata_len); 
  adata->len = adata_len;

  // filling payload buffer
  payload->data = malloc(payload_len);
  memcpy(payload->data, &data_buffer[HEADER_LEN+pad_adata_len], payload_len);
  payload->len = payload_len;

  printf("ADATA: %.*s\n\n", (int)adata->len, adata->data);
  printf("PAYLOAD: %.*s", (int)payload->len, payload->data);

  printf("\n------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
  printf("\n");

  free(data_buffer);
  free(counters_buffer);
  free(tag_buffer);

}

#endif