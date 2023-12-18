# CCM-Implementation-In-C
Counter Mode with CBC-MAC (CCM) Implementation in C

The project discussed in this paper is the implementation of the CCM algorithm in C.
Particularly replicating the steps of sending a message modified by CCM and receiving it via two
mock applications: consumer.c and producer.c. This is possible by including the module ccm.c
during the compilation of both applications. The CCM module is responsible for providing
methods to construct and send the CCM messages as well as to receive and deconstruct those
messages. Each of the applications designed for this project are executed on a Linux platform
and send packets using the TCP protocol. It should be noted that there are a few key differences
in this implementation compared to the exact CCM algorithm. These differences are:

1. Block cipher plugins: The block cipher encryption algorithm used by the CCM module is
provided by a function pointer which can be any valid 128-bit block cipher.
2. 128-bit MAC length: CCM specifies that this length can vary, but for simplifying the
implementation, a fixed length of an entire block was used.
3. Nonce requirement: The Nonce is always included in the CCM structure at a fixed length
of 7 bytes.
4. Associated Data requirement: The AD is always included, and the length cannot exceed
62580 bytes
5. 8-byte payload length: This limits the size of the payload to 2^64

Another note should recognize that the only block cipher tested was a simple flip cipher which
inverts the bits for a provided block. In theory, a more standardized and secure method could be
used such as AES, but this was not tested due to time limitations. 
