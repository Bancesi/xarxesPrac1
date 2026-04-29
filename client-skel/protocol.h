#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

//Enum to reference the state
typedef enum {              //hexadecimal expression
    OP_REGISTER = 1,        //0x01,
    OP_AUTH     = 2,        //0x02,
    OP_TRAFFIC  = 3,        //0x03,
    OP_KEEPALIVE = 4,       //0x04,
    OP_ACK      = 5,        //0x05,
    OP_REJECT   = 6,        //0x06
} pixes_opcode_t;

//Pixes structure
struct pixes_header {
    uint8_t  opcode;        // 1 byte
    uint16_t cid;           // 2 bytes
    uint8_t  payload[8];    // 8 bytes
} __attribute__((packed)); 

#endif