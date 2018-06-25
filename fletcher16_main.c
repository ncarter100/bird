/*
 * Generate fletcher16 checksums
 */
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>

#include "lib/fletcher16.h"

static unsigned short
checksum_gen(unsigned char *buf, int payload_len, int checksum_offset)
{
  // Zero checksum field
  buf[checksum_offset]= 0;
  buf[checksum_offset + 1] = 0;

  //
  // Initialise context
  struct fletcher16_context ctx;
  fletcher16_init(&ctx);

  // Process Data
  fletcher16_update(&ctx, buf, payload_len);
  // fletcher16_update_n32, don't need this, its hton convertion
  //                        packet crate does this for us
  //
  // Compute checksum value
  unsigned short checksum_be = fletcher16_final(&ctx, payload_len, checksum_offset);
  unsigned short checksum_host = ntohs(checksum_be);

  printf("Generated Checksum BE 0x%x Host 0x%x\n ", checksum_be, checksum_host);
  return checksum_host;
}

int main() {

    unsigned char buf [64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };

    unsigned short checksum_host = checksum_gen(buf, 64, 0);
    assert(checksum_host == 0x52c6);

    return 0;
}
