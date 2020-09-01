#ifndef MICROVISOR_H
#define MICROVISOR_H
#include <stdint.h>
#include "mem_layout.h"

#define METADATA_OFFSET APP_META
#define PAGE_SIZE 256

void load_image(uint8_t *page_buf, uint16_t offset);
void micro_decrypt(uint8_t *data, uint32_t length);
void VERIFY(uint8_t *mac);
void REVIVE(uint8_t *mac, uint16_t total_size);

#endif
