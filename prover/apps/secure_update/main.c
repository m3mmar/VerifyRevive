#include <avr/pgmspace.h>
#include <avr/io.h>

#define BAUD 57600
#include <util/setbaud.h>

#include "microvisor.h"
#include "Hacl_Chacha20.h"

void uart_init(void) {
  UBRR1H = UBRRH_VALUE;
  UBRR1L = UBRRL_VALUE;
#if USE_2X
  UCSR1A |= _BV(U2X1);
#else
  UCSR1A &= ~(_BV(U2X1));
#endif
  UCSR1C = _BV(UCSZ11) | _BV(UCSZ10);
  UCSR1B = _BV(TXEN1) | _BV(RXEN1);
}

char uart_getchar() {
  char c;
  loop_until_bit_is_set(UCSR1A, RXC1);
  c = UDR1;
  return c;
}

void uart_putchar(char c) {
  if (c == '\n') {
    uart_putchar('\r');
  }
  loop_until_bit_is_set(UCSR1A, UDRE1);
  UDR1 = c;
}

void uart_puts(char *c) {
  while(*c) {
    uart_putchar(*c++);
  }
}

void clear_buf(uint8_t *buf) {
  uint16_t i;
  for(i=0; i<PAGE_SIZE; i++)
    buf[i]=0xFF;
}

int main(void) {
  uint8_t buffer[PAGE_SIZE];
  uint16_t i;
  uint16_t j;

  uint16_t total_size;
  uint16_t nr_2ndwords;

  uart_init();

  /* MOSI and MISO pin */
  DDRB |= ( _BV(PB5) | _BV(PB6) );

  while(1) {
    // No memset support!
    clear_buf(buffer);

    // Total size (Arrives little endian, NOT network order!)
    buffer[0] = uart_getchar();
    buffer[1] = uart_getchar();
    total_size = buffer[1]<<8 | buffer[0];

    // Data start
    buffer[2] = uart_getchar();
    buffer[3] = uart_getchar();

    // Nr 2nd words (Arrives little endian, NOT network order!)
    buffer[4] = uart_getchar();
    buffer[5] = uart_getchar();
    nr_2ndwords = buffer[5]<<8 | buffer[4];

    // Unsafe 2nd words
    for(i=0; i<nr_2ndwords; i++) {
      buffer[6+i*2] = uart_getchar();
      buffer[7+i*2] = uart_getchar();
    }

    // HMAC digest (32 bytes)
    for(i=0; i<32; i++) {
      buffer[6+nr_2ndwords*2+i] = uart_getchar();
    }

    // Decrypt such data before writing it to Flash (no worries if tampering happened; it will be detected soon!)
    micro_decrypt(buffer,nr_2ndwords*2+38);

    // Write to flash + ready to receive more
    load_image(buffer, METADATA_OFFSET);
    uart_putchar('o');

    // Round down total_size/PAGE_SIZE to get amount of full pages to write
    for(j=0; j < total_size/PAGE_SIZE; j++) {
      for(i=0; i<PAGE_SIZE; i++) {
        buffer[i] = uart_getchar();
      }
      // decrypt each image before writing it to Flash 
      micro_decrypt(buffer, PAGE_SIZE);
      load_image(buffer, PAGE_SIZE*j);
      uart_putchar('o');
    }

    // Receive last (incomplete) page
    if(total_size%PAGE_SIZE) {
      // No memset support!
      clear_buf(buffer);
      // Write possible last incomplete page..
      for(i=0; i<(total_size%PAGE_SIZE); i++) {
        buffer[i] = uart_getchar();
      }

      // decrypt remaining data before writing it to Flash 
      micro_decrypt(buffer, total_size%PAGE_SIZE);
      load_image(buffer, PAGE_SIZE*j);
      uart_putchar('o');
    }

    clear_buf(buffer);
    /* receive VCN_O + HMAC */
    for(i=0; i<33; i++) {
        buffer[i] = uart_getchar();
      }

    // Everything received, done
    uart_putchar('d');

    // send proof of secure update
    REVIVE(buffer, total_size);

        for(i=0; i<32; i++) {
        uart_putchar(buffer[i]);
      }
  }
}
