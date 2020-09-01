#include <avr/io.h>

#define BAUD 57600
#include <util/setbaud.h>

#include "microvisor.h"

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

int main(void) {
  uint8_t buf[128];
  uint16_t i;

  uart_init();

  /* MOSI and MISO pin */
  DDRB |= ( _BV(PB5) | _BV(PB6) );

  while(1) {
    // Receive CV + nonce + H
    for(i=0; i<65; i++) {
      buf[i] = uart_getchar();
    }
    uart_putchar('o');

    // Do remote attest
    VERIFY(buf);

    // send attestation report and POE if exist! 
    if (buf[0] == 1){
      for(i=0; i<34; i++){
        uart_putchar(buf[i]);
      }
    }else{
      for(i=0; i<33; i++) {
      uart_putchar(buf[i]);
      }
      if (buf[0] == 0){
        // send POE
        for(i=0; i<32; i++) {
        uart_putchar(buf[i+33]);
      }
      }
    }
    
  }
}
