#include "microvisor.h"
#include "virt_i.h"
#include <avr/boot.h>
#include <avr/io.h>
#include <avr/pgmspace.h>
#include <avr/interrupt.h>
#include <string.h>
#include "bootloader_progmem.h"
#include "mem_layout.h"
//#include "hmac-sha1.h"
#include "string_boot.h"
#include "Hacl_HMAC.h"
#include "Hacl_Chacha20.h"

/* Sets some ELF metadata (not strictly required) */
#include <avr/signature.h>
#include <avr/fuse.h>
/* External crystal osc as clock, >8 MHz, minimum wake-up delay (258CK),
 * maximum additional reset delay (14CK+65ms). SPI and EESAVE enabled. Brownout
 * on 2.7V. FUSE_BOOTSZ is defined in mem_layout.h */
#define BOOTSIZE 8

/*FUSES = {
  .low = (FUSE_SUT1 & FUSE_CKSEL0),
  .high = (FUSE_SPIEN & FUSE_EESAVE & FUSE_BOOTSZ),
  .extended = (FUSE_BODLEVEL1),
};

/* Store all word addresses of valid microvisor entrypoints, terminated with
 * 0x0000 */
BOOTLOADER_PROGMEM
const uint16_t uvisor_entrypoints[] = {
    (uint16_t) &safe_icall_ijmp,
    (uint16_t) &safe_ret,
    (uint16_t) &safe_reti,
    (uint16_t) &load_image,
    (uint16_t) &micro_decrypt,
    (uint16_t) &VERIFY,
    (uint16_t) &REVIVE,
    0x0000
};

BOOTLOADER_PROGMEM static const uint8_t key_attest[] = {0x6e, 0x26, 0x88, 0x6e,
    0x4e, 0x07, 0x07, 0xe1, 0xb3, 0x0f, 0x24, 0x16, 0x0e, 0x99, 0xb9, 0x12,
    0xe4, 0x61, 0xc4, 0x24, 0xb3, 0x0f, 0x24, 0x16, 0x0e, 0x99, 0xb9, 0x12,
    0xe4, 0x61, 0xc4, 0x24};

BOOTLOADER_PROGMEM static const uint8_t key_auth[] = {0x6e, 0x26, 0x88, 0x6e,
    0x4e, 0x07, 0x07, 0xe1, 0xb3, 0x0f, 0x24, 0x16, 0x0e, 0x99, 0xb9, 0x12,
    0xe4, 0x61, 0xc4, 0x24, 0xb3, 0x0f, 0x24, 0x16, 0x0e, 0x99, 0xb9, 0x12,
    0xe4, 0x61, 0xc4, 0x24};

BOOTLOADER_PROGMEM static const uint8_t key_Oauth[] = {0x6e, 0x26, 0x88, 0x6e,
    0x4e, 0x07, 0x07, 0xe1, 0xb3, 0x0f, 0x24, 0x16, 0x0e, 0x99, 0xb9, 0x12,
    0xe4, 0x61, 0xc4, 0x24, 0xb3, 0x0f, 0x24, 0x16, 0x0e, 0x99, 0xb9, 0x12,
    0xe4, 0x61, 0xc4, 0x24};

BOOTLOADER_PROGMEM static const uint8_t fixed_nonce_ChaCha20[] = {0x16, 0x88, 
  0x26, 0x6e, 0x4e, 0x07, 0x07, 0xe1,0xb3, 0x0f, 0x24, 0xe6};

static  uint8_t MAC_true[] = {0x6e, 0x26, 0x88, 0x6e,
    0x4e, 0x07, 0x07, 0xe1, 0xb3, 0x0f, 0x24, 0x16, 0x0e, 0x99, 0xb9, 0x12,
    0xe4, 0x61, 0xc4, 0x24, 0xb3, 0x0f, 0x24, 0x16, 0x0e, 0x99, 0xb9, 0x12,
    0xe4, 0x61, 0xc4, 0x24};

 static  uint8_t counter_p[] = {0x00};
 static  uint8_t counter_T[] = {0x00};
 static  uint8_t VCN_p [] = {0x01};
/****************************************************************************/
/*                      MICROVISOR HELPER FUNCTIONS                         */
/****************************************************************************/

/* Verifies if _WORD_ address is safe to jump to for the app image to be
 * deployed */
BOOTLOADER_SECTION static uint8_t
verify_target_deploy(uint16_t target) {
  uint16_t address;
  uint16_t addr_ptr;
  uint8_t i;

  /* Everything is in upper progemem: 17th bit should be 1 for all these reads
   * */
  RAMPZ = 0x01;

  /* Get .data byte address (= end of app .text) and convert it to a word
   * address */
  address = pgm_read_word_far_no_rampz(SHADOW_META + 2);
  address >>= 1;
  if(target >= address) { /* Target is not inside app .text */
    /* Init pointer to entrypoint array in progmem */
    addr_ptr = (uint16_t) uvisor_entrypoints;
    do {
      address = pgm_read_word_far_no_rampz(addr_ptr);
      if(target == address)
        return 1; /* Success, target is entrypoint to uvisor */
      addr_ptr += 2;
    } while(address != 0x0000);

    /* Target outside of app .text + not an uvisor entrypoint */
    return 0;
  } else { /* Target is inside app .text */
    i = (uint8_t) pgm_read_word_far_no_rampz(SHADOW_META + 4);
    addr_ptr = (uint16_t) SHADOW_META + 6;
    while(i > 0) {
      address = pgm_read_word_far_no_rampz(addr_ptr);
      if(target == address)
        return 0; /* Fail, target is unsafe 2nd word */
      addr_ptr += 2;
      i--;
    }

    /* Target inside of app .text + not an unsafe 2nd word --> success */
    return 1;
  }
}

/* Writes to arbitrary page of progmem */
BOOTLOADER_SECTION static void
write_page(uint8_t *page_buf, uint32_t offset) {
  uint32_t pageptr;
  uint8_t i;

  /* Erase page */
  boot_page_erase(offset);
  boot_spm_busy_wait();

  /* Write a word (2 bytes) at a time */
  pageptr = offset;
  i = SPM_PAGESIZE/2;
  do {
	uint16_t w = *page_buf++;
	w |= (*page_buf++) << 8;
	boot_page_fill(pageptr, w);
    pageptr += 2;
  } while(i -= 1);
  boot_page_write(offset);     // Store buffer in flash page.
  boot_spm_busy_wait();        // Wait until the memory is written.

  /* Reenable RWW-section again. We need this if we want to jump back to the
   * application after bootloading. */
  boot_rww_enable();
}

/* Loads key into buff */
BOOTLOADER_SECTION static inline void
load_module(uint8_t *buff, uint8_t *module, uint8_t length) {
  uint8_t _reg;
  uint8_t *_buff = buff;
  uint8_t *_key = module;

  switch(length){

    case 12: 
              __asm__ __volatile__ (
                  "ldi %0, 0x01\n\t"
                  "out %5, %0\n\t"
                  "ldi %0, 12\n\t"
                  "1: elpm __tmp_reg__, Z+\n\t"
                  "st %a2+, __tmp_reg__\n\t"
                  "dec %0\n\t"
                  "brne 1b\n\t"
                  : "=&d" (_reg), "=z" (_key), "=e" (_buff)
                  : "1" (_key), "2" (_buff), "I" (_SFR_IO_ADDR(RAMPZ))
              );
              break;

    case 32: 

  
              __asm__ __volatile__ (
                  "ldi %0, 0x01\n\t"
                  "out %5, %0\n\t"
                  "ldi %0, 32\n\t"
                  "1: elpm __tmp_reg__, Z+\n\t"
                  "st %a2+, __tmp_reg__\n\t"
                  "dec %0\n\t"
                  "brne 1b\n\t"
                  : "=&d" (_reg), "=z" (_key), "=e" (_buff)
                  : "1" (_key), "2" (_buff), "I" (_SFR_IO_ADDR(RAMPZ))
              );
              break;

    default: break;
  }

}

/* Reads arbitrary page from progmem */
BOOTLOADER_SECTION static inline void
read_page(uint8_t *page_buf, uint32_t offset) {
  uint8_t _reg = (uint8_t) (offset >> 16);
  uint16_t _off = (uint16_t) offset;
  __asm__ __volatile__ (
      "out %6, %0\n\t"
      "clr %0\n\t"
      "1: elpm __tmp_reg__, Z+\n\t"
      "st %a2+, __tmp_reg__\n\t"
      "inc %0\n\t"
      "brne 1b\n\t"
      : "=r" (_reg), "=z" (_off), "=e" (page_buf)
      : "0" (_reg), "1" (_off), "2" (page_buf), "I" (_SFR_IO_ADDR(RAMPZ))
  );
}

/* Activates image by transfering image from deploy to running app space */
BOOTLOADER_SECTION static inline void
switch_image() {
  uint16_t pages;
  uint16_t i;
  uint8_t buf[PAGE_SIZE];

  /* Calculate amount of pages to copy */
  RAMPZ = 0x01;
  pages = pgm_read_word_far_no_rampz(SHADOW_META);
  pages = pages/PAGE_SIZE + (pages%PAGE_SIZE > 0);

  for(i=0; i<pages; i++) {
    read_page(buf, ((uint32_t) SHADOW) + PAGE_SIZE*i);
    write_page(buf, PAGE_SIZE*i);
  }

  /* Copy metadata page */
  read_page(buf, SHADOW_META);
  write_page(buf, APP_META);

  /* After switching delete any data in shadow */
  erase(SHADOW, SHADOW_META, 0, buf);


}

BOOTLOADER_SECTION static inline uint8_t
verify_shadow() {
  uint16_t current_word;
  uint16_t current_addr; //In WORDS, not bytes
  uint16_t pointer;
  uint8_t pointer_rampz;
  uint16_t text_size; //In WORDS, not bytes
  uint8_t prev_op_long;

  /* Init text_size variable */
  RAMPZ = 0x01;
  text_size = pgm_read_word_far_no_rampz(SHADOW_META + 2);
  text_size >>= 1;

  /* Loop over instructions word by word */
  pointer_rampz = 0x00;
  pointer = SHADOW;
  current_addr = 0x0000;
  prev_op_long = 0;
  while(current_addr < text_size) {
    /* Fetch next word */
    RAMPZ = pointer_rampz;
    current_word = pgm_read_word_far_no_rampz(pointer);

    /* Check target address of previous long op is correct */
    if(prev_op_long && !verify_target_deploy(current_word))
      return 0;

    /* Parse word as instruction and check if it is allowed. If this word is a
     * long call address (prev_op_long == 1), check if absent from list (i.e.
     * verify_target says we CAN jump to it) before rejecting */
    if((current_word == 0x940C) || (current_word == 0x940E)) {
      /* ---LONG INSTRUCTIONS WITH TARGET AS 2ND WORD--- */
      /* If target addr of long call gets decoded as long call and is not on
       * list, reject */
      if(prev_op_long && verify_target_deploy(current_addr))
        return 0;
      /* Set prev_op_long flag correctly: 1 in the normal case, and 0 if this
       * is the address of a long call. */
      prev_op_long = !prev_op_long;
    } else {
      /* ---NORMAL INSTRUCTIONS--- */

      /* Ops which need a relative address calculated set this flag. Signed
       * offset is stored in current_word */
      uint8_t calc_rel = 0;
      if((current_word == 0x9508)
          || (current_word == 0x9518)
          || (current_word == 0x9409)
          || (current_word == 0x9509)
          || (current_word == 0x95D8)
          || (current_word & 0xFE0F) == 0x9006
          || (current_word & 0xFE0F) == 0x9007) {
        /* PLAIN UNSAFE OPS: RET, RETI, IJMP, ICALL, ELPM, ELPM RD,Z(+) */
        /* In normal situation, reject. As target address of long call, reject
         * if not on list. */
        if( !prev_op_long || (prev_op_long && verify_target_deploy(current_addr)) )
          return 0;
      } else if((current_word & 0xFC00) == 0xF000
          || (current_word & 0xFC00) == 0xF400) {
        /* BRANCH OPS: extract offset and make signed 16 bit int */
        current_word &= 0x03F8;
        current_word >>= 3;
        if(current_word > 0x3F)
          current_word |= 0xFF80;
        calc_rel = 1;
      } else if((current_word & 0xF000) == 0xC000
          || (current_word & 0xF000) == 0xD000) {
        /* RJMP OR RCALL: extract offset and make signed 16 bit int */
        current_word &= 0x0FFF;
        if(current_word > 0x07FF)
          current_word |= 0xF000;
        calc_rel = 1;
      }

      /* Calculate target and check it */
      if(calc_rel) {
        current_word = current_addr + ((int16_t) current_word) + 1;
        if(!verify_target_deploy(current_word)) {
          /* In normal situation, reject. As target address of long call,
           * reject if not on list. */
          if( !prev_op_long || (prev_op_long && verify_target_deploy(current_addr)) )
            return 0;
        }
      }

      /* Set prev_op_long flag accordingly */
      prev_op_long = 0;
    }

    /* Increment loop variables */
    current_addr++;
    if((pointer += 2) == 0x0000)
      pointer_rampz = 0x01;
  }

  return 1;
}

BOOTLOADER_SECTION static inline uint8_t
verify_hmac(uint8_t *mac) {
  uint16_t image_size; //in BYTES
  uint8_t meta_size = 3; //in BYTES, without digest
  uint8_t digest[32]; //HMAC_SHA2_BYTES

  uint32_t offset = SHADOW;
  uint8_t buff[SPM_PAGESIZE];

  /* Init image_size variable */
  RAMPZ = 0x01;
  image_size = pgm_read_word_far_no_rampz(SHADOW_META);
  meta_size += (uint8_t) pgm_read_word_far_no_rampz(SHADOW_META + 4);
  meta_size <<= 1; //Convert words to bytes


  /* Hash full app pages first  and then the remaing + metadata*/
  compute_HMAC(buff, offset, image_size, 2);

  memcpy_boot(digest, buff+image_size+meta_size, 32); //Backup digest from metadata page

  /* Finalize + compare */
  if(memcmp_boot(buff, digest, 32) != 0)
    return 0;

  memcpy_boot(mac, digest, 32);
  return 1;
}

BOOTLOADER_SECTION void clear_temp(uint8_t *buf, uint8_t length) {
  uint16_t i;
  for(i=0; i<length; i++)
    buf[i]=0xFF;
}

BOOTLOADER_SECTION void micro_decrypt(uint8_t *data, uint32_t length){

  uint8_t sreg;
  sreg = SREG;
  cli();

  uint8_t nonce_buff[12];
  uint8_t key_buff[32];
  load_module(nonce_buff, fixed_nonce_ChaCha20, 12);
  load_module(key_buff, key_attest, 32);

  // parameters: Length of data, Source, Destination, Secret key, nonce, CTR
  Hacl_Chacha20_chacha20_decrypt(length, data, data,key_buff,nonce_buff,0);

  /* clear temp variables */
  clear_temp(nonce_buff, 12);
  clear_temp(key_buff, 32);

  SREG = sreg;
  sei();
}


/****************************************************************************/
/*                        MICROVISOR CORE FUNCTIONS                         */
/****************************************************************************/

/* ALWAYS first disable global interrupts as first order of business in these
 * fucntions. Failing to do so could have untrusted interrupt handlers modify
 * the state and outcome of any of these trusted functions. */

/* Writes page contained in page_buf (256 bytes) to offset in deployment space
 * (0xFE00-0x1FC00) */

BOOTLOADER_SECTION void
load_image(uint8_t *page_buf, uint16_t offset) {
  uint8_t sreg;
  sreg = SREG;
  cli();

  /* Write page if it is within the allowable space */
  if(offset<SHADOW)
    write_page(page_buf, ((uint32_t) SHADOW) + offset);

  SREG = sreg;
  sei();
}

/* Verifies and activates an image from deployment app space to running app space.
 * When successful, this function will not return but perform a soft reset. In
 * case of failure, 0 (false) is returned */

BOOTLOADER_SECTION uint8_t
verify_activate_image(uint8_t *mac) {
  //uint8_t sreg;
  //sreg = SREG;
  //cli();

  if(!verify_shadow() || !verify_hmac(mac)){
    return 0;
  }

  /* We passed all tests, activate new image and jump to it */
  switch_image();
  
  //SREG = sreg;
  return 1;
}

/* 
  classical remote attestation with no privacy considered
  If uncommented, please add the function header to microvisor.h. For optimised space,
  it is better to comment VERIFY function.  
*/

/*
BOOTLOADER_SECTION void
remote_attest(uint8_t *mac) {
  uint8_t sreg;
  sreg = SREG;
  cli();

  uint8_t buff[SPM_PAGESIZE];
  uint8_t key_buff[32];
  uint32_t offset;
  uint8_t key_len = 32;

  //Init hmac context with key (load 32 byte key temporary in buff) 
  load_module(key_buff, key_attest, key_len);

  // Taken from Hacl_HMAC.c 
  
  uint32_t l = (uint32_t)64U;
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t key_block[l];
  memset(key_block, 0U, l * sizeof (uint8_t));
  uint32_t i0;
  if (key_len <= (uint32_t)64U)
  {
    i0 = key_len;
  }
  else
  {
    i0 = (uint32_t)32U;
  }
  uint8_t *nkey = key_block;
  if (key_len <= (uint32_t)64U)
  {
    memcpy(nkey, key_buff, key_len * sizeof (uint8_t));
  }
  else
  {
    Hacl_Hash_SHA2_hash_256(key_buff, key_len, nkey);
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t ipad[l];
  memset(ipad, (uint8_t)0x36U, l * sizeof (uint8_t));
  for (uint32_t i = (uint32_t)0U; i < l; i++)
  {
    uint8_t xi = ipad[i];
    uint8_t yi = key_block[i];
    ipad[i] = xi ^ yi;
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t opad[l];
  memset(opad, (uint8_t)0x5cU, l * sizeof (uint8_t));
  for (uint32_t i = (uint32_t)0U; i < l; i++)
  {
    uint8_t xi = opad[i];
    uint8_t yi = key_block[i];
    opad[i] = xi ^ yi;
  }
  uint32_t
  s[8U] =
    {
      (uint32_t)0x6a09e667U, (uint32_t)0xbb67ae85U, (uint32_t)0x3c6ef372U, (uint32_t)0xa54ff53aU,
      (uint32_t)0x510e527fU, (uint32_t)0x9b05688cU, (uint32_t)0x1f83d9abU, (uint32_t)0x5be0cd19U
    };

  Hacl_Hash_Core_SHA2_init_256(s);
  Hacl_Hash_SHA2_update_multi_256(s, ipad, (uint32_t)1U);



  // Hash full image. This part is added to the Hacl part
  offset = 0x00;
  while(offset < MEM_FIXED) {
    read_page(buff, offset);
    // loop to HASH
    Hacl_Hash_SHA2_update_multi_256(s, buff,(uint32_t)4U);

    // Increment counter 
    offset += SPM_PAGESIZE;

  }
  // Hash nonce
 Hacl_Hash_SHA2_update_last_256(s, (uint64_t)(uint32_t)64U, mac, key_len);


  // Finalize
  uint8_t *dst1 = ipad;
  Hacl_Hash_Core_SHA2_finish_256(s, dst1);
  uint8_t *hash1 = ipad;
  Hacl_Hash_Core_SHA2_init_256(s);
  Hacl_Hash_SHA2_update_multi_256(s, opad, (uint32_t)1U);
  Hacl_Hash_SHA2_update_last_256(s, (uint64_t)(uint32_t)64U, hash1, (uint32_t)32U);
  Hacl_Hash_Core_SHA2_finish_256(s, mac);

  SREG = sreg;
  sei();
} */

BOOTLOADER_SECTION void
compute_HMAC(uint8_t *mac, uint32_t offset, uint16_t size, uint8_t type){

  uint8_t buff[SPM_PAGESIZE];
  uint8_t key_buff[32];
  uint8_t key_len = 32;

  /* Init hmac context with key (load 32 byte key temporary in buff) */
  load_module(key_buff, key_attest, key_len);

  /* Taken from Hacl_HMAC.c */
  
  uint32_t l = (uint32_t)64U;
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t key_block[l];
  memset(key_block, 0U, l * sizeof (uint8_t));
  uint32_t i0;
  if (key_len <= (uint32_t)64U)
  {
    i0 = key_len;
  }
  else
  {
    i0 = (uint32_t)32U;
  }
  uint8_t *nkey = key_block;
  if (key_len <= (uint32_t)64U)
  {
    memcpy(nkey, key_buff, key_len * sizeof (uint8_t));
  }
  else
  {
    Hacl_Hash_SHA2_hash_256(key_buff, key_len, nkey);
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t ipad[l];
  memset(ipad, (uint8_t)0x36U, l * sizeof (uint8_t));
  for (uint32_t i = (uint32_t)0U; i < l; i++)
  {
    uint8_t xi = ipad[i];
    uint8_t yi = key_block[i];
    ipad[i] = xi ^ yi;
  }
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  uint8_t opad[l];
  memset(opad, (uint8_t)0x5cU, l * sizeof (uint8_t));
  for (uint32_t i = (uint32_t)0U; i < l; i++)
  {
    uint8_t xi = opad[i];
    uint8_t yi = key_block[i];
    opad[i] = xi ^ yi;
  }
  uint32_t
  s[8U] =
    {
      (uint32_t)0x6a09e667U, (uint32_t)0xbb67ae85U, (uint32_t)0x3c6ef372U, (uint32_t)0xa54ff53aU,
      (uint32_t)0x510e527fU, (uint32_t)0x9b05688cU, (uint32_t)0x1f83d9abU, (uint32_t)0x5be0cd19U
    };

  Hacl_Hash_Core_SHA2_init_256(s);
  Hacl_Hash_SHA2_update_multi_256(s, ipad, (uint32_t)1U);

  /* This part is added to the Hacl part */

  switch(type){

    // For remote attestation purposes (VERIFY)
    case 1:

              /*** Hash full image ****/
              while(offset < size) {
                read_page(buff, offset);
                /* loop to HASH */
                Hacl_Hash_SHA2_update_multi_256(s, buff,(uint32_t)4U);

                /* Increment counter */
                offset += SPM_PAGESIZE;
              }
              /* Hash nonce if using the non-private version of VERIFY */
             //Hacl_Hash_SHA2_update_last_256(s, (uint64_t)(uint32_t)64U, mac, key_len);
             break;

    // For HMAC verification of received image
    case 2:

              /* Hash full app pages first */
              while(size >= SPM_PAGESIZE) {
                read_page(buff, offset);
                /* loop to HASH */
                Hacl_Hash_SHA2_update_multi_256(s, buff,(uint32_t)4U);

                /* Increment counter */
                size -= SPM_PAGESIZE;
                offset += SPM_PAGESIZE;
              }
              /* Hash last (semi)page + metadata */
              read_page(buff, offset);
              read_page(buff + size, SHADOW_META);
              Hacl_Hash_SHA2_update_last_256(s, (uint64_t)(uint32_t)64U, buff, size + 3); //meta_size
             break;

    default: break;

  }

  /* Finalize */
  uint8_t *dst1 = ipad;
  Hacl_Hash_Core_SHA2_finish_256(s, dst1);
  uint8_t *hash1 = ipad;
  Hacl_Hash_Core_SHA2_init_256(s);
  Hacl_Hash_SHA2_update_multi_256(s, opad, (uint32_t)1U);
  Hacl_Hash_SHA2_update_last_256(s, (uint64_t)(uint32_t)64U, hash1, (uint32_t)32U);
  Hacl_Hash_Core_SHA2_finish_256(s, mac);

  clear_temp(buff, SPM_PAGESIZE);
  clear_temp(key_buff, key_len);

}

/* Remote attestation */
BOOTLOADER_SECTION void
VERIFY(uint8_t *mac) {
  uint8_t sreg;
  sreg = SREG;
  cli();

  uint8_t key_buff[32];
  uint8_t result_buff[32];
  uint8_t Cp[1];
  uint8_t Ct[1];
  uint8_t Cv = mac[0];
  /* Load VCN_p to compare; Load secret key; Load C_T */
  load_module(Cp, counter_p, 1);
  load_module(key_buff, key_auth, 32);
  load_module(Ct, counter_T, 1);

  /* check authenticity */
  Hacl_HMAC_compute_sha2_256(result_buff, key_buff, 32, mac+1, 32);

  if (Cv > Cp && memcmp_boot(result_buff, mac+33, 32) == 0){
      compute_HMAC(mac+33, 0, MEM_FIXED, 1);

      /* Load MAC_true */
      load_module(result_buff, MAC_true, 32);
      if (memcmp_boot(result_buff, mac+33, 32) == 0){

            /* send an attestation report that indicates healthy state;*/
            uint8_t attest_rep[35];
            attest_rep[0] = 1;
            attest_rep[1] = Ct[0];
            attest_rep[2] = Cp[0];
            for(uint16_t i =3; i < 35; i++)
            attest_rep[i] = mac[i-2];

            Hacl_HMAC_compute_sha2_256(mac+2, key_buff, 32, attest_rep, 35);
            mac[0] = 1;
            mac[1] = Ct[0];

            /* update Cp */
            uint8_t buff[SPM_PAGESIZE];
            read_page(buff, &counter_p);
            buff[0] = Cv;
            write_page(buff, &counter_p);

      }else{
            /* send an attestation report that indicates failure; Malware! */
            uint8_t attest_rep[34];
            attest_rep[0] = 0;
            attest_rep[1] = Cp[0];
            for(uint16_t i =2; i < 34; i++)
            attest_rep[i] = mac[i-1];

            /* move nonce to avoid wasting it; it is needed for POE */
            for(uint16_t i =1; i < 33; i++)
              mac[i+32] = mac[i];

            Hacl_HMAC_compute_sha2_256(mac+1, key_buff, 32, attest_rep, 34);
            mac[0] = 0;

            /* Erase unprotected memory and send proof of secure erasure */
            erase(0x00, MEM_FIXED, 1, mac);
      }

  } else{
    /* send an attestation report that indicates failure; No authenticity */
    uint8_t attest_rep[34];
    attest_rep[0] = 0;
    attest_rep[1] = Cp[0];
    for(uint16_t i =2; i < 34; i++)
      attest_rep[i] = mac[i-1];

    Hacl_HMAC_compute_sha2_256(mac+1, key_buff, 32, attest_rep, 34);
    mac[0] = 2; //We wrote 2 just to distniguish it and show that it is related to authenticity.

  }

  /* clear temp buffs */
  clear_temp(key_buff, 32);
  clear_temp(result_buff, 32);
  clear_temp(Cp, 1);
  clear_temp(Ct, 1);

  SREG = sreg;
  sei();
}

/* Secure code Update or recovery */
BOOTLOADER_SECTION void
REVIVE(uint8_t *mac, uint16_t total_size) {
  uint8_t sreg;
  sreg = SREG;
  cli();

  uint8_t vcn_p[1];
  uint8_t buff[SPM_PAGESIZE];
  uint8_t key_buff[32];

  /* Load VCN_p to compare */
  load_module(vcn_p, VCN_p, 1);

  /* Load K_Oauth to verify HMAC */
  load_module(key_buff, key_Oauth, 32);

  Hacl_HMAC_compute_sha2_256(buff, key_buff, 32, vcn_p, 1);

    if(mac[0] >= vcn_p && memcmp_boot(buff, mac+1, 32) == 0){

      // Verify and activate if secure and correct
      uint8_t secure = verify_activate_image(mac);
      if (!secure){
          erase(SHADOW, SHADOW+total_size, 0, mac);
      }else{
        /* update VCN_P and MAC_true */ /* Do not forget that update is per page, not per byte or word */
        read_page(buff, &VCN_p);
        buff[0] += 1;
        write_page(buff, &VCN_p);

        read_page(buff, &MAC_true);
        for(uint16_t i =0; i<32; i++)
          buff[i] = mac[i];
        write_page(buff, &MAC_true);

        /* send proof of secure update */
        load_module(buff, VCN_p, 1);
        load_module(buff+1, MAC_true, 32);

        Hacl_HMAC_compute_sha2_256(mac, key_buff, 32, buff, 33);

      }

    } else{
      erase(SHADOW, SHADOW+total_size, 0, mac);

    }

  clear_temp(key_buff, 32);
  clear_temp(buff, SPM_PAGESIZE);

  SREG = sreg;
  sei();
  goto *(0x0000);
}

/* Secure Erasure */
BOOTLOADER_SECTION void
erase(uint16_t start_address, uint16_t end_address, uint8_t isCompromised, uint8_t *POE) {
  uint8_t sreg;
  sreg = SREG;

  if(isCompromised){

    while(start_address < end_address){

      /* Erase page */
      boot_page_erase(start_address);
      boot_spm_busy_wait();

      start_address += PAGE_SIZE;

      /* Create POE */

      uint8_t key_buff[32];
      load_module(key_buff, key_auth, 32);

      uint8_t buff[SPM_PAGESIZE];
      load_module(buff, counter_p, 1);

      for(uint16_t i =1; i < 33; i++){
        buff[i] = POE[i+32];
        buff[i+32] = POE[i];
      }


      Hacl_HMAC_compute_sha2_256(POE+33, key_buff, 32, buff, 65);

      clear_temp(key_buff, 32);
      clear_temp(buff, SPM_PAGESIZE);

    }

  }else{

    while(start_address < end_address){

      /* Erase page */
      boot_page_erase(start_address);
      boot_spm_busy_wait();

      start_address += PAGE_SIZE;
    }

      /* Erase meta-data */
      boot_page_erase(SHADOW_META);
      boot_spm_busy_wait();
  }

  SREG = sreg;
  sei();

}

