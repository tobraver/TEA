#ifndef __TEA_H__
#define __TEA_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool tea_encrypt(const uint8_t* from_buffer, const uint32_t from_length, const char* key, uint8_t* to_buffer, uint32_t* to_length);
bool tea_decrypt(const uint8_t* from_buffer, const uint32_t from_length, const char* key, uint8_t* to_buffer, uint32_t* to_length);

#ifdef __cplusplus
}
#endif


#endif 
