#ifndef __TEA_H__
#define __TEA_H__

#include <iostream>

bool tea_encrypt(const uint8_t* from_buffer, const uint32_t from_length, const char* key, uint8_t* to_buffer, uint32_t* to_length);
bool tea_decrypt(const uint8_t* from_buffer, const uint32_t from_length, const char* key, uint8_t* to_buffer, uint32_t* to_length);

bool tea_encrypt(std::string from_buffer, std::string key, uint8_t* to_buffer, uint32_t* to_length);
bool tea_decrypt(std::string from_buffer, std::string key, uint8_t* to_buffer, uint32_t* to_length);

#endif 
