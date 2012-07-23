#ifndef _BASE64_H_
#define _BASE64_H_

int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen);

size_t base64_decode(char *source, unsigned char *target, size_t targetlen);


#endif
