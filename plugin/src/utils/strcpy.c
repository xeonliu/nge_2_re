#include "strcpy.h"

char *strcpy(char *dest, const char *src)
{
    char *ret = dest;
    while ((*dest++ = *src++) != '\0')
        ;
    return ret;
}

char *strcpyn(char *dest, const char *src, size_t n)
{
    char *ret = dest;
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++)
        dest[i] = src[i];
    if (i < n)
        dest[i] = '\0';
    return ret;
}