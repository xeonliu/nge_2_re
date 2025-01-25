#include <stdio.h>
#include <stdarg.h>
#include <pspiofilemgr.h>

#include "log.h"
#define LOG_FILE "ms0:/PSP/load_log.txt"

size_t strlen(const char *str)
{
    const char *s = str;
    while (*s)
        s++;
    return s - str;
}

void *_exit = 0;

void dbg_log(const char *format, ...)
{
    SceUID f = sceIoOpen(LOG_FILE, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_APPEND, 0777);
    if (f >= 0)
    {
        va_list args;
        va_start(args, format);

        char buffer[256];
        vsnprintf(buffer, sizeof(buffer), format, args);
        sceIoWrite(f, buffer, strlen(buffer));

        va_end(args);
        sceIoClose(f);
    }
}