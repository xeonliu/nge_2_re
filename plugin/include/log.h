#pragma once

#include <stdio.h>
#include <psprtc.h>
#include <pspdebug.h>

#define LOG_FILENAME "ms0:/PSP/log.txt"

#define LOG(format, ...)                                                                               \
    {                                                                                                  \
        ScePspDateTime time;                                                                           \
        sceRtcGetCurrentClockLocalTime(&time);                                                         \
        FILE *_flog = fopen(LOG_FILENAME, "a");                                                        \
        fprintf(_flog, "[%04d-%02d-%02d %02d:%02d:%02d.%03d]" format, time.year, time.month, time.day, \
                time.hour, time.minute, time.second, time.microsecond / 1000, ##__VA_ARGS__);       \
        fprintf(_flog, "\n");                                                                          \
        fclose(_flog);                                                                                 \
        pspDebugScreenPrintf("[%02d:%02d.%03d]" format "\n",                                           \
                             time.minute, time.second, time.microsecond / 1000, ##__VA_ARGS__);     \
    }