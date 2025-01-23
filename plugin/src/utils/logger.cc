#include <pspiofilemgr.h>
#include "logger.h"

const char Logger::LOG_FILE[] = "ms0:/PSP/load_log.txt";

static int strlen(const char *str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

Logger* Logger::get_instance() {
    static Logger instance;
    return &instance;
}

void Logger::log(const char *message) {
    SceUID f = sceIoOpen(LOG_FILE, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_APPEND, 0777);
    if (f >= 0) {
        sceIoWrite(f, &line_number, sizeof(line_number));
        sceIoWrite(f, message, strlen(message));
        line_number++;
    }
    sceIoClose(f);
}