#pragma once
#include "logger.h"

class Patcher
{
public:
    Patcher();
    void patch();
    void patch_function();
    void patch_sentence();
    static Patcher *get_instance();
    Logger *logger_;
};
