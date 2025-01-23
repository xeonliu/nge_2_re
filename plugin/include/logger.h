#pragma once

class Logger
{
public:
    Logger() : line_number(0) {}
    void log(const char *message);
    static Logger *get_instance();

private:
    static const char LOG_FILE[];
    int line_number;
};