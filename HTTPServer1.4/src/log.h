#ifndef LOG_H
#define LOG_H

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} log_level_t;

void init_log();
void log_message(log_level_t level, const char *format, ...);
void log_access(const char *client_ip, const char *request, int status_code);
void set_log_level(const char *level);
void set_log_path(const char *path);

#endif // LOG_H

