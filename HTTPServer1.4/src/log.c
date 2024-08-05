#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "log.h"

#define DEFAULT_SYSTEM_LOG_FILE "/home/mo/ET/HTTPServer/logs/system.log"
#define DEFAULT_ACCESS_LOG_FILE "/home/mo/ET/HTTPServer/logs/access.log"

static const char *log_level_names[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
static log_level_t current_log_level = LOG_INFO;
static char system_log_file[256] = DEFAULT_SYSTEM_LOG_FILE;
static char access_log_file[256] = DEFAULT_ACCESS_LOG_FILE;

void init_log() {
    // Create logs directory if it doesn't exist
    struct stat st = {0};
    if (stat("/home/mo/ET/HTTPServer/logs", &st) == -1) {
        mkdir("/home/mo/ET/HTTPServer/logs", 0700);
    }
}

void set_log_level(const char *level) {
    if (strcmp(level, "DEBUG") == 0) {
        current_log_level = LOG_DEBUG;
    } else if (strcmp(level, "INFO") == 0) {
        current_log_level = LOG_INFO;
    } else if (strcmp(level, "WARNING") == 0) {
        current_log_level = LOG_WARNING;
    } else if (strcmp(level, "ERROR") == 0) {
        current_log_level = LOG_ERROR;
    }
}

void set_log_path(const char *path) {
    snprintf(system_log_file, sizeof(system_log_file), "%s/system.log", path);
    snprintf(access_log_file, sizeof(access_log_file), "%s/access.log", path);
}

void log_message(log_level_t level, const char *format, ...) {
    if (level < current_log_level) {
        return;
    }

    FILE *log_file = fopen(system_log_file, "a");
    if (!log_file) return;

    va_list args;
    va_start(args, format);

    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_buf[26];
    strftime(time_buf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(log_file, "[%s] %s: ", time_buf, log_level_names[level]);
    vfprintf(log_file, format, args);
    fprintf(log_file, "\n");

    va_end(args);
    fclose(log_file);
}

void log_access(const char *client_ip, const char *request, int status_code) {
    FILE *log_file = fopen(access_log_file, "a");
    if (!log_file) return;

    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_buf[26];
    strftime(time_buf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(log_file, "[%s] %s \"%s\" %d\n", time_buf, client_ip, request, status_code);

    fclose(log_file);
}

