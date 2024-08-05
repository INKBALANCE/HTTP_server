#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
    char address[64];
    char port[16];
    char log_level[16];
    char log_path[256];
} server_config_t;

int load_config(const char *filename);
const char* get_server_address();
const char* get_server_port();
const char* get_log_level();
const char* get_log_path();

#endif // CONFIG_H

