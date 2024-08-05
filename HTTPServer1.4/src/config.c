#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include "config.h"

static server_config_t config;

int load_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("malloc");
        fclose(file);
        return -1;
    }

    if (fread(buffer, file_size, 1, file) != 1) {
        perror("fread");
        free(buffer);
        fclose(file);
        return -1;
    }
    fclose(file);
    buffer[file_size] = '\0';

    struct json_object *parsed_json = json_tokener_parse(buffer);
    if (!parsed_json) {
        fprintf(stderr, "Error parsing JSON configuration\n");
        free(buffer);
        return -1;
    }

    struct json_object *address;
    struct json_object *port;
    struct json_object *log_level;
    struct json_object *log_path;

    json_object_object_get_ex(parsed_json, "address", &address);
    json_object_object_get_ex(parsed_json, "port", &port);
    json_object_object_get_ex(parsed_json, "log_level", &log_level);
    json_object_object_get_ex(parsed_json, "log_path", &log_path);

    strcpy(config.address, json_object_get_string(address));
    strcpy(config.port, json_object_get_string(port));
    strcpy(config.log_level, json_object_get_string(log_level));
    strcpy(config.log_path, json_object_get_string(log_path));

    json_object_put(parsed_json);
    free(buffer);

    return 0;
}

const char* get_server_address() {
    return config.address;
}

const char* get_server_port() {
    return config.port;
}

const char* get_log_level() {
    return config.log_level;
}

const char* get_log_path() {
    return config.log_path;
}

