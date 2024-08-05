#include <stdio.h>
#include <stdlib.h>
#include "http_server.h"
#include "log.h"
#include "config.h"

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    // 初始化日志系统
    init_log();
    log_message(LOG_INFO, "Starting HTTP server");

    // 解析配置文件
    if (load_config("/home/mo/ET/HTTPServer/config/server_config.json") == -1) {
        fprintf(stderr, "Error loading configuration\n");
        log_message(LOG_ERROR, "Error loading configuration");
        return 1;
    }

    // 设置日志级别和路径
    set_log_level(get_log_level());
    set_log_path(get_log_path());

    // 启动HTTP服务器
    start_http_server();

    log_message(LOG_INFO, "HTTP server stopped");

    return 0;
}

