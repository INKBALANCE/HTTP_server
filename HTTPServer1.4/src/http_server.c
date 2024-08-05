#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "http_server.h"
#include "log.h"
#include "config.h"
#include "auth.h"
#include "log.h"

#define MAX_EVENTS 64
#define AUTH_REALM "Restricted Area"

static const char *root = "/home/mo/ET/HTTPServer/www"; // 文档根目录路径

typedef struct {
    int code;
    const char *reason;
} http_status;

const http_status http_statuses[] = {
    {200, "OK"},
    {400, "Bad Request"},
    {401, "Unauthorized"},
    {403, "Forbidden"},
    {404, "Not Found"},
    {500, "Internal Server Error"},
};

User registered_user; // 全局变量存储注册的用户信息

void handle_connection(int fd);
void send_response(int fd, const char *header, const char *content_type, const char *body, size_t content_length);
void send_error_response(int fd, int status_code);
const char *get_mime_type(const char *path);
void url_decode(char *dst, const char *src);
int is_authorized(const char *auth_header);
int base64_decode(const char *input, char *output);
void handle_register_request(const char *username, const char *password);
int handle_login_request(const char *username, const char *password);
void send_unauthorized_response(int client_socket);
char* get_post_data(const char *key, const char *buffer);
void send_redirect_response(int client_socket, const char *location);

void start_http_server() {
    struct epoll_event event;
    struct epoll_event *events;

    int sfd = create_and_bind(get_server_port());
    if (sfd == -1) {
        log_message(LOG_ERROR, "Could not create and bind socket");
        return;
    }

    int s = make_socket_non_blocking(sfd);
    if (s == -1) {
        log_message(LOG_ERROR, "Could not make socket non-blocking");
        return;
    }

    s = listen(sfd, SOMAXCONN);
    if (s == -1) {
        perror("listen");
        log_message(LOG_ERROR, "Error on listen");
        return;
    }

    int efd = epoll_create1(0);
    if (efd == -1) {
        perror("epoll_create");
        log_message(LOG_ERROR, "Error on epoll_create");
        return;
    }

    event.data.fd = sfd;
    event.events = EPOLLIN | EPOLLET;
    s = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
    if (s == -1) {
        perror("epoll_ctl");
        log_message(LOG_ERROR, "Error on epoll_ctl");
        return;
    }

    events = calloc(MAX_EVENTS, sizeof(event));
    if (!events) {
        log_message(LOG_ERROR, "Could not allocate memory for events");
        return;
    }

    log_message(LOG_INFO, "HTTP server started");

    while (1) {
        int n = epoll_wait(efd, events, MAX_EVENTS, -1);
        if (n == -1) {
            perror("epoll_wait");
            log_message(LOG_ERROR, "Error on epoll_wait");
            free(events);
            close(sfd);
            return;
        }

        for (int i = 0; i < n; i++) {
            if ((events[i].events & EPOLLERR) ||
                (events[i].events & EPOLLHUP) ||
                (!(events[i].events & EPOLLIN))) {
                log_message(LOG_ERROR, "epoll error");
                close(events[i].data.fd);
                continue;
            } else if (sfd == events[i].data.fd) {
                while (1) {
                    struct sockaddr in_addr;
                    socklen_t in_len = sizeof(in_addr);
                    int infd = accept(sfd, &in_addr, &in_len);
                    if (infd == -1) {
                        if ((errno == EAGAIN) ||
                            (errno == EWOULDBLOCK)) {
                            break;
                        } else {
                            perror("accept");
                            break;
                        }
                    }

                    int s = make_socket_non_blocking(infd);
                    if (s == -1) {
                        log_message(LOG_ERROR, "Error on make_socket_non_blocking");
                        return;
                    }

                    event.data.fd = infd;
                    event.events = EPOLLIN | EPOLLET;
                    s = epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event);
                    if (s == -1) {
                        perror("epoll_ctl");
                        log_message(LOG_ERROR, "Error on epoll_ctl");
                        return;
                    }
                }
                continue;
            } else {
                handle_connection(events[i].data.fd);
            }
        }
    }

    free(events);
    close(sfd);
}

void handle_connection(int fd) {
    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(fd);
        return;
    }
    buf[n] = '\0';

    char method[16], path[256], protocol[16];
    sscanf(buf, "%s %s %s", method, path, protocol);

    if (strcmp(path, "/") == 0) {
        snprintf(path, sizeof(path), "/login.html");
    }

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s%s", root, path);
    
    char client_ip[INET_ADDRSTRLEN];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
    } else {
        strcpy(client_ip, "unknown");
    }

    int status_code = 200;

    if (strcmp(path, "/register") == 0 && strcmp(method, "POST") == 0) {
        char *username = get_post_data("username", buf);
        char *password = get_post_data("password", buf);
        handle_register_request(username, password);
        send_redirect_response(fd, "/login.html");
        status_code = 200;
        log_access(client_ip, buf, status_code);
        return;
    }

    if (strcmp(path, "/login") == 0 && strcmp(method, "POST") == 0) {
        char *username = get_post_data("username", buf);
        char *password = get_post_data("password", buf);
        if (handle_login_request(username, password)) {
            send_redirect_response(fd, "/index.html");
            status_code = 200;
        } else {
            send_unauthorized_response(fd);
            status_code = 401;
        }
        log_access(client_ip, buf, status_code);
        return;
    }
    
        if (strncmp(path, "/search", 7) == 0) {
        char *query = strchr(buf, '?');
        if (query != NULL) {
            query++;
            char *q = strstr(query, "q=");
            char *name = strstr(query, "name=");
            if (q && name) {
                q += 2;
                name += 5;
                char *q_end = strchr(q, '&');
                if (q_end) {
                    *q_end = '\0';
                }
                char *name_end = strchr(name, '&');
                if (name_end) {
                    *name_end = '\0';
                }

                // URL解码 q 和 name 参数
                char decoded_q[256], decoded_name[256];
                url_decode(decoded_q, q);
                url_decode(decoded_name, name);

                // 去除 name 参数中的额外空白字符
                char *name_value_end = strchr(decoded_name, ' ');
                if (name_value_end) {
                    *name_value_end = '\0';
                }

                char data_file_path[512];
                snprintf(data_file_path, sizeof(data_file_path), "%s/search/%s.txt", root, decoded_q);

                FILE *data_file = fopen(data_file_path, "r");
                if (!data_file) {
                    send_error_response(fd, 404);
                    status_code = 404;
                    log_access(client_ip, buf, status_code);
                    close(fd);
                    return;
                }

                char result[4096] = "";
                char line[256];
                int found = 0;
                while (fgets(line, sizeof(line), data_file)) {
                    if (strstr(line, decoded_name)) {
                        strcat(result, line);
                        found = 1;
                    }
                }
                fclose(data_file);

                if (!found) {
                    strcpy(result, "No results found");
                }

                send_response(fd, "HTTP/1.1 200 OK", "text/plain; charset=utf-8", result, strlen(result));
                status_code = 200;
                log_access(client_ip, buf, status_code);
                close(fd);
                return;
            }
        }

        snprintf(file_path, sizeof(file_path), "%s/search.html", root);
    }

    const char *mime_type = get_mime_type(file_path);

    int file_fd = open(file_path, O_RDONLY);
    if (file_fd == -1) {
        if (errno == EACCES) {
            send_error_response(fd, 403);
            status_code = 403;
        } else {
            send_error_response(fd, 404);
            status_code = 404;
        }
        log_access(client_ip, buf, status_code);
        close(fd);
        return;
    }

    struct stat file_stat;
    if (fstat(file_fd, &file_stat) == -1) {
        send_error_response(fd, 500);
        status_code = 500;
        log_access(client_ip, buf, status_code);
        close(file_fd);
        return;
    }

    char *file_content = malloc(file_stat.st_size);
    if (file_content == NULL) {
        send_error_response(fd, 500);
        status_code = 500;
        log_access(client_ip, buf, status_code);
        close(file_fd);
        return;
    }

    ssize_t bytes_read = read(file_fd, file_content, file_stat.st_size);
    if (bytes_read != file_stat.st_size) {
        perror("read");
        send_error_response(fd, 500);
        status_code = 500;
        log_access(client_ip, buf, status_code);
        close(file_fd);
        free(file_content);
        return;
    }
    close(file_fd);

    send_response(fd, "HTTP/1.1 200 OK", mime_type, file_content, file_stat.st_size);
    status_code = 200;
    log_access(client_ip, buf, status_code);
    free(file_content);
    close(fd);
}

void handle_register_request(const char *username, const char *password) {
    strncpy(registered_user.username, username, sizeof(registered_user.username) - 1);
    strncpy(registered_user.password, password, sizeof(registered_user.password) - 1);
    printf("User registered: %s\n", username);
}

int handle_login_request(const char *username, const char *password) {
    if (strcmp(registered_user.username, username) == 0 && strcmp(registered_user.password, password) == 0) {
        return 1; // 登录成功
    }
    return 0; // 登录失败
}

void send_unauthorized_response(int client_socket) {
    const char *response =
        "HTTP/1.1 401 Unauthorized\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 51\r\n"
        "\r\n"
        "<html><body>401 Unauthorized: Access is denied.</body></html>";
    send(client_socket, response, strlen(response), 0);
}

void send_redirect_response(int client_socket, const char *location) {
    char response[512];
    snprintf(response, sizeof(response),
             "HTTP/1.1 302 Found\r\n"
             "Location: %s\r\n"
             "Content-Length: 0\r\n"
             "\r\n", location);
    send(client_socket, response, strlen(response), 0);
}

char* get_post_data(const char *key, const char *buffer) {
    static char value[256];
    char *pos = strstr(buffer, key);
    if (pos) {
        pos += strlen(key) + 1; // Skip key and '='
        char *end = strchr(pos, '&');
        if (!end) {
            end = strchr(pos, ' ');
        }
        if (end) {
            strncpy(value, pos, end - pos);
            value[end - pos] = '\0';
        } else {
            strcpy(value, pos);
        }
    }
    return value;
}

void send_error_response(int fd, int status_code) {
    const char *reason = "Unknown";
    for (size_t i = 0; i < sizeof(http_statuses) / sizeof(http_statuses[0]); ++i) {
        if (http_statuses[i].code == status_code) {
            reason = http_statuses[i].reason;
            break;
        }
    }

    char header[256];
    snprintf(header, sizeof(header), "HTTP/1.1 %d %s", status_code, reason);
    char body[512];
    snprintf(body, sizeof(body),
             "<html>"
             "<head><title>%d %s</title></head>"
             "<body><h1>%d %s</h1><p>%s</p></body>"
             "</html>",
             status_code, reason, status_code, reason, reason);
    send_response(fd, header, "text/html; charset=utf-8", body, strlen(body));
    log_message(LOG_INFO, "Sent error response %d %s", status_code, reason);
}

void send_response(int fd, const char *header, const char *content_type, const char *body, size_t content_length) {
    char response[1024];
    int response_length = snprintf(response, sizeof(response),
                                   "%s\r\n"
                                   "Content-Type: %s\r\n"
                                   "Content-Length: %zu\r\n"
                                   "\r\n",
                                   header, content_type, content_length);

    ssize_t bytes_written = write(fd, response, response_length);
    if (bytes_written != response_length) {
        perror("write");
        log_message(LOG_ERROR, "Error writing response header");
        return;
    }

    bytes_written = write(fd, body, content_length);
    if (bytes_written != (ssize_t)content_length) {
        perror("write");
        log_message(LOG_ERROR, "Error writing response body");
        return;
    }
}

const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream"; // 默认类型

    if (strcmp(ext, ".html") == 0) return "text/html";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".pdf") == 0) return "application/pdf";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    if (strcmp(ext, ".jpg") == 0) return "image/jpeg";
    if (strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".svg") == 0) return "image/svg+xml";
    if (strcmp(ext, ".ico") == 0) return "image/x-icon";
    if (strcmp(ext, ".mp4") == 0) return "video/mp4";
    return "application/octet-stream"; // 默认类型
}

int make_socket_non_blocking(int sfd) {
    int flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        log_message(LOG_ERROR, "Error getting socket flags");
        return -1;
    }

    flags |= O_NONBLOCK;
    int s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        log_message(LOG_ERROR, "Error setting socket non-blocking");
        return -1;
    }

    return 0;
}

int create_and_bind(const char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        log_message(LOG_ERROR, "getaddrinfo error: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            break;
        }

        close(sfd);
    }

    if (rp == NULL) {
        fprintf(stderr, "Could not bind\n");
        log_message(LOG_ERROR, "Could not bind socket");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}

void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a')
                a -= 'a' - 'A';
            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a' - 'A';
            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

