#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

int make_socket_non_blocking(int sfd);
int create_and_bind(const char *port);
void start_http_server();

// 新增函数和全局变量声明
typedef struct {
    char username[256];
    char password[256];
} User;

extern User registered_user;

void handle_register_request(const char *username, const char *password);
int handle_login_request(const char *username, const char *password);
void send_unauthorized_response(int client_socket);
char* get_post_data(const char *key, const char *buffer);
void send_redirect_response(int client_socket, const char *location);

#endif

