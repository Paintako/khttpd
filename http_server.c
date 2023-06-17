#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "http_parser.h"
#include "http_server.h"

#define CRLF "\r\n"

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256
#define BUFFER_SIZE 256

struct khttpd_service daemon = {.is_stopped = false};
extern struct workqueue_struct *khttpd_wq;

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct list_head list;
    struct work_struct khttpd_work;
    struct dir_context dir_context;  // struct dir_context, defines in fs.h
};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static void send_http_header(struct socket *socket,
                             int status,
                             const char *status_msg,
                             char *type,
                             int length,
                             char *conn_msg)
{
    char buf[SEND_BUFFER_SIZE] = {0};
    snprintf(buf, SEND_BUFFER_SIZE,
             "HTTP/1.1 %d %s\r\n     \
                Content-Type: %s\r\n    \
                Content-Length: %d\r\n  \
                Connection: %s\r\n\r\n",
             status, status_msg, type, length, conn_msg);
    http_server_send(socket, buf, strlen(buf));
}

static void send_http_content(struct socket *socket, char *content)
{
    char buf[SEND_BUFFER_SIZE] = {0};
    snprintf(buf, SEND_BUFFER_SIZE, "%s\r\n", content);
    http_server_send(socket, buf, strlen(buf));
}

// concatenate string
static void catstr(char *res, char *first, char *second)
{
    int first_size = strlen(first);
    int second_size = strlen(second);
    memset(res, 0, BUFFER_SIZE);
    memcpy(res, first, first_size);
    memcpy(res + first_size, second, second_size);
}

static inline int read_file(struct file *fp, char *buf)
{
    return kernel_read(fp, buf, fp->f_inode->i_size, 0);
}

static int tracedir(struct dir_context *dir_context,
                    const char *name,
                    int namelen,
                    loff_t offset,
                    u64 ino,
                    unsigned int d_type)
{
    if (strcmp(name, ".") && strcmp(name, "..")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[SEND_BUFFER_SIZE] = {0};
        char *url =
            !strcmp(request->request_url, "/") ? "" : request->request_url;

        snprintf(buf, SEND_BUFFER_SIZE,
                 "<tr><td><a href=\"%s/%s\">%s</a></td></tr>\r\n", url, name,
                 name);
        http_server_send(request->socket, buf, strlen(buf));
    }
    return 0;
}

static bool handle_directory(struct http_request *request)
{
    struct file *fp;
    char pwd[BUFFER_SIZE] = {0};

    request->dir_context.actor = tracedir;
    if (request->method != HTTP_GET) {
        send_http_header(request->socket, HTTP_STATUS_NOT_IMPLEMENTED,
                         http_status_str(HTTP_STATUS_NOT_IMPLEMENTED),
                         "text/plain", 19, "close");
        send_http_content(request->socket, "501 Not Implemented");
        return false;
    }

    catstr(pwd, daemon.dir_path, request->request_url);
    fp = filp_open(pwd, O_RDONLY, 0);

    if (IS_ERR(fp)) {
        send_http_header(request->socket, HTTP_STATUS_NOT_FOUND,
                         http_status_str(HTTP_STATUS_NOT_FOUND), "text/plain",
                         14, "close");
        send_http_content(request->socket, "404 Not Found");
        kernel_sock_shutdown(request->socket, SHUT_RDWR);
        return false;
    }

    if (S_ISDIR(fp->f_inode->i_mode)) {
        char buf[SEND_BUFFER_SIZE] = {0};
        snprintf(buf, SEND_BUFFER_SIZE, "HTTP/1.1 200 OK\r\n%s%s%s",
                 "Connection: Keep-Alive\r\n", "Content-Type: text/html\r\n",
                 "Keep-Alive: timeout=5, max=1000\r\n\r\n");
        http_server_send(request->socket, buf, strlen(buf));

        snprintf(buf, SEND_BUFFER_SIZE, "%s%s%s%s", "<html><head><style>\r\n",
                 "body{font-family: monospace; font-size: 15px;}\r\n",
                 "td {padding: 1.5px 6px;}\r\n",
                 "</style></head><body><table>\r\n");
        http_server_send(request->socket, buf, strlen(buf));

        iterate_dir(fp, &request->dir_context);

        snprintf(buf, SEND_BUFFER_SIZE, "</table></body></html>\r\n");
        http_server_send(request->socket, buf, strlen(buf));

    } else if (S_ISREG(fp->f_inode->i_mode)) {
        char *read_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        int ret = read_file(fp, read_data);

        send_http_header(request->socket, HTTP_STATUS_OK,
                         http_status_str(HTTP_STATUS_OK), "text/plain",
                         fp->f_inode->i_size, "close");
        http_server_send(request->socket, read_data, ret);

        kfree(read_data);
    }
    kernel_sock_shutdown(request->socket, SHUT_RDWR);
    filp_close(fp, NULL);
    return true;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    // pr_info("requested_url = %s\n", request->request_url);

    if (handle_directory(request) == 0)
        printk("Something went wrong\n");

    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static void http_server_worker(struct work_struct *work)
{
    struct http_request *worker =
        container_of(work, struct http_request, khttpd_work);
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &worker->socket;
    while (!daemon.is_stopped) {
        int ret = http_server_recv(worker->socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (worker->complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(worker->socket, SHUT_RDWR);
    kfree(buf);
}

static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work;
    if (!(work = kmalloc(sizeof(struct http_request), GFP_KERNEL)))
        return NULL;

    work->socket = sk;

    INIT_WORK(&work->khttpd_work, http_server_worker);

    list_add(&work->list, &daemon.worker);
    return &work->khttpd_work;
}

static void free_work(void)
{
    struct http_request *l, *tar;
    /* cppcheck-suppress uninitvar */
    list_for_each_entry_safe (tar, l, &daemon.worker, list) {
        kernel_sock_shutdown(tar->socket, SHUT_RDWR);
        flush_work(&tar->khttpd_work);
        sock_release(tar->socket);
        kfree(tar);
    }
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct http_server_param *param = (struct http_server_param *) arg;
    struct work_struct *work;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon.worker);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }
        // worker = kthread_run(http_server_worker, socket, KBUILD_MODNAME);
        if (unlikely(!(work = create_work(socket)))) {
            printk(KERN_ERR MODULE_NAME
                   ": create work error, connection closed\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }
        /* start server worker */
        queue_work(khttpd_wq, work);
    }

    printk(MODULE_NAME ": daemon shutdown in progress...\n");
    daemon.is_stopped = true;
    free_work();
    return 0;
}
