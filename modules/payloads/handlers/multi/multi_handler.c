/* modules/auxiliary/multi/multi_handler.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <termios.h>
#include <fcntl.h>

#define MAX_CLIENTS 10
#define BUF_SIZE 8192

typedef struct {
    int sock;
    char ip[INET_ADDRSTRLEN];
    int active;
    pthread_t thread;
} Client;

Client clients[MAX_CLIENTS];
int server_sock = -1;
int client_count = 0;
int current_session = -1;  // Session yang sedang di-interact
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct termios old_tio;
void enable_raw() {
    struct termios raw;
    tcgetattr(STDIN_FILENO, &raw);
    old_tio = raw;
    raw.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}
void disable_raw() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_tio);
}

void* client_handler(void* arg) {
    int idx = (int)(intptr_t)arg;
    int sock = clients[idx].sock;
    char buffer[BUF_SIZE];
    int n;

    while (clients[idx].active) {
        // Jika ini session aktif → kirim input
        if (current_session == idx) {
            // Baca dari stdin → kirim ke client
            if (fcntl(STDIN_FILENO, F_GETFL) & O_NONBLOCK) {
                n = read(STDIN_FILENO, buffer, BUF_SIZE);
                if (n > 0) {
                    write(sock, buffer, n);
                }
            }
        }

        // Baca dari client → tampilkan jika session aktif
        n = read(sock, buffer, BUF_SIZE - 1);
        if (n <= 0) break;
        buffer[n] = '\0';

        pthread_mutex_lock(&mutex);
        if (current_session == idx) {
            printf("%s", buffer);
            fflush(stdout);
        }
        pthread_mutex_unlock(&mutex);
    }

    // Cleanup
    pthread_mutex_lock(&mutex);
    clients[idx].active = 0;
    close(sock);
    printf("\n[-] Session %d (%s) closed.\n", idx, clients[idx].ip);
    if (current_session == idx) current_session = -1;
    pthread_mutex_unlock(&mutex);
    return NULL;
}

void list_sessions() {
    printf("\n=== Active Sessions ===\n");
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            printf("  [%d] %s %s\n", i, clients[i].ip,
                   (current_session == i) ? "[ACTIVE]" : "");
        }
    }
    if (client_count == 0) printf("  No active sessions.\n");
    printf("========================\n");
    pthread_mutex_unlock(&mutex);
}

void interact_session(int idx) {
    pthread_mutex_lock(&mutex);
    if (idx < 0 || idx >= MAX_CLIENTS || !clients[idx].active) {
        printf("[!] Invalid or inactive session: %d\n", idx);
        pthread_mutex_unlock(&mutex);
        return;
    }
    if (current_session == idx) {
        printf("[*] Already interacting with session %d\n", idx);
        pthread_mutex_unlock(&mutex);
        return;
    }
    current_session = idx;
    printf("[+] Interacting with session %d (%s)\n", idx, clients[idx].ip);
    printf("[*] Type commands (Ctrl+C to exit session)\n\n");
    pthread_mutex_unlock(&mutex);
}

void kill_session(int idx) {
    pthread_mutex_lock(&mutex);
    if (idx >= 0 && idx < MAX_CLIENTS && clients[idx].active) {
        close(clients[idx].sock);
        clients[idx].active = 0;
        if (current_session == idx) current_session = -1;
        printf("[+] Killed session %d\n", idx);
    } else {
        printf("[!] Invalid session: %d\n", idx);
    }
    pthread_mutex_unlock(&mutex);
}

void* input_thread(void* arg) {
    char cmd[256];
    while (1) {
        if (current_session == -1) {
            // Mode command
            printf("multi> ");
            fflush(stdout);
            if (fgets(cmd, sizeof(cmd), stdin) == NULL) break;
            cmd[strcspn(cmd, "\n")] = 0;

            if (strcmp(cmd, "list") == 0 || strcmp(cmd, "sessions") == 0) {
                list_sessions();
            } else if (strncmp(cmd, "interact ", 9) == 0) {
                int idx = atoi(cmd + 9);
                interact_session(idx);
            } else if (strncmp(cmd, "kill ", 5) == 0) {
                int idx = atoi(cmd + 5);
                kill_session(idx);
            } else if (strcmp(cmd, "help") == 0) {
                printf("Commands: list, interact <id>, kill <id>, help, exit\n");
            } else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
                break;
            } else {
                printf("[!] Unknown command: %s\n", cmd);
            }
        } else {
            // Mode shell → input langsung ke session
            usleep(10000);
        }
    }
    return NULL;
}

void sigint(int s) {
    printf("\n[!] Shutting down...\n");
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) close(clients[i].sock);
    }
    if (server_sock != -1) close(server_sock);
    disable_raw();
    exit(0);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s <LHOST> <LPORT>\n", argv[0]);
        printf("  LHOST=0.0.0.0 → listen on LAN + WAN\n");
        return 1;
    }

    signal(SIGINT, sigint);
    enable_raw();
    atexit(disable_raw);

    struct sockaddr_in sa, ca;
    socklen_t clen = sizeof(ca);
    int port = atoi(argv[2]);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = (strcmp(argv[1], "0.0.0.0") == 0) ? INADDR_ANY : inet_addr(argv[1]);

    bind(server_sock, (struct sockaddr*)&sa, sizeof(sa));
    listen(server_sock, 5);

    printf("[*] Multi Handler listening on %s:%d\n", argv[1], port);
    printf("[*] Waiting for connections...\n");
    printf("[*] Type 'help' for commands.\n\n");

    pthread_t input_tid;
    pthread_create(&input_tid, NULL, input_thread, NULL);

    while (1) {
        int client_sock = accept(server_sock, (struct sockaddr*)&ca, &clen);
        if (client_sock < 0) continue;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));

        pthread_mutex_lock(&mutex);
        int idx = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].active) { idx = i; break; }
        }
        if (idx == -1) {
            close(client_sock);
            printf("[-] Max clients reached\n");
        } else {
            clients[idx].sock = client_sock;
            strcpy(clients[idx].ip, ip);
            clients[idx].active = 1;
            client_count++;
            printf("[+] New session %d from %s\n", idx, ip);
            pthread_create(&clients[idx].thread, NULL, client_handler, (void*)(intptr_t)idx);
        }
        pthread_mutex_unlock(&mutex);
    }
    return 0;
}
