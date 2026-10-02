/* vsock-hello PORT: connects to the host (CID 2) on PORT, sends one line, prints the reply. */
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    struct sockaddr_vm addr = {.svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = (unsigned)atoi(argv[1])};
    if (connect(s, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("connect"); return 1; }
    const char *msg = "VMKIT-VSOCK-HELLO\n";
    if (write(s, msg, strlen(msg)) < 0) { perror("write"); return 1; }
    char buf[128];
    ssize_t n = read(s, buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; printf("VMKIT-VSOCK-REPLY %s", buf); }
    return 0;
}
