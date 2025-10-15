#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    printf("Testing basic socket creation...\n");
    
    // Try to create a TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("❌ socket() failed - NETWORK BLOCKED");
        return 1;
    }
    
    printf("✅ socket() succeeded - NETWORK ALLOWED\n");
    
    // Try to create a UDP socket
    int sock_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_udp < 0) {
        perror("❌ UDP socket() failed");
        close(sock);
        return 1;
    }
    
    printf("✅ UDP socket() succeeded\n");
    
    close(sock);
    close(sock_udp);
    
    printf("Network access is AVAILABLE in sandbox\n");
    return 0;
}