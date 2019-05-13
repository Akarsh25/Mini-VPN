#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "10.0.2.4" 

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>




#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 
struct sockaddr_in peerAddr;
int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}

/*
int connectToUDPServer(){
    int sockfd;
    char *hello="Hello";

    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(PORT_NUMBER);
    peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Send a hello message to "connect" with the VPN server
    sendto(sockfd, hello, strlen(hello), 0,
                (struct sockaddr *) &peerAddr, sizeof(peerAddr));

    return sockfd;
}*/

void tunSelected(SSL *ssl,int tunfd, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    //printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    buff[len]='\0';
    SSL_write(ssl,buff,len);
    //printf("%s\n",buff);
    //sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
                    //sizeof(peerAddr));
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
       exit(0);
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
	printf("Error setting the verify locations. \n");
	exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}


void socketSelected (SSL *ssl, int tunfd, int sockfd){
    int  len;
    char buff[BUFF_SIZE];

    //printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len=SSL_read(ssl,buff,BUFF_SIZE);
    buff[len]='\0';
    //len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    write(tunfd, buff, len);

}

int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;

   // Get the IP address from hostname
   struct hostent* hp = gethostbyname(hostname);

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
   //server_addr.sin_addr.s_addr = inet_addr ("10.0.2.4"); 
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr,
           sizeof(server_addr));

   return sockfd;
}
int login(SSL *ssl,int sockfd){
	int len;
	char buf[9000];
	//char buff2[BUFF_SIZE];
	
	char uname[20];
	char pass[20];
	printf("Enter Username:\n");
	scanf("%s",uname);
	printf("Enter Password:\n");
	scanf("%s",pass);
        int l1=strlen(uname);
	SSL_write(ssl,uname,l1);
	int l2=strlen(pass);
	SSL_write(ssl,pass,l2);

        len=SSL_read(ssl,buf,sizeof(buf)-1);
	buf[len]='\0';
	//const char *str=buf;
	//printf("%s\n",buf);
	if (buf[0]=='F'){
		return 0;
		}
	else if(buf[0]=='T'){
		printf("Successfully logged into VPN srver\n");
		const char *str=buf;
		printf("%c\n",str[0]);
		}
}
		
		
int main(int argc, char *argv[])
{
   char *hostname = "yahoo.com";
   int port = 443;

   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);
   
   int tunfd = createTunDevice();
   /*----------------TLS initialization ----------------*/
   SSL *ssl   = setupTLSClient(hostname);

   /*----------------Create a TCP connection ---------------*/
   int sockfd = setupTCPClient(hostname, port);

   /*----------------TLS handshake ---------------------*/
   SSL_set_fd(ssl, sockfd);
   int err = SSL_connect(ssl); CHK_SSL(err);
   printf("SSL connection is successful\n");
   printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

   /*----------------Send/Receive data --------------------*/
   char buf[9000];
   char sendBuf[200];
   //sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
   //SSL_write(ssl, sendBuf, strlen(sendBuf));

   int x=login(ssl,sockfd);
   if (x==0){
	printf("Wrong username or password \n");
	exit(0);
	}
 
   int len;
   
   /*do {
     len = SSL_read (ssl, buf, sizeof(buf) - 1);
     buf[len] = '\0';
     printf("%s\n",buf);
   } while (len > 0);*/

   while(1){
    
     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(ssl,tunfd, sockfd);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(ssl,tunfd, sockfd);

     
   } 
}


