#include <stdio.h>  
#include <stdlib.h>  
#include <memory.h>  
#include <errno.h>  
#include <winsock2.h>  

#include <openssl/rsa.h>       
#include <openssl/crypto.h>  
#include <openssl/x509.h>  
#include <openssl/pem.h>  
#include <openssl/ssl.h>  
#include <openssl/err.h>  

#pragma comment( lib, "ws2_32.lib" )

/* 证书和密钥所在目录 */
#define HOME "D:/OpenSSL-Win32/certs/"  
/* 证书和密钥文件名 */
#define CERTF  HOME"alt1-cert.pem"  
#define KEYF	 HOME"alt1-key.pem"  

#define CHK_NULL(x) if ((x)==NULL) exit (1)  
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }  
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }  

void socket_init_tcpip()
{
#ifdef _WIN32  
	WORD     wVersionRequested;
	WSADATA  wsaData;

	wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		return;
	}
	/* 检查版本号 */
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		return;
	}
#else     
#endif  
}

void main()
{
	int err;
	int listen_sd;
	int sd;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	size_t client_len;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    client_cert;
	char*    str;
	char     buf[4096];
	SSL_METHOD *meth;

	/* OpenSSL初始化*/
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	/*创建CTX会话环境*/
	meth = (SSL_METHOD *)SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		printf("2");
		exit(2);
	}

	/*加载证书，并验证*/
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		printf("3");
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		printf("4");
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		printf("5");
		exit(5);
	}

	/*创建一个socket完成与服务器的TCP/IP连接*/
	socket_init_tcpip();
	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(listen_sd, "socket");

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(2174);          /* 这里指明本服务器所用端口号 */

	err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof(sa_serv));                   
	CHK_ERR(err, "bind");

	err = listen(listen_sd, 5);                    
	CHK_ERR(err, "listen");

	client_len = sizeof(sa_cli);
	sd = accept(listen_sd, (struct sockaddr*) &sa_cli, (int*)&client_len);
	CHK_ERR(sd, "accept");
	closesocket(listen_sd);

	printf("Connection from %lx, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);

	/* 完成TCP/IP连接后，开始SSL握手 */

	/*创建SSL套接字*/
	ssl = SSL_new(ctx);                           
	CHK_NULL(ssl);

	/*以读写模式绑定流套接字*/
	SSL_set_fd(ssl, sd);

	/*发起SSL握手*/
	err = SSL_accept(ssl);                        
	CHK_SSL(err);

	/* 获得密码cipher -（可选） */
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/* 获得客户端证书 - （可选） */
	client_cert = SSL_get_peer_certificate(ssl);
	if (client_cert != NULL) 
	{
		printf("Client certificate:\n");

		str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
		CHK_NULL(str);
		printf("\t subject: %s\n", str);
		OPENSSL_free(str);

		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
		CHK_NULL(str);
		printf("\t issuer: %s\n", str);
		OPENSSL_free(str);

		/* 证书验证结束，可以开始通信 */

		X509_free(client_cert);
	}
	else
		printf("Client does not have certificate.\n");

	/*数据传输阶段*/
	while (true)
	{
		/*从SSL套接字读数据*/
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		CHK_SSL(err);

		/*打印收到的内容*/
		buf[err] = '\0';
		printf("\n收到消息(%dbytes)：'%s'\n", err, buf);

		/*自动回应已收到*/
		err = SSL_write(ssl, "已收到.", strlen("已收到"));  
		CHK_SSL(err);
	}

	/*关闭SSL套接字，安全断连*/
	SSL_shutdown(ssl);

	/*关闭socket，TCP/IP断连*/
	closesocket(sd);
	
	/*释放SSL套接字，释放SSL会话环境*/
	SSL_free(ssl);
	SSL_CTX_free(ctx);
}