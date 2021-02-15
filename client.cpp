#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>  
#include <memory.h>  
#include <errno.h>  
#include <WinSock2.h>  

#include <openssl/crypto.h>  
#include <openssl/x509.h>  
#include <openssl/pem.h>  
#include <openssl/ssl.h>  
#include <openssl/err.h>   

#pragma comment( lib, "ws2_32.lib" )

/* 证书和密钥所在的目录 */
#define HOME "D:/OpenSSL-Win32/certs/"  
/* 证书和密钥文件名 */
#define CERTF  HOME "alt2-cert.pem"  
#define KEYF   HOME "alt2-key.pem"  

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
	char serverip[16];
	int portnum;
	printf("输入服务器IP地址：");
	scanf("%s", serverip);
	printf("输入服务器端口号：");
	scanf("%d", &portnum);

	int err = 0;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    server_cert;
	char*    str;
	char     buf[4096];
	SSL_METHOD *meth;

	/*初始化OpenSSL*/
	SSLeay_add_ssl_algorithms();
	meth = (SSL_METHOD *)SSLv23_client_method();
	SSL_load_error_strings();

	/*创建CTX会话环境*/
	ctx = SSL_CTX_new(meth);                        
	CHK_NULL(ctx);
	CHK_SSL(err);

	/*加载证书，并验证*/
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}

	/*创建一个socket完成与服务器的TCP/IP连接*/
	socket_init_tcpip();
	sd = socket(AF_INET, SOCK_STREAM, 0);       
	CHK_ERR(sd, "socket");

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(serverip);   /*这里传入服务器IP地址 */
	sa.sin_port = htons(2174);          /* 这里传入服务器端口号*/

	err = connect(sd, (struct sockaddr*) &sa,sizeof(sa));                   
	CHK_ERR(err, "connect");

	/* 完成TCP/IP连接后，开始SSL握手 */

	/*创建SSL套接字*/
	ssl = SSL_new(ctx);
	CHK_NULL(ssl);

	/*以读写模式绑定流套接字*/
	SSL_set_fd(ssl, sd);

	/*发起SSL握手*/
	err = SSL_connect(ssl);
	CHK_SSL(err);

	/* 获得密码cipher -（可选） */
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/* 获得服务器证书 - （可选） */
	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);
	printf("Server certificate:\n");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);	/*获得证书所用者的名字*/
	CHK_NULL(str);
	printf("\t subject: %s\n", str);
	OPENSSL_free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	CHK_NULL(str);
	printf("\t issuer: %s\n", str);
	OPENSSL_free(str);

	/* 证书验证结束，可以开始通信 */

	X509_free(server_cert);

	/*数据传输阶段*/
	while (1)
	{
		/*输入要发送的内容*/
		printf("\n发送：");
		char sendbuf[512] = { 0 };
		scanf("%s", sendbuf);

		/*向SSL套接字写数据*/
		err = SSL_write(ssl, sendbuf, strlen(sendbuf));
		CHK_SSL(err);

		/*从SSL套接字读数据*/
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		CHK_SSL(err);
		buf[err] = '\0';
		printf("得到回应(%d bytes)：%s\n",err, buf);
	}

	/*关闭SSL套接字，安全断连*/
	SSL_shutdown(ssl); 

	/*关闭socket，TCP/IP断连*/
	closesocket(sd);

	/*释放SSL套接字，释放SSL会话环境*/
	SSL_free(ssl);
	SSL_CTX_free(ctx);
}