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

/* ֤�����Կ����Ŀ¼ */
#define HOME "D:/OpenSSL-Win32/certs/"  
/* ֤�����Կ�ļ��� */
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
	/* ���汾�� */
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

	/* OpenSSL��ʼ��*/
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	/*����CTX�Ự����*/
	meth = (SSL_METHOD *)SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		printf("2");
		exit(2);
	}

	/*����֤�飬����֤*/
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

	/*����һ��socket������������TCP/IP����*/
	socket_init_tcpip();
	listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(listen_sd, "socket");

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(2174);          /* ����ָ�������������ö˿ں� */

	err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof(sa_serv));                   
	CHK_ERR(err, "bind");

	err = listen(listen_sd, 5);                    
	CHK_ERR(err, "listen");

	client_len = sizeof(sa_cli);
	sd = accept(listen_sd, (struct sockaddr*) &sa_cli, (int*)&client_len);
	CHK_ERR(sd, "accept");
	closesocket(listen_sd);

	printf("Connection from %lx, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);

	/* ���TCP/IP���Ӻ󣬿�ʼSSL���� */

	/*����SSL�׽���*/
	ssl = SSL_new(ctx);                           
	CHK_NULL(ssl);

	/*�Զ�дģʽ�����׽���*/
	SSL_set_fd(ssl, sd);

	/*����SSL����*/
	err = SSL_accept(ssl);                        
	CHK_SSL(err);

	/* �������cipher -����ѡ�� */
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/* ��ÿͻ���֤�� - ����ѡ�� */
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

		/* ֤����֤���������Կ�ʼͨ�� */

		X509_free(client_cert);
	}
	else
		printf("Client does not have certificate.\n");

	/*���ݴ���׶�*/
	while (true)
	{
		/*��SSL�׽��ֶ�����*/
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		CHK_SSL(err);

		/*��ӡ�յ�������*/
		buf[err] = '\0';
		printf("\n�յ���Ϣ(%dbytes)��'%s'\n", err, buf);

		/*�Զ���Ӧ���յ�*/
		err = SSL_write(ssl, "���յ�.", strlen("���յ�"));  
		CHK_SSL(err);
	}

	/*�ر�SSL�׽��֣���ȫ����*/
	SSL_shutdown(ssl);

	/*�ر�socket��TCP/IP����*/
	closesocket(sd);
	
	/*�ͷ�SSL�׽��֣��ͷ�SSL�Ự����*/
	SSL_free(ssl);
	SSL_CTX_free(ctx);
}