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

/* ֤�����Կ���ڵ�Ŀ¼ */
#define HOME "D:/OpenSSL-Win32/certs/"  
/* ֤�����Կ�ļ��� */
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
	char serverip[16];
	int portnum;
	printf("���������IP��ַ��");
	scanf("%s", serverip);
	printf("����������˿ںţ�");
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

	/*��ʼ��OpenSSL*/
	SSLeay_add_ssl_algorithms();
	meth = (SSL_METHOD *)SSLv23_client_method();
	SSL_load_error_strings();

	/*����CTX�Ự����*/
	ctx = SSL_CTX_new(meth);                        
	CHK_NULL(ctx);
	CHK_SSL(err);

	/*����֤�飬����֤*/
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

	/*����һ��socket������������TCP/IP����*/
	socket_init_tcpip();
	sd = socket(AF_INET, SOCK_STREAM, 0);       
	CHK_ERR(sd, "socket");

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(serverip);   /*���ﴫ�������IP��ַ */
	sa.sin_port = htons(2174);          /* ���ﴫ��������˿ں�*/

	err = connect(sd, (struct sockaddr*) &sa,sizeof(sa));                   
	CHK_ERR(err, "connect");

	/* ���TCP/IP���Ӻ󣬿�ʼSSL���� */

	/*����SSL�׽���*/
	ssl = SSL_new(ctx);
	CHK_NULL(ssl);

	/*�Զ�дģʽ�����׽���*/
	SSL_set_fd(ssl, sd);

	/*����SSL����*/
	err = SSL_connect(ssl);
	CHK_SSL(err);

	/* �������cipher -����ѡ�� */
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/* ��÷�����֤�� - ����ѡ�� */
	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);
	printf("Server certificate:\n");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);	/*���֤�������ߵ�����*/
	CHK_NULL(str);
	printf("\t subject: %s\n", str);
	OPENSSL_free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	CHK_NULL(str);
	printf("\t issuer: %s\n", str);
	OPENSSL_free(str);

	/* ֤����֤���������Կ�ʼͨ�� */

	X509_free(server_cert);

	/*���ݴ���׶�*/
	while (1)
	{
		/*����Ҫ���͵�����*/
		printf("\n���ͣ�");
		char sendbuf[512] = { 0 };
		scanf("%s", sendbuf);

		/*��SSL�׽���д����*/
		err = SSL_write(ssl, sendbuf, strlen(sendbuf));
		CHK_SSL(err);

		/*��SSL�׽��ֶ�����*/
		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		CHK_SSL(err);
		buf[err] = '\0';
		printf("�õ���Ӧ(%d bytes)��%s\n",err, buf);
	}

	/*�ر�SSL�׽��֣���ȫ����*/
	SSL_shutdown(ssl); 

	/*�ر�socket��TCP/IP����*/
	closesocket(sd);

	/*�ͷ�SSL�׽��֣��ͷ�SSL�Ự����*/
	SSL_free(ssl);
	SSL_CTX_free(ctx);
}