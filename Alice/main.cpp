#pragma warning(disable:4996)
#define _WINSOCK_DEPRECATED_NO_WARNINGS
extern "C"
{
#include <openssl/applink.c>
}
#include <assert.h>
#include <iostream>
#include <Windows.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <fstream>
#include <exception>
#include <cstdio>
#include <random>
#include <Windows.h>
#include <errno.h>
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib, "Crypt32")
#pragma comment(lib, "Ws2_32.lib")
using namespace std;

BOOL InitWinsock();
std::string rsa_pri_decrypt(unsigned char* cipher, size_t inlen, RSA* rsa);
std::string sha1(const std::string str);
void printHex(string str);
int main() {
    int sockfd = 0;
    short port = 2022;
    char recvBuf[1024] = { 0 };
    char sendBuf[1024] = { 0 };
    struct sockaddr_in serveraddr;
    struct sockaddr_in remoteaddr;
    int remoteaddrLen = sizeof(remoteaddr);
    srand(time(NULL));
    if (InitWinsock())
        cout << "\nWinsock2 start success" << endl;
    else
    {
        throw logic_error("Winsock2 start fail");
    }
    try {
        ::memset(&serveraddr, 0, sizeof(serveraddr));
        ::memset(&remoteaddr, 0, sizeof(remoteaddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
        serveraddr.sin_port = htons(port);
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd == INVALID_SOCKET) {
            throw logic_error("create socket error");
        }
        else {
            cout << "create UDP socket success\n";
        }
        auto ret = bind(sockfd, (sockaddr*)&serveraddr, sizeof(SOCKADDR));
        if (ret == SOCKET_ERROR)
        {
            closesocket(sockfd);
            return false;
        }
        else {
            cout << "bind Local Address : 127.0.0.1 port:2022 success\n";
        }

        //Load the Local User Data
        ifstream infile("./A/Hpw.dat", ifstream::binary);
        infile.seekg(0, ifstream::end);
        int fileLen = infile.tellg();
        infile.seekg(0, ifstream::beg);

        char* userData = new char[fileLen];
        memset(userData, 0, fileLen * sizeof(char));
        infile.read(userData, fileLen);
        infile.close();
        char* ss = strchr(userData, '\0');
        string userName;
        string hashPW;
        if (ss == userData || ss == NULL) {
            throw logic_error("unexcepted user data");
        }
        userName.assign(userData, ss);
        hashPW.assign(ss + 1, userData + fileLen);
        delete[] userData;

        //Load the RSA key
        infile.open("./A/key/Apubkey.pem", ifstream::binary);
        infile.seekg(0, ifstream::end);
        fileLen= infile.tellg();
        int bufferLen = fileLen;
        infile.seekg(0, ifstream::beg);
        char* buffer = new char[bufferLen]; //save the pubkey data in mem buffer and then send it by socket;
        infile.read(buffer, fileLen);
        infile.close();

        //get the RSA object
        BIO* bm = BIO_new_mem_buf(buffer, fileLen);
        RSA* rsa = RSA_new();
        rsa=PEM_read_bio_RSAPublicKey(bm, &rsa, NULL, NULL);
        BIO *bf = BIO_new_file("./A/key/Aprikey.pem", "r");
        rsa=PEM_read_bio_RSAPrivateKey(bf, &rsa, NULL, NULL);
        if (0 == RSA_check_key(rsa))
            throw logic_error("invalid RSA key pair");

        //B->A : Bob
        int recvLen = recvfrom(sockfd, recvBuf, 1024, 0, (sockaddr*)&remoteaddr, &remoteaddrLen);
        //cout<<WSAGetLastError();
        recvBuf[recvLen] = 0;
        if (0 == strcmp(recvBuf, "EXIT"))
            return 0;
        if (recvLen > 0) {
            std::printf("recv a message ip: %s, port: %d\n", inet_ntoa(remoteaddr.sin_addr), ntohs(remoteaddr.sin_port));
            cout << "whose username is "<<recvBuf << endl;
        }

        //A->B : pubkey.pem NA
        if (userName != string(recvBuf)) {
            sprintf(sendBuf, "Invalid User");
            sendto(sockfd,sendBuf, strlen(sendBuf),  0, (sockaddr*)&remoteaddr, remoteaddrLen);
            throw logic_error("Invalid User");
        }
        unsigned char NA[16];//128 bit Random Number;
        //generate NA
        for (int i = 0; i < sizeof(NA); ++i)
            NA[i] = rand() % 256;
        //send the pubkey
        sendto(sockfd, buffer, bufferLen, 0, (sockaddr*)&remoteaddr, remoteaddrLen);
        //send the NA
        sendto(sockfd, (char *)NA, sizeof(NA), 0, (sockaddr*)&remoteaddr, remoteaddrLen);


        //B->A: RSA(pk,OTP) OTP=H(Hpw,NA)
        recvLen = recvfrom(sockfd, recvBuf, 1024, 0,(sockaddr*)&remoteaddr, &remoteaddrLen);
        recvBuf[recvLen] = 0;
        if (0 == strcmp(recvBuf, "EXIT"))
            return 0;
        unsigned char* cipher = (unsigned char *)recvBuf;
        string OTP=rsa_pri_decrypt(cipher, recvLen, rsa);
        //A->B: sucess/fail
        string hashSource = hashPW + string(NA, NA + sizeof(NA));
        string localOTP = sha1(hashSource);
        cout << "\nOTP from Bob:\n";
        printHex(OTP);
        cout << "\nLocal OTP:\n";
        printHex(localOTP);
        if (localOTP == OTP) {
            cout << "\nverify sucess\n";
            sprintf(sendBuf, "success");
        }
        else {
            cout << "\nverify fail\n";
            sprintf(sendBuf, "fail");
        }
        sendto(sockfd, sendBuf, strlen(sendBuf), 0, (sockaddr*)&remoteaddr, remoteaddrLen);
        closesocket(sockfd);
    }
    catch (exception e) {
        cout << e.what() << endl;
    }
}
void printHex(string str) {
    int c = 0;
    for (int i = 0; i < str.size(); ++i) {
        printf("%02X ", (unsigned char)str[i]);
        ++c;
        if (c == 16) {
            printf("\n");
            c = 0;
        }

    }
    printf("\n");
}
std::string rsa_pri_decrypt(unsigned char* cipher, size_t inlen, RSA* rsa)
{
    std::string strRet;
    int len = RSA_size(rsa);
    char* encryptedText = (char*)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    int ret = RSA_private_decrypt(inlen, cipher, (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
        strRet = std::string(encryptedText, ret);
    free(encryptedText);
    return strRet;
}


std::string sha1(const std::string str)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, str.c_str(), str.size());
    SHA1_Final(hash, &sha1);
    std::string NewString(hash, hash + SHA_DIGEST_LENGTH);
    return NewString;
}

BOOL InitWinsock()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        return FALSE;
    }

    /* Confirm that the WinSock DLL supports 2.2.*/
    /* Note that if the DLL supports versions greater    */
    /* than 2.2 in addition to 2.2, it will still return */
    /* 2.2 in wVersion since that is the version we      */
    /* requested.                                        */

    if (LOBYTE(wsaData.wVersion) != 2 ||
        HIBYTE(wsaData.wVersion) != 2) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        WSACleanup();
        return FALSE;
    }

    /* The WinSock DLL is acceptable. Proceed. */
    return TRUE;
}
