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
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib, "Crypt32")
#pragma comment(lib, "Ws2_32.lib")
using namespace std;

BOOL InitWinsock();
std::string rsa_pub_encrypt(unsigned char* plain, size_t inlen, RSA* rsa);
std::string sha1(const std::string str);
void printHex(string str);
int main() {
    int sockfd = 0;
    short port = 2022;
    char recvBuf[1024] = { 0 };
    char sendBuf[1024] = { 0 };
    struct sockaddr_in remoteaddr;
    int remoteaddrLen = sizeof(remoteaddr);
    ::memset(&remoteaddr, 0, sizeof(remoteaddr));
    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    remoteaddr.sin_port = htons(port);
    if (InitWinsock())
        cout << "\nWinsock2 start success" << endl;
    else
    {
        throw logic_error("Winsock2 start fail");
    }
    try {

        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd == INVALID_SOCKET) {
            cout << "create socket error\n";
            return 0;
        }
        else {
            cout << "create UDP socket success\n";
        }

        //Load the Local Hpk
        ifstream infile("./B/Hpk.hash", ifstream::binary);
        infile.seekg(0, ifstream::end);
        int fileLen = infile.tellg();
        infile.seekg(0, ifstream::beg);

        char* buffer = new char[fileLen];
        memset(buffer, 0, fileLen * sizeof(char));
        infile.read(buffer, fileLen);
        infile.close();
        string hashPK(buffer, buffer + fileLen);
        delete[] buffer;

        cout << "---------------------------------------------------------------\n";
        cout << "Please Input UserName \n";
        string userName;
        string password;
        cin >> userName;
        cout << "Please Input Password\n";
        cin >> password;
        //B->A : Bob
        memset(sendBuf, 0, sizeof(sendBuf));
        sprintf(sendBuf, userName.c_str());
        sendto(sockfd, sendBuf, strlen(sendBuf), 0, (sockaddr*)&remoteaddr, remoteaddrLen);
        
        //A->B : pubkey.pem NA
        cout << "---------------------------------------------------------------\n";
        string NA;
        int recvLen = recvfrom(sockfd, recvBuf, 1024, 0, (sockaddr*)&remoteaddr, &remoteaddrLen);
        if (0==strcmp(recvBuf,"Invalid User")) {
            cout << "\nInvalid User\n";
            return 0;
        }
        recvBuf[recvLen] = 0; //get the pubkey
        string Hpk = sha1(string(recvBuf, recvBuf + recvLen));

        cout << "\nH(pk) From Alice:\n";
        printHex(Hpk);
        cout << "\nLocal public key hash:\n";
        printHex(hashPK);
        if (hashPK != Hpk) {
            throw logic_error("H(pk) from Alice does not match the stored vaule in local key's hash file");
        }
        else {
            cout << "H(pk) from Alice matches the stored vaule in local key's hash file\n";
        }

        BIO* bm =  BIO_new_mem_buf(recvBuf, recvLen);
        RSA* rsa = RSA_new();
        if (NULL == PEM_read_bio_RSAPublicKey(bm, &rsa, NULL, NULL))
            throw logic_error("resolve RSA key fail");
        recvLen = recvfrom(sockfd, recvBuf, 1024, 0, (sockaddr*)&remoteaddr, &remoteaddrLen);
        if (recvLen != 16)
            throw logic_error("recv NA fail");
        NA.assign(recvBuf, recvBuf + recvLen);

        cout << "---------------------------------------------------------------\n";
        //B->A: RSA(pk,OTP) OTP=H(Hpw,NA)
        string HPW = sha1(password);
        string OTP = sha1(string(HPW + NA));
        string cipher = rsa_pub_encrypt((unsigned char *)&OTP[0],OTP.size(),rsa);
        sendto(sockfd,cipher.data(),cipher.size(),0,(sockaddr*)&remoteaddr, remoteaddrLen);
        cout << "\nBob: OTP is:\n";
        printHex(OTP);
        cout << "\nBob: Send the RSA cipher to Alice:\n";
        printHex(cipher);
        //A->B: sucess/fail
        recvLen = recvfrom(sockfd, recvBuf, 1024, 0, (sockaddr*)&remoteaddr, &remoteaddrLen);
        recvBuf[recvLen] = 0;
        cout << "---------------------------------------------------------------\n";
        printf("\nVerify Message From Alice: %s\n", recvBuf);
        closesocket(sockfd);
    }
    catch (exception e) {
        cout << e.what() << endl;
        sprintf(sendBuf, "EXIT");
        sendto(sockfd, sendBuf, strlen(sendBuf), 0, (sockaddr*)&remoteaddr, remoteaddrLen);
        closesocket(sockfd);
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
std::string rsa_pub_encrypt(unsigned char* plain, size_t inlen, RSA* rsa)
{
    std::string strRet;
    int len = RSA_size(rsa);
    char* encryptedText = (char*)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    int ret = RSA_public_encrypt(inlen, plain, (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
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
