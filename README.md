不知道哪个国外大学的单子，C++ udp openssl编程实现的一个SSL通信协议，完成数据的安全交换

大概是2022年7月份接的单子。



# UDP Remote Login Protocol Programs

This program use C++ and OpenSSL to implemment a remote login protocal by UDP WIN_Socket

## Quick Start
Load the .sln into Visual Studio. 

Build and Run Alice.sln First, it would bind the local address 127.0.0.1 and port 2022. Then Run Bob.sln and input the user name and password. Default username is Bob, and password is 123456



## Libraries
# OpenSSL
This project uses OpenSSl to implemment the hash function and the RSA cypto.
see more:
https://www.openssl.org/

To use this Lib, you need to add two additional dependencies "libssl.lib" and "libcrypto.lib" in your visual studio project.

Also "libcrypto-1_1-x64.dll" and "libssl-1_1-x64.dll" files need to be added into the project directory.
# WinSock2
This project uses the WinSock2 to finish the UDP communication. This lib is  always a builtin lib of VC++. You can use it by add the dependencies
"Ws2_32.lib" in your visual studio project.


## Files
```
├─Alice
│  │  Alice.sln   //vs project
│  │  Alice.vcxproj
│  │  Alice.vcxproj.filters
│  │  Alice.vcxproj.user
│  │  libcrypto-1_1-x64.dll  //openssl dll files
│  │  libssl-1_1-x64.dll    //openssl dll files
│  │  main.cpp  //source code of Alice
│  │  
│  └─A
│      │  Hpw.dat   //the H(pw) files, it has one record "Bob+H(123456)"
│      │  
│      └─key
│              Aprikey.pem  //A's private RSA key
│              Apubkey.pem //A's public RSA key
│              
├─Bob
│  │  Bob.sln //vs project
│  │  Bob.vcxproj
│  │  Bob.vcxproj.filters
│  │  Bob.vcxproj.user
│  │  libcrypto-1_1-x64.dll
│  │  libssl-1_1-x64.dll
│  │  main.cpp    //B's source file
│  │  
│  └─B
│          Hpk.hash  //the H(Apubkey) data
│          
└─Lib
    └─OpenSSL   //openSSL lib
```