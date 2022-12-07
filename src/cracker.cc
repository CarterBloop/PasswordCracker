#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "cracker.h"
#include <string>
#include <string.h>

#include <crypt.h>


/*
 * Find the four character plain-text password PASSWD given the 
 * password hash HASH.
 *
 * If the keyspace is restricted to [a..z][A..Z][0..9], i.e ALPHABET
 * is "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
 * then "Y6f0" is a valid password, but "a$^K" is not.
 */
void crackk(const char *alphabet, const char *hash, char *passwd, int i, std::atomic<bool> &done) {
    int b1 = 0;
    int b2 = 0;
    if(i < 17) {
        b1 = i * 3;
        b2 = (i+1) * 3;
    } else if(i == 17){
        b1 = 51;
        b2 = 53;
    } else if(i == 18){
        b1 = 53;
        b2 = 55;
    } else if(i == 19){
        b1 = 55;
        b2 = 57;
    } else if(i == 20){
        b1 = 57;
        b2 = 59;
    } else if(i == 21){
        b1 = 59;
        b2 = 61;
    } else if(i == 22){
        b1 = 61;
        b2 = 62;
    }
    char salt[] = {hash[0],hash[1]};
    char test[4];
    crypt_data data;
    data.initialized = 0;
    for(int i = b1; i < b2; i++) {
        for(int j = 0; j < 62; j++) {
            for(int m = 0; m < 62; m++) {
                for(int n = 0; n < 62; n++) {
                    if(done == true) {
                        return;
                    }
                    test[0] = alphabet[i];
                    test[1] = alphabet[j];
                    test[2] = alphabet[m];
                    test[3] = alphabet[n];
                    if(strcmp(crypt_r(test,salt,&data),hash) == 0) {
                        passwd[0] = test[0];
                        passwd[1] = test[1];
                        passwd[2] = test[2];
                        passwd[3] = test[3];
                        done = true;
                        return;
                    }
                }
            }
        }
    }
}

Message recieveMulticast() {

    int sockfd = socket(AF_INET,SOCK_DGRAM, 0);
    if(sockfd < 0) exit(-1);

    struct sockaddr_in server_addr;
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(get_multicast_port());

    if(bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) exit(-1);

    struct ip_mreq multicastRequest;
    multicastRequest.imr_multiaddr.s_addr = get_multicast_address(); //MULTICAST ADDRESS
    multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);

    if(setsockopt(sockfd,IPPROTO_IP,IP_ADD_MEMBERSHIP,(void *) &multicastRequest, sizeof(multicastRequest)) < 0) //JOIN MULTICAST
        exit(-1);
    
    char buffer[256];
    Message msg;
    bzero(buffer,256);
    int n = recvfrom(sockfd,(void *) &msg,sizeof(Message),0,NULL,0);
    if(n < 0) exit(-1);
    close(sockfd);
    return msg;
}

// General thread info from: 
// https://stackoverflow.com/questions/54551371/creating-thread-inside-a-for-loop-c
Message crackMsg(Message msg) {
    std::atomic<bool> done {false};
    char p[4];
    unsigned int num = ntohl(msg.num_passwds);
    for(unsigned int i = 0; i < num;i++) {
        std::vector<std::thread> ThreadVector;
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,0,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,1,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,2,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,3,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,4,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,5,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,6,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,7,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,8,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,9,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,10,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,11,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,12,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,13,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,14,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,15,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,16,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,17,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,18,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,19,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,20,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,21,std::ref(done));});
        ThreadVector.emplace_back([&](){crackk(msg.alphabet,msg.passwds[i],p,22,std::ref(done));});
        //Join Threads
        for(auto& t: ThreadVector)
        {   
            t.join();
        }
        memset(msg.passwds[i], '\0', sizeof(msg.passwds[i]));
        strcpy(msg.passwds[i],p);
        ThreadVector.clear();
        done = false;
    }
    return msg;
}

void sendBack(Message msg) {

    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // Specify server to connect to
    struct hostent *server = gethostbyname(msg.hostname);

    struct sockaddr_in serv_addr;
    bzero((char*) &serv_addr,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char*)server->h_addr,(char*)&serv_addr.sin_addr.s_addr,server->h_length);

    serv_addr.sin_port = msg.port;

    // Connect to server
    connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));

    // Send Msg
    write(sockfd, (void*)&msg, sizeof(Message));

    close(sockfd);
}


int main() {
    
    char hostname[64]; 
    gethostname(hostname, sizeof(hostname)); 
    if(strcmp(hostname,"olaf") == 0) {
        while(true) {
            Message msg = recieveMulticast();
            Message cmsg = crackMsg(msg);
            sendBack(cmsg);
        }
    }
}

