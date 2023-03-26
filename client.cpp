#include <iostream>
#include <WinSock2.h>
#include <thread>
#include "protocol.h"
#include "aes.h"

#include <fstream>
#include <cstdlib>
#include <time.h>
#include "RSA/bigInt.h"
#include "RSA/gcd.h"
#include "RSA/mrTest.h"
#include "RSA/power.h"
#include "RSA/random.h"
#pragma comment(lib, "ws2_32.lib")
typedef unsigned char uchar;
using namespace std;

class client
{
private:
    int endflag = 1;
    int act; // 1:active，2：passive

    int text[4][4];     // temp array for AES
    int key[4][4];      // AES key
    MsgStruct msg_send; // msg to send or recv
    MsgStruct msg_recv;

    WSADATA wdata;
    SOCKET sock_Client;
    u_short Active_port = 6666; // network
    u_short Passive_port = 6667;
    DWORD Active_ip = inet_addr("127.0.0.1");
    DWORD Passive_ip = inet_addr("127.0.0.2");
    SOCKADDR_IN address_des;
    SOCKADDR_IN address_my;
    int addlen = sizeof(address_des);

public:
    client();
    ~client()
    {
        closesocket(sock_Client);
        WSACleanup();
    }
    void working();
    void recvmsg(SOCKET myskt);
    void packmsg(int ctrl, char *msg); // pack msg and AES encrypt
    void decode_msg();                 // AES decode
    void aes_encode(uchar a[16]);
    void aes_decode(uchar a[16]);

    void RSA_keygen();
    void RSA_decrypt(string aeskey);
    string RSA_encrypt(string src);
};

int main()
{
    client myclient;
    myclient.working();
}

client::client()
{
    if (WSAStartup(MAKEWORD(2, 2), &wdata))
    {
        cout << "init fail\n";
        WSACleanup();
        return;
    }

    sock_Client = socket(AF_INET, SOCK_DGRAM, 0); // Ipv4,UDP
    if (sock_Client == -1)
    {
        cout << "Socket fail";
        WSACleanup();
        return;
    }

    printf("\nPlease select your state:Active one--1,Passive one--2\n");
    cin >> act;
    switch (act)
    {
    case 2: // passively waiting for connection
    {
        address_my.sin_family = AF_INET;              // Ipv4
        address_my.sin_addr.S_un.S_addr = Passive_ip; // addr
        address_my.sin_port = Passive_port;           // Port
        bind(sock_Client, (SOCKADDR *)&address_my, sizeof(SOCKADDR));

        address_des.sin_addr.S_un.S_addr = Active_ip;
        address_des.sin_family = AF_INET;
        address_des.sin_port = Active_port;
        printf("\nPassive init success!\nwaiting for AES key...\n");
        break;
    }
    case 1: // connect client actively
    {
        address_my.sin_family = AF_INET;             // Ipv4
        address_my.sin_addr.S_un.S_addr = Active_ip; // addr
        address_my.sin_port = Active_port;           // Port

        address_des.sin_addr.S_un.S_addr = Passive_ip;
        address_des.sin_family = AF_INET;
        address_des.sin_port = Passive_port;
        bind(sock_Client, (SOCKADDR *)&address_my, sizeof(SOCKADDR));

        printf("\nRandom AES key:\n"); // generate random aes key
        memset(&msg_send, 0, sizeof(msg_send));
        string aes_key;
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                key[i][j] = rand() % 255;
                aes_key.append(1, key[i][j] / 100 + '0'); // number to string,so we can decode successfully
                aes_key.append(1, (key[i][j] % 100) / 10 + '0');
                aes_key.append(1, key[i][j] % 10 + '0');
                aes_key.append(1, ' ');
                printf("%d ", key[i][j]);
            }
        }
        string key_send = RSA_encrypt(aes_key);
        for (int i = 0; i < key_send.length(); i++)
        {
            msg_send.MsgBuf[i] = (uchar)key_send[i];
        }
        msg_send.ctrl = MyAES_key;
        msg_send.MsgLen=key_send.length();
        printf("\nAES key has been encrypted,msg length:%d\n",msg_send.MsgLen);
        if (sendto(sock_Client, (char *)&msg_send, sizeof(msg_send), 0, (struct sockaddr *)&address_des, addlen) == -1)
        {
            WSACleanup();
            printf("sending AES key fail");
            return;
        }
        else
        {
            printf("\nsend AES key to client succeed\n");
        }

        printf("\nActive init succeed!\n");
        break;
    }
    default:
        printf("\nerror input,pls restart\n");
        break;
    }
}

void client::working()
{
    thread t_recvmsg(recvmsg, this, sock_Client); // new thread to receive msg
    t_recvmsg.detach();
    while (endflag)
    {
        printf("\nPlease input:0--exit;1--send msg(max:512 byte);2--regenerate RSA key(need restart)\n@user $> ");
        int select;
        cin.sync();
        cin >> select;
        switch (select)
        {
        case 0:
            endflag = 0;
            printf("\nExited!\n");
            break;
        case 1:
        {
            char msg[256] = {0};
            cin.sync();
            cin.get(msg, 256);
            packmsg(Crypt_Msg, msg);
            if (sendto(sock_Client, (char *)&msg_send, sizeof(msg_send), 0, (struct sockaddr *)&address_des, addlen) == -1)
            {
                WSACleanup();
                printf("\nsend data fail,pls restart\n");
                return;
            }
            else
            {
                printf("\nsend success\n");
            }
            break;
        }
        case 2:
            RSA_keygen();
            break;
        default:
            printf("\nerror input\n");
            break;
        }
    }
    Sleep(500);
}

void client::recvmsg(SOCKET myskt)
{
    while (endflag)
    {
        if (recvfrom(sock_Client, (char *)&msg_recv, sizeof(msg_recv), 0, (struct sockaddr *)&address_des, &addlen) == -1)
        {
            WSACleanup();
            cout << "\nrecv data fail" << endl;
            break;
        }
        printf("\nRec Msg!\n");
        switch (msg_recv.ctrl)
        {
        case Error_Msg:
            printf("\nerror msg\n");
            break;
        case Plain_Msg:
        {
            printf("\nreceived plain msg:\n%s\n", msg_recv.MsgBuf);
            break;
        }
        case Crypt_Msg:
        {
            printf("\nreceived encrypted msg,len:%d,trying to decode:\n", msg_recv.MsgLen);
            decode_msg();
            break;
        }
        case MyAES_key:
        {
            printf("\nAES key received!starting decode...\n"); // convert uchar to char.
            string aes_key;
            for (int i = 0; i < msg_recv.MsgLen; i++)
            {
                aes_key.append(1, (char)msg_recv.MsgBuf[i]);
            }
            RSA_decrypt(aes_key);
            // printf("\n");
            break;
        }
        }
    }
}

void client::aes_decode(uchar ipt_msg[16]) // only for 128 bits msg, saving result in text[][]
{
    // printf("\nencrypted msg(ascii):\n");
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            text[i][j] = (int)ipt_msg[i * 4 + j];
            // printf("%d ", text[i][j]);
        }
    }

    Decode(text, key);
    return;
}

void client::aes_encode(uchar ipt_msg[16]) // only for 128 bits msg, saving result in text[][]
{
    // printf("\ninit(plain) msg:\n");
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            text[i][j] = (int)ipt_msg[i * 4 + j];
            // printf("%d ", (int)ipt_msg[i * 4 + j]);
        }
    }

    Encode(text, key);
    // cout << "\nEncoding success,encrypted msg:\n";
    // for (int i = 0; i < 4; i++)
    // {
    //     for (int j = 0; j < 4; j++)
    //     {
    //         cout << text[i][j] << " ";
    //     }
    // }
    cout << endl;
    return;
}

void client::packmsg(int ctrl, char *msg)
{
    memset(&msg_send, 0, sizeof(msg_send));
    msg_send.ctrl = ctrl;
    msg_send.MsgLen = strlen(msg);
    int round = msg_send.MsgLen / 16 + (msg_send.MsgLen % 16 == 0 ? 0 : 1); // long msg,need AES-CBC encrypt
    uchar msg_temp[16];
    uchar init_vector[16]; // init vetor for CBC of AES
    memcpy(msg_temp, msg, 16);
    aes_encode(msg_temp);
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
            msg_send.MsgBuf[4 * i + j] = (uchar)text[i][j];
    }
    if (round > 1) // need AES-CBC
    {
        for (int i = 1; i < round; i++)
        {
            memcpy(init_vector, msg_send.MsgBuf + (i - 1) * 16, 16); // IV=last encrypt msg
            memcpy(msg_temp, msg + 16 * i, 16);                      // put the next group to msg_temp
            for (int j = 0; j < 16; j++)
            {
                msg_temp[j] = (msg_temp[j] ^ init_vector[j]); // XOR by bits
            }
            aes_encode(msg_temp);
            for (int m = 0; m < 4; m++)
            {
                for (int n = 0; n < 4; n++)
                    msg_send.MsgBuf[16 * i + m * 4 + n] = text[m][n];
            }
            // printf("\nEncrypt round %d succeed\n", i + 1);
        }
    }
    printf("msg has been packed successfully,ctrl:%d,len:%d\n", ctrl, msg_send.MsgLen);
}

void client::decode_msg()
{
    int round = msg_recv.MsgLen / 16 + (msg_recv.MsgLen % 16 == 0 ? 0 : 1); // long msg,need AES-CBC encrypt
    uchar msg_temp[16];
    uchar init_vector[16]; // init vetor for CBC of AES
    memcpy(msg_temp, msg_recv.MsgBuf, 16);
    aes_decode(msg_temp);
    printf("\n");
    for (int m = 0; m < 4; m++)
    {
        for (int n = 0; n < 4; n++)
            printf("%c", (uchar)text[m][n]); // the first group is not XORed
    }
    if (round > 1) // need AES-CBC
    {
        for (int i = 1; i < round; i++)
        {
            memcpy(init_vector, msg_recv.MsgBuf + (i - 1) * 16, 16); // IV=last encrypt msg
            memcpy(msg_temp, msg_recv.MsgBuf + 16 * i, 16);          // put the next group to msg_temp
            aes_decode(msg_temp);
            // printf("\n");
            for (int m = 0; m < 4; m++)
            {
                for (int n = 0; n < 4; n++)
                    printf("%c", (uchar)text[m][n] ^ init_vector[4 * m + n]); // now we need recover XORed text
            }
        }
    }
    printf("\n\nmsg has been decoded successfully,len:%d\n@user $> ", msg_recv.MsgLen);
}

void client::RSA_decrypt(string aes_key)
{
    bigInt c(aes_key);
    bigInt d, n;
    ifstream i("./RSA/prikey.txt");
    i >> n >> d;
    i.close();
    clock_t start, finish;
    cout << "AES key is been decrypting...len:" <<aes_key.length()<< endl;
    start = clock();
    bigInt text = power(c, d, n);
    // cout << "plain is:" << text << endl;
    string my_key = bigInt2string(text);
    cout << "128 bits AES key(dec):\n" << my_key << endl;
    finish = clock();
    cout << "decryption costs " << finish - start << "ms \n";
    ;
    printf("\nSaving AES key..\n");
    ;
    int str_ptr = 0; // ptr to aes key
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            int temp = 0;
            for (int k = 0; k < 3; k++)
            {
                temp += int(my_key.c_str()[str_ptr] - '0');
                // the aes key is saved as string which is divided by space,such as:000 111 222
                str_ptr++;
                if (k < 2)
                    temp *= 10;
            }
            str_ptr++; // this is the space
            key[i][j] = temp;
            printf("%d ", key[i][j]);
        }
    }
    printf("\n@user $> ");
}

string client::RSA_encrypt(string src)
{
    bigInt b = string2bigInt(src);
    bigInt e, n;
    ifstream i("./RSA/pubkey.txt");
    i >> n >> e;
    i.close();
    clock_t start, finish;
    cout << "\nAES key is been encrypting..." << endl;
    start = clock();
    bigInt c = power(b, e, n);
    finish = clock();
    // cout << "cipher is:" << c << endl;
    cout << "encryption costs " << finish - start << "ms \n";
    // cout<<c.getnum();
    return c.getnum(); // return the num string
}

void client::RSA_keygen()
{
    ofstream o1("./RSA/pubkey.txt");
    ofstream o2("./RSA/prikey.txt");
    setRandom(time(NULL));
    clock_t start, finish;

    cout << "generating p and q...(this may take a minites)" << endl;
    start = clock();
    bigInt p, q;
    p = createprime();
    q = createprime();
    while (p == q)
        q = createprime();
    finish = clock();
    cout << "generate p and q costs " << finish - start << "ms \n";

    bigInt n = p * q;
    bigInt fai = (p - bigInt("1")) * (q - bigInt("1"));

    cout << "generating d and e..." << endl;
    bigInt d, e;
    start = clock();
    d = bigInt("3");
    while (!(gcd(d, fai) == bigInt("1")))
        d = d + bigInt("2");
    e = inv(d, fai);
    finish = clock();
    cout << "generate d and e costs " << finish - start << "ms \n";

    o1 << n << " " << e;
    o2 << n << " " << d << " " << p << " " << q;
    printf("\ngen RSA succeed\n");
    o1.close();
    o2.close();
    ;
}