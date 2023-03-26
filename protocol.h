// ctrl字段定义
#ifndef _TEST_H_
#define _TEST_H_
const int Error_Msg = 0;
const int Crypt_Msg = 1;
const int Plain_Msg = 2;
const int MyAES_key = 3;    //RSA加密的AES key
struct MsgStruct // 512+4+4=520字节
{
    //客户端输入的控制字段
    int ctrl = Error_Msg;
    int MsgLen = 0; // 有效消息长度
    unsigned char MsgBuf[512];
};
#endif