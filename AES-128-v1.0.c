//gcc 7.4.0
#include  <stdio.h>
#include  <string.h>
#include  <ctype.h>

#define Nb 4 //加解密数据块大小，固定为4

//加密类型对应的密匙长度，单位bit
typedef enum {
    AES128 = 128,
    AES192 = 192,
    AES256 = 256,
} AESType_t;

//加解密模式
typedef enum {
    AES_MODE_ECB = 0,   // 电子密码本模式
    AES_MODE_CBC = 1,   // 密码分组链接模式
} AESMode_t;

typedef struct {
    int Nk;  //用户不需要填充，密钥长度，单位字节, AES128:Nk=16、AES192:Nk=24、AES256:Nr=32
    int Nr;  //用户不需要填充，加密的轮数 AES128:Nr=10、AES192:Nr=12、AES256:Nr=14
    int type;//用户需填充，关联AESType_t
    int mode;//用户需填充，关联AESMode_t
    const void *key;//用户需填充，密匙
    const void *pIV;//用户需填充，初始化向量, 当mode=AES_MODE_CBC时需要设置，指向unsigned char IV[4*Nb];
    //AES拓展密匙, 空间大小 AES128:4*Nb*(10+1):4*Nb*(12+1)、AES256:4*Nb*(14+1)
    unsigned char expandKey[4*Nb*(14+1)];//用户不需要填充，[4*Nb*(Nr+1)]、这里按最大的AES256进行初始化
} AESInfo_t;

//秘钥，根据实际情况自己定义，AES128 用16字节、AES192 用24字节、AES256 用32字节
unsigned char aes_key[16]/*= {'a','s','d','f','+','-','*','/','h','j','k','m',5,6,7,8}*/;
/*unsigned char key[32] = {	0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x41,0x42,0x43,0x44,0x45,0x46,	0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x41,0x42,0x43,0x44,0x45,0x46
};
*/

//初始化向量, 固定长度16个, 当mode=AES_MODE_CBC时用到
// unsigned char IV[4*Nb] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x41,0x42,0x43,0x44,0x45,0x46};
unsigned char aes_IV[16] = {'q','w','e','r','t','y','u','i','o','p','g','b',51,53,55,59};

//设置加密方式、密匙
AESInfo_t aesInfo = {
	.type = AES128,
	.mode = AES_MODE_CBC,
	.key = aes_key,
    .pIV = aes_IV
};


// GF(2^8) 多项式
#define BPOLY 0x1B //x^4 + x^3 + x^1 + x^0= 从右边开始算，bit0、bit1、bit3、bit4、为1，bit2、bit5、bit6、bit7为0，即00011011=0x1B

/*
SubstituteBytes()
加密时：使用S盒，将待加密数据为S盒索引将加密数据替换为S盒的内容
解密时：使用逆S盒，将已加密数据为逆S盒索引将已加密数据替换为逆S盒子的内容
其实就是将数据按表替换，
例如待加密数据unsigned char data = 9;
加密数据:encryptData = SBox[data] = SBox[9] = 0x01;//注意索引从0开始
解密数据:decryptData = InvSBox[encryptData] = InvSBox[0x01] = 9;
SBox和InvSBox的关系是 data = InvSBox[SBox[data]];还跟GF(2^8) 多项式有关
*/

// 加密用的S盒
static const unsigned char SBox[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// 解密用的SBox
static const unsigned char InvSBox[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/*****************************************************************************
*	函数名：	RShiftWord
*	功能描述：	对一个pWord 4字节数据进行循环右移。
*	输入参数：	pWord -- 要右移的4字节数据。
*	输出参数：	pWord -- 右移后的4字节数据。
*	返回值：      无。
*****************************************************************************/
static void RShiftWord(unsigned char *pWord)
{
    unsigned char temp = pWord[0];
    pWord[0]  = pWord[1];
    pWord[1]  = pWord[2];
    pWord[2]  = pWord[3];
    pWord[3]  = temp;
}

/*****************************************************************************
*	函数名：	XorBytes
*	功能描述：	异或两组数据。
*	输入参数：	pData1 -- 要异或的第一组数据。
*			   pData2 -- 要异或的第二组数据。
*			   nCount -- 参与异或的数据长度。
*	输出参数：	pData1 -- 异或后的结果。
*	返回值：    无。
*****************************************************************************/
static void XorBytes(unsigned char *pData1, const unsigned char *pData2, unsigned char nCount)
{
    unsigned char i;
    for (i = 0; i < nCount; i++) {
        pData1[i] ^= pData2[i];
    }
}

/*****************************************************************************
*	函数名：	AddKey
*	功能描述：	把 pData数据 加上（异或）pKey密钥，数据长度为16字节。
*	输入参数：	pData	  -- 数据。
*			   pKey      -- 密钥。
*	输出参数：	pStpDataate	  -- 加上子密钥后的数据。
*	返回值：	无。
*****************************************************************************/
static void AddKey(unsigned char *pData, const unsigned char *pKey)
{
    XorBytes(pData, pKey, 4 * Nb);
}

/*****************************************************************************
*	函数名：	SubstituteBytes
*	功能描述：	通过S盒子置换数据。
*	输入参数：	pData  	-- 数据。
*			   dataCnt -- 数据长度。
*			   pBox	   -- 置换盒子，加密时使用SBox, 解密时使用InvSBox
*	输出参数：	pData	-- 置换后的状态数据。
*	返回值：	无。
*****************************************************************************/
static void SubstituteBytes(unsigned char *pData, unsigned char dataCnt, const unsigned char *pBox)
{
    unsigned char i;
    for (i = 0; i < dataCnt; i++) {
        pData[i] = pBox[pData[i]];
    }
}

/*****************************************************************************
*	函数名：	ShiftRows
*	功能描述：	把状态数据移行。
*	输入参数：	pState	-- 状态数据。
*			   bInvert	-- 是否反向移行（解密时使用）。
*	输出参数：	pState	-- 移行后的状态数据。
*	返回值：	无。
*****************************************************************************/
static void ShiftRows(unsigned char *pState, unsigned char bInvert)
{
    // 注意：状态数据以列形式存放！
    unsigned char r;	// row，   行
    unsigned char c;	// column，列
    unsigned char temp;
    unsigned char rowData[4];

    for (r = 1; r < 4; r++) {
        // 备份一行数据
        for (c = 0; c < 4; c++) {
            rowData[c] = pState[r + 4*c];
        }

        temp = bInvert ? (4 - r) : r;
        for (c = 0; c < 4; c++) {
            pState[r + 4*c] = rowData[(c + temp) % 4];
        }
    }
}

/*****************************************************************************
*	函数名：	GfMultBy02
*	功能描述：	在GF(28)域的 乘2 运算。
*	输入参数：	num	-- 乘数。
*	输出参数：	无。
*	返回值：	num乘以2的结果。
*****************************************************************************/
static unsigned char GfMultBy02(unsigned char num)
{
    if (0 == (num & 0x80)) {
        num = num << 1;
    } else {
        num = (num << 1) ^ BPOLY;
    }

    return num;
}

/*****************************************************************************
*	函数名：	MixColumns
*	功能描述：	混合各列数据。
*	输入参数：	pData	 -- 数据。
*			   bInvert	-- 是否反向混合（解密时使用）。
*	输出参数：	pData	 -- 混合列后的状态数据。
*	返回值：	无。
*****************************************************************************/
static void MixColumns(unsigned char *pData, unsigned char bInvert)
{
    unsigned char i;
    unsigned char temp;
    unsigned char a0Pa2_M4;	// 4(a0 + a2)
    unsigned char a1Pa3_M4;	// 4(a1 + a3)
    unsigned char result[4];

    for (i = 0; i < 4; i++, pData += 4) {
        temp = pData[0] ^ pData[1] ^ pData[2] ^ pData[3];
        result[0] = temp ^ pData[0] ^ GfMultBy02((unsigned char)(pData[0] ^ pData[1]));
        result[1] = temp ^ pData[1] ^ GfMultBy02((unsigned char)(pData[1] ^ pData[2]));
        result[2] = temp ^ pData[2] ^ GfMultBy02((unsigned char)(pData[2] ^ pData[3]));
        result[3] = temp ^ pData[3] ^ GfMultBy02((unsigned char)(pData[3] ^ pData[0]));

        if (bInvert) {
            a0Pa2_M4 = GfMultBy02(GfMultBy02((unsigned char)(pData[0] ^ pData[2])));
            a1Pa3_M4 = GfMultBy02(GfMultBy02((unsigned char)(pData[1] ^ pData[3])));
            temp	 = GfMultBy02((unsigned char)(a0Pa2_M4 ^ a1Pa3_M4));
            result[0] ^= temp ^ a0Pa2_M4;
            result[1] ^= temp ^ a1Pa3_M4;
            result[2] ^= temp ^ a0Pa2_M4;
            result[3] ^= temp ^ a1Pa3_M4;
        }

        memcpy(pData, result, 4);
    }
}

/*****************************************************************************
*	函数名：	BlockEncrypt
*	功能描述：	对单块数据加密。
*	输入参数：	pData -- 要加密的块数据。
*	输出参数：	pData -- 加密后的块数据。
*	返回值：	无。
*****************************************************************************/
static void BlockEncrypt(AESInfo_t *aesInfoP, unsigned char *pData)
{
    unsigned char i;

    AddKey(pData, aesInfoP->expandKey);
    for (i = 1; i <= aesInfoP->Nr; i++) {
        SubstituteBytes(pData, 4 * Nb, SBox);
        ShiftRows(pData, 0);

        if (i != aesInfoP->Nr) {
            MixColumns(pData, 0);
        }

        AddKey(pData, &aesInfoP->expandKey[4*Nb*i]);
    }
}

/*****************************************************************************
*	函数名：	BlockDecrypt
*	功能描述：	对单块数据解密。
*	输入参数：	pData -- 要解密的数据。
*	输出参数：	pData -- 解密后的数据。
*	返回值：	无。
*****************************************************************************/
static void BlockDecrypt(AESInfo_t *aesInfoP, unsigned char *pData)
{
    unsigned char i;

    AddKey(pData, &aesInfoP->expandKey[4*Nb*aesInfoP->Nr]);

    for (i = aesInfoP->Nr; i > 0; i--) {
        ShiftRows(pData, 1);
        SubstituteBytes(pData, 4 * Nb, InvSBox);
        AddKey(pData, &aesInfoP->expandKey[4*Nb*(i-1)]);

        if (1 != i) {
            MixColumns(pData, 1);
        }
    }
}


/*****************************************************************************
*	函数名：	AESAddPKCS7Padding
*	描述：		PKCS7 方式填充数据
*	输入参数：	data -- 后面最多预留16个字节空间用于存放填充值
*			   len --  数据的长度
*	输出参数：	data  -- 添加填充码后的数据
*	返回值：	填充后的长度
*****************************************************************************/
static unsigned int AESAddPKCS7Padding(unsigned char *data, unsigned int len)
{
    unsigned int newLen;
    newLen = len + 16 - (len % 16);
    memset(&data[len], newLen-len, newLen-len);
    return newLen;
}

/*****************************************************************************
*	函数名：	AESDelPKCS7Padding
*	描述：		PKCS7Padding 填充密文解密后剔除填充值
*	输入参数：	pData -- 解密后的数据
*			   len --  数据的长度
*	输出参数：	pData  -- 删除填充码后的数据
*	返回值：	删除后的实际有效数据长度，为0表示传入的数据异常
*****************************************************************************/
static unsigned int AESDelPKCS7Padding(unsigned char *pData, unsigned int len)
{
    if (0 != (len & 0x0F)) {//1组16字节，(0 != (len & 0x0F)说明不是16的倍数
        return 0;
    }
    if (pData[len - 1] > len) {
        return 0;
    }

    return len - pData[len - 1];
}

/*****************************************************************************
*	函数名：	AESInit
*	功能描述：	初始化
*	输入参数：	aesInfoP -- 用户需要填充
*	输出参数：	无。
*	返回值：	无。
*****************************************************************************/
void AESInit(AESInfo_t *aesInfoP)
{

    unsigned char i;
    unsigned char *pExpandKey;//扩展密钥
    unsigned char Rcon[4] = {0x01, 0x00, 0x00, 0x00};

    switch (aesInfoP->type) {
        case AES128:
            aesInfoP->Nr = 10;
            aesInfoP->Nk = 4;
            break;
        case AES192:
            aesInfoP->Nr = 12;
            aesInfoP->Nk = 6;
            break;
        case AES256:
            aesInfoP->Nr = 14;
            aesInfoP->Nk = 8;
            break;
        default:
            aesInfoP->Nr = 10;
            aesInfoP->Nk = 4;
            break;
    }

    //拓展密匙
    memcpy(aesInfoP->expandKey, aesInfoP->key, 4 * aesInfoP->Nk);//第一个是原始密匙，
    pExpandKey = &aesInfoP->expandKey[4*aesInfoP->Nk]; //拓展密匙AES128:10个、AES192:12个、AES256:14个
    for (i = aesInfoP->Nk; i < Nb*(aesInfoP->Nr + 1); pExpandKey += 4, i++) {
        memcpy(pExpandKey, pExpandKey - 4, 4);

        if (0 == i % aesInfoP->Nk) {
            RShiftWord(pExpandKey);
            SubstituteBytes(pExpandKey, 4, SBox);
            XorBytes(pExpandKey, Rcon, 4);

            Rcon[0] = GfMultBy02(Rcon[0]);
        } else if (6 < aesInfoP->Nk && i % aesInfoP->Nk == Nb) {
            SubstituteBytes(pExpandKey, 4, SBox);
        }

        XorBytes(pExpandKey, pExpandKey - 4 * aesInfoP->Nk, 4);
    }
}

/*****************************************************************************
*	函数名：	AESEncrypt
*	功能描述：	加密数据
*	输入参数：  aesInfoP    -- 包含key、加密方式等初始化信息
*              pPlainText   -- 要加密的明文数据，其长度为dataLen字节。
*			    dataLen	   -- 明文数据长度，以字节为单位
*	输出参数：	pCipherText	-- 加密后的数据
*	返回值：	解密后的数据长度。
*****************************************************************************/
unsigned int AESEncrypt(AESInfo_t *aesInfoP, const unsigned char *pPlainText, unsigned char *pCipherText,
                 unsigned int dataLen)
{
    unsigned int i;
    const void *pIV;

    if (pPlainText != pCipherText) {
        memcpy(pCipherText, pPlainText, dataLen);
    }

    //必须是16的整倍数，不够的填充，pkcs7算法是缺n补n个n，比如13字节数据缺了3个，后面就补3个3;如果刚好是16的倍数，就填充16个16
    dataLen = AESAddPKCS7Padding(pCipherText, dataLen);//注意如果是使用NOpadding方式，则此句注释掉即可，同时解密函数对应的AESDelPKCS7Padding()函数也需一同注释掉。

    pIV = aesInfoP->pIV;
    for (i = dataLen / (4 * Nb); i > 0 ; i--, pCipherText += 4 * Nb) {
        if (AES_MODE_CBC == aesInfoP->mode) {
            XorBytes(pCipherText, pIV, 4 * Nb);
        }

        BlockEncrypt(aesInfoP, pCipherText);
        pIV = pCipherText;
    }
    return dataLen;
}

/*****************************************************************************
*	函数名：	AESDecrypt
*	功能描述：	解密数据
*	输入参数：	aesInfoP    -- 包含key、加密方式等初始化信息
*	            pCipherText	-- 要解密的密文
*			    dataLen	   -- 密文数据长度，以字节为单位，必须是整倍数，AES128:16倍数、AES192:24倍数、AES256:32倍数。
*  输出参数：  pPlainText  -- 解密出来的明文
*	返回值：	返回解密后的数据长度。
*****************************************************************************/
unsigned int AESDecrypt(AESInfo_t *aesInfoP, unsigned char *pPlainText, const unsigned char *pCipherText,
                 unsigned int dataLen)
{
    unsigned int i;
    unsigned char *pPlainTextBack = pPlainText;

    if (pPlainText != pCipherText) {
        memcpy(pPlainText, pCipherText, dataLen);
    }

    //当mode=AES_MODE_CBC时需要从最后一块数据开始解密
    pPlainText += dataLen - 4 * Nb;
    for (i = dataLen / (4 * Nb); i > 0 ; i--, pPlainText -= 4 * Nb) {
        BlockDecrypt(aesInfoP, pPlainText);
        if (AES_MODE_CBC == aesInfoP->mode) {
            if (1 == i) {//原来的第一块数据是初始变量加密的
                XorBytes(pPlainText, aesInfoP->pIV, 4 * Nb);
            } else {
                XorBytes(pPlainText, pPlainText - 4 * Nb, 4 * Nb);
            }
        }
    }

    //因为数据需要16字节对齐，可能有填充数据，需要去除后面的填充数据
    return AESDelPKCS7Padding(pPlainTextBack, dataLen);//注意如果是使用NOpadding方式，则此句注释掉直接return datalen即可，同时加密函数对应的AESAddPKCS7Padding()函数也需一同注释掉。

}

void PrintData(const char *head, unsigned char *data, unsigned int len)
{
    unsigned int i;

    printf("%s, len:%u:\r\n", head, len);

    //按16进制打印出来
    printf("HEX:[");
    for (i=0; i<len; i++) {
        printf("%02X ", data[i]);
    }
    printf("]\r\n");

    //按ASCII码打印出来
    printf("ASCII:[");
    for (i=0; i<len; i++) {
        if (isprint(data[i])) {//可打印字符
            printf("%c", data[i]);
        } else {
            printf("\\%02X ", data[i]);
        }

    }
    printf("]\r\n");
}


void my_aes_init(void)
{
	//初始化
    AESInit(&aesInfo);
}

//加密
void my_aes_encrypt(unsigned char* sou_data, unsigned char* enc_data,unsigned char len)
{
    unsigned char  enc_len;             //加密后的密文长度
    enc_len = AESEncrypt(&aesInfo, sou_data, enc_data, len);
    PrintData("encryptMsg", enc_data, enc_len);
}


//解密
void my_aes_decrypt(unsigned char* enc_data, unsigned char* dec_data, unsigned char len)
{
    unsigned char  dec_len;                //解密后的明文长度
    dec_len = AESDecrypt(&aesInfo, dec_data, enc_data, len);
    PrintData("decryptMsg", dec_data, dec_len);
}
//要加密的内容
unsigned char sourceMsg[128] = "hello";
//AES128启动单元
int Klen;
void my_aes_unit(void)
{
    
    unsigned char encrypt_data[513]={0};
    unsigned char decrypt_data[513]={0};
    my_aes_init();
//    PrintData("sourceMsg", sourceMsg, strlen(sourceMsg));
    printf("Please select AES128 Mode:\n1 [E]ncrypt\n2 [D]ecrypt\nEnter [E] or [D]: ");
    char symbol;
    
    scanf("%c",&symbol);
    if(symbol!='E'&&symbol!='D'){printf("ERROR\n \'%c\' IS NOT A VALID MODE!\n",symbol);}
    if(symbol=='E'){
        printf("Please input Source Message:\n");
        scanf("%s",&sourceMsg);
        PrintData("sourceMsg", sourceMsg, strlen(sourceMsg));
        my_aes_encrypt(sourceMsg,encrypt_data, strlen(sourceMsg));
    }
    if(symbol=='D'){
        printf("Please input ENCRYPTED length and Encrypted Message:\n");
        scanf("%d",&Klen);
        for (int i=0; i<Klen; ++i) {
            scanf("%02X",&encrypt_data[i]);
        }
        my_aes_decrypt(encrypt_data,decrypt_data, Klen);
    }
}
void AES_KEY_GET(){
    printf("Please input AES-KEY(16 characters long):");
    for(int i=0;i<16;++i) scanf("%c",&aes_key[i]);
    getchar();
}
int main(void)
{
    AES_KEY_GET();
    while(1){
        my_aes_unit();
        printf("Do YOU want to QUIT? Type 0 if you want to QUIT, or 1 if you want to CHANGE AES KEY:");
        int flag;
        scanf("%d",&flag);
        if(flag==0) break;
        if(flag==1) AES_KEY_GET();
    }
    return 0;
}

