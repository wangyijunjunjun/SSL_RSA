# SSL_RSA


三者之间的关系:
openssl是一个工具包,一个程序,用来生成rsa,des需要的密钥和公钥

des 对称加密:
需要对加密和解密使用相同密钥的加密算法。由于其速度快，对称性加密通常在消息发送方需要加密大量数据时使用。对称性加密也称为密钥加密。
所谓对称，就是采用这种加密方法的双方使用方式用同样的密钥进行加密和解密。密钥是控制加密及解密过程的指令。算法是一组规则，规定如何进行加密和解密。
因此[1]  加密的安全性不仅取决于加密算法本身，密钥管理的安全性更是重要。因为加密和解密都使用同一个密钥，如何把密钥安全地传递到解密者手上就成了必须要解决的问题。


rsa是非对称加密,公钥公开,私钥自持,其主要有两个使用场景:

1)通常使用私钥对摘要进行加密，然后把加密后的摘要追加到明文的后面，再使用对称密钥对明文和摘要进行整体加密。假如a为私钥拥有者，那么接收者b拿到密文后，可以用对称密钥解密，
使用公钥对摘要进行解密，通过对比摘要，可以证明密文是否被篡改，也可以证明密文是否来自私钥的拥有者a，这也就是验签。

2)传输对称算法的密匙:
但RSA存在计算效率低的问题，所以一般的做法是使用对称密钥加密数据，然后再把这个只在当前有效的临时生成的对称密钥用非对称密钥的公钥加密之后传递给目标方，目标方使用约定好的非对称密钥中的私钥解开，
得到数据加密的密钥，再进行数据解密，得到数据，这种使用方式很常见，可以认为是对HTTPS的裁剪。对称密钥加密可以选择AES，比DES更优秀。


     RSA加解密需要先用openssl工具生成RSA公钥和RSA私钥。方法：
1、产生私钥：openssl genrsa -out privkey.pem 1024；
2、根据私钥产生公钥：openssl rsa -in privkey.pem -pubout。
1024只是测试用，使用2048位才比较安全。
     RSA加密部分代码demo：
复制代码
    std::string EncodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )
    {
        if (strPemFileName.empty() || strData.empty())
        {
            assert(false);
            return "";
        }
        FILE* hPubKeyFile = NULL;
        if(fopen_s(&hPubKeyFile, strPemFileName.c_str(), "rb") || hPubKeyFile == NULL)
        {
            assert(false);
            return ""; 
        }
        std::string strRet;
        RSA* pRSAPublicKey = RSA_new();
        if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
        {
            assert(false);
            return "";
        }

        int nLen = RSA_size(pRSAPublicKey);
        char* pEncode = new char[nLen + 1];
        int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            strRet = std::string(pEncode, ret);
        }
        delete[] pEncode;
        RSA_free(pRSAPublicKey);
        fclose(hPubKeyFile);
        CRYPTO_cleanup_all_ex_data(); 
        return strRet;
    }
复制代码
     RSA解密部分代码demo：
复制代码
    std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )
    {
        if (strPemFileName.empty() || strData.empty())
        {
            assert(false);
            return "";
        }
        FILE* hPriKeyFile = NULL;
        if(fopen_s(&hPriKeyFile, strPemFileName.c_str(),"rb") || hPriKeyFile == NULL)
        {
            assert(false);
            return "";
        }
        std::string strRet;
        RSA* pRSAPriKey = RSA_new();
        if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
        {
            assert(false);
            return "";
        }
        int nLen = RSA_size(pRSAPriKey);
        char* pDecode = new char[nLen+1];

        int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
        if(ret >= 0)
        {
            strRet = std::string((char*)pDecode, ret);
        }
        delete [] pDecode;
        RSA_free(pRSAPriKey);
        fclose(hPriKeyFile);
        CRYPTO_cleanup_all_ex_data(); 
        return strRet;
    }
复制代码
     RSA的API中当使用参数RSA_PKCS1_PADDING时，明文长度不能大于密文长度-11；当使用参数RSA_NO_PADDING时，明文长度需要正好是128。
     AES加密部分代码：
复制代码
    std::string EncodeAES( const std::string& password, const std::string& data )
    {
        AES_KEY aes_key;
        if(AES_set_encrypt_key((const unsigned char*)password.c_str(), password.length() * 8, &aes_key) < 0)
        {
            assert(false);
            return "";
        }
        std::string strRet;
        std::string data_bak = data;
        unsigned int data_length = data_bak.length();
        int padding = 0;
        if (data_bak.length() % AES_BLOCK_SIZE > 0)
        {
            padding =  AES_BLOCK_SIZE - data_bak.length() % AES_BLOCK_SIZE;
        }
        data_length += padding;
        while (padding > 0)
        {
            data_bak += '\0';
            padding--;
        }
        for(unsigned int i = 0; i < data_length/AES_BLOCK_SIZE; i++)
        {
            std::string str16 = data_bak.substr(i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            unsigned char out[AES_BLOCK_SIZE];
            ::memset(out, 0, AES_BLOCK_SIZE);
            AES_encrypt((const unsigned char*)str16.c_str(), out, &aes_key);
            strRet += std::string((const char*)out, AES_BLOCK_SIZE);
        }
        return strRet;
    }
复制代码
     AES解密部分代码：
复制代码
    std::string DecodeAES( const std::string& strPassword, const std::string& strData )
    {
        AES_KEY aes_key;
        if(AES_set_decrypt_key((const unsigned char*)strPassword.c_str(), strPassword.length() * 8, &aes_key) < 0)
        {
            assert(false);
            return "";
        }
        std::string strRet;
        for(unsigned int i = 0; i < strData.length()/AES_BLOCK_SIZE; i++)
        {
            std::string str16 = strData.substr(i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            unsigned char out[AES_BLOCK_SIZE];
            ::memset(out, 0, AES_BLOCK_SIZE);
            AES_decrypt((const unsigned char*)str16.c_str(), out, &aes_key);
            strRet += std::string((const char*)out, AES_BLOCK_SIZE);
        }
        return strRet;
    }
复制代码
     AES加密，块大小必须为128位（16字节），如果不是，则要补齐，密钥长度可以选择128位、192位、256位。
 
     不同语言解密补充：
　　使用python解密的时候，public key可能要求是PKCS#1格式，而openssl是不支持的，openssl默认是x509格式的public key，为此，如果要把上边生成的public key提供给python使用，需要先从x509格式转换为PKCS#1格式。网络上的资料显示，php有一个api支持这种转换，但我没试过。由于我的私钥是2048位的，所以可以很方便的实现x509转PKCS#1，转换是可逆的，说下PKCS#1转x509的方法：首先删除head和foot的“RSA”，然后在第二行开头增加文本“MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A”，最后，对齐文本。如果私钥不是2048的怎么办呢？可以使用php的api转一下了，或者到网上查找转换的资料解决。RSA key Formats。 2013.11.27.
　　
