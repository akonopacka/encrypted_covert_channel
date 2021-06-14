//
// Created by root on 02/11/2020.
//

#include "../include/Cryptographer.h"
#define PASS "8888"
#define PUBLICKEY "../keys/pub.pem"
#define PRIVATEKEY "../keys/pri.pem"

Cryptographer::Cryptographer(const string &method) : method(method) {}

std::string string_to_hex(const std::string& in) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; in.length() > i; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(in[i]));
    }
    return ss.str();
}

std::string hex_to_string(const std::string& in) {
    std::string output;
    if ((in.length() % 2) != 0) {
        throw std::runtime_error("String is not valid length ...");
    }
    size_t cnt = in.length() / 2;
    for (size_t i = 0; cnt > i; ++i) {
        uint32_t s = 0;
        std::stringstream ss;
        ss << std::hex << in.substr(i * 2, 2);
        ss >> s;
        output.push_back(static_cast<unsigned char>(s));
    }
    return output;
}


string Cryptographer::encrypt(string plaintext){
    cout<<"Encrypting with method "<<method<<endl;

    if (method=="aes"){
        return encrypt_aes(plaintext);
    }
    else if (method=="des"){
        return encrypt_des(plaintext);
    }
    else if (method=="present"){
        return encrypt_present(plaintext);
    }
     else if (method=="rsa"){
         return encrypt_rsa(plaintext);
     }
    else if (method=="clefia"){
        return encrypt_clefia(plaintext);
    }
    else if (method=="grain"){
        return encrypt_grain(plaintext);
    }
    return "OK";
}

string Cryptographer::decrypt(string ciphertext){
    if (method=="aes"){
        return decrypt_aes(ciphertext);
    }
    else if (method=="des"){
        return decrypt_des(ciphertext);
    }
    else if (method=="present"){
        return decrypt_present(ciphertext);
    }
    else if (method=="rsa"){
        return decrypt_rsa(ciphertext);
    }
    else if (method=="clefia"){
        return decrypt_clefia(ciphertext);
    }
    else if (method=="grain"){
        return decrypt_grain(ciphertext);
    }
    return "OK";
}

string Cryptographer::encrypt_aes(string plaintext_) {

    const std::string raw_data = plaintext_;
    const std::vector<unsigned char> key_ = plusaes::key_from_string(&"EncryptionKey128"); // 16-char = 128-bit
    const unsigned char iv_[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };

    // encrypt
    const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(raw_data.size());
    std::vector<unsigned char> encrypted(encrypted_size);

    plusaes::encrypt_cbc((unsigned char*)raw_data.data(), raw_data.size(), &key_[0], key_.size(), &iv_, &encrypted[0], encrypted.size(), true);
    // fb 7b ae 95 d5 0f c5 6f 43 7d 14 6b 6a 29 15 70

    cout<<"Message: "<<plaintext_<<" \nEncrypted: ";

    for (int i= 0 ;i<  encrypted.size(); ++i) {
        cout << encrypted[i] ;
    }
    cout<<endl;
    string binaryString = "";

    for (int i= 0 ;i<  encrypted.size(); ++i) {
        binaryString +=bitset<8>(encrypted[i]).to_string();
    }
//    Checking decription
//    decrypt_aes(binaryString);
    return binaryString;
}

string bintohex(const string &s){
    string out;
    for(uint i = 0; i < s.size(); i += 4){
        int8_t n = 0;
        for(uint j = i; j < i + 4; ++j){
            n <<= 1;
            if(s[j] == '1')
                n |= 1;
        }

        if(n<=9)
            out.push_back('0' + n);
        else
            out.push_back('A' + n - 10);
    }

    return out;
}

string Cryptographer::decrypt_aes(string ciphertext_bin) {

    const std::vector<unsigned char> key_1 = plusaes::key_from_string(&"EncryptionKey128"); // 16-char = 128-bit
    const unsigned char iv_1[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    const unsigned long encrypted_size = 32;
//            plusaes::get_padded_encrypted_size(raw_data.size());
    std::vector<unsigned char> encrypted(encrypted_size);

    // decrypt
    unsigned long padded_size = 0;
    std::vector<unsigned char> decrypted(encrypted_size);

    std::stringstream sstream(ciphertext_bin);
    int i = 0;
    while (sstream.good()) {
        std::bitset<8> bits;
        sstream >> bits;
        unsigned char c;
        c = bits.to_ulong();
        encrypted[i] = c;
        i++;
    }

    plusaes::decrypt_cbc(&encrypted[0], encrypted.size(), &key_1[0], key_1.size(), &iv_1, &decrypted[0], decrypted.size(), &padded_size);
    // Hello, plusaes

    string s(decrypted.begin(), decrypted.end());
    return s;
}

static void writeOutputToFileUint64(char* outFileName, uint8_t* output, long lenght){
    FILE* fp = fopen(outFileName, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to load file.\n");
        exit(1);
    }
    fwrite(output, sizeof(uint8_t), lenght, fp);
    fclose(fp);
}

int32_t fsize(FILE *fp){
    long prev = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, prev, SEEK_SET); //go back to where we were
    return sz;
}


string Cryptographer::encrypt_clefia(string plaintext_){
    unsigned char rs[384];
    unsigned char *lookupTables[576];
    const unsigned char skey[32] = {
            0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
            0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
            0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
            0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
    };

    plaintext_.resize (16,'1');
    const unsigned char pt[16] = "12z2465896abcdF";
    strcpy((char *) pt, plaintext_.c_str() );


    unsigned char ct[16];
    unsigned char dst[16];
    unsigned char rk[8 * 26 + 16]; /* 8 bytes x 26 rounds(max) + whitening keys */
    clefia::ClefiaRandomSet(rs);
    clefia::ClefiaKeySet(rk, skey, 128);

    clefia::WBtableSet128(lookupTables,pt,rk,rs,skey);

    clefia::WBInterEnc128(ct,pt,lookupTables);
//    printf("ciphertext: "); clefia::BytePut(ct, 16);

    int r;
    /* encryption */
    r = clefia::ClefiaKeySet(rk, skey, 128);
    clefia::ClefiaEncrypt(dst, pt, rk, r);
//    printf("ciphertext: "); clefia::BytePut(dst, 16);
    string binaryString = "";
    for (unsigned char _char : dst) {
        binaryString +=bitset<8>(_char).to_string();
    }
//    decrypt_clefia(binaryString);
    return binaryString;
}

string Cryptographer::decrypt_clefia(string ciphertext_bin){
    const unsigned char skey[32] = {
            0xffU,0xeeU,0xddU,0xccU,0xbbU,0xaaU,0x99U,0x88U,
            0x77U,0x66U,0x55U,0x44U,0x33U,0x22U,0x11U,0x00U,
            0xf0U,0xe0U,0xd0U,0xc0U,0xb0U,0xa0U,0x90U,0x80U,
            0x70U,0x60U,0x50U,0x40U,0x30U,0x20U,0x10U,0x00U
    };
    unsigned char ct[16];
    unsigned char rk[8 * 26 + 16];
    int r;

    std::stringstream sstream(ciphertext_bin);
    std::string output;

    unsigned char encrypted[16];
    int i =0;
    while (sstream.good()) {
        std::bitset<8> bits;
        sstream >> bits;
        unsigned char c = (unsigned char)(bits.to_ulong());
        encrypted[i]= c;
        i++;
    }

    /* decryption */
    unsigned char decrypted[16];
    clefia::ByteCpy(ct, encrypted, 16);
    r = clefia::ClefiaKeySet(rk, skey, 128);
    clefia::ClefiaDecrypt(decrypted, encrypted, rk, r);

    std::string s = "";
    for (unsigned char c: decrypted) {
        s=s+(char)c;
    }
//    cout<< "String: "<<s<<endl;
    return s;
}

const char* hex_char_to_bin(char c)
{
    // TODO handle default / error
    switch(toupper(c))
    {
        case '0': return "0000";
        case '1': return "0001";
        case '2': return "0010";
        case '3': return "0011";
        case '4': return "0100";
        case '5': return "0101";
        case '6': return "0110";
        case '7': return "0111";
        case '8': return "1000";
        case '9': return "1001";
        case 'A': return "1010";
        case 'B': return "1011";
        case 'C': return "1100";
        case 'D': return "1101";
        case 'E': return "1110";
        case 'F': return "1111";
    }
}

string Cryptographer::encrypt_des(string plaintext_){

    char message[plaintext_.size() + 1];
    strcpy(message, plaintext_.c_str());
    string cipher;

    char key[32] = {"0E329232EA6D0D73"}, mode[3] = {"En"};
    cipher = des::des(message, key, mode);

//    cout<< "EN: " << cipher << endl;

    // TODO use a loop from <algorithm> or smth
    std::string bin;
    for(unsigned i = 0; i != cipher.length(); ++i)
        bin += hex_char_to_bin(cipher[i]);
//    cout<< "BIN: " << bin << endl;

    return bin;
}

char getHexCharacter(std::string str)
{
    if(str.compare("1111") == 0) return 'F';
    else if(str.compare("1110") == 0) return 'E';
    else if(str.compare("1101")== 0) return 'D';
    else if(str.compare("1100")== 0) return 'C';
    else if(str.compare("1011")== 0) return 'B';
    else if(str.compare("1010")== 0) return 'A';
    else if(str.compare("1001")== 0) return '9';
    else if(str.compare("1000")== 0) return '8';
    else if(str.compare("0111")== 0) return '7';
    else if(str.compare("0110")== 0) return '6';
    else if(str.compare("0101")== 0) return '5';
    else if(str.compare("0100")== 0) return '4';
    else if(str.compare("0011")== 0) return '3';
    else if(str.compare("0010")== 0) return '2';
    else if(str.compare("0001")== 0) return '1';
    else if(str.compare("0000")== 0) return '0';
    else if(str.compare("111")== 0) return '7';
    else if(str.compare("110")== 0) return '6';
    else if(str.compare("101")== 0) return '5';
    else if(str.compare("100")== 0) return '4';
    else if(str.compare("011")== 0) return '3';
    else if(str.compare("010")== 0) return '2';
    else if(str.compare("001")== 0) return '1';
    else if(str.compare("000")== 0) return '0';
    else if(str.compare("11")== 0) return '3';
    else if(str.compare("10")== 0) return '2';
    else if(str.compare("01")== 0) return '1';
    else if(str.compare("00")== 0) return '0';
    else if(str.compare("1")== 0) return '1';
    else if(str.compare("0")== 0) return '0';
}

std::string getHexRowFails(string rowresult)
{
    std::string endresult = "";
    for(int i = 0; i < rowresult.length(); i = i+4)
    {
        endresult += getHexCharacter(rowresult.substr(i,4));
    }
    return endresult;
}

string Cryptographer::decrypt_des(string ciphertext_bin){
    string cipher_hex = getHexRowFails(ciphertext_bin);
    char cstr[cipher_hex.size() + 1];
    strcpy(cstr, cipher_hex.c_str());

    char key_[32] = {"0E329232EA6D0D73"}, mode_[3] = {"De"};

    string decrypted_message = des::des(cstr, key_, mode_);
    cout<< "Decrypted message: " << decrypted_message << endl;
    return decrypted_message;
}

string Cryptographer::encrypt_present(string plaintext_){
    string p =string_to_hex(plaintext_);

// the plaintext (64 bits) in hexadecimal format
    const char *plaintext = p.c_str();
    char * p_= const_cast<char *>(plaintext);
//    the key (80 bits) in hexadecimal format\nUse lower case characters
    char *key_ = "1f1f1ffa90e329231f1f1ffa90e32923";

    //declare a pointer for the ciphertext
    char *ciphertext;

    ciphertext = encrypt_present_(p_, key_);


    printf("The ciphertext is: ");
    puts(ciphertext);

    string binaryString = "";
    string hex(ciphertext);

// hex to bin
    for (int i= 0 ;i<  hex.size(); ++i) {
        binaryString +=bitset<8>(hex[i]).to_string();
    }
// return hex string as bin
    return binaryString;
}
string Cryptographer::decrypt_present(string ciphertext_bin){
    char *key_ = "1f1f1ffa90e329231f1f1ffa90e32923";
    std::stringstream sstream(ciphertext_bin);
    std::string ciphertext_hex;
    while (sstream.good()) {
        std::bitset<8> bits;
        sstream >> bits;
        char c = char(bits.to_ulong());
        ciphertext_hex += c;
    }
    //calling the decrypt function and printing the result
    char *cstr = new char[ciphertext_hex.length() + 1];
    strcpy(cstr, ciphertext_hex.c_str());
    char * s = decrypt_present_(cstr, key_);
    string s_(s);
    cout<<hex_to_string(s_)<<endl;

    return hex_to_string(s_);
}

string Cryptographer::encrypt_rsa(string plaintext_){
    FILE *fp = NULL;
    RSA *publicRsa = NULL;
    RSA *privateRsa = NULL;
    if ((fp = fopen(PUBLICKEY, "r")) == NULL)
    {
        printf("public key path error\n");
        return "-1";
    }

    if ((publicRsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)) == NULL)
    {
        printf("PEM_read_RSA_PUBKEY error\n");
        return "-1";
    }
    fclose(fp);

    if ((fp = fopen(PRIVATEKEY, "r")) == NULL)
    {
        printf("private key path error\n");
        return "-1";
    }
//    OpenSSL_add_all_algorithms();
    if ((privateRsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, (char *)PASS)) == NULL)
    {
        printf("PEM_read_RSAPrivateKey error\n");
        return "NULL";
    }
    fclose(fp);

    unsigned char *source = (unsigned char *) plaintext_.c_str();

    int rsa_len = RSA_size(publicRsa);

    unsigned char *encryptMsg = (unsigned char *)malloc(rsa_len);
    memset(encryptMsg, 0, rsa_len);

    int len = rsa_len - 11;
    string binaryString = "";

    if (RSA_public_encrypt(len, source, encryptMsg, publicRsa, RSA_PKCS1_PADDING) < 0)
        printf("RSA_public_encrypt error\n");

    else
    {
        string s( reinterpret_cast< char const* >(encryptMsg) ) ;

        for (char& _char : s) {
            binaryString +=bitset<8>(_char).to_string();
        }
//        cout<<binaryString<<endl;
        string decrypted = decrypt_rsa(binaryString);
        cout<<"dec: "<<decrypted<<endl;
        return binaryString;
    }

    RSA_free(publicRsa);
    RSA_free(privateRsa);
    return binaryString;

}
string Cryptographer::decrypt_rsa(string ciphertext_bin){
    FILE *fp = NULL;
    RSA *publicRsa = NULL;
    RSA *privateRsa = NULL;
    if ((fp = fopen("../keys/pub.pem", "r")) == NULL)
    {
        printf("public key path error\n");
        return "-1";
    }

    if ((publicRsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)) == NULL)
    {
        printf("PEM_read_RSA_PUBKEY error\n");
        return "-1";
    }
    fclose(fp);

    if ((fp = fopen(PRIVATEKEY, "r")) == NULL)
    {
        printf("private key path error\n");
        return "-1";
    }
    if ((privateRsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, (char *)PASS)) == NULL)
    {
        printf("PEM_read_RSAPrivateKey error\n");
        return "NULL";
    }
    fclose(fp);
    OpenSSL_add_all_algorithms();
    int rsa_len = RSA_size(publicRsa);

    rsa_len = RSA_size(privateRsa);
    unsigned char *decryptMsg = (unsigned char *)malloc(rsa_len);
    memset(decryptMsg, 0, rsa_len);

    unsigned char *encryptMsg = (unsigned char *)malloc(rsa_len);

    std::stringstream sstream(ciphertext_bin);
    std::string output;
    while (sstream.good()) {
        std::bitset<8> bits;
        sstream >> bits;
        unsigned char c = (unsigned char)(bits.to_ulong());
        output += c;
    }

    unsigned char *val=new unsigned char[output.length()+1];
    strcpy((char *)val,output.c_str());
    encryptMsg = val;

    int mun =  RSA_private_decrypt(rsa_len, encryptMsg, decryptMsg, privateRsa, RSA_PKCS1_PADDING);


    if ( mun < 0){
        printf("RSA_private_decrypt error\n");
        return "";
    }
    else
    {
//        printf("RSA_private_decrypt %s\n", decryptMsg);
//        printf("RSA_public_encrypt %s\n", encryptMsg);
        string s_(reinterpret_cast<char*>(decryptMsg));
        return s_;
    }
}

string Cryptographer::encrypt_grain(string plaintext_){

    int i =0;
    int plaintext[10];
    for(i=0;i<10; i++){
        if(i<plaintext_.length())
            plaintext[i]=(int) plaintext_[i];
        else
            plaintext[i]=0;
    }

//    int plaintext[10]={0xa3,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x02};
//    plaintext = text;
    int encrypted_text[10];
    int decrypted_text[10];

    grain mygrain;
    int ks[10];

    int key2[10] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x12,0x34},
            IV2[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};

    grain mygrain2 = mygrain;
    keysetup(&mygrain,key2,80,64);
    ivsetup(&mygrain,IV2);
    keystream_bytes(&mygrain,ks,10);
    mygrain2 = mygrain;
    encrypt_bytes(&mygrain,plaintext,encrypted_text,10);

//     from int array to bin string
    string ciphertext_bin = "";
    for (int j:encrypted_text){
        std::string binary = std::bitset<8>(j).to_string();
        ciphertext_bin = ciphertext_bin + binary;
    }
//    decrypt_grain(ciphertext_bin);

    return ciphertext_bin;
}

string Cryptographer::decrypt_grain(string ciphertext_bin){
    int encrypted_text[10];
    int decrypted_text[10];


    int ks[10];

    int key2[10] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x12,0x34},
            IV2[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    grain mygrain;
    keysetup(&mygrain,key2,80,64);
    ivsetup(&mygrain,IV2);
    keystream_bytes(&mygrain,ks,10);

    std::stringstream sstream(ciphertext_bin);
    std::string output;
    int encrypted_text_[10];
    memset(encrypted_text_, 0, sizeof(encrypted_text_));
    int j = 0;
    cout<<endl;
    while (sstream.good()) {
        std::bitset<8> bits;
        sstream >> bits;
        int c = (bits.to_ulong());
        encrypted_text_[j]=c;
        j++;
//        output += c;
    }

    decrypt_bytes(&mygrain,encrypted_text_,decrypted_text,10);
    string text = "";

    for (int k: decrypted_text){
        text = text + (char) k;
    }

//    cout<<endl<<"message:"<<text<<endl;
    return text;
}