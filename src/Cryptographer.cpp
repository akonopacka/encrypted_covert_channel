//
// Created by root on 02/11/2020.
//

#include "../include/Cryptographer.h"


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
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE
string Cryptographer::encrypt(string plaintext){
    cout<<"Encrypting with method "<<method<<endl;

    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   msg[KEY_LENGTH/8];  // Message to encrypt
    char   *encrypt = NULL;    // Encrypted message
    char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages


    // Generate key pair
    printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    fflush(stdout);
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = static_cast<char *>(malloc(pri_len + 1));
    pub_key = static_cast<char *>(malloc(pub_len + 1));

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

#ifdef PRINT_KEYS
    printf("\n%s\n%s\n", pri_key, pub_key);
#endif
    printf("done.\n");

//    // Get the message to encrypt
//    printf("Message to encrypt: ");
//    fgets(msg, KEY_LENGTH-1, stdin);
//    msg[0]='a';
//    msg[strlen(msg)-1] = '\0';

    strcpy(msg, plaintext.c_str());

    // Encrypt the message
    encrypt = static_cast<char *>(malloc(RSA_size(keypair)));
    int encrypt_len;
    err = static_cast<char *>(malloc(130));
    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
//        goto free_stuff;
    }

    // Decrypt it
    decrypt = static_cast<char *>(malloc(encrypt_len));
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
    }
    printf("Decrypted message: %s\n", decrypt);

    cout<<"koni"<<endl;

//    free_stuff:
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);


    if (method=="aes"){
        return encrypt_aes(plaintext);
    }
    else if (method=="des"){
        return encrypt_des(plaintext);
    }
    else if (method=="present"){
        return encrypt_present(plaintext);
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

    cout<<"Message: "<<plaintext_<<" Encrypted: ";

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
//    int code_mode = strcmp("c", "c");
//    if (code_mode == 0) {
//        printf("Coding %s\n", "c.txt");
//    } else {
//        printf("Decoding %s\n", "d.txt");
//    }
//
//    FILE* fp_src = fopen("c.txt", "rb");
//    if (fp_src == NULL) {
//        perror("Can't open src file");
//    }
//    FILE* fp_key = fopen("d.txt", "rb");
//    if (fp_key == NULL) {
//        perror("Can't open key file");
//    }
//    FILE* fp_result = fopen("result", "wb");
//    if (fp_result == NULL) {
//        perror("Can't create resulting file");
//    }
//
//    uint32_t input_block[4] = {0, 0, 0, 0};
//    uint32_t key_block[4] = {0, 0, 0, 0};
//
//    fread(key_block, sizeof(uint32_t), 4, fp_key);
//
//    uint32_t white_keys[4];
//    uint32_t round_keys[36];
//
//    generate_keys(key_block, white_keys, round_keys);
//
//    uint32_t result_block[4];
//
//    printf("Size of input file: %d\n", fsize(fp_src) * 8);
//    while (!feof(fp_src)) {
//        memset(input_block, 0, sizeof(uint32_t) * 4);
//        //Set blocks to 0
//
//        size_t read = fread(input_block, sizeof(uint32_t), 4, fp_src);
//        if (read == 0) {
//            continue;
//        }
//        printf("Read: %d\n", read * sizeof(uint32_t) * 8);
//        //Read blocks from file
//
//        if (code_mode == 0) {
//            crypt_white(input_block, round_keys, white_keys, result_block);
//        } else {
//            decrypt_white(input_block, round_keys, white_keys, result_block);
//        }
//
//        fwrite(result_block, sizeof(uint32_t), 4, fp_result);
//    }
//
//    fclose(fp_key);
//    fclose(fp_src);
//    fclose(fp_result);

    return "s";
}

string Cryptographer::decrypt_clefia(string ciphertext_bin){
    return "s";
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