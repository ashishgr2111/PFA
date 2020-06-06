#define ENC 0
#define DEC 1
#define char unsigned char
class Des
{
public:
    int keyi[16][48], total[64], left[32], right[32], ck[28], dk[28], expansion[48], round_key[48], xor1[48], sub[32], p[32], xor2[32], temp[64],
        pc1[56], ip[64], inv_ip[64];

    char final[20000];

    void IP();
    void inverseIP();
    void PermChoice1();
    void PermChoice2();
    void round_function(int,int,bool);
    void Expansion();    
    void xor_key(int,int);
    void substitution();
    void permutation();
    void xor_left();
    void keygen();
    char *run_des(const char *,int, bool);
    char *Encrypt(const char *, bool);
    char *Decrypt(const char *);
};