using namespace std;
// asymmetric keys functions
void generate_asymmetric_keys(string*, uint8_t*);
string asymmetric_encypt(const string&, uint8_t*);
string asymmetric_decrypt(const string&, string*);

// symmetric keys functions
string encrypt_symmetric(const string&, const string&);
string decrypt_symmetric(const string&, const string&);
void symmetric_key_create(string*);