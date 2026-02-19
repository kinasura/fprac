// caesar.cpp
static char current_key = 0;

extern "C" {
    void set_key(char key) {
        current_key = key;
    }

    void caesar(void* src, void* dst, int len) {
        char* s = static_cast<char*>(src);
        char* d = static_cast<char*>(dst);
        for (int i = 0; i < len; ++i) {
            d[i] = s[i] ^ current_key;
        }
    }
}