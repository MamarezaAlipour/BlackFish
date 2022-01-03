#ifndef _BFISH_SUPPORT_H_
#define _BFISH_SUPPORT_H_

char *argvncpy(char *, char **, u_int);

#define C_STRING_LEN 64 * 1024

class c_string
{
protected:
    string *data;
    u_int len;

public:
    c_string();
    c_string(const c_string &);
    c_string(string *, ...);

    ~c_string();

    void clear();

    u_int add(const c_string &);
    u_int add(string *, ...);
    u_int add(char);

    u_int add_raw(byte *, u_int);

    u_int add_bin(byte);
    u_int add_bin(string *, byte);
    u_int add_bin(word);
    u_int add_bin(string *, word);
    u_int add_bin(dword);
    u_int add_bin(string *, dword);

    u_int add_hex(byte);
    u_int add_hex(string *, byte);
    u_int add_hex(word);
    u_int add_hex(string *, word);
    u_int add_hex(dword);
    u_int add_hex(string *, dword);

    c_string &operator=(const c_string &);
    c_string &operator=(const string *);
    c_string &operator+=(const c_string &);
    c_string &operator+=(const string *);
    c_string &operator<<(const c_string &);
    c_string &operator<<(const string *);
    bool operator==(const c_string &);
    bool operator==(const string *);

    string *get_data() const;
    u_int get_len() const;
};

/*
enum output_mode
{
    VERBOSE_1,
    VERBOSE_2,
    VERBOSE_3, VERBOSE_3_PLUS, VERBOSE_3_PLUS_PLUS,
    RAW_ISO_LAYER_2, RAW_ISO_LAYER_3, RAW_ISO_LAYER_4, RAW_ISO_LAYER_5,
    HEX_ISO_LAYER_2, HEX_ISO_LAYER_3, HEX_ISO_LAYER_4, HEX_ISO_LAYER_5
};
*/

c_string print_line();

c_string print_options_string(c_string options_string);

#endif /* _BFISH_SUPPORT_H_ */
