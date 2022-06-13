#ifndef __SDB_HPP
#define __SDB_HPP
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <cstring>
#include <capstone/capstone.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <sstream>

using namespace std;

#define WORD 8
#define DISASM_INS 10
#define ELF_ENTRY_POINT_OFFSET 0x18
#define ELF_ENTRY_POINT_SIZE 0x08
#define ELF_HEADER_SIZE 0x40

typedef enum {
    not_load,
    loaded,
    running,
    terminated,
} sdb_state;

typedef enum {
    vm_region,
    vm_flags,
    vm_pgoff,
    vm_dev,
    vm_node,
    vm_path,
} vmmap_list;

typedef struct break_point {
    unsigned long long addr;
    int id;
    unsigned char orig_content;
} break_point;

typedef struct arguments {
    string script;
    string prog_path;
    bool is_script;
    bool is_invalid;
} arguments;

typedef struct prog_info {
    sdb_state state;
    unsigned long long entry_point;
    string loaded_prog;
    pid_t pid;
    unsigned long long text_start;
    unsigned long long text_end;
    vector<break_point> bps;
    int bp_id;
} prog_info;

using namespace std;

typedef void (*func_ptr)(vector<string> args);

void set_bp(vector<string>);
void cont(vector<string>);
void delete_bp(vector<string>);
void disasm(vector<string>);
void dump(vector<string>);
void exit(vector<string>);
void get_reg(vector<string>);
void get_all_regs(vector<string>);
void help(vector<string>);
void list_bp(vector<string>);
void load(vector<string>);
void run(vector<string>);
void vmmap(vector<string>);
void set_reg(vector<string>);
void single_step(vector<string>);
void start(vector<string>);
#endif