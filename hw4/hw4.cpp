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
#define DISASM_LEN 10
#define ELF_ENTRY_POINT_OFFSET 0x18
#define ELF_ENTRY_POINT_SIZE 0x08
#define ELF_HEADER_SIZE 0x40
#define DUMP_SIZE 80
#define DUMP_WIDTH 16

enum sdb_state{
    not_load,
    loaded,
    running,
    terminated,
};

enum vmmap_list{
    vm_region,
    vm_flags,
    vm_pgoff,
    vm_dev,
    vm_node,
    vm_path,
};

struct break_point {
    unsigned long long addr;
    int id;
    unsigned char origin_content;
};

struct arguments {
    string script;
    string program_path;
    bool is_script;
};

struct prog_info {
    sdb_state state;
    unsigned long long entry_point;
    string loaded_prog;
    pid_t pid;
    unsigned long long text_start;
    unsigned long long text_end;
    vector<break_point> bps;
    int bp_id;
};

using namespace std;

typedef void (*func_ptr)(vector<string> args);
unordered_map<string, func_ptr> commands;

static const string state_name[] = {"not_load", "loaded", "running"};

user_regs_struct regs;

const string all_regs_list[] = {
    "rax", "rbx", "rcx", "rdx",
    "r8",  "r9",  "r10", "r11",
    "r12", "r13", "r14", "r15",
    "rdi", "rsi", "rbp", "rsp",
    "rip", "flags"
};

prog_info info = {
    .state = not_load,
    .entry_point = 0,
    .loaded_prog = "",
    .bp_id = 0,
};

#define check_state(cur)                                                                                                               \
    if (cur != info.state) {                                                                                                           \
        cerr << "** This command is valid for '" << state_name[cur] << "', but current state is '" << state_name[info.state] << "'\n"; \
        return;                                                                                                                        \
    }

#define _WIFEXITED(status)                                                                               \
    if (WIFEXITED(status)) {                                                                             \
        dprintf(STDERR_FILENO, "** child process %d terminated normally (code %d)\n", info.pid, status); \
        info.state = terminated;                                                                         \
        return;                                                                                          \
    }

#define check_text_segment(addr)                                            \
    if ((addr < info.text_start) || (addr >= info.text_end)) {              \
        cerr << "** the address is out of the range of the text segment\n"; \
        return;                                                             \
    }

#define check_argv(argv, req)                     \
    if (argv.size() < 2) {                        \
        cerr << "** no " << req << " is given\n"; \
        return;                                   \
    }

static inline void call_cmd(vector<string> argv) {
    auto it = commands.find(argv[0]);
    if (it != commands.end()) {
        it->second(argv);
    } else {
        cerr << "** command '" << argv[0] << "' not found\n";
    }
}

static vector<string> split_str(string line) {
    vector<string> ret;
    stringstream ss(line);
    string arg;
    while (ss >> arg) {
        ret.push_back(arg);
    }
    return ret;
}

static inline void err_quit(const char *msg) {
    cerr << msg << endl;
    exit(-1);
}

static unordered_map<string, unsigned long long *> _get_all_regs() {
    ptrace(PTRACE_GETREGS, info.pid, 0, &regs);

    unordered_map<string, unsigned long long *> _regs;
    _regs["r15"] = &regs.r15;
    _regs["r14"] = &regs.r14;
    _regs["r13"] = &regs.r13;
    _regs["r12"] = &regs.r12;
    _regs["rbp"] = &regs.rbp;
    _regs["rbx"] = &regs.rbx;
    _regs["r11"] = &regs.r11;
    _regs["r10"] = &regs.r10;
    _regs["r9"] = &regs.r9;
    _regs["r8"] = &regs.r8;
    _regs["rax"] = &regs.rax;
    _regs["rcx"] = &regs.rcx;
    _regs["rdx"] = &regs.rdx;
    _regs["rsi"] = &regs.rsi;
    _regs["rdi"] = &regs.rdi;
    _regs["orig_rax"] = &regs.orig_rax;
    _regs["rip"] = &regs.rip;
    _regs["cs"] = &regs.cs;
    _regs["flags"] = &regs.eflags;
    _regs["rsp"] = &regs.rsp;
    _regs["ss"] = &regs.ss;
    _regs["fs_base"] = &regs.fs_base;
    _regs["gs_base"] = &regs.gs_base;
    _regs["ds"] = &regs.ds;
    _regs["es"] = &regs.es;
    _regs["fs"] = &regs.fs;
    _regs["gs"] = &regs.gs;

    return _regs;
}

arguments parse_arg(int argc, char *argv[]) {
    int cmd_opt;
    arguments args = {
        .script = "",
        .program_path = "",
        .is_script = false,
    };

    while ((cmd_opt = getopt(argc, argv, "s:")) != -1) {
        switch (cmd_opt) {
            case 's':
                args.script = optarg;
                break;
            case '?':
                cerr << "usage: ./hw4 [-s script] [program]" << endl;
                exit(-1);
            default:
                break;
        }
    }
    if (argc > optind) args.program_path = argv[optind]; // in the last place of input

    return args;
}

static unsigned long long _stoull(string str) {
    int base = 10;
    if (!str.compare(0, 2, "0x"))
        base = 16;
    return stoull(str, NULL, base);
}

static long restore_origin_content(long raw, unsigned long long addr, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        unsigned char *check_char = &(((unsigned char *)&raw)[i]);
        if (*check_char == 0xcc) {
            for (auto bp = info.bps.begin(); bp != info.bps.end(); ++bp) {
                if (bp->addr == addr + i) *check_char = bp->origin_content;
            }
        }
    }
    return raw;
}

static void _disasm(const uint8_t *codes, size_t code_size, uint64_t addr, size_t _count) {
    static csh handle = 0;
    cs_insn *insn = NULL;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;

    size_t count = cs_disasm(handle, codes, code_size, addr, _count, &insn);
    if (count <= 0) return;
    for (size_t i = 0; i < count; ++i) {
        check_text_segment(insn[i].address);

        dprintf(STDERR_FILENO, "%12lx: ", insn[i].address);
        for (int j = 0; j < 12; ++j) {
            if (j < insn[i].size) {
                dprintf(STDERR_FILENO, "%02x ", (unsigned int)insn[i].bytes[j]);
            } else {
                dprintf(STDERR_FILENO, "   ");
            }
        }
        dprintf(STDERR_FILENO, "%-10s%s\n", insn[i].mnemonic, insn[i].op_str);
    }
    cs_free(insn, count);
}

static void print_bp() {
    auto _reg = _get_all_regs();
    long raw = ptrace(PTRACE_PEEKTEXT, info.pid, *(_reg["rip"]), 0);
    long codes = restore_origin_content(raw, *(_reg["rip"]), 1);
    dprintf(STDERR_FILENO, "** breakpoint @");
    // just disasm without restore to mem
    _disasm((uint8_t *)&codes, WORD - 1, *(_reg["rip"]), 1);
}

static bool is_encounter_cc(unsigned long long addr) {
    auto code = ptrace(PTRACE_PEEKTEXT, info.pid, addr, 0);
    return *(unsigned char *)&code == 0xcc;
}

void set_bp(vector<string> argv) {
    check_state(running);
    check_argv(argv, "addr");
    
    unsigned long long addr = _stoull(argv[1]);
    check_text_segment(addr);
    if (addr == info.entry_point) {
        cerr << "** the address should not be the same as the entry point\n";
        return;
    }

    auto code = ptrace(PTRACE_PEEKTEXT, info.pid, addr, 0);
    break_point new_bp = {addr, info.bp_id++, (unsigned char)code};
    info.bps.push_back(new_bp);
    // Software Breakpoint: INT3(0xcc)
    ptrace(PTRACE_POKETEXT, info.pid, addr, (code & 0xffffffffffffff00) | 0xcc);
}

void delete_bp(vector<string> argv) {
    check_state(running);
    check_argv(argv, "id");

    int target_id = stoi(argv[1], NULL, 10);
    auto bp = std::find_if(info.bps.begin(), info.bps.end(), [target_id](const break_point& bp) { return bp.id == target_id; });
    if (bp != info.bps.end()) {
        auto code = ptrace(PTRACE_PEEKTEXT, info.pid, bp->addr, nullptr);
        ptrace(PTRACE_POKETEXT, info.pid, bp->addr, (code & 0xffffffffffffff00) | bp->origin_content); // replace 0xcc
        info.bps.erase(bp);
        dprintf(STDERR_FILENO, "** breakpoint %d deleted.\n", target_id);
    } else {
        dprintf(STDERR_FILENO, "** breakpoint %d is not exist.\n", target_id);
    }
}

void list_bp(vector<string> argv) {
    for (auto bp : info.bps) {
        dprintf(STDERR_FILENO, "  %d:%8llx\n", bp.id, bp.addr);
    }
}

static void cont_end() {
    int status;
    waitpid(info.pid, &status, 0);

    _WIFEXITED(status);

    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) != SIGTRAP) {
            dprintf(STDERR_FILENO, "** [cont] stopped by signal %d\n", WSTOPSIG(status));
        }

        // because process stopped so %rip would point to next instruction, we want to let %rip stop at break point
        auto _reg = _get_all_regs();
        *(_reg["rip"]) -= 1;
        if (is_encounter_cc(*(_reg["rip"]))) {
            ptrace(PTRACE_SETREGS, info.pid, NULL, &regs);
            print_bp();
        }
    }
}

void cont(vector<string> argv) {
    check_state(running);
    auto _reg = _get_all_regs();
    bool has_restored = false;
    long inst;
    if (is_encounter_cc(*(_reg["rip"]))) {
        inst = ptrace(PTRACE_PEEKTEXT, info.pid, *(_reg["rip"]), 0);
        long origin = restore_origin_content(inst, *(_reg["rip"]), 1); // only restore 0xcc 1 byte;
        ptrace(PTRACE_POKETEXT, info.pid, *(_reg["rip"]), origin);
        has_restored = true;
    }

    // run only one instruciton after replacing break point with original contents
    ptrace(PTRACE_SINGLESTEP, info.pid, 0, 0);
    int status;
    waitpid(info.pid, &status, 0);
    _WIFEXITED(status);

    // set 0xcc back if replaced
    if (has_restored) ptrace(PTRACE_POKETEXT, info.pid, *(_reg["rip"]), inst);

    ptrace(PTRACE_CONT, info.pid, 0, 0);
    cont_end();
}

static void si_end(int status) {
    _WIFEXITED(status);
    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) != SIGTRAP) {
            dprintf(STDERR_FILENO, "** [si] stopped by signal %d\n", WSTOPSIG(status));
        }

        auto _reg = _get_all_regs();
        if (is_encounter_cc(*(_reg["rip"]))) print_bp();
    }
}

void single_step(vector<string> argv) {
    check_state(running);
    
    auto _reg = _get_all_regs();
    bool has_restored = false;
    long inst;
    if (is_encounter_cc(*(_reg["rip"]))) {
        inst = ptrace(PTRACE_PEEKTEXT, info.pid, *(_reg["rip"]), 0); // only restore 0xcc 1 byte;
        long orig = restore_origin_content(inst, *(_reg["rip"]), 1);
        ptrace(PTRACE_POKETEXT, info.pid, *(_reg["rip"]), orig);
        has_restored = true;
    }
    ptrace(PTRACE_SINGLESTEP, info.pid, 0, 0);
    int status;
    waitpid(info.pid, &status, 0);

    if (has_restored) ptrace(PTRACE_POKETEXT, info.pid, *(_reg["rip"]), inst); // set 0xcc back to the bp
    si_end(status);
}

void disasm(vector<string> argv) {
    check_state(running);
    check_argv(argv, "addr");
    
    unsigned long long addr = _stoull(argv[1]);
    check_text_segment(addr);
    
    unsigned long long target_addr = addr;
    long codes[DISASM_LEN];
    for (int i = 0; i < DISASM_LEN; ++i) {
        long content = ptrace(PTRACE_PEEKTEXT, info.pid, target_addr, 0);
        codes[i] = restore_origin_content(content, target_addr, WORD);
        target_addr += WORD;
    }
    _disasm((uint8_t *)codes, sizeof(codes) - 1, addr, DISASM_LEN);
}

void dump(vector<string> argv) {
    check_state(running);
    check_argv(argv, "addr");

    unsigned long long addr = stoull(argv[1], NULL, 16);

    for (auto i = 0; i < DUMP_SIZE; i += DUMP_WIDTH) {
        dprintf(STDERR_FILENO, "      %llx: ", addr);

        string mem = "";
        for (auto j = 0; j < DUMP_WIDTH; j += WORD, addr += WORD) {
            auto tracee_mem = ptrace(PTRACE_PEEKTEXT, info.pid, addr, NULL);
            mem += string((char *)&tracee_mem, 8);
        }
        for (auto _char : mem) {
            dprintf(STDERR_FILENO, "%02x ", (unsigned char)_char);
        }

        cerr << "|";
        for (auto _char : mem) {
            dprintf(STDERR_FILENO, "%c", (!isprint(_char) ? '.' : _char));
        }
        cerr << "|\n";
    }
}

void get_reg(vector<string> argv) {
    check_state(running);
    
    string target = argv[1];
    auto _regs = _get_all_regs();
    if (_regs.count(target)) {
        dprintf(STDERR_FILENO, "%s = %lld (0x%llx)\n", target.c_str(), *_regs[target], *_regs[target]);
    } else {
        dprintf(STDERR_FILENO, "** register '%s' is not exist.\n", target.c_str());
    }
}

void get_all_regs(vector<string> argv) {
    check_state(running);

    auto _regs = _get_all_regs();
    int count = 0;
    for (auto reg : all_regs_list) {
        string upper_reg = reg;
        transform(upper_reg.begin(), upper_reg.end(), upper_reg.begin(), [](char c){ return toupper(c); });
        if (upper_reg != "FLAGS") {
            dprintf(STDERR_FILENO, "%-3s %-16llx", upper_reg.c_str(), *_regs[reg]);
        } else {
            dprintf(STDERR_FILENO, "%-3s %016llx", upper_reg.c_str(), *_regs[reg]);
        }

        count = (count + 1) % 4;
        if (count == 0) cerr << endl;
    }
    if (count != 0) cerr << endl;
}

void set_reg(vector<string> argv) {
    check_state(running);

    string target = argv[1], val = argv[2];
    auto _regs = _get_all_regs();
    *_regs[target] = _stoull(val);

    ptrace(PTRACE_SETREGS, info.pid, 0, &regs);
}

void help(vector<string> argv) {
    cerr << "- break {instruction-address}: add a break point\n";
    cerr << "- cont: continue execution\n";
    cerr << "- delete {break-point-id}: remove a break point\n";
    cerr << "- disasm addr: disassemble instructions in a file or a memory region\n";
    cerr << "- dump addr: dump memory content\n";
    cerr << "- exit: terminate the debugger\n";
    cerr << "- get reg: get a single value from a register\n";
    cerr << "- getregs: show registers\n";
    cerr << "- help: show this message\n";
    cerr << "- list: list break points\n";
    cerr << "- load {path/to/a/program}: load a program\n";
    cerr << "- run: run the program\n";
    cerr << "- vmmap: show memory layout\n";
    cerr << "- set reg val: get a single value to a register\n";
    cerr << "- si: step into instruction\n";
    cerr << "- start: start the program and stop at the first instruction\n";
}

static void set_entry_point(const char *program) {
    int fd = open(program, O_RDONLY);
    unsigned char elf_header[ELF_HEADER_SIZE]; // elf header: first 64 bytes
    if (fd == -1) return;

    read(fd, elf_header, ELF_HEADER_SIZE);

    unsigned long long res = 0;
    for (size_t i = ELF_ENTRY_POINT_SIZE + ELF_ENTRY_POINT_OFFSET - 1; i >= ELF_ENTRY_POINT_OFFSET; i--) {
        res = res * 256 + elf_header[i];
    }
    info.entry_point = res;
}

void _load() {
    info.pid = fork();
    if (info.pid < 0) {
        err_quit("**[load] fail to fork\n");
    } else if (info.pid == 0) { // child process run the program
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) err_quit("** [load] traceme\n");
        char *argv[] = {strdup(info.loaded_prog.c_str()), NULL};
        if (execvp(argv[0], argv) < 0) err_quit("** [load] execvp\n");
    } else {
        int status;
        if (waitpid(info.pid, &status, 0) < 0) err_quit("** [load] waitpid");
        ptrace(PTRACE_SETOPTIONS, info.pid, 0, PTRACE_O_EXITKILL);

        set_entry_point(info.loaded_prog.c_str());
        info.state = loaded;
    }
}

static void init_text_segment_addr() {
    ifstream text_if("/proc/" + to_string(info.pid) + "/stat");
    if (!text_if.is_open()) {
        err_quit("** vmmap fail to open the stat file\n");
    } else {
        string line;

        if (!getline(text_if, line)) {
            err_quit("** vmmap fail to getline from stat\n");
        }
        auto item = split_str(line);
        // start and end place
        info.text_start = _stoull(item[25]);
        info.text_end = _stoull(item[26]);
    }
    return;
}

void load(vector<string> argv) {
    if (info.state != not_load) {
        dprintf(STDERR_FILENO, "** The program has alreay been load. entry point 0x%llx\n", info.entry_point);
        return;
    }

    info.loaded_prog = argv[1];
    _load();
    dprintf(STDERR_FILENO, "** program '%s' loaded. entry point 0x%llx\n", info.loaded_prog.c_str(), info.entry_point);
    init_text_segment_addr();
}

void start(vector<string> argv) {
    check_state(loaded);

    dprintf(STDERR_FILENO, "** pid %d\n", info.pid);
    info.state = running;
}

static void repatch_bps() {
    for (auto bp = info.bps.begin(); bp != info.bps.end(); ++bp) {
        auto code = ptrace(PTRACE_PEEKTEXT, info.pid, bp->addr, 0);
        ptrace(PTRACE_POKETEXT, info.pid, bp->addr, (code & 0xffffffffffffff00) | 0xcc);
    }
}

void run(vector<string> argv) {
    if (info.state == running) {
        cerr << "** program " << info.loaded_prog << " is already running" << endl;
    } else if (info.state == loaded) {
        start(argv);
    } else if (info.state == terminated) {
        _load();
        start(argv);
        repatch_bps();
    }
    cont(argv);
}

void vmmap(vector<string> argv) {
    check_state(running);

    ifstream maps_if("/proc/" + to_string(info.pid) + "/maps");
    if (!maps_if.is_open()) err_quit("** vmmap fail to open the maps file\n");

    string line = "";
    while (getline(maps_if, line)) {
        vector<string> item = split_str(line);
        // format the output
        auto dash = item[vm_region].find('-');
        string start_str = item[vm_region].substr(0, dash);
        string end_str = item[vm_region].substr(dash + 1, item[vm_region].size() - dash);
        unsigned long long start = stoull(start_str, NULL, 16);
        unsigned long long end = stoull(end_str, NULL, 16);

        string flags = item[vm_flags].substr(0, 3);

        unsigned long long offset = stoull(item[vm_pgoff], NULL, 16);

        dprintf(STDERR_FILENO, "%016llx-%016llx %s %llx        %s\n", start, end, flags.c_str(), offset, item[vm_path].c_str());
    }
}

void exit(vector<string> argv) {
    exit(0);
}

/* helper functions */
static void init_commands() {
    commands["break"] = &set_bp;
    commands["b"] = &set_bp;
    commands["cont"] = &cont;
    commands["c"] = &cont;
    commands["delete"] = &delete_bp;
    commands["disasm"] = &disasm;
    commands["dump"] = &dump;
    commands["x"] = &dump;
    commands["exit"] = &exit;
    commands["q"] = &exit;
    commands["get"] = &get_reg;
    commands["g"] = &get_reg;
    commands["getregs"] = &get_all_regs;
    commands["help"] = &help;
    commands["h"] = &help;
    commands["list"] = &list_bp;
    commands["l"] = &list_bp;
    commands["load"] = &load;
    commands["run"] = &run;
    commands["r"] = &run;
    commands["vmmap"] = &vmmap;
    commands["m"] = &vmmap;
    commands["set"] = &set_reg;
    commands["s"] = &set_reg;
    commands["si"] = &single_step;
    commands["start"] = &start;
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    arguments args = parse_arg(argc, argv);

    init_commands();

    // load program if it's a parameter
    ifstream script_if(args.script);
    if (!args.script.empty()) {
        if (!script_if.is_open()) err_quit("** open script failed.\n");
        args.is_script = true;
    }
    if (!args.program_path.empty()) call_cmd({"load", args.program_path});

    // load program from input
    while (true) {
        if (!args.is_script) cerr << "sdb> ";
        
        string cmd = "";
        if (!getline(args.is_script ? script_if : cin, cmd)) break;

        vector<string> input_list = split_str(cmd);
        if (!input_list.empty()) call_cmd(input_list);
    }    
    
    return 0;
}