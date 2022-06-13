#include "sdb.h"

unordered_map<string, func_ptr> commands;
static const string state_name[] = {"not_load", "loaded", "running"};
struct user_regs_struct regs;
const string all_regs_list[] = {
    "rax", "rbx", "rcx", "rdx",
    "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15",
    "rdi", "rsi", "rbp", "rsp",
    "rip", "flags"};
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

static inline void errquit(const char *msg) {
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

struct arguments parse_arg(int argc, char *argv[]) {
    int cmd_opt;
    struct arguments args = {
        .script = "",
        .prog_path = "",
        .is_script = false,
        .is_invalid = false,
    };

    while ((cmd_opt = getopt(argc, argv, "s:")) != -1) {
        switch (cmd_opt) {
        case 's':
            args.script = optarg;
            break;
        case '?':
            cerr << "usage: ./hw4 [-s script] [program]" << endl;
            args.is_invalid = true;
            break;
        default:
            break;
        }
    }
    if (argc > optind) {
        args.prog_path = argv[optind];
    }

    return args;
}

static unsigned long long _stoull(string str) {
    int base = 10;
    if (!str.compare(0, 2, "0x"))
        base = 16;
    return stoull(str, NULL, base);
}
static void init_text_segment_addr() {
    ifstream text_if("/proc/" + to_string(info.pid) + "/stat");
    if (!text_if.is_open()) {
        errquit("** vmmap fail to open the stat file\n");
    } else {
        string line;

        if (!getline(text_if, line)) {
            errquit("** vmmap fail to getline from stat\n");
        }
        auto item = split_str(line);
        // start and end place
        info.text_start = _stoull(item[25]);
        info.text_end = _stoull(item[26]);
    }
    return;
}

static inline bool is_text_segment(unsigned long long addr) {
    return (addr >= info.text_start) && (addr < info.text_end);
}

static void repatch_bps() {
    for (auto bp = info.bps.begin(); bp != info.bps.end(); ++bp) {
        auto code = ptrace(PTRACE_PEEKTEXT, info.pid, bp->addr, 0);
        ptrace(PTRACE_POKETEXT, info.pid, bp->addr, (code & 0xffffffffffffff00) | 0xcc); // Software Breakpoint INT3(0xcc)
    }
}

static long restore_orig_content(long raw, unsigned long long addr, size_t size) {
    // size should less than long size
    long ret = raw;
    for (size_t i = 0; i < size; ++i) {
        unsigned char *check_char = &(((unsigned char *)&raw)[i]);
        unsigned char *ret_char = &(((unsigned char *)&ret)[i]);
        if (*check_char == 0xcc) {
            for (auto bp = info.bps.begin(); bp != info.bps.end(); ++bp) {
                if (bp->addr == addr + i) {
                    *check_char = bp->orig_content;
                }
            }
        }
        *ret_char = *check_char;
    }
    return ret;
}

static void _disasm(const uint8_t *codes, size_t code_size, uint64_t addr, size_t _count) {
    static csh handle = 0;
    cs_insn *insn = NULL;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return;
    }
    size_t count = cs_disasm(handle, codes, code_size, addr, _count, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; ++i) {
            if (!is_text_segment(insn[i].address)) {
                cerr << "** the address is out of the range of the text segment\n";
                return;
            }
            dprintf(STDERR_FILENO, "%12lx: ", insn[i].address);
            for (int j = 0; j < insn[i].size; ++j) {
                dprintf(STDERR_FILENO, "%02x ", (unsigned int)insn[i].bytes[j]);
            }
            for (int j = 0; j < (12 - insn[i].size); ++j) {
                dprintf(STDERR_FILENO, "   ");
            }

            dprintf(STDERR_FILENO, "%-10s%s\n", insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    }
}

static void print_bp() {
    auto _reg = _get_all_regs();
    long raw = ptrace(PTRACE_PEEKTEXT, info.pid, *(_reg["rip"]), 0);
    long codes = restore_orig_content(raw, *(_reg["rip"]), 1);
    dprintf(STDERR_FILENO, "** breakpoint @");
    // just disasm without restore to mem
    _disasm((uint8_t *)&codes, WORD - 1, *(_reg["rip"]), 1);
}

static bool is_encounter_cc(unsigned long long addr) {
    auto code = ptrace(PTRACE_PEEKTEXT, info.pid, addr, 0);
    unsigned char *_char = ((unsigned char *)&code);
    return *_char == 0xcc;
}

static void cont_end() {
    int status;
    waitpid(info.pid, &status, 0);

    _WIFEXITED(status);
    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) != SIGTRAP) {
            dprintf(STDERR_FILENO, "** [cont] stopped by signal %d\n", WSTOPSIG(status));
        }

        auto _reg = _get_all_regs();
        *(_reg["rip"]) -= 1;
        if (is_encounter_cc(*(_reg["rip"]))) {
            // rip-1
            ptrace(PTRACE_SETREGS, info.pid, NULL, &regs);
            print_bp();
        }
    }
}

static void si_end(int status) {
    _WIFEXITED(status);
    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) != SIGTRAP) {
            dprintf(STDERR_FILENO, "** [si] stopped by signal %d\n", WSTOPSIG(status));
        }

        auto _reg = _get_all_regs();
        if (is_encounter_cc(*(_reg["rip"]))) {
            print_bp();
        }
    }
}

static void set_entry_point(const char *program) {
    int fd = open(program, O_RDONLY);
    unsigned char elf[ELF_HEADER_SIZE];
    if (fd == -1) {
        return;
    }

    // elf_header in executable file first 64 byte
    read(fd, elf, ELF_HEADER_SIZE);

    unsigned long long res = 0;
    for (size_t i = ELF_ENTRY_POINT_SIZE + ELF_ENTRY_POINT_OFFSET - 1; i >= ELF_ENTRY_POINT_OFFSET; i--) {
        res = res * 256 + elf[i];
    }
    info.entry_point = res;
}

/* implementation of sdb's using */
void set_bp(vector<string> argv) {
    check_state(running);
    if (argv.size() < 2) {
        cerr << "** no addr is given\n";
        return;
    }
    unsigned long long addr = _stoull(argv[1]);
    if (!is_text_segment(addr)) {
        cerr << "** the address is out of the range of the text segment\n";
        return;
    }
    if (addr == info.entry_point) {
        cerr << "** the address should not be the same as the entry point\n";
    }
    auto code = ptrace(PTRACE_PEEKTEXT, info.pid, addr, 0);
    break_point new_bp = {addr, ++info.bp_id, (unsigned char)code};
    info.bps.push_back(new_bp);
    // Software Breakpoint INT3(0xcc)
    ptrace(PTRACE_POKETEXT, info.pid, addr, (code & 0xffffffffffffff00) | 0xcc);
}

void delete_bp(vector<string> argv) {
    if (argv.size() < 2) {
        cerr << "** no id is given\n";
        return;
    }
    int target_id = stoi(argv[1], NULL, 10);
    for (auto bp = info.bps.begin(); bp != info.bps.end(); ++bp) {
        if (bp->id == target_id) {
            auto code = ptrace(PTRACE_PEEKTEXT, info.pid, bp->addr, NULL);
            // just replace the first byte instead of a word;
            ptrace(PTRACE_POKETEXT, info.pid, bp->addr, (code & 0xffffffffffffff00) | bp->orig_content);
            info.bps.erase(bp);
            dprintf(STDERR_FILENO, "** breakpoint %d deleted.\n", target_id);
            return;
        }
    }
}

void list_bp(vector<string> argv) {
    for (auto bp : info.bps) {
        dprintf(STDERR_FILENO, "  %d:%8llx\n", bp.id, bp.addr);
    }
}

void cont(vector<string> argv) {
    check_state(running);
    auto _reg = _get_all_regs();
    bool has_restored = false;
    long inst;
    if (is_encounter_cc(*(_reg["rip"]))) {
        inst = ptrace(PTRACE_PEEKTEXT, info.pid, *(_reg["rip"]), 0);
        long orig = restore_orig_content(inst, *(_reg["rip"]), 1); // only restore 0xcc 1 byte;
        ptrace(PTRACE_POKETEXT, info.pid, *(_reg["rip"]), orig);
        has_restored = true;
    }

    /* execute one instruction which may not been executed because of 0xcc */
    ptrace(PTRACE_SINGLESTEP, info.pid, 0, 0);
    int status;
    waitpid(info.pid, &status, 0);
    _WIFEXITED(status);

    if (has_restored) {
        // set 0xcc back to the bp
        ptrace(PTRACE_POKETEXT, info.pid, *(_reg["rip"]), inst);
    }
    ptrace(PTRACE_CONT, info.pid, 0, 0);
    cont_end();
}

void single_step(vector<string> argv) {
    check_state(running);
    auto _reg = _get_all_regs();
    bool has_restored = false;
    long inst;
    if (is_encounter_cc(*(_reg["rip"]))) {
        inst = ptrace(PTRACE_PEEKTEXT, info.pid, *(_reg["rip"]), 0);
        // only restore 0xcc 1 byte;
        long orig = restore_orig_content(inst, *(_reg["rip"]), 1);
        ptrace(PTRACE_POKETEXT, info.pid, *(_reg["rip"]), orig);
        has_restored = true;
    }
    ptrace(PTRACE_SINGLESTEP, info.pid, 0, 0);
    int status;
    waitpid(info.pid, &status, 0);

    if (has_restored) {
        // set 0xcc back to the bp
        ptrace(PTRACE_POKETEXT, info.pid, *(_reg["rip"]), inst);
    }
    si_end(status);
}

void disasm(vector<string> argv) {
    check_state(running);
    if (argv.size() < 2) {
        cerr << "** no addr is given\n";
        return;
    }
    unsigned long long addr = _stoull(argv[1]);
    if (!is_text_segment(addr)) {
        cerr << "** the address is out of the range of the text segment\n";
    }
    unsigned long long target_addr = addr;
    long codes[DISASM_INS];
    for (int i = 0; i < DISASM_INS; ++i) {
        long content = ptrace(PTRACE_PEEKTEXT, info.pid, target_addr, 0);
        codes[i] = restore_orig_content(content, target_addr, WORD);
        target_addr += WORD;
    }
    _disasm((uint8_t *)codes, sizeof(codes) - 1, addr, DISASM_INS);
}

void dump(vector<string> argv) {
    check_state(running);
    if (argv.size() < 2) {
        cerr << "** no addr is given\n";
        return;
    }
    unsigned long long addr = stoull(argv[1], NULL, 16);
    int size = 80, line = 16;

    for (auto i = 0; i < size; i += line) {
        dprintf(STDERR_FILENO, "      %llx: ", addr);
        string mem = "";
        for (auto j = 0; j < line; j += WORD, addr += WORD) {
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
        transform(upper_reg.begin(), upper_reg.end(), upper_reg.begin(), [](char c){return toupper(c);});
        if (upper_reg != "FLAGS") {
            dprintf(STDERR_FILENO, "%-3s %-16llx", upper_reg.c_str(), *_regs[reg]);
        } else {
            dprintf(STDERR_FILENO, "%-3s %016llx", upper_reg.c_str(), *_regs[reg]);
        }

        count = (count + 1) % 4;
        if (count == 0) {
            cerr << endl;
        }
    }
    if (count != 0) {
        cerr << endl;
    }
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

void _load() {
    if ((info.pid = fork()) < 0) {
        errquit("**[load] fail to fork\n");
        return;
    }
    if (info.pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            errquit("** [load] traceme\n");
        }
        char *argv[] = {strdup(info.loaded_prog.c_str()), NULL};
        execvp(argv[0], argv);
        errquit("** [load] execvp\n");
    } else {
        int status;
        if (waitpid(info.pid, &status, 0) < 0) {
            errquit("** [load] waitpid");
        }
        ptrace(PTRACE_SETOPTIONS, info.pid, 0, PTRACE_O_EXITKILL);

        set_entry_point(info.loaded_prog.c_str());
        info.state = loaded;
    }
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
    if (!maps_if.is_open()) {
        errquit("** vmmap fail to open the maps file\n");
    } else {
        string line;
        while (true) {
            if (!getline(maps_if, line)) {
                break;
            }
            auto item = split_str(line);
            /* format the output */
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
    return;
}

void start(vector<string> argv) {
    check_state(loaded);
    dprintf(STDERR_FILENO, "** pid %d\n", info.pid);
    info.state = running;
}

void exit(vector<string> argv) {
    exit(0);
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    struct arguments args = parse_arg(argc, argv);
    if (args.is_invalid) return 1;

    init_commands();

    ifstream script_if(args.script);
    if (!args.script.empty()) {
        if (!script_if.is_open()) {
            errquit("** open script failed.\n");
            return 1;
        }
        args.is_script = true;
    }
    if (!args.prog_path.empty()) {
        call_cmd({"load", args.prog_path});
    }
    while (true) {
        if (!args.is_script) {
            cerr << "sdb> ";
        }
        
        string cmd;
        if (!getline(args.is_script ? script_if : cin, cmd)) {
            break;
        }

        vector<string> input_list = split_str(cmd);
        if (!input_list.empty()) {
            call_cmd(input_list);        
        }
    }    
    
    return 0;
}