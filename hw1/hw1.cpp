#include <iostream>
#include <unistd.h> // for POSIX API (system call)
#include <set>
#include <dirent.h> // for file op in linux
#include <fstream>
#include <sys/stat.h> // get file attributes with struct stat
#include <pwd.h> // provide struct passwd
#include <regex>

using namespace std;

struct option {
    bool type_c;
    bool type_t;
    bool type_f;
    string arg_c;
    string arg_t;
    string arg_f;
};

struct file_info {
    string fd;
    string type;
    string node;
    string name;
};

struct pid_info {
    string cmd;
    string pid;
    string username;
    vector<file_info> files;
    string type;
};

bool is_valid(char *arg) {
    if (!strcmp(arg, "REG") || !strcmp(arg, "CHR") ||
        !strcmp(arg, "DIR") || !strcmp(arg, "FIFO") ||
        !strcmp(arg, "SOCK") || !strcmp(arg, "unknown")) {
        return true;
    }
    return false;
}

bool is_num(string str) {
    for (auto ch: str) {
        if (!isdigit(ch)) return false;
    }
    return true;
}

option parse_arg(option opt, int argc, char *argv[]) {
    int cmd_opt;
    while ((cmd_opt = getopt(argc, argv, "c:t:f:")) != -1) {
        switch (cmd_opt) {
            case 'c':
                opt.type_c = true;
                opt.arg_c = string(optarg);
                break;
            case 't':
                if (is_valid(optarg)) {
                    opt.type_t = true;
                    opt.arg_t = string(optarg);
                } else {
                    cout << "Invalid TYPE option." << endl;
                    exit(-1);
                }
                break;
            case 'f':
                opt.type_f = true;
                opt.arg_f = string(optarg);
                break;
            case '?':
                exit(-1);
            default:
                break;
        }
    }

    return opt;
}

void regex_cmd_filter(vector<struct pid_info> &info_table, string arg) {
    regex reg(arg);
    for (auto iter = info_table.begin(); iter != info_table.end(); ++iter) {
        smatch sm;
        if (!regex_search(iter->cmd, sm, reg)) info_table.erase(iter--);
    }
}

void type_filter(vector<struct pid_info> &info_table, string arg) {
    for (int i = 0; i < info_table.size(); ++i) {
        for (auto iter = info_table[i].files.begin(); iter != info_table[i].files.end(); ++iter) {
            if (iter->type != arg) info_table[i].files.erase(iter--);
        }

        if (info_table[i].files.empty()) {
            info_table.erase(info_table.begin() + i);
            i--;
        }
    }
}

void regex_fliename_filter(vector<struct pid_info> &info_table, string arg) {
    regex reg(arg);
    for (int i = 0; i < info_table.size(); ++i) {
        for (auto iter = info_table[i].files.begin(); iter != info_table[i].files.end(); ++iter) {
            smatch sm;
            istringstream ss(iter->name);
            string filename = "";
            ss >> filename;
            if (!regex_search(filename, sm, reg)) info_table[i].files.erase(iter--);
        }

        if (info_table[i].files.empty()) {
            info_table.erase(info_table.begin() + i);
            i--;
        }
    }
}

void print_all(vector<struct pid_info> info_table) {
    for (int i = 0; i < info_table.size(); ++i) {
        for (int j = 0; j < info_table[i].files.size(); ++j) {
            printf("%-24s%-8s%-24s%-8s%-8s%-16s%-16s\n", info_table[i].cmd.c_str(), info_table[i].pid.c_str(), info_table[i].username.c_str(),
                   info_table[i].files[j].fd.c_str(), info_table[i].files[j].type.c_str(), info_table[i].files[j].node.c_str(), info_table[i].files[j].name.c_str());
        }
    }
}

string get_cmd(string pid) {
    string path = "/proc/" + pid + "/comm";
    ifstream file_comm(path.c_str());
    string comm;
    file_comm >> comm;

    file_comm.close();
    return comm;
}

string get_username(string pid) {
    string path = "/proc/" + pid + "/";
    struct stat pid_stat;

    stat(path.c_str(), &pid_stat);

    return getpwuid(pid_stat.st_uid)->pw_name;
}

string check_type(mode_t mode) {
    if (S_ISDIR(mode)) return "DIR";
    else if (S_ISREG(mode)) return "REG";
    else if (S_ISCHR(mode)) return "CHR";
    else if (S_ISFIFO(mode)) return "FIFO";
    else if (S_ISSOCK(mode)) return "SOCK";
    return "unknown";
}

// file_type 0:cwd, 1:root, 2:exe
file_info get_special_fd(string pid, int file_type) {
    vector<string> type_list = {"cwd", "root", "exe"};
    vector<string> name_list = {"cwd", "rtd", "txt"};
    string path = "/proc/" + pid + "/" + type_list[file_type];
    struct stat st;
    stat(path.c_str(), &st);
    char dst_link[PATH_MAX];
    memset(dst_link, '\0', sizeof(dst_link));
    file_info file;
    
    file.fd = name_list[file_type];
    file.type = check_type(st.st_mode);
    if (!access(path.c_str(), R_OK)) {
        file.node = st.st_ino;
        readlink(path.c_str(), dst_link, sizeof(dst_link)-1);
        file.name = dst_link;
    } else {
        file.node = "\t";
        file.name = path + " (Permission denied)";
    }
    
    return file;
}

vector<file_info> get_maps(string pid) {
    vector<file_info> maps_infos;
    string path = "/proc/" + pid + "/maps";

    if (!access(path.c_str(), R_OK)) {
        string line = "";
        ifstream file_map(path);
        set<int> inodes;
        
        while (getline(file_map, line)) {
            istringstream ss(line);
            vector<string> str_parsed;
            string str = "";
            while (ss >> str) {
                str_parsed.push_back(str);
            }
            int inode = stoi(str_parsed[4]);

            if (inode != 0 && inodes.find(inode) == inodes.end()) {
                inodes.insert(inode);
                struct stat st;
                stat(path.c_str(), &st);
                file_info file;

                // check if error msg is "(deleted)"
                if (str_parsed.size() > 6 && str_parsed[6] == "(deleted)") {
                    file.fd = "DEL";
                    file.type = "unknown";
                    file.node = to_string(inode);
                    file.name = str_parsed[5];
                } else {
                    file.fd = "mem";
                    file.type = check_type(st.st_mode);
                    file.node = to_string(inode);
                    file.name = str_parsed[5];
                }

                maps_infos.push_back(file);
            }
        }
        file_map.close();
    }

    return maps_infos;
}

string check_fdtype(string fd_type, string fdinfo_path) {
    ifstream fdinfo(fdinfo_path);
    string temp = "";

    fdinfo >> temp; // ->pos: num
    fdinfo >> temp; // pos: ->num
    fdinfo >> temp; // ->flags: num
    fdinfo >> temp; // flags: ->num
    fdinfo.close();
    switch (temp.back()) {
        case '0':
            fd_type += 'r';
            break;
        case '1':
            fd_type += 'w';
            break;
        case '2':
            fd_type += 'u';
            break;
    }

    return fd_type;
}

vector<file_info> get_fds(string pid) {
    vector<file_info> fds_infos;
    string path = "/proc/" + pid + "/fd";

    if (!access(path.c_str(), R_OK)) {
        DIR *dir = opendir(path.c_str());
        struct dirent *dir_ptr;

        while ((dir_ptr = readdir(dir)) != NULL) {
            if (is_num(dir_ptr->d_name)) {
                string fdinfo_path = "/proc/" + pid + "/fdinfo/" + dir_ptr->d_name;
                string dir_path = path + "/" + dir_ptr->d_name;
                struct stat st;
                stat(dir_path.c_str(), &st);                
                char dst_link[PATH_MAX];
                memset(dst_link, '\0', sizeof(dst_link));
                readlink(dir_path.c_str(), dst_link, sizeof(dst_link)-1);

                file_info file;

                file.fd = check_fdtype(dir_ptr->d_name, fdinfo_path);
                file.type = check_type(st.st_mode);
                file.node = to_string(st.st_ino);
                file.name = dst_link;

                fds_infos.push_back(file);
            }
        }
        closedir(dir);
    } else {
        file_info file;

        file.fd = "NOFD";
        file.type = "\t";
        file.node = "\t";
        file.name = path + " (Permission denied)";

        fds_infos.push_back(file);
    }

    return fds_infos;
}

int main(int argc, char *argv[]) {
    // parse args
    struct option opt = {
        .type_c = false,
        .type_t = false,
        .type_f = false
    };
    opt = parse_arg(opt, argc, argv);
    
    printf("%-24s%-8s%-24s%-8s%-8s%-16s%-16s\n", "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME");

    // get all pids
    struct dirent **pid_list;
    int pid_count = scandir("/proc", &pid_list, [](const struct dirent *pid_list){ return isdigit(pid_list->d_name[0]) ? 1 : 0; }, alphasort);

    // traverse /proc/<pid>
    vector<struct pid_info> info_table;
    for (int i = 0; i < pid_count; ++i) {
        struct pid_info info;

        // get pid, command, username
        info.pid = pid_list[i]->d_name;

        info.cmd = get_cmd(info.pid);
        if (info.cmd.empty()) continue;

        info.username = get_username(info.pid);
        if (info.username.empty()) continue;

        // special files (cwd/ root/ exe/ fd)
        for (int j = 0; j < 3; ++j) {
            info.files.push_back(get_special_fd(info.pid, j));
        }

        // parse <pid>/maps
        vector<file_info> maps = get_maps(info.pid);
        if (!maps.empty()) info.files.insert(info.files.end(), maps.begin(), maps.end());

        // traverse all <pid>/fd/<fd>
        vector<file_info> fds = get_fds(info.pid);
        if (!fds.empty()) info.files.insert(info.files.end(), fds.begin(), fds.end());

        info_table.push_back(info);
    }

    // deal filter
    if (opt.type_c) regex_cmd_filter(info_table, opt.arg_c);
    if (opt.type_t) type_filter(info_table, opt.arg_t);
    if (opt.type_f) regex_fliename_filter(info_table, opt.arg_f);
    print_all(info_table);

    return 0;
}