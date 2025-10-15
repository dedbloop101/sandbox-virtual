// sandbox_runner.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <jansson.h>
#include <seccomp.h>
#include <sys/resource.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

#define CGROUP_ROOT "/sys/fs/cgroup"
#define CGROUP_PREFIX "safezone_"
#define CGROUP_CPU_PERIOD_US 100000  // 100ms period

// POLICY STRUCT 
typedef struct {
    unsigned long memory_bytes;
    int cpu_quota_us;
    int network_allowed;
    char **deny_syscalls;
    size_t deny_count;
} Policy;

// UTILITY HELPERS 
void log_info(const char *message) {
    printf("INFO: %s\n", message);
}

void log_error(const char *context) {
    fprintf(stderr, "ERROR [%s]: %s\n", context, strerror(errno));
}

void log_warning(const char *message) {
    printf("WARNING: %s\n", message);
}

void free_policy(Policy *p) {
    if (!p) return;
    if (p->deny_syscalls) {
        for (size_t i = 0; i < p->deny_count; ++i)
            free(p->deny_syscalls[i]);
        free(p->deny_syscalls);
    }
    memset(p, 0, sizeof(Policy));
}

int write_file_str(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        log_error(path);
        return -1;
    }
    ssize_t w = write(fd, value, strlen(value));
    close(fd);
    return (w == (ssize_t)strlen(value)) ? 0 : -1;
}

int dir_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

// Check if cgroups v2 is available
int cgroups_v2_available() {
    return dir_exists(CGROUP_ROOT);
}

// POLICY PARSER 
int parse_policy_file(const char *policy_path, Policy *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(Policy));

    json_error_t err;
    json_t *root = json_load_file(policy_path, 0, &err);
    if (!root) {
        fprintf(stderr, "Error loading policy file: %s\n", err.text);
        return -1;
    }

    json_t *resources = json_object_get(root, "resources");
    json_t *network   = json_object_get(root, "network");
    json_t *syscalls  = json_object_get(root, "syscalls");

    if (resources) {
        json_t *mem = json_object_get(resources, "memory_bytes");
        json_t *cpu = json_object_get(resources, "cpu_quota_us");
        if (mem && json_is_integer(mem)) out->memory_bytes = (unsigned long)json_integer_value(mem);
        if (cpu && json_is_integer(cpu)) out->cpu_quota_us = (int)json_integer_value(cpu);
    }

    out->network_allowed = 1;
    if (network) {
        json_t *allow = json_object_get(network, "allow");
        if (allow) out->network_allowed = json_is_true(allow) ? 1 : 0;
    }

    out->deny_syscalls = NULL;
    out->deny_count = 0;
    if (syscalls) {
        json_t *deny = json_object_get(syscalls, "deny");
        if (deny && json_is_array(deny)) {
            size_t n = json_array_size(deny);
            out->deny_syscalls = calloc(n, sizeof(char*));
            if (!out->deny_syscalls) {
                json_decref(root);
                return -1;
            }
            for (size_t i = 0; i < n; ++i) {
                json_t *it = json_array_get(deny, i);
                if (json_is_string(it)) {
                    out->deny_syscalls[out->deny_count++] = strdup(json_string_value(it));
                }
            }
        }
    }

    // Log parsed policy
    printf("=== Policy Configuration ===\n");
    printf("Memory limit: %lu bytes\n", out->memory_bytes);
    printf("CPU quota: %d µs\n", out->cpu_quota_us);
    printf("Network allowed: %s\n", out->network_allowed ? "Yes" : "No");
    if (out->deny_count) {
        printf("Denied syscalls:");
        for (size_t i = 0; i < out->deny_count; ++i)
            printf(" %s", out->deny_syscalls[i]);
        printf("\n");
    }
    printf("============================\n");

    json_decref(root);
    return 0;
}

// RESOURCE LIMITS 
int apply_resource_limits_rlimit(const Policy *p) {
    if (!p) return -1;

    log_info("Applying resource limits via rlimit");

    if (p->memory_bytes > 0) {
        struct rlimit rl = {p->memory_bytes, p->memory_bytes};
        if (setrlimit(RLIMIT_AS, &rl) != 0) {
            log_error("setrlimit(RLIMIT_AS)");
        } else {
            printf("Memory limit set: %lu bytes\n", p->memory_bytes);
        }
    }

    if (p->cpu_quota_us > 0) {
        int secs = (p->cpu_quota_us + 999999) / 1000000;
        if (secs < 1) secs = 1;
        struct rlimit rl = {secs, secs};
        if (setrlimit(RLIMIT_CPU, &rl) != 0) {
            log_error("setrlimit(RLIMIT_CPU)");
        } else {
            printf("CPU limit set: %d seconds\n", secs);
        }
    }

    return 0;
}

// CGROUP HANDLERS 
int setup_cgroup_v2_move_pid(const char *cgname, pid_t pid, const Policy *p, char *out_cgpath, size_t len) {
    if (!cgname || !out_cgpath) return -1;

    if (!cgroups_v2_available()) {
        log_warning("Cgroups v2 not available - continuing without cgroup limits");
        return 0;
    }

    snprintf(out_cgpath, len, "%s/%s%s", CGROUP_ROOT, CGROUP_PREFIX, cgname);
    
    if (mkdir(out_cgpath, 0755) != 0 && errno != EEXIST) {
        log_error("cgroup mkdir");
        return -1;
    }

    log_info("Cgroup directory created");

    int success_count = 0;

    if (p->memory_bytes > 0) {
        char path[512], buf[64];
        snprintf(path, sizeof(path), "%s/memory.max", out_cgpath);
        snprintf(buf, sizeof(buf), "%lu", p->memory_bytes);
        if (write_file_str(path, buf) == 0) {
            printf("Cgroup memory limit: %lu bytes\n", p->memory_bytes);
            success_count++;
        } else {
            log_warning("Failed to set cgroup memory limit");
        }
    }

    if (p->cpu_quota_us > 0) {
        char path[512], buf[64];
        snprintf(path, sizeof(path), "%s/cpu.max", out_cgpath);
        snprintf(buf, sizeof(buf), "%d %d", p->cpu_quota_us, CGROUP_CPU_PERIOD_US);
        if (write_file_str(path, buf) == 0) {
            printf("Cgroup CPU limit: %d/%d us\n", p->cpu_quota_us, CGROUP_CPU_PERIOD_US);
            success_count++;
        } else {
            log_warning("Failed to set cgroup CPU limit");
        }
    }

    char procpath[512], pidbuf[32];
    snprintf(procpath, sizeof(procpath), "%s/cgroup.procs", out_cgpath);
    snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
    if (write_file_str(procpath, pidbuf) == 0) {
        printf("Process %d moved to cgroup\n", pid);
        success_count++;
    } else {
        log_warning("Failed to move process to cgroup");
    }

    return (success_count > 0) ? 0 : -1;
}

void cleanup_cgroup_v2(const char *cgpath) {
    if (cgpath && dir_exists(cgpath)) {
        if (rmdir(cgpath) == 0) {
            log_info("Cgroup cleaned up");
        } else {
            log_warning("Failed to cleanup cgroup (may contain processes)");
        }
    }
}

// SECCOMP HANDLER 
int apply_seccomp_policy(const Policy *p) {
    if (!p) return -1;

    log_info("Setting up seccomp filter");

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        return -1;
    }

    printf("Seccomp → Setting up filter with %zu denied syscalls\n", p->deny_count);
    for (size_t i = 0; i < p->deny_count; ++i) {
        int sc = seccomp_syscall_resolve_name(p->deny_syscalls[i]);
        if (sc != __NR_SCMP_ERROR) {
            printf("Seccomp → Denying syscall: %s (num=%d)\n", p->deny_syscalls[i], sc);
            seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), sc, 0);
        } else {
            printf("Seccomp → Unknown syscall: %s\n", p->deny_syscalls[i]);
        }
    }

    // Deny network if not allowed
    if (!p->network_allowed) {
        printf("Seccomp → Network access denied\n");
        const char *net_calls[] = {
            "socket", "connect", "accept", "bind", "listen",
            "sendto", "recvfrom", "sendmsg", "recvmsg",
            "sendmmsg", "recvmmsg", "shutdown"
        };
        size_t n = sizeof(net_calls)/sizeof(net_calls[0]);
        for (size_t i = 0; i < n; ++i) {
            int sc = seccomp_syscall_resolve_name(net_calls[i]);
            if (sc != __NR_SCMP_ERROR) {
                seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), sc, 0);
            }
        }
    }

    if (seccomp_load(ctx) != 0) {
        fprintf(stderr, "seccomp_load failed\n");
        seccomp_release(ctx);
        return -1;
    }

    printf("Seccomp filter loaded successfully\n");
    seccomp_release(ctx);
    return 0;
}

// MAIN EXECUTION 
int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <program_path> <run_dir> <policy_file>\n", argv[0]);
        fprintf(stderr, "Example: %s ./test_prog runs/test1 policy.json\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *prog_path = argv[1];
    const char *run_dir   = argv[2];
    const char *policy_path = argv[3];

    printf("\n=== SafeZone Sandbox Runner (cgroup v2 + seccomp) ===\n");
    printf("Starting at: %ld\n", (long)time(NULL));

    // Verify program exists
    if (access(prog_path, X_OK) != 0) {
        fprintf(stderr, "Program not found or not executable: %s\n", prog_path);
        return EXIT_FAILURE;
    }

    Policy policy;
    if (parse_policy_file(policy_path, &policy) != 0) {
        fprintf(stderr, "Failed to parse policy file. Using defaults.\n");
        memset(&policy, 0, sizeof(policy));
        policy.network_allowed = 1;
    }

    // Create run directory
    if (mkdir(run_dir, 0755) != 0 && errno != EEXIST) {
        log_error("mkdir run_dir");
        free_policy(&policy);
        return EXIT_FAILURE;
    }

    char stdout_path[512], stderr_path[512];
    snprintf(stdout_path, sizeof(stdout_path), "%s/stdout.log", run_dir);
    snprintf(stderr_path, sizeof(stderr_path), "%s/stderr.log", run_dir);

    int fd_out = open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int fd_err = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd_out < 0 || fd_err < 0) {
        log_error("open log files");
        if (fd_out >= 0) close(fd_out);
        if (fd_err >= 0) close(fd_err);
        free_policy(&policy);
        return EXIT_FAILURE;
    }

    pid_t child = fork();
    if (child == 0) {
        // Child process
        dup2(fd_out, STDOUT_FILENO);
        dup2(fd_err, STDERR_FILENO);
        close(fd_out);
        close(fd_err);

        printf("Sandboxed process starting: %s\n", prog_path);
        apply_resource_limits_rlimit(&policy);
        apply_seccomp_policy(&policy);

        execl(prog_path, prog_path, (char *)NULL);
        perror("exec failed");
        _exit(127);
    } else if (child < 0) {
        log_error("fork");
        close(fd_out);
        close(fd_err);
        free_policy(&policy);
        return EXIT_FAILURE;
    }

    // Parent process
    close(fd_out);
    close(fd_err);

    printf("Sandbox supervisor started for PID: %d\n", child);

    char cgname[64], cgpath[512] = {0};
    snprintf(cgname, sizeof(cgname), "%d", child);
    if (setup_cgroup_v2_move_pid(cgname, child, &policy, cgpath, sizeof(cgpath)) != 0) {
        log_warning("Cgroup setup incomplete - using fallback limits");
    }

    int status;
    printf("Waiting for child process to complete...\n");
    waitpid(child, &status, 0);

    printf("\n=== Execution Results ===\n");
    if (WIFEXITED(status)) {
        printf("Program exited with status: %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("Program killed by signal: %d\n", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        printf("Program stopped by signal: %d\n", WSTOPSIG(status));
    }

    // Read and display output
    printf("\n=== Program Output ===\n");
    char buffer[1024];
    FILE *out_file = fopen(stdout_path, "r");
    if (out_file) {
        while (fgets(buffer, sizeof(buffer), out_file)) {
            printf("%s", buffer);
        }
        fclose(out_file);
    }

    printf("\n=== Program Errors ===\n");
    FILE *err_file = fopen(stderr_path, "r");
    if (err_file) {
        while (fgets(buffer, sizeof(buffer), err_file)) {
            printf("%s", buffer);
        }
        fclose(err_file);
    }

    cleanup_cgroup_v2(cgpath);
    free_policy(&policy);

    printf("Sandbox execution completed at: %ld\n", (long)time(NULL));
    return EXIT_SUCCESS;
}