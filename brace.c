#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include "callnames.h"

#define die(s, args...) do { fprintf(stderr, s, ##args); fprintf(stderr, "\n"); exit(1); } while (0)
static void run_strace(pid_t pid);
extern char **environ;

char *usage = "%s: {command and args}";

int main(int argc, char **argv)
{
	if (argc < 2)
		die(usage, *argv);
	if (argv[1][0] == '-')
		die(usage, *argv);
	pid_t pid = fork();
	if (pid < 0)
		die("Couldn't fork: %s", strerror(errno));
	if (pid) {
		run_strace(pid);
		fprintf(stderr, "\n");
	} else {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		kill(getpid(), SIGSTOP);
		execvp(argv[1], &(argv[1]));
		die("Couldn't exec %s: %s", argv[1], strerror(errno));
	}
	return 0;
}

int wait_for_syscall(pid_t child)
{
	for (;;) {
		ptrace(PTRACE_SYSCALL, child, 0, 0);
		int status = 0;
		waitpid(child, &status, 0);
		if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
			return 0;
		if (WIFEXITED(status))
			return 1;
	}
}

void run_strace(pid_t pid)
{
	int status = 0;
	waitpid(pid, &status, 0);
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
	while(1) {
		if (wait_for_syscall(pid))
			break;

#if defined(ORIG_EAX)
		int syscall = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*ORIG_EAX);
#elif defined(ORIG_RAX)
		int syscall = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*ORIG_RAX);
#else
#error "I don't know your arch"
#endif

		char buf[64];
		fprintf(stderr, "%s() = ", syscall_name(syscall, buf, sizeof(buf)));

		if (wait_for_syscall(pid))
			break;

#if defined(EAX)
		int ret = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*EAX);
#elif defined(RAX)
		int ret = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*RAX);
#else
#error "I don't know your arch"
#endif

		fprintf(stderr, "%d\n", ret);
	}
}
