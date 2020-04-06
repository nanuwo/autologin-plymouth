#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <security/pam_appl.h>

int handle_error(char *operation, int error) {
	if (error != -1)
		return error;
	fprintf(stderr, "%s failed: %s (%d)\n", operation, strerror(errno), errno);
	exit(EXIT_FAILURE);
}

int handle_pam_error(struct pam_handle *handle, char *operation, int error) {
	if (error == PAM_SUCCESS)
		return 0;
	fprintf(stderr, "%s failed: %s\n", operation, pam_strerror(handle, error));
	if (handle != NULL)
		pam_end(handle, error);
	exit(EXIT_FAILURE);
}

int null_handle(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
	*resp = calloc(num_msg, sizeof (struct pam_response));
	return *resp == NULL ? PAM_BUF_ERR : PAM_SUCCESS;
}

int pam_putenv_tuple(struct pam_handle* handle, char* key, char* value) {
	char buf[256];
	snprintf(buf, sizeof buf, "%s=%s", key, value);
	return pam_putenv(handle, buf);
}

void child(struct passwd *pwd, char* user_cmd, char** env) {
	handle_error("initgroups", initgroups(pwd->pw_name, pwd->pw_gid));
	handle_error("setgid", setgid(pwd->pw_gid));
	handle_error("setuid", setuid(pwd->pw_uid));
	handle_error("chdir", chdir(pwd->pw_dir));
	handle_error("prctl", prctl(PR_SET_PDEATHSIG, SIGTERM));

	char arg[1024];
	snprintf(arg, sizeof arg, "[ -f /etc/profile ] && . /etc/profile; [ -f $HOME/.profile ] && . $HOME/.profile; exec %s", user_cmd);
	char *const cmd[] = { "/bin/sh", "-c", arg, NULL, };
	execvpe(cmd[0], cmd, env);
}

void setup_vt(int vt) {
	char p[32];
	snprintf(p, sizeof p, "/dev/tty%d", vt);
	int fd = handle_error("open tty", open(p, O_RDWR));

	handle_error("dup2", dup2(fd, 0));
	handle_error("dup2", dup2(fd, 1));
	handle_error("dup2", dup2(fd, 2));

	struct vt_mode mode = { 0 };
	mode.mode = VT_AUTO;
	handle_error("KDSETMODE", ioctl(fd, KDSETMODE, KD_TEXT));
	handle_error("VT_SETMODE", ioctl(fd, VT_SETMODE, &mode));
	handle_error("VT_ACTIVATE", ioctl(fd, VT_ACTIVATE, vt));
	handle_error("VT_WAITACTIVE", ioctl(fd, VT_WAITACTIVE, vt));
	close(fd);
}

int main(int argc, char *argv[]) {
	struct pam_conv conv = { null_handle, NULL };
	struct pam_handle* handle;

	handle_pam_error(handle, "pam_start", pam_start("greetd", argv[1], &conv, &handle));
	handle_pam_error(handle, "pam_acct_mgmt", pam_acct_mgmt(handle, PAM_SILENT));
	handle_pam_error(handle, "pam_setcred", pam_setcred(handle, PAM_ESTABLISH_CRED));

//	handle_error("setsid", setsid());
	setup_vt(1);

	struct passwd* pwd = getpwnam(argv[1]);
	if (pwd == NULL) {
		fprintf(stderr, "getpwnam failed\n");
		return 1;
	}

	handle_pam_error(handle, "pam_putenv", pam_putenv(handle, "XDG_SEAT=seat0"));
	handle_pam_error(handle, "pam_putenv", pam_putenv(handle, "XDG_SESSION_CLASS=user"));
	handle_pam_error(handle, "pam_putenv", pam_putenv(handle, "XDG_VTNR=1"));
	handle_pam_error(handle, "pam_putenv", pam_putenv_tuple(handle, "HOME", pwd->pw_dir));
	handle_pam_error(handle, "pam_putenv", pam_putenv_tuple(handle, "PWD", pwd->pw_dir));
	handle_pam_error(handle, "pam_putenv", pam_putenv_tuple(handle, "SHELL", pwd->pw_shell));
	handle_pam_error(handle, "pam_putenv", pam_putenv_tuple(handle, "USER", pwd->pw_name));
	handle_pam_error(handle, "pam_putenv", pam_putenv_tuple(handle, "LOGNAME", pwd->pw_name));
	handle_pam_error(handle, "pam_putenv", pam_putenv_tuple(handle, "TERM", getenv("TERM") ?: "linux"));

	handle_pam_error(handle, "pam_open_session", pam_open_session(handle, PAM_SILENT));
	char** env = pam_getenvlist(handle);

	pid_t pid = handle_error("fork", fork());
	if (pid == 0)
		child(pwd, argv[2], env);

	int res;
	while ((res = waitpid(pid, NULL, 0)) <= 0) {
		if (res == -1 && errno != EINTR) {
			fprintf(stderr, "waitpid failed: %s (%d)\n", strerror(errno), errno);
			break;
		}
	}

	handle_pam_error(handle, "pam_close_session", pam_close_session(handle, PAM_SILENT));
	handle_pam_error(handle, "pam_setcred", pam_setcred(handle, PAM_DELETE_CRED));
	handle_pam_error(handle, "pam_end", pam_end(handle, 0));
	return 0;
}
