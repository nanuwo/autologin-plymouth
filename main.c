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

int check_errno(char *operation, int error) {
	if (error != -1)
		return error;
	fprintf(stderr, "%s failed: %s (%d)\n", operation, strerror(errno), errno);
	exit(EXIT_FAILURE);
}

int check_pam(struct pam_handle *handle, char *operation, int error) {
	if (error == PAM_SUCCESS)
		return 0;
	fprintf(stderr, "%s failed: %s\n", operation, pam_strerror(handle, error));
	if (handle != NULL)
		pam_end(handle, error);
	exit(EXIT_FAILURE);
}

int pam_null_conv(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
	*resp = calloc(num_msg, sizeof (struct pam_response));
	return *resp == NULL ? PAM_BUF_ERR : PAM_SUCCESS;
}

int pam_putenv_tuple(struct pam_handle* handle, char* key, char* value) {
	char buf[256];
	snprintf(buf, sizeof buf, "%s=%s", key, value);
	return pam_putenv(handle, buf);
}

void setup_vt(int vt) {
	char p[32];
	snprintf(p, sizeof p, "/dev/tty%d", vt);
	int fd = check_errno("open tty", open(p, O_RDWR));

	check_errno("dup2", dup2(fd, 0));
	check_errno("dup2", dup2(fd, 1));
	check_errno("dup2", dup2(fd, 2));

	struct vt_mode mode = { 0 };
	mode.mode = VT_AUTO;
	check_errno("KDSETMODE", ioctl(fd, KDSETMODE, KD_TEXT));
	check_errno("VT_SETMODE", ioctl(fd, VT_SETMODE, &mode));
	check_errno("VT_ACTIVATE", ioctl(fd, VT_ACTIVATE, vt));
	check_errno("VT_WAITACTIVE", ioctl(fd, VT_WAITACTIVE, vt));
	close(fd);
}

void child_main(struct passwd *pwd, char* user_cmd, char** env) {
	check_errno("initgroups", initgroups(pwd->pw_name, pwd->pw_gid));
	check_errno("setgid", setgid(pwd->pw_gid));
	check_errno("setuid", setuid(pwd->pw_uid));
	check_errno("chdir", chdir(pwd->pw_dir));
	check_errno("prctl", prctl(PR_SET_PDEATHSIG, SIGTERM));

	char arg[1024];
	snprintf(arg, sizeof arg, "[ -f /etc/profile ] && . /etc/profile; [ -f $HOME/.profile ] && . $HOME/.profile; exec %s", user_cmd);
	char *const cmd[] = { "/bin/sh", "-c", arg, NULL, };
	execvpe(cmd[0], cmd, env);
}

int main(int argc, char *argv[]) {
	struct pam_conv conv = { pam_null_conv, NULL };
	struct pam_handle* handle;

	check_pam(handle, "pam_start", pam_start("autologin", argv[1], &conv, &handle));
	check_pam(handle, "pam_acct_mgmt", pam_acct_mgmt(handle, PAM_SILENT));
	check_pam(handle, "pam_setcred", pam_setcred(handle, PAM_ESTABLISH_CRED));

	setup_vt(1);

	struct passwd* pwd = getpwnam(argv[1]);
	if (pwd == NULL) {
		fprintf(stderr, "getpwnam failed\n");
		return 1;
	}

	check_pam(handle, "pam_putenv", pam_putenv(handle, "XDG_SEAT=seat0"));
	check_pam(handle, "pam_putenv", pam_putenv(handle, "XDG_SESSION_CLASS=user"));
	check_pam(handle, "pam_putenv", pam_putenv(handle, "XDG_VTNR=1"));
	check_pam(handle, "pam_putenv", pam_putenv_tuple(handle, "HOME", pwd->pw_dir));
	check_pam(handle, "pam_putenv", pam_putenv_tuple(handle, "PWD", pwd->pw_dir));
	check_pam(handle, "pam_putenv", pam_putenv_tuple(handle, "SHELL", pwd->pw_shell));
	check_pam(handle, "pam_putenv", pam_putenv_tuple(handle, "USER", pwd->pw_name));
	check_pam(handle, "pam_putenv", pam_putenv_tuple(handle, "LOGNAME", pwd->pw_name));
	check_pam(handle, "pam_putenv", pam_putenv_tuple(handle, "TERM", getenv("TERM") ?: "linux"));

	check_pam(handle, "pam_open_session", pam_open_session(handle, PAM_SILENT));
	char** env = pam_getenvlist(handle);

	pid_t pid = check_errno("fork", fork());
	if (pid == 0)
		child_main(pwd, argv[2], env);

	int res;
	while ((res = waitpid(pid, NULL, 0)) <= 0) {
		if (res == -1 && errno != EINTR) {
			fprintf(stderr, "waitpid failed: %s (%d)\n", strerror(errno), errno);
			break;
		}
	}

	check_pam(handle, "pam_close_session", pam_close_session(handle, PAM_SILENT));
	check_pam(handle, "pam_setcred", pam_setcred(handle, PAM_DELETE_CRED));
	check_pam(handle, "pam_end", pam_end(handle, 0));
	return 0;
}
