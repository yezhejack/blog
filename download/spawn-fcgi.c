#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_PWD_H
# include <grp.h>
# include <pwd.h>
#endif

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#define FCGI_LISTENSOCK_FILENO 0

# include <sys/socket.h>
# include <sys/ioctl.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <sys/un.h>
# include <arpa/inet.h>

# include <netdb.h>

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

/* for solaris 2.5 and netbsd 1.3.x */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

//查看执行的权限是否被修改过,如果是不一样则说明设置了suid或者guid，导致运行者可以直接拥有文件所有者的权限
#ifndef HAVE_ISSETUGID
static int issetugid() {
	return (geteuid() != getuid() || getegid() != getgid());
}
#endif

#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
# define USE_IPV6
#endif

#ifdef USE_IPV6
#define PACKAGE_FEATURES " (ipv6)"
#else
#define PACKAGE_FEATURES ""
#endif

#define PACKAGE_DESC "spawn-fcgi v" PACKAGE_VERSION PACKAGE_FEATURES " - spawns FastCGI processes\n"

#define CONST_STR_LEN(s) s, sizeof(s) - 1

static mode_t read_umask(void) {
	mode_t mask = umask(0);
	umask(mask);
	return mask;
}

static ssize_t write_all(int fildes, const void *buf, size_t nbyte) {
	size_t rem;
	for (rem = nbyte; rem > 0;) {
		ssize_t res = write(fildes, buf, rem);
		if (-1 == res) {
			if (EINTR != errno) return res;
		} else {
			buf = res + (char const*) buf;
			rem -= res;
		}
	}
	return nbyte;
}

static int bind_socket(const char *addr, unsigned short port, const char *unixsocket, uid_t uid, gid_t gid, mode_t mode, int backlog) {
	int fcgi_fd, socket_type, val;
    //unix 套接字
	struct sockaddr_un fcgi_addr_un;
	// 网络ipv4套接字
	struct sockaddr_in fcgi_addr_in;
#ifdef USE_IPV6
	struct sockaddr_in6 fcgi_addr_in6;
#endif
	struct sockaddr *fcgi_addr;

	socklen_t servlen;

	if (unixsocket) {
		memset(&fcgi_addr_un, 0, sizeof(fcgi_addr_un));

		fcgi_addr_un.sun_family = AF_UNIX;
		/* already checked in main() */
		if (strlen(unixsocket) > sizeof(fcgi_addr_un.sun_path) - 1) return -1;
		strcpy(fcgi_addr_un.sun_path, unixsocket);

#ifdef SUN_LEN
		servlen = SUN_LEN(&fcgi_addr_un);
#else
		/* stevens says: */
		servlen = strlen(fcgi_addr_un.sun_path) + sizeof(fcgi_addr_un.sun_family);
#endif
		socket_type = AF_UNIX;
		fcgi_addr = (struct sockaddr *) &fcgi_addr_un;

		/* check if some backend is listening on the socket
		 * as if we delete the socket-file and rebind there will be no "socket already in use" error
		 */
		if (-1 == (fcgi_fd = socket(socket_type, SOCK_STREAM, 0))) {
			fprintf(stderr, "spawn-fcgi: couldn't create socket: %s\n", strerror(errno));
			return -1;
		}

		if (0 == connect(fcgi_fd, fcgi_addr, servlen)) {
			fprintf(stderr, "spawn-fcgi: socket is already in use, can't spawn\n");
			close(fcgi_fd);
			return -1;
		}

		/* cleanup previous socket if it exists */
		if (-1 == unlink(unixsocket)) {
			switch (errno) {
			case ENOENT:
				break;
			default:
				fprintf(stderr, "spawn-fcgi: removing old socket failed: %s\n", strerror(errno));
				close(fcgi_fd);
				return -1;
			}
		}

		close(fcgi_fd);
	} else {
		memset(&fcgi_addr_in, 0, sizeof(fcgi_addr_in));
		fcgi_addr_in.sin_family = AF_INET;
		fcgi_addr_in.sin_port = htons(port);

		servlen = sizeof(fcgi_addr_in);
		socket_type = AF_INET;
		fcgi_addr = (struct sockaddr *) &fcgi_addr_in;

#ifdef USE_IPV6
		memset(&fcgi_addr_in6, 0, sizeof(fcgi_addr_in6));
		fcgi_addr_in6.sin6_family = AF_INET6;
		fcgi_addr_in6.sin6_port = fcgi_addr_in.sin_port;
#endif

		if (addr == NULL) {
			fcgi_addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
#ifdef HAVE_INET_PTON
		} else if (1 == inet_pton(AF_INET, addr, &fcgi_addr_in.sin_addr)) {
			/* nothing to do */
#ifdef HAVE_IPV6
		} else if (1 == inet_pton(AF_INET6, addr, &fcgi_addr_in6.sin6_addr)) {
			servlen = sizeof(fcgi_addr_in6);
			socket_type = AF_INET6;
			fcgi_addr = (struct sockaddr *) &fcgi_addr_in6;
#endif
		} else {
			fprintf(stderr, "spawn-fcgi: '%s' is not a valid IP address\n", addr);
			return -1;
#else
		} else {
			if ((in_addr_t)(-1) == (fcgi_addr_in.sin_addr.s_addr = inet_addr(addr))) {
				fprintf(stderr, "spawn-fcgi: '%s' is not a valid IPv4 address\n", addr);
				return -1;
			}
#endif
		}
	}


	if (-1 == (fcgi_fd = socket(socket_type, SOCK_STREAM, 0))) {
		fprintf(stderr, "spawn-fcgi: couldn't create socket: %s\n", strerror(errno));
		return -1;
	}

	val = 1;
	if (setsockopt(fcgi_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		fprintf(stderr, "spawn-fcgi: couldn't set SO_REUSEADDR: %s\n", strerror(errno));
		close(fcgi_fd);
		return -1;
	}

	if (-1 == bind(fcgi_fd, fcgi_addr, servlen)) {
		fprintf(stderr, "spawn-fcgi: bind failed: %s\n", strerror(errno));
		close(fcgi_fd);
		return -1;
	}

	if (unixsocket) {
		if (-1 == chmod(unixsocket, mode)) {
			fprintf(stderr, "spawn-fcgi: couldn't chmod socket: %s\n", strerror(errno));
			close(fcgi_fd);
			unlink(unixsocket);
			return -1;
		}

		if (0 != uid || 0 != gid) {
			if (0 == uid) uid = -1;
			if (0 == gid) gid = -1;
			if (-1 == chown(unixsocket, uid, gid)) {
				fprintf(stderr, "spawn-fcgi: couldn't chown socket: %s\n", strerror(errno));
				close(fcgi_fd);
				unlink(unixsocket);
				return -1;
			}
		}
	}

	if (-1 == listen(fcgi_fd, backlog)) {
		fprintf(stderr, "spawn-fcgi: listen failed: %s\n", strerror(errno));
		close(fcgi_fd);
		if (unixsocket) unlink(unixsocket);
		return -1;
	}

	return fcgi_fd;
}

static int fcgi_spawn_connection(char *appPath, char **appArgv, int fcgi_fd, int fork_count, int child_count, int pid_fd, int nofork) {
	int status, rc = 0;
	struct timeval tv = { 0, 100 * 1000 };

	pid_t child;

	while (fork_count-- > 0) {

		if (!nofork) {
			child = fork();

		} else {
			child = 0;
		}

		switch (child) {
		case 0: {
			char cgi_childs[64];
			int max_fd = 0;

			int i = 0;

			if (child_count >= 0) {
				snprintf(cgi_childs, sizeof(cgi_childs), "PHP_FCGI_CHILDREN=%d", child_count);
				putenv(cgi_childs);
			}

			if(fcgi_fd != FCGI_LISTENSOCK_FILENO) {
				close(FCGI_LISTENSOCK_FILENO);
				dup2(fcgi_fd, FCGI_LISTENSOCK_FILENO);
				close(fcgi_fd);
			}

			/* loose control terminal */
			if (!nofork) {
				setsid();
                //因为文件描述符总是从小到大安排，因此这个是最大的文件描述符
				max_fd = open("/dev/null", O_RDWR);
				if (-1 != max_fd) {
					if (max_fd != STDOUT_FILENO) dup2(max_fd, STDOUT_FILENO);
					if (max_fd != STDERR_FILENO) dup2(max_fd, STDERR_FILENO);
					if (max_fd != STDOUT_FILENO && max_fd != STDERR_FILENO) close(max_fd);
				} else {
					fprintf(stderr, "spawn-fcgi: couldn't open and redirect stdout/stderr to '/dev/null': %s\n", strerror(errno));
				}
			}
            //将其它的所有socket关闭
            //0,1,2分别是stdout stderr stdin
			/* we don't need the client socket */
			for (i = 3; i < max_fd; i++) {
				if (i != FCGI_LISTENSOCK_FILENO) close(i);
			}

			/* fork and replace shell */
			if (appArgv) {
				execv(appArgv[0], appArgv);

			} else {
				char *b = malloc((sizeof("exec ") - 1) + strlen(appPath) + 1);
				strcpy(b, "exec ");
				strcat(b, appPath);

				/* exec the cgi */
				execl("/bin/sh", "sh", "-c", b, (char *)NULL);

				free(b);
			}

			/* in nofork mode stderr is still open */
			fprintf(stderr, "spawn-fcgi: exec failed: %s\n", strerror(errno));
			exit(errno);

			break;
		}
		case -1:
			/* error */
			fprintf(stderr, "spawn-fcgi: fork failed: %s\n", strerror(errno));
			break;
		default:
			/* father */

			/* wait */
			select(0, NULL, NULL, NULL, &tv);
            
			switch (waitpid(child, &status, WNOHANG)) {
			case 0:
				fprintf(stdout, "spawn-fcgi: child spawned successfully: PID: %d\n", child);

				/* write pid file */
				if (-1 != pid_fd) {
					/* assume a 32bit pid_t */
					char pidbuf[12];

					snprintf(pidbuf, sizeof(pidbuf) - 1, "%d", child);

					if (-1 == write_all(pid_fd, pidbuf, strlen(pidbuf))) {
						fprintf(stderr, "spawn-fcgi: writing pid file failed: %s\n", strerror(errno));
						close(pid_fd);
						pid_fd = -1;
					}
					/* avoid eol for the last one */
					if (-1 != pid_fd && fork_count != 0) {
						if (-1 == write_all(pid_fd, "\n", 1)) {
							fprintf(stderr, "spawn-fcgi: writing pid file failed: %s\n", strerror(errno));
							close(pid_fd);
							pid_fd = -1;
						}
					}
				}

				break;
			case -1:
				break;
			default:
				if (WIFEXITED(status)) {
					fprintf(stderr, "spawn-fcgi: child exited with: %d\n",
						WEXITSTATUS(status));
					rc = WEXITSTATUS(status);
				} else if (WIFSIGNALED(status)) {
					fprintf(stderr, "spawn-fcgi: child signaled: %d\n",
						WTERMSIG(status));
					rc = 1;
				} else {
					fprintf(stderr, "spawn-fcgi: child died somehow: exit status = %d\n",
						status);
					rc = status;
				}
			}

			break;
		}
	}

	if (-1 != pid_fd) {
		close(pid_fd);
	}

	close(fcgi_fd);

	return rc;
}

static int find_user_group(const char *user, const char *group, uid_t *uid, gid_t *gid, const char **username) {
	uid_t my_uid = 0;
	gid_t my_gid = 0;
	struct passwd *my_pwd = NULL;
	struct group *my_grp = NULL;
	char *endptr = NULL;
	*uid = 0; *gid = 0;
	if (username) *username = NULL;

	if (user) {
		//这句话用来区分用户在参数-u后面添加的是uid还是username，如果是uid则会跳转到else分支中
		my_uid = strtol(user, &endptr, 10);

		if (my_uid <= 0 || *endptr) {
			//getpwname 是用于查找系统中的用户，返回一个passwd的结构体，这个结构体包涵了用户的各种信息，包括加密过的用户密码
			if (NULL == (my_pwd = getpwnam(user))) {
				fprintf(stderr, "spawn-fcgi: can't find user name %s\n", user);
				return -1;
			}
			//获得用户的uid
			my_uid = my_pwd->pw_uid;

			if (my_uid == 0) {
				fprintf(stderr, "spawn-fcgi: I will not set uid to 0\n");
				return -1;
			}

			if (username) *username = user;
		} else {
			my_pwd = getpwuid(my_uid);
			if (username && my_pwd) *username = my_pwd->pw_name;
		}
	}

	if (group) {
		my_gid = strtol(group, &endptr, 10);

		if (my_gid <= 0 || *endptr) {
			if (NULL == (my_grp = getgrnam(group))) {
				fprintf(stderr, "spawn-fcgi: can't find group name %s\n", group);
				return -1;
			}
			my_gid = my_grp->gr_gid;

			if (my_gid == 0) {
				fprintf(stderr, "spawn-fcgi: I will not set gid to 0\n");
				return -1;
			}
		}
	} else if (my_pwd) {
		my_gid = my_pwd->pw_gid;

		if (my_gid == 0) {
			fprintf(stderr, "spawn-fcgi: I will not set gid to 0\n");
			return -1;
		}
	}

	*uid = my_uid;
	*gid = my_gid;
	return 0;
}

static void show_version () {
	(void) write_all(1, CONST_STR_LEN(
		PACKAGE_DESC
	));
}

static void show_help () {
	(void) write_all(1, CONST_STR_LEN(
		"Usage: spawn-fcgi [options] [-- <fcgiapp> [fcgi app arguments]]\n" \
		"\n" \
		PACKAGE_DESC \
		"\n" \
		"Options:\n" \
		" -f <path>      filename of the fcgi-application (deprecated; ignored if\n" \
		"                <fcgiapp> is given; needs /bin/sh)\n" \
		" -d <directory> chdir to directory before spawning\n" \
		" -a <address>   bind to IPv4/IPv6 address (defaults to 0.0.0.0)\n" \
		" -p <port>      bind to TCP-port\n" \
		" -s <path>      bind to Unix domain socket\n" \
		" -M <mode>      change Unix domain socket mode (octal integer, default: allow\n" \
		"                read+write for user and group as far as umask allows it) \n" \
		" -C <children>  (PHP only) numbers of childs to spawn (default: not setting\n" \
		"                the PHP_FCGI_CHILDREN environment variable - PHP defaults to 0)\n" \
		" -F <children>  number of children to fork (default 1)\n" \
		" -b <backlog>   backlog to allow on the socket (default 1024)\n" \
		" -P <path>      name of PID-file for spawned process (ignored in no-fork mode)\n" \
		" -n             no fork (for daemontools)\n" \
		" -v             show version\n" \
		" -?, -h         show this help\n" \
		"(root only)\n" \
		" -c <directory> chroot to directory\n" \
		" -S             create socket before chroot() (default is to create the socket\n" \
		"                in the chroot)\n" \
		" -u <user>      change to user-id\n" \
		" -g <group>     change to group-id (default: primary group of user if -u\n" \
		"                is given)\n" \
		" -U <user>      change Unix domain socket owner to user-id\n" \
		" -G <group>     change Unix domain socket group to group-id\n" \
	));
}


int main(int argc, char **argv) {
	char *fcgi_app = NULL, *changeroot = NULL, *username = NULL,
	     *groupname = NULL, *unixsocket = NULL, *pid_file = NULL,
	     *sockusername = NULL, *sockgroupname = NULL, *fcgi_dir = NULL,
	     *addr = NULL;
	char **fcgi_app_argv = { NULL };
	char *endptr = NULL;
	unsigned short port = 0;
	mode_t sockmode =  (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) & ~read_umask();
	int child_count = -1;
	int fork_count = 1;
	int backlog = 1024;
	int i_am_root, o;
	int pid_fd = -1;
	int nofork = 0;
	int sockbeforechroot = 0;
	struct sockaddr_un un;
	int fcgi_fd = -1;

	if (argc < 2) { /* no arguments given */
		show_help();
		return -1;
	}
    //getuid 返回启用这个进程的真实用户的ID，如果是0说明是root用户，i_am_root也就是true
	i_am_root = (getuid() == 0);
    /* 解析参数
     * argc记录了参数的数量 
     * argv是一个纪录参数的数据
     * optind是指向当前的参数指针，初始值为1
     * getopt会让optind不断下移，当没有更多的参数的时候返回getopt 返回－1
     * getopt的第三个参数是optstring，如果有冒号，则说明这个选项需要一个参数
     * 每次都会把参数的指针放到optarg中
     * strtol 用于将一个字符串转换为对应基数的长整型，它会先忽略optarg的前面的尽量多的空格，然后遇到一个非空格字符后，就开始尽可能地转换字符
     * 返回的时候如果endptr不为空的话，会让它指向翻译后的第一个字符。猜测：如果完全翻译完，是会返回NULL的，这样才可以看输入是否合法
     */
	while (-1 != (o = getopt(argc, argv, "c:d:f:g:?hna:p:b:u:vC:F:s:P:U:G:M:S"))) {
		switch(o) {
		case 'f': fcgi_app = optarg; break;
		case 'd': fcgi_dir = optarg; break;
		case 'a': addr = optarg;/* ip addr */ break;
		case 'p': port = strtol(optarg, &endptr, 10);/* port */
			if (*endptr) {
				fprintf(stderr, "spawn-fcgi: invalid port: %u\n", (unsigned int) port);
				return -1;
			}
			break;
		case 'C': child_count = strtol(optarg, NULL, 10);/*  */ break;
		case 'F': fork_count = strtol(optarg, NULL, 10);/*  */ break;
		case 'b': backlog = strtol(optarg, NULL, 10);/*  */ break;
		case 's': unixsocket = optarg; /* unix-domain socket */ break;
		//只有root用户下面这些参数才有意义，否则不会赋值
		case 'c': if (i_am_root) { changeroot = optarg; }/* chroot() */ break;
		case 'u': if (i_am_root) { username = optarg; } /* set user */ break;
		case 'g': if (i_am_root) { groupname = optarg; } /* set group */ break;
		case 'U': if (i_am_root) { sockusername = optarg; } /* set socket user */ break;
		case 'G': if (i_am_root) { sockgroupname = optarg; } /* set socket group */ break;
		case 'S': if (i_am_root) { sockbeforechroot = 1; } /* open socket before chroot() */ break;
		case 'M': sockmode = strtol(optarg, NULL, 8); /* set socket mode */ break;
		case 'n': nofork = 1; break;
		case 'P': pid_file = optarg; /* PID file */ break;
		case 'v': show_version(); return 0;
		case '?':
		case 'h': show_help(); return 0;
		default:
			show_help();
			return -1;
		}
	}
    // 获得需要运行的app的参数放在fcgi_app_argv中
	if (optind < argc) {
		fcgi_app_argv = &argv[optind];
	}
    // 处理没有给出app及参数的警告
	if (NULL == fcgi_app && NULL == fcgi_app_argv) {
		fprintf(stderr, "spawn-fcgi: no FastCGI application given\n");
		return -1;
	}
    // 只可以使用一种socket，一种是给出端口号的常见的网络的socket，另一中叫做unixsocket，本质是一个文件，用于本机的进程通信
	if (0 == port && NULL == unixsocket) {
		//没有指定任何的socket
		fprintf(stderr, "spawn-fcgi: no socket given (use either -p or -s)\n");
		return -1;
	} else if (0 != port && NULL != unixsocket) {
		//同时指定了两种socket
		fprintf(stderr, "spawn-fcgi: either a Unix domain socket or a TCP-port, but not both\n");
		return -1;
	}
    // 这里需要检查一下unixsocket的长度，因为有C语言风格的字符串需要最后一位存储/0来表示字符串的结尾，所以需要－1
	if (unixsocket && strlen(unixsocket) > sizeof(un.sun_path) - 1) {
		fprintf(stderr, "spawn-fcgi: path of the Unix domain socket is too long\n");
		return -1;
	}
    
    // 查看是否有执行权限
	/* SUID handling */
	if (!i_am_root && issetugid()) {
		fprintf(stderr, "spawn-fcgi: Are you nuts? Don't apply a SUID bit to this binary\n");
		return -1;
	}

	if (nofork) pid_file = NULL; /* ignore pid file in no-fork mode */
    // 创建一个文件pid_file，同时有一些列的标志位
    // O_WRONLY 以只写方式打开文件
    // O_CREAT 若欲打开的文件不存在则自动建立该文件
    // O_EXCL 和O_CRET 同时被设置，则此命令会去检查文件是否存在，若存在则会打开失败，这个命令用来防止已有的文件被覆盖。
    // O_TRUNC 是用来将文件的长度缩短到0，只能是regular文件
    // 第三个参数是关于文件的权限的，可以参考gnu的C语言，可以看到这个是用户可读写，其它都是可读的文件，只有在创建的时候可用，但其它情况下也不会有任何损失
	if (pid_file &&
	    (-1 == (pid_fd = open(pid_file, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)))) {
		struct stat st;
	    // 如果O_EXCL 和 O_CRET都被设置了，且文件也存在则失败
	    // 程序已开始就定义好了三种标准输入输出流stdin stdout stderr
	    // errno 记录了系统最后一次的错误代号，这个不是C自动的事情，而是一些库函数实现写好的，在崩溃之前把错误写入errno中
		if (errno != EEXIST) {
			fprintf(stderr, "spawn-fcgi: opening PID-file '%s' failed: %s\n",
				pid_file, strerror(errno));
			return -1;
		}

		/* ok, file exists */
        // stat 检查一个文件的状态，结果存在st中
		if (0 != stat(pid_file, &st)) {
			fprintf(stderr, "spawn-fcgi: stating PID-file '%s' failed: %s\n",
				pid_file, strerror(errno));
			return -1;
		}

		/* is it a regular file ? */

		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "spawn-fcgi: PID-file exists and isn't regular file: '%s'\n",
				pid_file);
			return -1;
		}
        // 前面的一个open是检查了这个文件是不是已经存在了，存在了进入这个if，然后检查是不是存在，并且是不是一个常规文件。
		if (-1 == (pid_fd = open(pid_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) {
			fprintf(stderr, "spawn-fcgi: opening PID-file '%s' failed: %s\n",
				pid_file, strerror(errno));
			return -1;
		}
	}

	if (i_am_root) {
		// uid_t 和 gid_t 实际上就是unsigned int的别名
		uid_t uid, sockuid;
		gid_t gid, sockgid;
		const char* real_username;
        //当运行spawn-fcgi的用户是root的情况下，找到用户指定的用户或组，以及socket的用户和组
		if (-1 == find_user_group(username, groupname, &uid, &gid, &real_username))
			return -1;

		if (-1 == find_user_group(sockusername, sockgroupname, &sockuid, &sockgid, NULL))
			return -1;

		if (uid != 0 && gid == 0) {
			fprintf(stderr, "spawn-fcgi: WARNING: couldn't find the user for uid %i and no group was specified, so only the user privileges will be dropped\n", (int) uid);
		}

		if (0 == sockuid) sockuid = uid;
		if (0 == sockgid) sockgid = gid;

		if (sockbeforechroot && -1 == (fcgi_fd = bind_socket(addr, port, unixsocket, sockuid, sockgid, sockmode, backlog)))
			return -1;

		/* Change group before chroot, when we have access
		 * to /etc/group
		 */
		if (gid != 0) {
			if (-1 == setgid(gid)) {
				fprintf(stderr, "spawn-fcgi: setgid(%i) failed: %s\n", (int) gid, strerror(errno));
				return -1;
			}
			if (-1 == setgroups(0, NULL)) {
				fprintf(stderr, "spawn-fcgi: setgroups(0, NULL) failed: %s\n", strerror(errno));
				return -1;
			}
			if (real_username) {
				if (-1 == initgroups(real_username, gid)) {
					fprintf(stderr, "spawn-fcgi: initgroups('%s', %i) failed: %s\n", real_username, (int) gid, strerror(errno));
					return -1;
				}
			}
		}

		if (changeroot) {
			if (-1 == chroot(changeroot)) {
				fprintf(stderr, "spawn-fcgi: chroot('%s') failed: %s\n", changeroot, strerror(errno));
				return -1;
			}
			if (-1 == chdir("/")) {
				fprintf(stderr, "spawn-fcgi: chdir('/') failed: %s\n", strerror(errno));
				return -1;
			}
		}

		if (!sockbeforechroot && -1 == (fcgi_fd = bind_socket(addr, port, unixsocket, sockuid, sockgid, sockmode, backlog)))
			return -1;
        
		/* drop root privs */
		if (uid != 0) {
			if (-1 == setuid(uid)) {
				fprintf(stderr, "spawn-fcgi: setuid(%i) failed: %s\n", (int) uid, strerror(errno));
				return -1;
			}
		}
	} else {
		if (-1 == (fcgi_fd = bind_socket(addr, port, unixsocket, 0, 0, sockmode, backlog)))
			return -1;
	}

	if (fcgi_dir && -1 == chdir(fcgi_dir)) {
		fprintf(stderr, "spawn-fcgi: chdir('%s') failed: %s\n", fcgi_dir, strerror(errno));
		return -1;
	}
    //总之，至此获得了一个fcgi_fd来表示我们的服务端需要监听的socket
    //并且，对程序的一系列权限进行了转换
	return fcgi_spawn_connection(fcgi_app, fcgi_app_argv, fcgi_fd, fork_count, child_count, pid_fd, nofork);
}
