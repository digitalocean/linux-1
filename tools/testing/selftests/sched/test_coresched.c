// SPDX-License-Identifier: GPL-2.0-only
/*
 * Core-scheduling selftests.
 *
 * Copyright (C) 2020, Joel Fernandes.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PR_SCHED_CORE_SHARE
#define PR_SCHED_CORE_SHARE 59
# define PR_SCHED_CORE_CLEAR            0
# define PR_SCHED_CORE_SHARE_FROM       1
# define PR_SCHED_CORE_SHARE_TO         2
#endif

#ifndef DEBUG_PRINT
#define dprint(...)
#else
#define dprint(str, args...) printf("DEBUG: %s: " str "\n", __func__, ##args)
#endif

void print_banner(char *s)
{
    printf("coresched: %s:  ", s);
}

void print_pass(void)
{
    printf("PASS\n");
}

void assert_cond(int cond, char *str)
{
    if (!cond) {
	printf("Error: %s\n", str);
	abort();
    }
}

char *make_group_root(void)
{
	char *mntpath, *mnt;
	int ret;

	mntpath = malloc(50);
	if (!mntpath) {
	    perror("Failed to allocate mntpath\n");
	    abort();
	}

	sprintf(mntpath, "/tmp/coresched-test-XXXXXX");
	mnt = mkdtemp(mntpath);
	if (!mnt) {
		perror("Failed to create mount: ");
		exit(-1);
	}

	ret = mount("nodev", mnt, "cgroup", 0, "cpu");
	if (ret == -1) {
		perror("Failed to mount cgroup: ");
		exit(-1);
	}

	return mnt;
}

char *read_group_cookie(char *cgroup_path)
{
    char path[50] = {}, *val;
    int fd;

    sprintf(path, "%s/cpu.core_group_cookie", cgroup_path);
    fd = open(path, O_RDONLY, 0666);
    if (fd == -1) {
	perror("Open of cgroup tag path failed: ");
	abort();
    }

    val = calloc(1, 50);
    if (read(fd, val, 50) == -1) {
	perror("Failed to read group cookie: ");
	abort();
    }

    val[strcspn(val, "\r\n")] = 0;

    close(fd);
    return val;
}

void assert_group_tag(char *cgroup_path, char *tag)
{
    char tag_path[50] = {}, rdbuf[8] = {};
    int tfd;

    sprintf(tag_path, "%s/cpu.core_tag", cgroup_path);
    tfd = open(tag_path, O_RDONLY, 0666);
    if (tfd == -1) {
	perror("Open of cgroup tag path failed: ");
	abort();
    }

    if (read(tfd, rdbuf, 1) != 1) {
	perror("Failed to enable coresched on cgroup: ");
	abort();
    }

    if (strcmp(rdbuf, tag)) {
	printf("Group tag does not match (exp: %s, act: %s)\n", tag, rdbuf);
	abort();
    }

    if (close(tfd) == -1) {
	perror("Failed to close tag fd: ");
	abort();
    }
}

void tag_group(char *cgroup_path)
{
	char tag_path[50];
	int tfd;

	sprintf(tag_path, "%s/cpu.core_tag", cgroup_path);
	tfd = open(tag_path, O_WRONLY, 0666);
	if (tfd == -1) {
		perror("Open of cgroup tag path failed: ");
		abort();
	}

	if (write(tfd, "1", 1) != 1) {
		perror("Failed to enable coresched on cgroup: ");
		abort();
	}

	if (close(tfd) == -1) {
		perror("Failed to close tag fd: ");
		abort();
	}

	assert_group_tag(cgroup_path, "1");
}

void untag_group(char *cgroup_path)
{
	char tag_path[50];
	int tfd;

	sprintf(tag_path, "%s/cpu.core_tag", cgroup_path);
	tfd = open(tag_path, O_WRONLY, 0666);
	if (tfd == -1) {
		perror("Open of cgroup tag path failed: ");
		abort();
	}

	if (write(tfd, "0", 1) != 1) {
		perror("Failed to disable coresched on cgroup: ");
		abort();
	}

	if (close(tfd) == -1) {
		perror("Failed to close tag fd: ");
		abort();
	}

	assert_group_tag(cgroup_path, "0");
}

char *make_group(char *parent, char *name)
{
	char *cgroup_path;
	int ret;

	if (!parent && !name)
	    return make_group_root();

	cgroup_path = malloc(50);
	if (!cgroup_path) {
	    perror("Failed to allocate cgroup_path\n");
	    abort();
	}

	/* Make the cgroup node for this group */
	sprintf(cgroup_path, "%s/%s", parent, name);
	ret = mkdir(cgroup_path, 0644);
	if (ret == -1) {
		perror("Failed to create group in cgroup: ");
		abort();
	}

	return cgroup_path;
}

static void del_group(char *path)
{
    if (rmdir(path) != 0) {
	printf("Removal of group failed\n");
	abort();
    }

    free(path);
}

static void del_root_group(char *path)
{
    if (umount(path) != 0) {
	perror("umount of cgroup failed\n");
	abort();
    }

    if (rmdir(path) != 0) {
	printf("Removal of group failed\n");
	abort();
    }

    free(path);
}

void assert_group_cookie_equal(char *c1, char *c2)
{
    char *v1, *v2;

    v1 = read_group_cookie(c1);
    v2 = read_group_cookie(c2);
    if (strcmp(v1, v2)) {
	printf("Group cookies not equal\n");
	abort();
    }

    free(v1);
    free(v2);
}

void assert_group_cookie_not_equal(char *c1, char *c2)
{
    char *v1, *v2;

    v1 = read_group_cookie(c1);
    v2 = read_group_cookie(c2);
    if (!strcmp(v1, v2)) {
	printf("Group cookies equal\n");
	abort();
    }

    free(v1);
    free(v2);
}

void assert_group_cookie_not_zero(char *c1)
{
    char *v1 = read_group_cookie(c1);

    v1[1] = 0;
    if (!strcmp(v1, "0")) {
	printf("Group cookie zero\n");
	abort();
    }
    free(v1);
}

void assert_group_cookie_zero(char *c1)
{
    char *v1 = read_group_cookie(c1);

    v1[1] = 0;
    if (strcmp(v1, "0")) {
	printf("Group cookie not zero");
	abort();
    }
    free(v1);
}

struct task_state {
    int pid_share;
    char pid_str[50];
    pthread_mutex_t m;
    pthread_cond_t cond;
    pthread_cond_t cond_par;
};

struct task_state *add_task(char *p)
{
    struct task_state *mem;
    pthread_mutexattr_t am;
    pthread_condattr_t a;
    char tasks_path[50];
    int tfd, pid, ret;

    sprintf(tasks_path, "%s/tasks", p);
    tfd = open(tasks_path, O_WRONLY, 0666);
    if (tfd == -1) {
	perror("Open of cgroup tasks path failed: ");
	abort();
    }

    mem = mmap(NULL, sizeof *mem, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(mem, 0, sizeof(*mem));

    pthread_condattr_init(&a);
    pthread_condattr_setpshared(&a, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_init(&am);
    pthread_mutexattr_setpshared(&am, PTHREAD_PROCESS_SHARED);

    pthread_cond_init(&mem->cond, &a);
    pthread_cond_init(&mem->cond_par, &a);
    pthread_mutex_init(&mem->m, &am);

    pid = fork();
    if (pid == 0) {
	while(1) {
	    pthread_mutex_lock(&mem->m);
	    while(!mem->pid_share)
		pthread_cond_wait(&mem->cond, &mem->m);

	    pid = mem->pid_share;
	    mem->pid_share = 0;

	    if (pid == -1) {
		if (prctl(PR_SCHED_CORE_SHARE, PR_SCHED_CORE_CLEAR, getpid(), 0, 0))
		    perror("prctl() PR_SCHED_CORE_CLEAR failed");
	    } else {
		if (prctl(PR_SCHED_CORE_SHARE, PR_SCHED_CORE_SHARE_FROM, pid, 0, 0))
		    perror("prctl() PR_SCHED_CORE_SHARE_FROM failed");
	    }
	    pthread_mutex_unlock(&mem->m);
	    pthread_cond_signal(&mem->cond_par);
	}
    }

    sprintf(mem->pid_str, "%d", pid);
    dprint("add task %d to group %s", pid, p);

    ret = write(tfd, mem->pid_str, strlen(mem->pid_str));
    assert_cond(ret != -1,
	    "Failed to write pid into tasks");

    close(tfd);
    return mem;
}

/* Make t1 share with t2 */
void make_tasks_share(struct task_state *t1, struct task_state *t2)
{
    int p2 = atoi(t2->pid_str);
    dprint("task %s %s", t1->pid_str, t2->pid_str);

    pthread_mutex_lock(&t1->m);
    t1->pid_share = p2;
    pthread_mutex_unlock(&t1->m);

    pthread_cond_signal(&t1->cond);

    pthread_mutex_lock(&t1->m);
    while (t1->pid_share)
	pthread_cond_wait(&t1->cond_par, &t1->m);
    pthread_mutex_unlock(&t1->m);
}

/* Make t1 share with t2 */
void reset_task_cookie(struct task_state *t1)
{
    dprint("task %s", t1->pid_str);

    pthread_mutex_lock(&t1->m);
    t1->pid_share = -1;
    pthread_mutex_unlock(&t1->m);

    pthread_cond_signal(&t1->cond);

    pthread_mutex_lock(&t1->m);
    while (t1->pid_share)
	pthread_cond_wait(&t1->cond_par, &t1->m);
    pthread_mutex_unlock(&t1->m);
}

char *get_task_core_cookie(char *pid)
{
    char proc_path[50];
    int found = 0;
    char *line;
    int i, j;
    FILE *fp;

    line = malloc(1024);
    assert_cond(!!line, "Failed to alloc memory");

    sprintf(proc_path, "/proc/%s/sched", pid);

    fp = fopen(proc_path, "r");
    while ((fgets(line, 1024, fp)) != NULL)
    {
        if(!strstr(line, "core_cookie"))
            continue;

        for (j = 0, i = 0; i < 1024 && line[i] != '\0'; i++)
            if (line[i] >= '0' && line[i] <= '9')
                line[j++] = line[i];
        line[j] = '\0';
        found = 1;
        break;
    }

    fclose(fp);

    if (found) {
        return line;
    } else {
        free(line);
	printf("core_cookie not found. Enable SCHED_DEBUG?\n");
	abort();
        return NULL;
    }
}

void assert_tasks_share(struct task_state *t1, struct task_state *t2)
{
    char *c1, *c2;

    c1 = get_task_core_cookie(t1->pid_str);
    c2 = get_task_core_cookie(t2->pid_str);
    dprint("check task (%s) cookie (%s) == task (%s) cookie (%s)",
	    t1->pid_str, c1, t2->pid_str, c2);
    assert_cond(!strcmp(c1, c2), "Tasks don't share cookie");
    free(c1); free(c2);
}

void assert_tasks_dont_share(struct task_state *t1,  struct task_state *t2)
{
    char *c1, *c2;
    c1 = get_task_core_cookie(t1->pid_str);
    c2 = get_task_core_cookie(t2->pid_str);
    dprint("check task (%s) cookie (%s) != task (%s) cookie (%s)",
	    t1->pid_str, c1, t2->pid_str, c2);
    assert_cond(strcmp(c1, c2), "Tasks don't share cookie");
    free(c1); free(c2);
}

void assert_task_has_cookie(char *pid)
{
    char *tk;

    tk = get_task_core_cookie(pid);

    assert_cond(strcmp(tk, "0"), "Task does not have cookie");

    free(tk);
}

void kill_task(struct task_state *t)
{
    int pid = atoi(t->pid_str);

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

/*
 * Test that a group's children have a cookie inherrited
 * from their parent group _after_ the parent was tagged.
 *
 *   p ----- c1 - c11
 *     \ c2 - c22
 */
static void test_cgroup_parent_child_tag_inherit(char *root)
{
    char *p, *c1, *c11, *c2, *c22;

    print_banner("TEST-CGROUP-PARENT-CHILD-TAG");

    p = make_group(root, "p");
    assert_group_cookie_zero(p);

    c1 = make_group(p, "c1");
    assert_group_tag(c1, "0"); /* Child tag is "0" but inherits cookie from parent. */
    assert_group_cookie_zero(c1);
    assert_group_cookie_equal(c1, p);

    c11 = make_group(c1, "c11");
    assert_group_tag(c11, "0");
    assert_group_cookie_zero(c11);
    assert_group_cookie_equal(c11, p);

    c2 = make_group(p, "c2");
    assert_group_tag(c2, "0");
    assert_group_cookie_zero(c2);
    assert_group_cookie_equal(c2, p);

    tag_group(p);

    /* Verify c1 got the cookie */
    assert_group_tag(c1, "0");
    assert_group_cookie_not_zero(c1);
    assert_group_cookie_equal(c1, p);

    /* Verify c2 got the cookie */
    assert_group_tag(c2, "0");
    assert_group_cookie_not_zero(c2);
    assert_group_cookie_equal(c2, p);

    /* Verify c11 got the cookie */
    assert_group_tag(c11, "0");
    assert_group_cookie_not_zero(c11);
    assert_group_cookie_equal(c11, p);

    /*
     * Verify c22 which is a nested group created
     * _after_ tagging got the cookie.
     */
    c22 = make_group(c2, "c22");

    assert_group_tag(c22, "0");
    assert_group_cookie_not_zero(c22);
    assert_group_cookie_equal(c22, c1);
    assert_group_cookie_equal(c22, c11);
    assert_group_cookie_equal(c22, c2);
    assert_group_cookie_equal(c22, p);

    del_group(c22);
    del_group(c11);
    del_group(c1);
    del_group(c2);
    del_group(p);
    print_pass();
}

/*
 * Test that a tagged group's children have a cookie inherrited
 * from their parent group.
 */
static void test_cgroup_parent_tag_child_inherit(char *root)
{
    char *p, *c1, *c2, *c3;

    print_banner("TEST-CGROUP-PARENT-TAG-CHILD-INHERIT");

    p = make_group(root, "p");
    assert_group_cookie_zero(p);
    tag_group(p);
    assert_group_cookie_not_zero(p);

    c1 = make_group(p, "c1");
    assert_group_cookie_not_zero(c1);
    /* Child tag is "0" but it inherits cookie from parent. */
    assert_group_tag(c1, "0");
    assert_group_cookie_equal(c1, p);

    c2 = make_group(p, "c2");
    assert_group_tag(c2, "0");
    assert_group_cookie_equal(c2, p);
    assert_group_cookie_equal(c1, c2);

    c3 = make_group(c1, "c3");
    assert_group_tag(c3, "0");
    assert_group_cookie_equal(c3, p);
    assert_group_cookie_equal(c1, c3);

    del_group(c3);
    del_group(c1);
    del_group(c2);
    del_group(p);
    print_pass();
}

static void test_prctl_in_group(char *root)
{
    char *p;
    struct task_state *tsk1, *tsk2, *tsk3;

    print_banner("TEST-PRCTL-IN-GROUP");

    p = make_group(root, "p");
    assert_group_cookie_zero(p);
    tag_group(p);
    assert_group_cookie_not_zero(p);

    tsk1 = add_task(p);
    assert_task_has_cookie(tsk1->pid_str);

    tsk2 = add_task(p);
    assert_task_has_cookie(tsk2->pid_str);

    tsk3 = add_task(p);
    assert_task_has_cookie(tsk3->pid_str);

    /* tsk2 share with tsk3 -- both get disconnected from CGroup. */
    make_tasks_share(tsk2, tsk3);
    assert_task_has_cookie(tsk2->pid_str);
    assert_task_has_cookie(tsk3->pid_str);
    assert_tasks_share(tsk2, tsk3);
    assert_tasks_dont_share(tsk1, tsk2);
    assert_tasks_dont_share(tsk1, tsk3);

    /* now reset tsk3 -- get connected back to CGroup. */
    reset_task_cookie(tsk3);
    assert_task_has_cookie(tsk3->pid_str);
    assert_tasks_dont_share(tsk2, tsk3);
    assert_tasks_share(tsk1, tsk3);      // tsk3 is back.
    assert_tasks_dont_share(tsk1, tsk2); // but tsk2 is still zombie

    /* now reset tsk2 as well to get it connected back to CGroup. */
    reset_task_cookie(tsk2);
    assert_task_has_cookie(tsk2->pid_str);
    assert_tasks_share(tsk2, tsk3);
    assert_tasks_share(tsk1, tsk3);
    assert_tasks_share(tsk1, tsk2);

    /* Test the rest of the cases (2 to 4)
     *
     *		t1		joining		t2
     * CASE 1:
     * before	0				0
     * after	new cookie			new cookie
     *
     * CASE 2:
     * before	X (non-zero)			0
     * after	0				0
     *
     * CASE 3:
     * before	0				X (non-zero)
     * after	X				X
     *
     * CASE 4:
     * before	Y (non-zero)			X (non-zero)
     * after	X				X
     */

    /* case 2: */
    dprint("case 2");
    make_tasks_share(tsk1, tsk1);
    assert_tasks_dont_share(tsk1, tsk2);
    assert_tasks_dont_share(tsk1, tsk3);
    assert_task_has_cookie(tsk1->pid_str);
    make_tasks_share(tsk1, tsk2); /* Will reset the task cookie. */
    assert_task_has_cookie(tsk1->pid_str);
    assert_task_has_cookie(tsk2->pid_str);

    /* case 3: */
    dprint("case 3");
    make_tasks_share(tsk2, tsk2);
    assert_tasks_dont_share(tsk2, tsk1);
    assert_tasks_dont_share(tsk2, tsk3);
    assert_task_has_cookie(tsk2->pid_str);
    make_tasks_share(tsk1, tsk2);
    assert_task_has_cookie(tsk1->pid_str);
    assert_task_has_cookie(tsk2->pid_str);
    assert_tasks_share(tsk1, tsk2);
    assert_tasks_dont_share(tsk1, tsk3);
    reset_task_cookie(tsk1);
    reset_task_cookie(tsk2);

    /* case 4: */
    dprint("case 4");
    assert_tasks_share(tsk1, tsk2);
    assert_task_has_cookie(tsk1->pid_str);
    assert_task_has_cookie(tsk2->pid_str);
    make_tasks_share(tsk1, tsk1);
    assert_task_has_cookie(tsk1->pid_str);
    make_tasks_share(tsk2, tsk2);
    assert_task_has_cookie(tsk2->pid_str);
    assert_tasks_dont_share(tsk1, tsk2);
    make_tasks_share(tsk1, tsk2);
    assert_task_has_cookie(tsk1->pid_str);
    assert_task_has_cookie(tsk2->pid_str);
    assert_tasks_share(tsk1, tsk2);
    assert_tasks_dont_share(tsk1, tsk3);
    reset_task_cookie(tsk1);
    reset_task_cookie(tsk2);

    kill_task(tsk1);
    kill_task(tsk2);
    kill_task(tsk3);
    del_group(p);
    print_pass();
}

int main() {
    char *root = make_group(NULL, NULL);

    test_cgroup_parent_tag_child_inherit(root);
    test_cgroup_parent_child_tag_inherit(root);
    test_prctl_in_group(root);

    del_root_group(root);
    return 0;
}
