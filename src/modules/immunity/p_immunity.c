/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - (Un)Immunization module
 *
 * Notes:
 *  - Gives kernel a dose of vaccine
 *
 * Timeline:
 *  - Created: 20.I.2022
 *
 * Author:
 *  - Ilya 'milabs' Matveychikov (https://github.com/milabs)
 *
 */

#include "../../p_lkrg_main.h"

static struct {
	const char *	name;
	struct path	path;
	umode_t		mode;
} p_paths_to_fix[] = {
	{ "/boot" },
	{ "/lib/modules" },
};

static void *p__cmdline_proc_show = NULL;
static void *p__saved_command_line = NULL;

static int p_cmdline_proc_show(struct seq_file *m, void *v) {
	if (uid_eq(current_cred()->uid, GLOBAL_ROOT_UID)) {
		seq_puts(m, *(char **)p__saved_command_line);
	} else {
		seq_puts(m, "ro");
	}
	seq_putc(m, '\n');
	return 0;
}

void p_vaccinate(void) {
	int i;

	for (i = 0; i < ARRAY_SIZE(p_paths_to_fix); i++) {
		if (!p_paths_to_fix[i].name)
			continue;
		if (kern_path(p_paths_to_fix[i].name, LOOKUP_FOLLOW, &p_paths_to_fix[i].path)) {
			p_print_log(P_LKRG_WARN,
				"Unable to fix path %s\n", p_paths_to_fix[i].name);
			p_paths_to_fix[i].name = NULL;
		} else {
			p_paths_to_fix[i].mode = p_paths_to_fix[i].path.dentry->d_inode->i_mode;
			p_paths_to_fix[i].path.dentry->d_inode->i_mode &= 077700;
		}
	}

	/* FIXME: lookup /proc/cmdline dentry & replace show callback */

	p__cmdline_proc_show = p__cmdline_proc_show ?:
		(void *)P_SYM(p_kallsyms_lookup_name)("cmdline_proc_show");
	p__saved_command_line = p__saved_command_line ?:
		(void *)P_SYM(p_kallsyms_lookup_name)("saved_command_line");

	if (p__cmdline_proc_show &&
	    p__saved_command_line) {
		remove_proc_entry("cmdline", NULL);
		proc_create_single("cmdline", 0, NULL, p_cmdline_proc_show);
	} else {
		p_print_log(P_LKRG_WARN,
			"Unable to forge /proc/cmdline");
	}

	/* TODO: forge utsname */
}

void p_devaccinate(void) {
	int i;

	for (i = 0; i < ARRAY_SIZE(p_paths_to_fix); i++) {
		if (!p_paths_to_fix[i].name)
			continue;
		p_paths_to_fix[i].path.dentry->d_inode->i_mode = p_paths_to_fix[i].mode;
		path_put(&p_paths_to_fix[i].path);
	}

	if (p__cmdline_proc_show &&
	    p__saved_command_line) {
		remove_proc_entry("cmdline", NULL);
		proc_create_single("cmdline", 0, NULL, p__cmdline_proc_show);
	}
}
