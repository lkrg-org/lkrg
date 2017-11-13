##
# Makefile for p_lkrg
#
# Author:
#  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
##

export CFLAGS="$CFLAGS"

P_OUTPUT = "output"

P_CLI_CMD = "p_lkrg-client"
P_CLI_KMOD = "p_lkrg_kmod_cli.ko"

obj-m += p_lkrg.o
p_lkrg-objs += src/modules/ksyms/p_resolve_ksym.o \
               src/modules/hashing/p_super_fast_hash.o \
               src/modules/comm_channel/p_comm_channel.o \
               src/modules/wrap/p_struct_wrap.o \
               src/modules/hashing/p_crypto_sha1.o \
               src/modules/integrity_timer/p_integrity_timer.o \
               src/modules/kmod/p_kmod.o \
               src/modules/database/CPU.o \
               src/modules/database/arch/x86/IDT_MSR_CRx.o \
               src/modules/database/p_database.o \
               src/modules/notifiers/p_notifiers.o \
               src/modules/self-defense/hiding/p_hiding.o \
               src/modules/exploit_detection/p_rb_ed_trees/p_rb_ed_pids/p_rb_ed_pids_tree.o \
               src/modules/exploit_detection/syscalls/p_sys_execve/p_sys_execve.o \
               src/modules/exploit_detection/syscalls/p_do_exit/p_do_exit.o \
               src/modules/exploit_detection/syscalls/p_do_fork/p_do_fork.o \
               src/modules/exploit_detection/syscalls/p_sys_setuid/p_sys_setuid.o \
               src/modules/exploit_detection/syscalls/p_sys_setreuid/p_sys_setreuid.o \
               src/modules/exploit_detection/syscalls/p_sys_setresuid/p_sys_setresuid.o \
               src/modules/exploit_detection/syscalls/p_sys_setfsuid/p_sys_setfsuid.o \
               src/modules/exploit_detection/syscalls/p_sys_setgid/p_sys_setgid.o \
               src/modules/exploit_detection/syscalls/p_sys_setregid/p_sys_setregid.o \
               src/modules/exploit_detection/syscalls/p_sys_setresgid/p_sys_setresgid.o \
               src/modules/exploit_detection/syscalls/p_sys_setfsgid/p_sys_setfsgid.o \
               src/modules/exploit_detection/syscalls/p_sys_setgroups/p_sys_setgroups.o \
               src/modules/exploit_detection/syscalls/p_do_init_module/p_do_init_module.o \
               src/modules/exploit_detection/syscalls/p_sys_delete_module/p_sys_delete_module.o \
               src/modules/exploit_detection/syscalls/p_may_open/p_may_open.o \
               src/modules/exploit_detection/syscalls/p_sel_write_enforce/p_sel_write_enforce.o \
               src/modules/exploit_detection/p_exploit_detection.o \
               src/p_lkrg_main.o


all:
#	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mkdir -p $(P_OUTPUT)
	mv $(PWD)/p_lkrg.ko $(P_OUTPUT)

install:
	mkdir -p /lib/modules/`uname -r`/kernel/arch/x86/kernel/
	cp p_krd.ko /lib/modules/`uname -r`/kernel/arch/x86/kernel/p_krd.ko
	depmod /lib/modules/`uname -r`/kernel/arch/x86/kernel/p_krd.ko

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(RM) Module.markers modules.order
	$(RM) $(PWD)/src/modules/kmod/client/kmod/Module.markers
	$(RM) $(PWD)/src/modules/kmod/client/kmod/modules.order
	$(RM) -rf $(P_OUTPUT)
