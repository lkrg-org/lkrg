#!/bin/bash

PATH=$PATH:/sbin

image=ubuntu:jammy
qemu=qemu-system-x86_64
opts="-bios bios.bin"
console=ttyS0
root=/dev/sda
append=no_timer_check
init=/lkrg/.github/workflows/run-boot-tests.sh
kernel=linux-virtual
[ -n "$1" ] && declare "$@"

[ -v pkgs ] || pkgs="libelf-dev linux-headers-generic $kernel"

echo "::group::Build image ($image)"
set -exfu

# Keep it in other directory since we will COPY . .
td=$(mktemp -d)

# Generate system and build in the Docker.
docker build --tag test -f - . <<EOF
# bionic is the latest Ubuntu with i386 support.
FROM $image
ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update -y && \
    apt-get install -y \
            gcc \
            git \
            make \
            $pkgs
WORKDIR /lkrg
COPY . .
RUN git clean -dxfq
RUN DESTDIR= ./mkosi.build
RUN depmod -a \$(cd /lib/modules; ls)
EOF

# Convert Docker container into QEMU image (first extract rootfs).
docker rm test-container || :
docker create --name test-container test
mkdir -p $td/rootfs
docker export test-container | tar x -C $td/rootfs
docker rm test-container

# Since inside of the Docker is qemu-user we need to do as much
# as possible heavy operations outside of emulation.
# Also, qemu-system will be run externally to avoid double emulation.

qemu-img create -f raw $td/disk.img 8G
mkfs.ext4 -q -d $td/rootfs -F $td/disk.img
# Instead of hurling with the grub will boot using -kernel/-initrd.

set +xe
echo "::endgroup::"

echo "::group::Boot image ($qemu)"
# Output command in a handy way for a user.
set -x
set -- $qemu \
	-m 2G \
	-nographic \
	-no-reboot \
	-drive file=$td/disk.img,format=raw \
	-kernel $(find $td/rootfs/boot -name vmlinuz-* -print -quit) \
	-initrd $(find $td/rootfs/boot -name initrd.img-* -print -quit) \
	${dtb+-dtb $(find $td/rootfs/lib/firmware -name $dtb)} \
	$opts \
	-append "console=$console root=$root $append panic=-1 oops=panic panic_on_warn softlockup_panic=1 init=$init"
set +x
# Different versions of QEMU and kernels are not reliable at powering off ARM32
# machines, so seek help from expect(1) to terminate qemu when power off is
# failed.
expect - <<EOF -- "$@"
set timeout 300
spawn -noecho {*}\$argv
expect {
	"reboot: Power down" {
		send_user "ABORT\n"
		exit
	} "Reboot failed -- System halted" {
		send_user "ABORT\n"
		exit
	} timeout {
		send_user "TIMEOUT\n"
		exit
	}
}
EOF
rm -rf $td
echo "::endgroup::"
