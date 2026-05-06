# fs-pancake VM harness — build/boot a verity-imaged system that supports
# live rootfs swap via pivot_root(2).
#
#   make all       build base + sshd-{v1,v2} + chronyd-{v1,v2} + initramfs
#   make boot      launch the VM under qemu/kvm
#   make ssh       ssh into the booted VM
#   make clean     drop images + staging (keeps keys)
#   make clean-all also drop keys

KEY := keys/pancake_id_ed25519

IMAGES := images/base.img \
          images/sshd-v1.img images/sshd-v2.img \
          images/chronyd-v1.img images/chronyd-v2.img \
          images/pancake-initramfs.cpio.gz

.PHONY: all boot ssh clean clean-all

all: $(IMAGES)

images/base.img: build-base.sh lib.sh init
	./build-base.sh

images/sshd-v1.img images/sshd-v2.img: build-pkg.sh lib.sh
	./build-pkg.sh sshd $(patsubst images/sshd-%.img,%,$@)

images/chronyd-v1.img images/chronyd-v2.img: build-pkg.sh lib.sh
	./build-pkg.sh chronyd $(patsubst images/chronyd-%.img,%,$@)

images/pancake-initramfs.cpio.gz: build-initramfs.sh lib.sh init
	./build-initramfs.sh

boot: images/base.img images/sshd-v1.img images/chronyd-v1.img images/pancake-initramfs.cpio.gz
	./run-vm.sh

ssh:
	ssh -i $(KEY) -p 2222 \
	    -o StrictHostKeyChecking=no \
	    -o UserKnownHostsFile=/dev/null \
	    root@127.0.0.1

clean:
	rm -rf images
	sudo rm -rf staging

clean-all: clean
	rm -rf keys
