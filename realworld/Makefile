# assix realworld test harness — phase 1.
#
#   make all    builds base + sshd-v1 + sshd-v2 + chronyd-v1 + chronyd-v2 + initramfs
#   make boot   launches the VM
#   make ssh    ssh into the booted VM
#   make clean  drops images + staging (keeps keys)

KEY := keys/assix_id_ed25519

IMAGES := images/base.img \
          images/sshd-v1.img images/sshd-v2.img \
          images/chronyd-v1.img images/chronyd-v2.img \
          images/assix-initramfs.cpio.gz

.PHONY: all boot ssh clean clean-all keys

all: $(IMAGES)

images/base.img: build-base.sh lib.sh init
	./build-base.sh

images/sshd-v1.img: build-pkg.sh lib.sh
	./build-pkg.sh sshd v1
images/sshd-v2.img: build-pkg.sh lib.sh
	./build-pkg.sh sshd v2
images/chronyd-v1.img: build-pkg.sh lib.sh
	./build-pkg.sh chronyd v1
images/chronyd-v2.img: build-pkg.sh lib.sh
	./build-pkg.sh chronyd v2

images/assix-initramfs.cpio.gz: build-initramfs.sh lib.sh init
	./build-initramfs.sh

boot: images/base.img images/sshd-v1.img images/chronyd-v1.img images/assix-initramfs.cpio.gz
	./run-vm.sh

ssh:
	ssh -i $(KEY) -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1

clean:
	rm -rf images
	sudo rm -rf staging

clean-all: clean
	rm -rf keys
