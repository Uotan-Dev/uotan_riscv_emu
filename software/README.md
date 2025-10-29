# Booting Linux on uemu

## Prereqs

* RISC-V Linux cross toolchain (example prefix: `riscv64-linux-gnu-`) on `PATH`.
* `dtc` (device tree compiler).
* `make`, `gcc` (host) and other usual build tools.
* `uemu` built from this repository.

---

## 1) Build the kernel

A `uemu_defconfig` is provided in the directory. Copy it to `arch/riscv/configs/` and configure:

```bash
cd /path/to/linux-stable
cp /path/to/uemu_defconfig arch/riscv/configs/uemu_defconfig
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- uemu_defconfig
```

<!-- **Embed an initramfs**
Before the full `make`, set `CONFIG_INITRAMFS_SOURCE` to point to your `rootfs.cpio`:

```bash
nano .config
# edit .config manually to set:
# CONFIG_INITRAMFS_SOURCE="/path/to/rootfs.cpio"
``` -->

Then build the kernel Image:

```bash
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j$(nproc)
# kernel Image will be at arch/riscv/boot/Image
```

---

## 2) Build the device tree blob (DTB)

`uemu.dts has been provided in this directory`:

```bash
dtc -I dts -O dtb -o /path/to/uemu.dtb /path/to/uemu.dts
```

---

## 3) Build OpenSBI (embedding kernel as payload + DTB)

Example OpenSBI build command you used (keeps important flags):

```bash
cd /path/to/opensbi
make BUILD_INFO=y \
     CROSS_COMPILE=riscv64-linux-gnu- \
     PLATFORM=generic \
     FW_FDT_PATH=/path/to/uemu.dtb \
     PLATFORM_RISCV_ISA="rv64imafd_zicsr_zifencei" \
     PLATFORM_RISCV_ABI="lp64" \
     FW_TEXT_START=0x80000000 \
     FW_PAYLOAD_PATH=/path/to/linux-stable/arch/riscv/boot/Image \
     -j$(nproc)
```

After success you get the firmware image: `build/platform/generic/firmware/fw_payload.elf`

---

## 4) Run uemu

```bash
uemu /path/to/fw_payload.elf
```
