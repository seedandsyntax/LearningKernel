# Kernel Bug Testing Tools

- Specifically tailored examples that work in the kernel.
- There had been User-Space related examples as well (primarily for glibc) to learn about such spaces intricately.

# Repository Structure

- `CustomPlayground` isolates the User-Space related examples.
- `build` has the kernel out-of-tree build in it. (not pushed to github)
- `drivers` are custom kernel modules that I build and test various Kernel Tools upon.
- `linux` has the actual linux kernel source code (not pushed to github)
- `Makefile` to cover the structured buildups for modules, kernel and boot-up of the kernel in QEMU (`qemu-system-x86_64`) as well as clean up of build artifacts.

# Makefile Configuration

- The `config` target generates a `.config` with the debug options/instrumentations enabled.
- `kernel` target compiles the setup as per the found configurations in the respected variables set (This is a out-of-tree build!).
- All of the custom drivers are build separately, this is necessary to load them and unload them for checks accordingly.
- For the while, we are only taking a look at the builds where a driver causes the issue.
- `run` boots the built in QEMU `qemu-system-x86_64` with a minimal initramfs and drops you at a shell. The `drivers/` folder sharing is automatically done, you simply need load them up via `insmod` command.
- `run-<name>` like `run-oob` would do the same but also auto-load the `driver/<name>/<name>.ko` file.
- `clean` is to clean up the build artifacts in `drivers/` folder recursively.

---
