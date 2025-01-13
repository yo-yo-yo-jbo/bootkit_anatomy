# The anatomy of a bootkit
This year I discovered some interesting [vulnerabilities](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-56737) in [GRUB2](https://www.gnu.org/software/grub/), the de-facto Linux bootloader standard.  
But why are vulnerabilities in a bootloader are so interesting? That's what I'd like to explain today.  

## GRUB2 and Secure Boot
Before 2006, Intel-based computers booted into startup firmware code commonly known as the [BIOS](https://en.wikipedia.org/wiki/BIOS) (Basic Input/Output System), which was responsible for hardware initialization and setup of common services to later be used by a [bootloader](https://en.wikipedia.org/wiki/Bootloader). Ultimately, the BIOS would transfer control to a Bootloader coded in Real Mode, which would commonly load an operating system.  
With time, attackers realized there is no root-of-trust verification of bootloaders by the firmware, thus began the era of Bootkits, which are bootloader-based rootkits.  To standardize the boot process, a unified firmware schema to replace BIOS was introduced in 2006, which is currently known as [UEFI](https://en.wikipedia.org/wiki/UEFI) (Unified Extensible Firmware Interface).  
UEFI also helped combat Bootkits, as it offers services that validate bootloaders and its own extensible modules by means of digital signatures. That protocol is known as [Secure Boot](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot), and is essential to establishing a root of trust for the boot process, in which the firmware verifies UEFI drivers and OS modules with a platform key or a Key Exchange Key, and bootloaders verify the loaded operating system.  
Trust is then achieved with the help of OEMs, which can sign code trusted by Secure Boot, by means of Certificate Authorities (CA). Essentially, OEMs sign code with their private key, and their public key is signed with a root CA, commonly [Microsoft’s UEFI CA](https://uefi.org/sites/default/files/resources/UEFI_Plugfest_2013_-_New_Orleans_-_Microsoft_UEFI_CA.PDF). This is also essential to supporting non-Windows bootloaders such as GRUB2 (which commonly boots Linux) and allowing 3rd party operating systems to benefit from Secure Boot. Since GRUB2 is fully open-sourced, vendors install a small program called a [Shim](https://www.gnu.org/software/grub/manual/grub/html_node/UEFI-secure-boot-and-shim.html), which is signed by Microsoft’s UEFI CA and is responsible for validating the integrity of GRUB2.

## The dangers of GRUB2
Since bootloaders run before operating systems run, they mostly have UEFI-provided services as APIs to rely on. Therefore, bootloaders do not benefit from modern operating systems security features, such as:
-	No-Execute (NX): known in Windows as [DEP](https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention) (Data Execution Prevention), and treats memory page execute protections. Before the introduction of NX, attackers could override return addresses (which are maintained in-memory) and jump to arbitrary code (commonly a [shellcode](https://en.wikipedia.org/wiki/Shellcode)) that could be placed via the provided input.
-	[ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) (Address Space Layout Randomization): randomizes the base address of modules, which makes return address overrides and function pointer overrides highly unreliable, since attackers do not know where usable code might be found.
-	Safe dynamic allocators: dynamic allocations are a favorite target for attackers, and modern operating systems harden their heap allocators with various techniques, including [Safe Unlinking](https://msrc.microsoft.com/blog/2009/05/safe-unlinking-in-the-kernel-pool/), [type-safety](https://security.apple.com/blog/towards-the-next-generation-of-xnu-memory-safety/), Pointer Authentication and [others](https://theapplewiki.com/wiki/Heap_Hardening).
-	[Stack cookies \ Canaries](https://en.wikipedia.org/wiki/Buffer_overflow_protection): those are randomly generated values pushed between the return address and local variables, on the stack, with the intent on detecting changes in their values before using the return address (commonly in a RET instruction).

 Additionally, GRUB2 offers complex logic to deal various features, including:
-	Image file parsers (PNG, TGA and JPEG)
-	Font parsing and support (PF2 file format)
-	Network support (HTTP, FTP, DNS, ICMP, etc.)
-	Various filesystem supportability (FAT, NTFS, EXT, JFS, HFS, ReiserFS, etc.)
-	Bash-like command-line utility
-	Extensible dynamic module loading capabilities

Furthermore, GRUB2 is coded in C, which is considered a memory-unsafe language, and as mentioned, does not benefit from any modern security mitigation. Considering the implication of defeating Secure Boot and strategically assessing the project (e.g. with Google’s [Rule of 2](https://chromium.googlesource.com/chromium/src/+/master/docs/security/rule-of-2.md)), it is clear why GRUB2 should become a lucrative target for vulnerability researchers.
