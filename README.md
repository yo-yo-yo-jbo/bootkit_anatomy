# The anatomy of a bootkit
This year I [discovered](https://www.microsoft.com/en-us/security/blog/2025/03/31/analyzing-open-source-bootloaders-finding-vulnerabilities-faster-with-ai/) some interesting vulnerabilities in [GRUB2](https://www.gnu.org/software/grub/), the de-facto Linux bootloader standard.  
But why are vulnerabilities in a bootloader are so interesting? That's what I'd like to explain today.  

## GRUB2 and Secure Boot
Before 2006, Intel-based computers booted into startup firmware code commonly known as the [BIOS](https://en.wikipedia.org/wiki/BIOS) (Basic Input/Output System), which was responsible for hardware initialization and setup of common services to later be used by a [bootloader](https://en.wikipedia.org/wiki/Bootloader). Ultimately, the BIOS would transfer control to a Bootloader coded in Real Mode, which would commonly load an operating system.  
With time, attackers realized there is no root-of-trust verification of bootloaders by the firmware, thus began the era of Bootkits, which are bootloader-based rootkits.  To standardize the boot process, a unified firmware schema to replace BIOS was introduced in 2006, which is currently known as [UEFI](https://en.wikipedia.org/wiki/UEFI) (Unified Extensible Firmware Interface).  
UEFI also helped combat Bootkits, as it offers services that validate bootloaders and its own extensible modules by means of digital signatures. That protocol is known as [Secure Boot](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot), and is essential to establishing a root of trust for the boot process, in which the firmware verifies UEFI drivers and OS modules with a platform key or a Key Exchange Key, and bootloaders verify the loaded operating system.  
Trust is then achieved with the help of OEMs, which can sign code trusted by Secure Boot, by means of Certificate Authorities (CA). Essentially, OEMs sign code with their private key, and their public key is signed with a root CA, commonly [Microsoft’s UEFI CA](https://uefi.org/sites/default/files/resources/UEFI_Plugfest_2013_-_New_Orleans_-_Microsoft_UEFI_CA.PDF). This is also essential to supporting non-Windows bootloaders such as GRUB2 (which commonly boots Linux) and allowing 3rd party operating systems to benefit from Secure Boot. Since GRUB2 is fully open-sourced, vendors install a small program called a [Shim](https://www.gnu.org/software/grub/manual/grub/html_node/UEFI-secure-boot-and-shim.html), which is signed by Microsoft’s UEFI CA and is responsible for validating the integrity of GRUB2.

### The dangers of GRUB2
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

## How does a bootkit work
As we explained, finding a vulnerability in an OEM-trusted bootloader (such as GRUB2) means attackers might be able to bypass Secure Boot.  
Since bootloader usually handle complex inputs, coded in unsafe languages, implement their own heap and do not use modern mitigations - getting arbitrary code execution is quite likely.  
Assuming an attacker is able to achieve arbitrary code execution - what should they do?  
For this I'd like to examine one Bootkit - initially I wanted to examine BlackLotus ([found on Github](https://github.com/ldpreload/BlackLotus/tree/main)) as a modern example, but the source code there actually is missing several key functions used there (and yes, it won't compile).  
I did find one very similar to it called [Calypso](https://github.com/3a1/Calypso/), which is way easier to read, so I will be sticking to it mostly.  
With that, let us examine some source code!  
Remark: in this analysis, I might be skipping some code to make this blogpost more comprehensible. 

### Hooking EFI services
This Bootkit is compiled as an EFI module - essentially, a PE file that can be loaded through UEFI. Therefore, its code will start at an `EfiMain` function, located in `Bootkit/main.cpp`:
```c
EXTERN_C EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable)
{
    global::RuntimeServices = SystemTable->RuntimeServices;
    global::BootServices    = SystemTable->BootServices;
    global::SystemTable     = SystemTable;

    global::ExitBootServices = global::BootServices->ExitBootServices;
    global::BootServices->ExitBootServices = ExitBootServicesWrapper;

    global::BootServices->CreateEvent(EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, TPL_NOTIFY, NotifySetVirtualAddressMap, NULL, &global::NotifySetVirtualAddressMapEvent);

    return EFI_SUCCESS;
}
```

Each `EFI` module gets a pointer to a `SystemTable` which contains a bunch of other tables, which contain function pointers.  
Just like an old bootloader used to call `BIOS interrupts` to use as services (e.g. reading the disk or printing to the terminal), so do `EFI` modules get capabilities.  
The most important piece here is the [BootServices](https://uefi.org/specs/UEFI/2.9_A/07_Services_Boot_Services.html) which contain several functions.  
With that out of the way, the code here is very easy!
1. It saves several pointers in a global namespace (the services and the system table itself).
2. It saves the function pointer to `ExitBootServices` in that global as well, and then hooks it with the `ExitBootServicesWrapper` function. Note `ExitBootServices` is called just before the handoff to the OS kernel, so that's an excellent point to hook! Also note how easy it is to hook when you have function pointers and no page protections - essentially it's a single assignment in C!
3. It creates a callback for `SetVirtualAddressMap`, which we'll be using later.
With that, let's continue to the `ExitBootServicesWrapper` function!



