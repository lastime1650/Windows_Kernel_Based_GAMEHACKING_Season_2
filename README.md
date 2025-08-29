*면책 조항 ( disclaimer )* 

*I strongly inform you that this is not for game hacking purposes (the title is just to attract attention (for publicity)), but for research purposes. You are solely responsible for its use.*

*이는 게임 해킹 목적(제목은 단지 관심을 끌기 위한 목적(홍보용))이 아닌 연구 목적임을 강력히 알려드립니다. 그 사용에 대한 책임은 전적으로 귀하에게 있습니다.*

---

# I'm going to officially release a stable distribution version. Please wait a little bit !!

`Also, provide instructions with API usage (with Python).`

---

> [!IMPORTANT]
>
> # 2025 08 24 ~
> I'm currently considering adding **`hypervisor`** technology that is compatible with both **`AMD`** and **`INTEL`** to the kernel drivers in this repository
> 
> If this is possible, I think we can experience a fun sight at Ring-1 level. ( Type 2 )
>
> ![initial](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/HYPERVISOR12.png)
>
> ![initial](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/HyperVisor4.png)
>
> ## Anti-Cheat Bypass & Kernel Access :=> **`HyperVisor`**
> 
> ## GameProcess & User Access :=> **`KernelDriver`**
> 
> ## User :=> **`API Server and Clients`**
> 
---

# 🖥 `64Bit` Windows Kernel-Based GAMEHACKING Season 2  

<a href="https://opensource.org/">
    <img src="https://i0.wp.com/opensource.org/wp-content/uploads/2023/03/cropped-OSI-horizontal-large.png" alt="Open Source Initiative" width="250"/>
</a>  

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)  
![Made with Open Source](https://img.shields.io/badge/Made%20with-Open%20Source-blue.svg)  

---

**Game Hacking Season 2** is now released!  
This version aims to **implement the maximum capabilities possible in a Windows kernel driver** while allowing the `IOCTL` requester (User Program) to send commands easily to the kernel using **JSON**.

---

## 📌 Welcome
![Windows KernelBased GAMEHACK Logo](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/New_Project1.png)

---

## ⚙ How It Works?
![Architecture](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/SimpleArch.png)

Previously, **MFC** was used, but now it has been replaced with an **API server** approach for a more user-friendly experience.  
For example, a **WebSocket-based API** is provided, allowing access to the Windows kernel directly from **Python**.

> **Goal:** Enable **high-level control** over the Windows kernel.

In addition, the features built a year ago have been **reinforced** and further developed so that the kernel can interact **more aggressively** with user space.

---

## ⚙ so How can I use it?

> [!TIP]
> Before running the target process, you must run driver and API server_program .

> [!IMPORTANT]
> 
> 1. Disabled HVCI
> 2. Load [KernelDriver](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/tree/main/KernelDriver/NewGameHack/x64/Release/NewGameHack) with [KDUMapper](https://github.com/hfiref0x/KDU)
> 3. Execute the [API_server](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/tree/main/API_Server/GameHackClient/x64/Debug)
> 4. and then, you should be made a query tool (query to `API SERVER` in JSON format) ( Python ,, etc,, ) enjoy!
> 5. if you have some bug ( BSOD ), call me !
>
> **query tool** ---> **API SERVER** ---> **Windows Kernel Driver** ---> **Target Game EXE**

> [!WARNING]
> The kernel driver for this project did not consider Unload. (Reboot is required.)

## Disabled HVCI 

### A. Turn off the HVCI options
![initial](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/DISABLE_HVCI.png)

### B. Using the KDU Mapper
![initial](https://github.com/lastime1650/KernelBased_GAMEHACKING/blob/main/Images/image.png)


---

## 🚀 Features

### 🔹 In [Kernel](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/tree/main/KernelDriver/NewGameHack)
1. **Kernel-Based DLL Injection**
2. **Memory Scan** 
3. **Memory Write** *(with Force Mode)*
4. **Memory Dump** *(with Memory PAGE dump(optional) )*
5. **Kernel-Based Hardware Breakpoint** *`(The VEH handler must implement the EXCEPTION_SINGLE_STEP handler.)`*
6. **Memory ALL Scan** -> value to return all datas in gave that size
7. **Pointer Scan**

**Internal_Func_1. `Get Real User_Process CR3`**

**Internal_Func_2. `APC based Async datas transfer to UserMode`**

---

### 🔹 In [Hypervisor](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/tree/main/Hypervisor/AMD)
1. Kernel API Hooking ( NPF( NPT table Fault ) based )

---

### 🔹 In [API Server](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/tree/main/API_Server) (IOCTL Requester)
1. **WebSocket API Server**
2. **JSON Support**
3. **WebServer on API Server** (coming soon)

---

💡 **Force Mode:** Forces the memory page protection property to **`PAGE_EXECUTE_READWRITE`**.

---

## 📅 Updates

> [!CAUTION]
>
> ## {TESTING} ( 2025-08-27 - 08:55(UTC +09:00)) - **"AMD (SVM) Hypervisor Based Kernel API Hooking"**
> ![initial](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/HYPERVISOR11.png)
>
> ![inital](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/HYPERVISOR13.png)
> 
> Based on the hypervisor [sample code](https://github.com/sariaki/amd-hypervisor) running on AMD-based CPUs, I release the code that implements kernel API hooking using NPT's page fault. 
> 
> At the end of the test process, I will further implement and complete the main kernel driver and communication process.
>
> Because I created a hypervisor based on that sample code, the `GPL-3.0` license is enforced, so it exists independently in the `Hypervisor/AMD` folder as a "separate kernel driver" folder.

---

> [!NOTE]
> ### (2025-08-28 - 05:06(UTC +09:00) ) — * "APC-Based Asynchronous User Mode Callback Implementation !"*
>
> ![initial](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/APC1.png)
>
> I used APC to allow the kernel to pass data transfer events to the user mode (IOCTL requester) asynchronously.
>
> This is a medium that can deliver asynchronous events, such as hooking signals from the kernel or hypervisor, to the user mode!!!!


---

> ### (2025-08-22 - 03:40(UTC +09:00) ) — * "Kernel Based Pointer Scanner is opened !"*
> I have implemented a "pointer scanner" that works on a kernel basis in version 2 of this season
>
> Additionally, the .data and .rdata areas are implemented to simply extract paths in JSON-type APIs with a "fixed offset" for one variable address found in EXE and dll (except Windows System dll) loaded into target process memory.

---

> ### (2025-08-22 - 22:20(UTC +09:00) ) — * "(Physical Memory Page Based) Kernel logic has been changed to connect to the User Mode stack by referring to a **valid CR3 register** !"*
> In addition, the user mode was always accessed through a valid CR3 and changed to Copy form.
>
> These measures are intended to prevent CR3 modulation of anti-cheats.
> 
> **Basic**
> ![Alt test](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/Virtual_to_Physical.png)
> 
> # **CR3 Brute-Force Processing**
>
> 1. **Acquire PEPROCESS**  
>    - Obtain the `PEPROCESS` of the target process.
>
> 2. **Extract ImageBaseAddress from PEPROCESS**  
>    - Retrieve the `ImageBaseAddress` from the PEPROCESS structure.
>
> 3. **Split Base Virtual Address into Bits**  
>    - Split the ImageBaseAddress extracted in step (2) into **individual bits**.
>
> 4. **Obtain Full Physical Page Map and Calculate PFN Upper Limit**  
>    - Use the `MmGetPhysicalMemoryRanges()` API to get the full physical page map.  
>    - Pre-calculate the upper limit of PFN (Page Frame Number).
>
> 5. **Traverse the Physical Page Map**  
>    - Traverse the physical page map from start to end using **index-based iteration**.
>
> 6. **CR3 Candidate Brute-Forcing**  
>    - Assume each PFN as **CR3** and reference the page tables.  
>      ```
>      PML4 -> PDP -> PD -> PT
>      ```  
>    - Use the PFN upper limit from step (4) and the `MmCopyMemory()` API to verify validity.
>
> 7. **Verify EXE File and Check PEB**  
>    - If step (6) is successful, convert to a DOS header and verify the signature to confirm the process EXE.  
>    - Since collisions with other processes are possible, assume the CR3 is correct and retrieve the PEB using the same method (`PML4 -> PDP -> PD -> PT`).  
>    - Finally, confirm that the PEB's `ImageBaseAddress` matches the address extracted in step (2).
>
> 8. **Final CR3 Determination**  
>    - If step (7) is successful, the CR3 can be obtained with 100% certainty.
>    
> Code is **[Here](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/b7101e6991da2b5bfaa9cde1f257387a3f0c5962/KernelDriver/NewGameHack/NewGameHack/UserProcess_Helper.c#L319)**

---

> ### (2025-08-10 - 16:00(UTC +09:00) ) — * "Highly stable hardware breakpoint"*
> NMore reliably than previous methods, you can import and modify thread contexts without conflict at the kernel end. There is a **`98.13`** percent chance that you **`no longer experience conflict issues with Thread Context`**. 
> 
> **if want to use Hardware Breakpoint, you can see this [VEH_HANDLER](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Samples/dll/GameHackDLL/GameHackDLL/VEH_Handler.cpp) in [DLL sample](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/tree/main/Samples/dll/GameHackDLL)**
> Preview) Kernel returns a path based on a "Linked list" to the user mode process, which converts it to JSON to give you results.
---

> ### (2025-08-09 - 19:00(UTC +09:00)  ) — *Added "Memory ALL Scan"*
> When it provides a size, by default, copy data from the **`PAGE_READWRITE`** area and import it to the node.

---

> ### (2025-08-09 - 15:00(UTC +09:00) ) — *Improved "Hardware Breakpoint"*
> Now more **stable** than the first-generation implementation.  
> The kernel driver now **pauses the target process’s threads** before **modifying the debug register**.

---



