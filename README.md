# 🖥 Windows Kernel-Based GAMEHACKING Season 2  

[![Open Source Initiative](https://opensource.org/files/osi_keyhole_300X300_90ppi_0.png)](https://opensource.org/)  
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)  
[![GitHub Repo stars](https://img.shields.io/github/stars/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2?style=social)](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2)  
![Made with Open Source](https://img.shields.io/badge/Made%20with-Open%20Source-blue.svg)  

---

**Game Hacking Season 2** is now released!  
This version aims to **implement the maximum capabilities possible in a Windows kernel driver** while allowing the `IOCTL` requester (User Program) to send commands easily to the kernel using **JSON**.

---

## 📌 Welcome
![Windows KernelBased GAMEHACK Logo](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/Windows_KernelBased_GAMEHACK_LOGO.png)

---

## ⚙ How It Works?
![Architecture](https://github.com/lastime1650/Windows_Kernel_Based_GAMEHACKING_Season_2/blob/main/Images/SimpleArch.png)

Previously, **MFC** was used, but now it has been replaced with an **API server** approach for a more user-friendly experience.  
For example, a **WebSocket-based API** is provided, allowing access to the Windows kernel directly from **Python**.

> **Goal:** Enable **high-level control** over the Windows kernel.

In addition, the features built a year ago have been **reinforced** and further developed so that the kernel can interact **more aggressively** with user space.

---

## 🚀 Features

### 🔹 In Kernel
1. **Kernel-Based DLL Injection**
2. **Memory Scan** *(with Force Mode)*
3. **Memory Write** *(with Force Mode)*
4. **Memory Dump** *(with Force Mode)*

---

### 🔹 In API Server (IOCTL Requester)
1. **WebSocket API Server**
2. **JSON Support**

---

💡 **Force Mode:** Forces the memory page protection property to **`PAGE_EXECUTE_READWRITE`**.

---

## 📅 Updates

### (2025-08-09) — *Improved "Hardware Breakpoint"*
Now more **stable** than the first-generation implementation.  
The kernel driver now **pauses the target process’s threads** before **modifying the debug register**.

---
