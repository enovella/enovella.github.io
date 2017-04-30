---
layout: post
title:  "Android OWASP crackmes: Write-up Level 3"
date:   2017-04-30 03:39:03 +0700
categories: [android, reverse]
---

<div style="text-align:center" markdown="1">
![0](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level3-logo.jpg "OWASP Logo")
{:.image-caption}
*"An Android crackme arose from hell. It doesn't make prisoners"*
</div>

This post details a way of solving the level 3 of Android crackmes released by the OWASP guys. Assuming you want to reproduce this write-up, let's make sure you know about binary disassemblers, decompilers, Dalvik bytecode and crackmes before reading this post. 

**Requirements: What do we need?**

* Android phone or emulator to run the crackme APK
* Binary disassembler to analyze assembly code and/or ARM decompiler to get C-like code. (IDA Pro and Hex-rays decompiler or radare2)
* Android decompiler of your preference to obtain Java code. (BytecodeViewer, Jadx-gui, JEB, JD-GUI,...)
* Very basic understanding of the JNI interface
* Time and a bit of thinking


**Assumptions and highlights:**

* There are two previous levels with less difficulty, I would recommend to take a look at the challenges or write-ups first of reading this one
* Anti-instrumentation, anti-debugging, anti-tampering and anti-rooting checks are in place both at the Java and native level. We do not need to bypass all of them but get the flag
* The Android phone does not need to be rooted. If rooted, root checks should be overcome as well
* The native layer is where important code is executed. Do not be distracted with the Java bytecode (`Dalvik`)
* Static reverse engineering is enough to obtain the secrets to pass the string verification. Therefore, all security checks do not need to be circumvented
* Dynamic binary instrumentation is not required although it could help to speed up the flag extraction. This write-up does not utilize this technique
* `Hex-rays` decompiler was used due to the quick decompilation of ARM code. However, `radare2` can also do a great job when disassembling ARM code.



**My Solution:**

This challenge can be solved in many different ways. Though, I decided to approach it in a static way without debugging or instrumenting the Android app. This means, just pure static analysis of the Java and native code. 

First of all, several files need to be unpacked from the APK to be reverse engineered later on. For doing that you can use `apktool` or `7zip`. Once the APK is unpacked, two files are very important to follow this post. These files are:

* `./lib/armeabi-v7a/libfoo.so` is a native library that contains ARM assembly code. We refer to this when talking about native code during this post (feel free to use the x86 code if preferred) 
* `./classes.dex` contains the Java Dalvik bytecode

**Native constructor: Section `.init_array`**

 An ELF binary contains a section called `.init_array` which holds the pointers to functions that will be executed when the program starts. If we observe what this ARM shared object has in its constructor, then we can see the following function pointer `sub_2788` at offset `0x4de8`: (in IDA Pro uses the shortcut `ctrl`+`s` for showing sections)

```c
.init_array:00004DE8 ; ===========================================================================
.init_array:00004DE8
.init_array:00004DE8 ; Segment type: Pure data
.init_array:00004DE8                 AREA .init_array, DATA
.init_array:00004DE8                 ; ORG 0x4DE8
.init_array:00004DE8                 DCD sub_2788+1
.init_array:00004DEC                 ALIGN 0x10
.init_array:00004DEC ; .init_array   ends
.init_array:00004DEC
.got:00004F10 ; ===========================================================================
```

Going to the function itself, we realize that the native library also calls to the function `__somonitor_loop` as well as clears memory to receive a value from the Java side. Before going further with the reverse engineering, we need to fix an IDA problem with JNI. IDA does not know that several functions are defined and called at the Java level but executed at the native level. For that reason, we need to fix the function prototype of all the Java callbacks starting with the package name `Java_sg_vantagepoint_uncrackable3_`. 


Please notice that I have renamed several variables to progressively understand the code. The constructor `sub_2788()` does the following things:

* `pthread_create()` function creates a new thread executing the code of the function `__somonitor_loop()`
* `xorkey` is cleared out from memory before being initialized from the Java side. Note that this variable name was given due to the initialization of the method at the Java side with exactly the same name (`xorkey`)
* `codecheck` variable is a counter to determine integrity. Note that this variable name was assigned in other function where the Android log reveals the use of this variable
* `_stack_chk_guard` is a macro that proves that the code was compiled with stack cookies to prevent memory corruption issues

The decompiled code of `sub_2788()`:
```c
int sub_2788()
{
  int v1; // [sp+0h] [bp-10h]@1
  int v2; // [sp+4h] [bp-Ch]@1

  pthread_create((pthread_t *)&v1, 0, (void *(*)(void *))__somonitor_loop, 0);
  _aeabi_memclr8(xorkey, 25);
  ++codecheck;
  return _stack_chk_guard - v2;
}
```

Finally, the function `__somonitor_loop`  performs several security checks in order to avoid people tampering with the application at the native level. If we take a peek at the following decompiled code, then we observe that:

several frameworks for dynamic binary instrumentation are checked just when the native code is loaded. For checking so, the code reads the memory space of the program and filters by the well-known frameworks: 


* `xposed` is a framework for modules that can change the behavior of the system and apps without touching any APKs.
* `frida` is a framework that injects JavaScript to explore native apps on Windows, macOS, Linux, iOS, Android, and QNX. 

The decompiled code is as follows:

```c
void __fastcall __noreturn __somonitor_loop(void *a1)
{
  FILE *fd; // r5@1
  const char *str1; // r1@7
  const char *str2; // r2@7
  int s; // [sp+0h] [bp-20Ch]@2

  fd = fopen("/proc/self/maps", "r");
  if ( fd )
  {
    do
    {
      while ( !fgets((char *)&s, 512, fd) )
      {
        fclose(fd);
        usleep(500u);
        fd = fopen("/proc/self/maps", "r");
        if ( !fd )
          goto ERROR;
      }
    }
    while ( !strstr((const char *)&s, "frida") && !strstr((const char *)&s, "xposed") );
    str1 = "UnCrackable3";
    str2 = "Tampering detected! Terminating...";
  }
  else
  {
ERROR:
    str1 = "UnCrackable3";
    str2 = "Error opening /proc/self/maps! Terminating...";
  }
  _android_log_print(2, str1, str2);
  goodbye();
}
```


**Native anti-debugging checks:**

The Java and native code are communicated through the JNI interface. 
```c
int *__fastcall Java_sg_vantagepoint_uncrackable3_MainActivity_init(JNIEnv *jni, int self, const char *src_xorkey)
{
  int *result; // r0@1

  anti_debug();
  strncpy(xorkey, src_xorkey, 25u);
  result = &codecheck;
  ++codecheck;
  return result;
}
```

Decompiling and manually renaming the native code leads to the following `anti_debug()` function:

```c
int anti_debug(void)
{
  __pid_t ppid; // r4@3
  int result; // r0@7
  pthread_t newthread; // [sp+4h] [bp-14h]@2
  int stat_loc; // [sp+8h] [bp-10h]@4
  int cookie; // [sp+Ch] [bp-Ch]@7

  pid = fork();
  if ( pid )
  {
    pthread_create(&newthread, 0, (void *(*)(void *))monitor_pid, 0);
  }
  else
  {
    ppid = getppid();
    if ( !ptrace(PTRACE_ATTACH, ppid, 0, 0) )
    {
      waitpid(ppid, &stat_loc, 0);
      ptrace(PTRACE_CONT, ppid, 0, 0);
      if ( waitpid(ppid, &stat_loc, 0) )
      {
        while ( (stat_loc & 0x7F) == 127 )
        {
          ptrace(PTRACE_CONT, ppid, 0, 0);
          if ( !waitpid(ppid, &stat_loc, 0) )
            goto LABEL_7;
        }
LABEL_8:
        exit(0);
      }
    }
  }
LABEL_7:
  result = _stack_chk_guard - cookie;
  if ( _stack_chk_guard != cookie )
    goto LABEL_8;
  return result;
}
```

**Native verification:**

```c
signed int __fastcall Java_sg_vantagepoint_uncrackable3_CodeCheck_bar(JNIEnv *jni, int self, int user_input)
{
  int n; // r0@3
  signed int sec_xor_c; // r3@3
  int user_input_c; // r6@5
  int sec_xor; // [sp+3h] [bp-29h]@2
  int v10; // [sp+7h] [bp-25h]@2
  int v11; // [sp+Bh] [bp-21h]@2
  int v12; // [sp+Fh] [bp-1Dh]@2
  int v13; // [sp+13h] [bp-19h]@2
  int v14; // [sp+17h] [bp-15h]@2

  _android_log_print(2, "UnCrackable3", "bar called\n");
  _android_log_print(2, "UnCrackable3", "codecheck: initialized = %d", codecheck);
  if ( codecheck != 2 )
    return 0;
  _aeabi_memclr((char *)&v10 + 2, 19);
  sec_xor = 0x1311081D;
  v10 = 0x1549170F;
  v11 = 0x1903000D;
  v12 = 0x15131D5A;
  v13 = 0x5A0E08;
  v14 = 0x14130817;
  ((void (__fastcall *)(JNIEnv *, int, _DWORD))(*jni)->GetByteArrayElements)(jni, user_input, 0);
  if ( ((int (__fastcall *)(JNIEnv *, int))(*jni)->GetArrayLength)(jni, user_input) != 24 )
    return 0;
  n = 0;
  for ( sec_xor_c = 0x1D; ; sec_xor_c = *((unsigned __int8 *)&sec_xor + n++ + 1) )
  {
    user_input_c = *(unsigned __int8 *)(user_input + n);
    if ( (sec_xor_c | user_input_c) & 0xFF )
      goto LABEL_8;
    if ( !xorkey[n] )
      break;
    LOBYTE(sec_xor_c) = 0;
LABEL_8:
    if ( user_input_c != (unsigned __int8)(xorkey[n] ^ sec_xor_c) )
      return 1;
  }
  if ( n != 25 )
    return 1;
  return 0;
}
```


**The flag:**

The following python script generates the string needed to obtain the message of success:
```python
# Hardcoded secret
sec_xor = "1d0811130f1749150d0003195a1d1315080e5a0017081314".decode("hex")
# Java value: "pizzapizzapizzapizzapizz"
xorkey1 = "7a7a6970617a7a6970617a7a6970617a7a6970617a7a6970".decode("hex")
xorkey2 = "7a7a6970617a7a6970617a7a6970617a7a6970617a7a6970"


def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

xored1 = xor_strings(sec_xor,xorkey1)
xored2 = xor_strings(sec_xor,xorkey2)

print "The flag is: " + xored1
print "The flag is: " + xored2
```

Running the script we obtain two possible flags:
```bash
[21:07 edu@ubuntu level3] > python getflag.py 
The flag is: grxcnm3|}ayc3mrorg*amrzd
The flag is: *i&r9.~%;14xm|%,?>l1 i$u
```

<div style="text-align:center" markdown="1">
![1](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level3-1.png "Flag 1"){: .center-image }
{:.image-caption}
*Flag1*
</div>

<div style="text-align:center" markdown="1">
![2](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level3-2.png "Flag 2"){: .center-image }
{:.image-caption}
*Flag2*
</div>


**References:**

* [https://github.com/OWASP/owasp-mstg/blob/master/OMTG-Files/02_Crackmes/List_of_Crackmes.md](List of OWASP crackmes)

