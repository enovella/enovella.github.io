---
layout: post
title:  "Android OWASP crackmes: Write-up Level 3"
date:   2017-04-30 03:39:03 +0700
categories: [android, reverse]
---

This post details a way of solving the level 3 of Android crackmes released by the OWASP guys. 

**Requirements**

* Android phone or emulator. 
* 

**Input/Output**

* [time limit] 4000ms (py)
* [input] integer n (A positive integer).

**_Constraints:_**

* 1 ≤ n ≤ 106.

* **[output] integer**

**My Solution:**

The challenge can be solved in many different ways. Though, I decided to approach it in a static way without debugging or instrumentation. This means, just pure static analysis of the Java and native code.

The Java and native code is managed by the JNI interface. 
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


**Native constructors: .init.array section**
 The `.init_array` section in an ELF binary contains the pointers to functions which will be executed when program starts. If we observe what this ARM shared object holds in its constructor then we can see the following function pointer `sub_2788` at offset `0x4de8`:

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

Going to the function itself, we realize that the native library also calls to the function `__somonitor_loop` as well as clears memory to receive a value from the Java side. Please notice that I have renamed several variables to  as clearly understand the code such as `xorkey` and `codecheck`:

* `pthread_create()` creates a new thread with the code of the function `__somonitor_loop()`
* `xorkey` is cleared out from memory before being initialized
* `codecheck` variable is a counter to determine integrity
* `_stack_chk_guard` is a macro that proves that the code was compiled with stack cookies to prevent memory corruption issues

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

Decompiling and manually renaming the native code by using IDA Pro leads to the following `C` code.

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

