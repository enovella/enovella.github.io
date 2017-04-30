---
layout: post
title:  "Android OWASP crackmes: Write-up Level 2"
date:   2017-05-01 03:59:03 +0700
categories: [android, reverse]
---

<div style="text-align:center" markdown="1">
![0](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-uncrackable-logo.png "OWASP Logo")
{:.image-caption}
*"UnCrackable App for Android Level 2. This app holds a secret inside. May include traces of native code."*
</div>

This post details a way of solving the level 2 of Android crackmes released by the OWASP guys. Assuming you want to reproduce this write-up, let's make sure you know about binary disassemblers, decompilers, bytecode and crackmes before reading this post. 

**Requirements: What do we need?**

* Android phone or emulator to run the crackme APK
* Android decompiler of your preference to obtain Java code. (BytecodeViewer, Jadx-gui, JEB, JD-GUI,...)
* Dynamic binary instrumentation of your preference (Xposed or Frida)
* Time and a bit of thinking


**Assumptions and highlights:**

* Anti-debugging and anti-rooting checks are in place at the Java level. We do not need to bypass all of them but get the flag
* Dynamic binary instrumentation is the approach chosen to obtain the secret inside the application
* Repackaging the application and patching out the security checks might be also possible but it is not covered in this write-up


**My Solution:**

This challenge can be solved in many different ways. Though, I decided to approach it in dynamic way by performing dynamic binary instrumentation with `Frida`. 


The following C-like code represents the verification native code:
```c
signed int __fastcall Java_sg_vantagepoint_uncrackable2_CodeCheck_bar(JNIEnv *jni, int self, int src_input)
{
  const char *input; // r6@2
  signed int result; // r0@4
  char *flag; // [sp+0h] [bp-28h]@2
  char *v8; // [sp+4h] [bp-24h]@2
  int v9; // [sp+8h] [bp-20h]@2
  int v10; // [sp+Ch] [bp-1Ch]@2
  int v11; // [sp+10h] [bp-18h]@2
  __int16 v12; // [sp+14h] [bp-14h]@2
  char v13; // [sp+16h] [bp-12h]@2
  int cookie; // [sp+18h] [bp-10h]@5

  if ( codecheck == 1 )
  {
    _aeabi_memclr(&v8 + 2, 18);
    flag = "nahT";
    v8 = "f sk";
    v9 = "a ro";
    v10 = "t ll";
    v11 = "f eh";
    v12 = "si";
    v13 = "h";
    input = ((*jni)->GetByteArrayElements)(jni, src_input, 0);
    if ( ((*jni)->GetArrayLength)(jni, src_input) == 23 && !strncmp(input, &flag, 23u) )
      goto SUCCESS;
  }
  result = 0;
  while ( _stack_chk_guard != cookie )
SUCCESS:
    result = 1;
  return result;
}
```

<div style="text-align:center" markdown="1">
![1](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level2.png "Flag 1"){: .center-image }
{:.image-caption}
*Flag1*
</div>



**References:**

* [List of OWASP crackmes](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/README.md)

