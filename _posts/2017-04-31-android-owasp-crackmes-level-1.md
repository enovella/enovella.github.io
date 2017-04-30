---
layout: post
title:  "Android OWASP crackmes: Write-up Level 1"
date:   2017-04-31 03:59:03 +0700
categories: [android, reverse]
---

<div style="text-align:center" markdown="1">
![0](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-uncrackable-logo.png "OWASP Logo")
{:.image-caption}
*"UnCrackable App for Android Level 1. This app holds a secret inside. Can you find it?"*
</div>

This post details a way of solving the level 1 of Android crackmes released by the OWASP guys. Assuming you want to reproduce this write-up, let's make sure you know about binary disassemblers, decompilers, bytecode and crackmes before reading this post. 

**Requirements: What do we need?**

* Android phone or emulator to run the crackme APK
* Android decompiler of your preference to obtain Java code. (BytecodeViewer, Jadx-gui, JEB, JD-GUI,...)
* Dynamic binary instrumentation of your preference (Xposed or Frida)
* Time and a bit of thinking


**Assumptions and highlights:**

* Anti-debugging and anti-rooting checks are in place both at the Java level. We do not need to bypass all of them but get the flag
* Dynamic binary instrumentation is the approach chosen to obtain the secret inside the application
* Repackaging the application and patching out the security checks might be also possible but it is not covered in this write-up


**My Solution:**

This challenge can be solved in many different ways. Though, I decided to approach it in dynamic way by performing dynamic binary instrumentation with `Frida`. 



<div style="text-align:center" markdown="1">
![1](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level1.png "Flag 1"){: .center-image }
{:.image-caption}
*Flag1*
</div>



**References:**

* [List of OWASP crackmes](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/README.md)

