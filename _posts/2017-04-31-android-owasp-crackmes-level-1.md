---
layout: post
title:  "Android OWASP crackmes: Write-up Level 1"
date:   2017-04-31 03:59:03 +0700
categories: [android, reverse]
---

<div style="text-align:center" markdown="1">
![0](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level3-logo.jpg "OWASP Logo")
{:.image-caption}
*"An Android crackme arose from hell. It doesn't make prisoners"*
</div>

This post details a way of solving the level 3 of Android crackmes released by the OWASP guys. Assuming you want to reproduce this write-up, let's make sure you know about binary disassemblers, decompilers, bytecode and crackmes before reading this post. 

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
* The native layer is where important code is executed. Do not be distracted with the Java bytecode
* Static reverse engineering is enough to obtain the secrets to pass the string verification. Therefore, all security checks do not need to be circumvented
* Dynamic binary instrumentation is not required although it could help to speed up the flag extraction. This write-up does not utilize this technique
* `Hex-rays` decompiler was used due to the quick decompilation of ARM code. However, `radare2` can also do a great job when disassembling ARM code.



**My Solution:**

This challenge can be solved in many different ways. Though, I decided to approach it in .....



<div style="text-align:center" markdown="1">
![1](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level1.png "Flag 1"){: .center-image }
{:.image-caption}
*Flag1*
</div>



**References:**

* [List of OWASP crackmes](https://github.com/OWASP/owasp-mstg/blob/master/OMTG-Files/02_Crackmes/List_of_Crackmes.md)

