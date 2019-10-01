---
layout: post
title:  "Android OWASP crackmes: Write-up UnCrackable Level 2"
date:   2017-05-20 13:59:03 +0700
categories: [android, reverse]
---

<div style="text-align:center" markdown="1">
![0](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-uncrackable-logo.png "OWASP Logo")
{:.image-caption}
*"UnCrackable App for Android Level 2. This app holds a secret inside. May include traces of native code."*
</div>

This post details a way of solving the level 2 of Android crackmes released by the OWASP guys. Assuming you want to reproduce this write-up, let's make sure you know about binary disassemblers, decompilers, bytecode and crackmes.

**Requirements: What do we need?**

* Android phone or emulator to run the crackme APK
* Android decompiler of your preference to obtain Java code. (JADX-gui, JEB...)
* Dynamic binary instrumentation of your preference (frida)
* Disassembler (Radare2)
* Native decompiler (Radare2 plugin r2ghidra)
* The pinch of salt of the all magic: r2frida, a Radare2 plugin that combines static and dynamic analysis.
* Time and a bit of thinking


**Assumptions and highlights:**

* Anti-debugging and anti-rooting checks are in place at the Java level. We do not need to bypass all of them but get the flag
* Dynamic binary instrumentation is the approach chosen to obtain the secret inside the application
* Repackaging the application and patching out the security checks might be also possible but it is not covered in this write-up


**My Solution:**

This challenge can be solved in many different ways. Though, I decided to approach it in dynamic way by performing dynamic binary instrumentation with `r2frida`. Also, we'll show a bit of static analysis with Radare2.

After reversing the application, we find a lazy trick to avoid bypassing all the root detections one by one. In this manner, we hijack the control of the function that closes the application and warns us that this is unacceptable. Yeah yeah Blah Blah Blah `Root detected! The app is now going to to exit`... We'll see the toast with the message of rooted detected. Just press OK, the application won't be killed. First challenge solved with the following Frida hook:

```java
Java.perform(function () {
  var sysexit = Java.use("java.lang.System");
  sysexit.exit.overload("int").implementation = function(a0) {
    console.log("java.lang.System.exit(I)V  // We avoid exiting the application  :)");
  };
});
```

Time to find the string comparison in the native library. Fire the bin up into Radare2 (r2) and decompile the function `CodeCheck_bar`:
```sh
[edu@xps arm64-v8a] >  r2 -A libfoo.so
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Finding xrefs in noncode section with anal.in=io.maps
[x] Analyze value pointers (aav)
[x] Value from 0x00000000 to 0x00001e78 (aav)
[x] 0x00000000-0x00001e78 in 0x0-0x1e78 (aav)
[x] Emulate code to find computed references (aae)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
 -- The more 'a' you add after 'aa' the more analysis steps are executed.
[0x000008a0]> afl
0x000008a0    1 12           entry0
0x00000dac    8 236          sym.Java_sg_vantagepoint_uncrackable2_CodeCheck_bar
0x00000d8c    1 32           entry.init0
0x00000918   10 220          fcn.00000918
0x000007f0    1 16           sym.imp.pthread_create
0x00000800    1 16           sym.imp.__cxa_finalize
0x00000810    1 16           sym.imp.ptrace
0x00000820    1 16           sym.imp.strncmp
0x00000830    1 16           sym.imp._exit
0x00000840    1 16           sym.imp.__stack_chk_fail
0x00000850    1 16           sym.imp.fork
0x00000860    1 16           sym.imp.getppid
0x00000870    1 16           sym.imp.waitpid
0x00000880    1 16           sym.imp.pthread_exit
0x00000890    1 16           sym.imp.__cxa_atexit
0x000008b0    2 8            entry.fini0
[0x000008a0]> s sym.Java_sg_vantagepoint_uncrackable2_CodeCheck_bar
[0x00000dac]> pdg

undefined8 sym.Java_sg_vantagepoint_uncrackable2_CodeCheck_bar(int32_t arg3, int32_t arg1)
{
    int64_t iVar1;
    undefined8 *puVar2;
    undefined8 *puVar3;
    int32_t iVar4;
    int64_t *piVar5;
    undefined8 uVar6;
    undefined8 uStack80;
    undefined8 uStack72;
    undefined8 uStack64;
    undefined8 uStack56;

    piVar5 = (int64_t *)(uint64_t)(uint32_t)arg1;
    puVar2 = &uStack80;
    iVar1 = cRead_8(tpidr_el0);
    uVar6 = 0;
    uStack56 = *(undefined8 *)(iVar1 + 0x28);
    puVar3 = &uStack80;
    if (cRam000000000001300c == '\x01') {
        uStack72 = str.Thanks_for_all_t._8_8_;
        uStack80 = str.Thanks_for_all_t._0_8_;
        uStack64 = 0x68736966206568;
        uVar6 = (**(code **)(*piVar5 + 0x5c0))(piVar5, (uint64_t)(uint32_t)arg3, 0);
        iVar4 = (**(code **)(*piVar5 + 0x558))(piVar5, (uint64_t)(uint32_t)arg3);
        if (iVar4 == 23) {
            iVar4 = sym.imp.strncmp(uVar6, &uStack80, 23);
            puVar2 = &uStack72;
            puVar3 = &uStack72;
            if (iVar4 == 0) {
                uVar6 = 1;
                goto exit;
            }
        }
        uVar6 = 0;
        puVar3 = puVar2;
    }
exit:
    if (*(int64_t *)(iVar1 + 0x28) == *(int64_t *)((undefined *)puVar3 + 0x18)) {
        return uVar6;
    }
    sym.imp.__stack_chk_fail();
}
```

The above pseudocode indicates that the native verification will return `1` if the input string length is 23 and the comparison returns `0`. Let's hook it then! Now the goal is only to show the strncmp from the target native library. Therefore, we parse the backtrace of all the strncmp's functions and print the input arguments only when it comes from `libfoo.so`. The Frida code could be:

```java
// Filename: owasp2.js
function backtrace(c) {
    return (Thread.backtrace(c.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n") + "\n");
}

Interceptor.attach(Module.findExportByName("libc.so", "strncmp"), {
    onEnter: function (args) {
        var bt = backtrace(this);

        if (bt.includes("libfoo.so")) {
            var a0 = Memory.readUtf8String(args[0]);
            var a1 = Memory.readUtf8String(args[1]);
            console.log("\nstrncmp(" + a0 + "," + a1 + ")\n");
        }
    },
    onLeave: function (retval) {
    }
});

// Bypass root detections
Java.perform(function () {
  const sysexit = Java.use("java.lang.System");
  sysexit.exit.overload("int").implementation = function(a0) {
    console.log("java.lang.System.exit(I)V  // We avoid exiting the application  :)");
  };
});
```

Now, we can now intercept the input arguments to the comparison function in the native library, all this at runtime with `r2frida`:
```sh
[edu@xps ~] >  r2 frida://spawn/usb//owasp.mstg.uncrackable2
 -- This computer has gone to sleep.
[0x00000000]> \. /tmp/owasp2.js
[0x00000000]> \dc
resumed spawned process.
[0x00000000]> !python -c "print 'A'*23"
AAAAAAAAAAAAAAAAAAAAAAA
[0x00000000]> java.lang.System.exit(I)V  // We avoid exiting the application  :)

strncmp(AAAAAAAAAAAAAAAAAAAAAAA,Thanks for all the fish)

[0x00000000]>
[0x00000000]> \iE libfoo.so
0x726a22cdac f Java_sg_vantagepoint_uncrackable2_CodeCheck_bar
0x726a22cd8c f Java_sg_vantagepoint_uncrackable2_MainActivity_init
[0x00000000]> .\iE* libfoo.so
[0x00000000]> .\ii* libfoo.so
[0x00000000]> s sym.fun.Java_sg_vantagepoint_uncrackable2_CodeCheck_bar
[0x726a22cdac]> pdg
Ghidra Decompiler Error: No function at this offset
[0x726a22cdac]> af
[0x726a22cdac]> pdg

undefined8 sym.fun.Java_sg_vantagepoint_uncrackable2_CodeCheck_bar(int32_t arg3, int32_t arg1)
{
    int64_t iVar1;
    int32_t iVar2;
    int64_t *piVar3;
    undefined8 uVar4;
    undefined8 uStack80;
    undefined8 uStack72;
    undefined8 uStack64;
    int64_t iStack56;

    piVar3 = (int64_t *)(uint64_t)(uint32_t)arg1;
    iVar1 = cRead_8(tpidr_el0);
    iStack56 = *(int64_t *)(iVar1 + 0x28);
    uVar4 = 0;
    if (cRam000000726a23f00c == '\x01') {
        uStack72 = uRam000000726a22cea8;
        uStack80 = uRam000000726a22cea0;
        uStack64 = 0x68736966206568;
        uVar4 = (**(code **)(*piVar3 + 0x5c0))(piVar3, (uint64_t)(uint32_t)arg3, 0);
        iVar2 = (**(code **)(*piVar3 + 0x558))(piVar3, (uint64_t)(uint32_t)arg3);
        if ((iVar2 == 0x17) && (iVar2 = func_0x00726a22c820(uVar4, &uStack80, 0x17), iVar2 == 0)) {
            uVar4 = 1;
        } else {
            uVar4 = 0;
        }
    }
    if (*(int64_t *)(iVar1 + 0x28) == iStack56) {
        return uVar4;
    }
    func_0x00726a22c840();
}
```

<div style="text-align:center" markdown="1">
![1](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level2.png "Flag 1"){: .center-image }
{:.image-caption}
*Flag1*
</div>



**References:**

* [List of OWASP crackmes](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/README.md)

