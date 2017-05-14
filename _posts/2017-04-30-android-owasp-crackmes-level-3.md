---
layout: post
title:  "Android OWASP crackmes: Write-up UnCrackable Level 3"
date:   2017-04-30 03:39:03 +0700
categories: [android, reverse]
---

<div style="text-align:center" markdown="1">
![0](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level3-logo.jpg "OWASP Logo")
{:.image-caption}
*"An Android crackme arose from hell. It doesn't make prisoners"*
</div>

This post details a way of solving the level 3 of the Android crackmes released by the OWASP guys. Assuming you want to reproduce this write-up, let's make sure you know a bit about binary disassemblers, decompilers, bytecode and crackmes before reading this post. Anyhow, you can go further with the reading although some steps might be omitted.

**Toolbox: Choose your guns!**

The following list illustrates different tools that could be used with the same goal. Feel free to pick the ones you prefer the most:

* Android phone or emulator to run the crackme APK.
* Reverse-engineering:
    - Disassemblers:
        + `Radare2` from git.
        + `IDA Pro`.
    - Decompilers:
        + Native code:
            * `Hexrays`.
            * `Retdec`.
            * `Snowman`.
        + Dalvik bytecode:
            * `BytecodeViewer` (including various decompilers such as `Procyon`, `JD-GUI`, `CFR`,...).
            * `Jadx-gui`.
            * `JEB`.
* Dynamic binary instrumentation (DBI) framework:
    - `Frida`.
    - `Xposed`.

My selection of tools was as such; `Frida` for performing dynamic analysis, `Hexrays` for native decompilation and `BytecodeViewer` (Procyon) for Java decompilation. The `Hexrays` decompiler was used because its reliable decompilation on ARM code. However, `Radare2` plus open-source decompilers can also do a great job.



**Before get started:**

To begin with, consider the remarks below before analyzing the APK:

* The Android phone needs to be rooted.
* Anti-instrumentation, anti-debugging, anti-tampering and anti-rooting checks are in place both at the Java and native level. We do not need to bypass all of them but get the flag.
* The native layer is where the important code is executed. Do not be distracted with the Dalvik bytecode.
* My solution(s) is/are a possible way to solve the challenge, but others ways are also totally valid.



Anti-hacking techniques are implemented within the UnCrackable APK, principally to slow down reversers. Take a seat because now because we will have to deal with them. Very exciting though!. To sum up, we have detected the following protections on the mobile application:
- Java anti-debugging
- Java integrity checks
- Java root checks
- Native anti-DBI
- Native anti-debugging
- Native integrity checks of the Dalvik bytecode

The following security mechanisms were not found in the application:
- Java anti-DBI
- Java obfuscation
- Native obfuscation (only a bit of symbol stripping)
- Native root checks
- Native integrity checks of the native code itself

**Possibles solutions:**

This challenge could be solved in many ways. First of all we need to know what the application does. This performs a verification of the user input by verifying it against an XOR operation between a Java and native secret hidden within the application. The verification is done at the native level after sending the Java secret data through the JNI bridge to the native library. Basically, the verification is a simple `strncmp` with the user input and the `xor` operation of the secrets. The pseudo-code of the verification is as follows: (names are given by me)
```c
strncmp_with_xor(user_input_native, native_secret, java_xorkey) == 24;
```

Therefore, we need to extract two secrets to determine the right user input that display the message of success. The Java secret can be recovered very straightforward just by decompiling the APK. The native secret needs to be recovered by a reverse engineering the code though static analysis does not seem to be a good idea. Some kind of hooking or symbolic execution would be a clever idea instead of going for pure static reverse engineering. For extracting such secrets, my initial thoughts were performing:

* static reverse engineering of the Dalvik and native code plus code emulation with `Unicorn`.
* static reverse engineering of the Dalvik and native code plus symbolic execution by using `angr`.
* static reverse engineering plus dynamic analysis by using `Frida`.
* patching Smali code (Dalvik) and native code to NOP out all the security checks using `Radare2`.


**My Solution:**

My final inclination was going for the binary instrumentation of the Android app at runtime. For that purpose, `Frida` was my choice. This tool is a framework that injects JavaScript to explore native apps on Windows, macOS, Linux, iOS, Android, and QNX and on top of that it is being continuously improved. What else can we ask for? Let's use `Frida` then. Further info, either join the Telegram/IRC chat or read the docs at its website.

That being said, let's walk through how we can extract both secrets and reverse-engineer and instrument the target application. Note that this needs to be reversed first and then instrumented at Java and native level. Thus, we first reverse and look at both sides before placing any hook. The structure of this post is split in four sections:
* 1. Reverse-engineering Dalvik bytecode.
* 2. Reverse-engineering native code.
* 3. Instrumenting Dalvik bytecode with `Frida`.
* 4. Instrumenting native code with `Frida`.

## 1. Reverse-engineering Dalvik bytecode

First of all, several files need to be unpacked from the APK to be reverse engineered later on. For doing that you can use `apktool` or `7zip`. Once the APK is unpacked, two files are very important to follow this post. These files are:

* `./classes.dex` contains the Dalvik bytecode.
* `./lib/arm64-v8a/libfoo.so` is a native library that contains ARM64 assembly code. We refer to this when talking about native code during this post (feel free to use the x86/ARM32 code if preferred). As I was running the app in a Nexus5X, the library to reverse engineer was the compiled for ARM64 architectures.

<div style="text-align:center" markdown="1">
![1](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/package-tree.png "APK packages overview"){: .center-image }
{:.image-caption}
*APK packages overview. Source code decompiled from the Dalvik bytecode (`classes.dex`)*
</div>

The following code snippet was obtained by decompiling the main class of the uncrackable app Level3. This has the interesting points to discuss:

* a hardcoded key in the code (`String xorkey = "pizzapizzapizzapizzapizz"`).
* The loading of the native library `libfoo.so` and declaration of two native methods: `init()` and `baz()`, which will be invoked through JNI calls. Notice that the native method is initialized with the xorkey.
* Variables and class fields to keep track if tampering has been detected at runtime.


The main activity gets decompiled as follows:
```java
public class MainActivity extends AppCompatActivity {
    private static final String TAG = "UnCrackable3";
    private CodeCheck check;
    Map crc;
    static int tampered = 0;
    private static final String xorkey = "pizzapizzapizzapizzapizz";

    static {
        MainActivity.tampered = 0;
        System.loadLibrary("foo");
    }

    public MainActivity() {
        super();
    }

    private native long baz();

    private native void init(byte[] xorkey) {
    }
    //<REDACTED>
 }
```


Furthermore, when the application is launched, the method `onCreate()` of the main activity gets executed. This method does the following at the Java level:

* Verifies the integrity of the native libraries by calculating the CRC checksum. Note that none cryptography is used to sign the native libraries.
* Initializes the native library and sends the Java secret (`"pizzapizzapizzapizzapizz"`) towards the native code through JNI calls.
* Performs rooting, debugging and tampering detection. If detected any of them, then the application aborts.

The decompiled code is as follows:

```java
protected void onCreate(Bundle savedInstanceState) {
    this.verifyLibs();
    this.init("pizzapizzapizzapizzapizz".getBytes());
    new AsyncTask() {
        protected Object doInBackground(Object[] arg2) {
            return this.doInBackground(((Void[])arg2));
        }

        protected String doInBackground(Void[] params) {
            while(!Debug.isDebuggerConnected()) {
                SystemClock.sleep(100);
            }

            return null;
        }

        protected void onPostExecute(Object arg1) {
            this.onPostExecute(((String)arg1));
        }

        protected void onPostExecute(String msg) {
            MainActivity.this.showDialog("Debugger detected!");
            System.exit(0);
        }
    }.execute(new Void[]{null, null, null});
    if((RootDetection.checkRoot1()) || (RootDetection.checkRoot2()) || (RootDetection.checkRoot3())
             || (IntegrityCheck.isDebuggable(this.getApplicationContext())) || MainActivity.tampered
             != 0) {
        this.showDialog("Rooting or tampering detected.");
    }

    this.check = new CodeCheck();
    super.onCreate(savedInstanceState);
    this.setContentView(0x7F04001B);
}
```


**Integrity checks:**

As already mentioned above, integrity checks for native libraries and Dalvik bytecode are identified in the function `verifyLibs`. Notice that repackaging the Dalvik bytecode and native code may be still possible. For doing that, just by patching out the function `verifyLibs` in the Dalvik bytecode and the function `baz` in the native library, an attacker could bypass all the integrity checks and thus continue attacking the mobile app. The function responsible for verifying libraries gets decompiled as follows:

```java
private void verifyLibs() {
    (this.crc = new HashMap<String, Long>()).put("armeabi", Long.parseLong(this.getResources().getString(2131099684)));
    this.crc.put("mips", Long.parseLong(this.getResources().getString(2131099689)));
    this.crc.put("armeabi-v7a", Long.parseLong(this.getResources().getString(2131099685)));
    this.crc.put("arm64-v8a", Long.parseLong(this.getResources().getString(2131099683)));
    this.crc.put("mips64", Long.parseLong(this.getResources().getString(2131099690)));
    this.crc.put("x86", Long.parseLong(this.getResources().getString(2131099691)));
    this.crc.put("x86_64", Long.parseLong(this.getResources().getString(2131099692)));
    ZipFile zipFile = null;
    Label_0419: {
        try {
            zipFile = new ZipFile(this.getPackageCodePath());
            for (final Map.Entry<String, Long> entry : this.crc.entrySet()) {
                final String string = "lib/" + entry.getKey() + "/libfoo.so";
                final ZipEntry entry2 = zipFile.getEntry(string);
                Log.v("UnCrackable3", "CRC[" + string + "] = " + entry2.getCrc());
                if (entry2.getCrc() != entry.getValue()) {
                    MainActivity.tampered = 31337;
                    Log.v("UnCrackable3", string + ": Invalid checksum = " + entry2.getCrc() + ", supposed to be " + entry.getValue());
                }
            }
            break Label_0419;
        }
        catch (IOException ex) {
            Log.v("UnCrackable3", "Exception");
            System.exit(0);
        }
        return;
    }
    final ZipEntry entry3 = zipFile.getEntry("classes.dex");
    Log.v("UnCrackable3", "CRC[" + "classes.dex" + "] = " + entry3.getCrc());
    if (entry3.getCrc() != this.baz()) {
        MainActivity.tampered = 31337;
        Log.v("UnCrackable3", "classes.dex" + ": crc = " + entry3.getCrc() + ", supposed to be " + this.baz());
    }
}
```

On top of these integrity checks, we also observe the class `IntegrityCheck` that verifies that the application has not been tampered with and thus does not contain the flag of debuggable. This class gets decompiled as follows:

```java
package sg.vantagepoint.util;

import android.content.*;

public class IntegrityCheck
{
    public static boolean isDebuggable(final Context context) {
        return (0x2 & context.getApplicationContext().getApplicationInfo().flags) != 0x0;
    }
}
```

Reading the ADB logs, we can also track which calculations are performed when the app is run. An example of these checks at runtime is as follows:
```bash
05-06 16:58:39.353  9623 10651 I ActivityManager: Start proc 15027:sg.vantagepoint.uncrackable3/u0a92 for activity sg.vantagepoint.uncrackable3/.MainActivity
05-06 16:58:40.096 15027 15027 V UnCrackable3: CRC[lib/armeabi/libfoo.so] = 1285790320
05-06 16:58:40.096 15027 15027 V UnCrackable3: CRC[lib/mips/libfoo.so] = 839666376
05-06 16:58:40.096 15027 15027 V UnCrackable3: CRC[lib/armeabi-v7a/libfoo.so] = 2238279083
05-06 16:58:40.096 15027 15027 V UnCrackable3: CRC[lib/arm64-v8a/libfoo.so] = 2185392167
05-06 16:58:40.096 15027 15027 V UnCrackable3: CRC[lib/mips64/libfoo.so] = 2232215089
05-06 16:58:40.096 15027 15027 V UnCrackable3: CRC[lib/x86_64/libfoo.so] = 1653680883
05-06 16:58:40.097 15027 15027 V UnCrackable3: CRC[lib/x86/libfoo.so] = 1546037721
05-06 16:58:40.097 15027 15027 V UnCrackable3: CRC[classes.dex] = 2378563664
```

As we do not want to patch binary code, then we do not investigate more about these checks.


**Rooting checks:**

The Java package `sg.vantagepoint.util` has a class called `RootDetection` that performs up to three checks to detect if the device running the application is potentially rooted. These three checks are mainly:

* `checkRoot1()` that checks the existence of the binary `su` in the file system.
* `checkRoot2()` that checks the BUILD tag for `test-keys`. By default, stock Android ROMs from Google are built with release-keys tags. If `test-keys` are present, this can mean that the Android build on the device is either a developer build or an unofficial Google build.
* `checkRoot2()` that checks the existence of dangerous root applications, configuration files and daemons.

The Java code responsible for performing root checks is as follows:
```java
package sg.vantagepoint.util;

import android.os.Build;
import java.io.File;

public class RootDetection {
    public RootDetection() {
        super();
    }

    public static boolean checkRoot1() {
        boolean bool = false;
        String[] array_string = System.getenv("PATH").split(":");
        int i = array_string.length;
        int i1 = 0;
        while(i1 < i) {
            if(new File(array_string[i1], "su").exists()) {
                bool = true;
            }
            else {
                ++i1;
                continue;
            }

            return bool;
        }

        return bool;
    }

    public static boolean checkRoot2() {
        String string0 = Build.TAGS;
        boolean bool = string0 == null || !string0.contains("test-keys") ? false : true;
        return bool;
    }

    public static boolean checkRoot3() {
        boolean bool = true;
        String[] array_string = new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
                "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon",
                "/dev/com.koushikdutta.superuser.daemon/"};
        int i = array_string.length;
        int i1 = 0;
        while(true) {
            if(i1 >= i) {
                return false;
            }
            else if(!new File(array_string[i1]).exists()) {
                ++i1;
                continue;
            }

            return bool;
        }

        return false;
    }
}
```

2. Reverse-engineering native code

**Native constructor: Section `.init_array`**

 An ELF binary contains a section called `.init_array` which holds the pointers to functions that will be executed when the program starts. If we observe what this ARM shared object has in its constructor, then we can see the following function pointer `sub_73D0` at offset `0x19cb0`: (in IDA Pro uses the shortcut `ctrl`+`s` for showing sections)

```c
.init_array:0000000000019CB0                   ; ===========================================================================
.init_array:0000000000019CB0
.init_array:0000000000019CB0                   ; Segment type: Pure data
.init_array:0000000000019CB0                                   AREA .init_array, DATA, ALIGN=3
.init_array:0000000000019CB0                                   ; ORG 0x19CB0
.init_array:0000000000019CB0 D0 73 00 00 00 00+                DCQ sub_73D0
.init_array:0000000000019CB8 00 00 00 00 00 00+                ALIGN 0x20
.init_array:0000000000019CB8 00 00             ; .init_array   ends
.init_array:0000000000019CB8
.fini_array:0000000000019CC0                   ; ===========================================================================
```

`Radare2` also supports the identification of the JNI init methods since very recently. Thanks to `@pancake` and `@alvaro_fe` for their quick implementation on detecting JNI entrypoints on `radare`. More info about the commits in the references.

Going to the function itself, we realize that the native library also calls to the function `monitor_frida_xposed` as well as clears memory to receive a value from the Java side. Before going further with the reverse engineering, we need to fix an IDA problem with JNI. IDA does not know that several functions are defined and called at the Java level but executed at the native level. For that reason, we need to fix the function prototype of all the Java callbacks starting with the package name `Java_sg_vantagepoint_uncrackable3_`.

Please notice that I have renamed several variables to progressively understand the code. The constructor `sub_73D0()` does the following things:

* `pthread_create()` function creates a new thread executing the code of the function pointer `monitor_frida_xposed()`.
* `xorkey_native` memory is cleared before being initialized from the Java secret.
* `codecheck` variable is a counter to determine integrity. Later on, it is checked before computing the native secret and xored with the `xorkey`.

The decompiled code of `sub_73D0()` (renamed to `init`):
```c
int init()
{
  int result; // r0@1
  pthread_t newthread; // [sp+10h] [bp-10h]@1

  result = pthread_create(&newthread, 0, (void *(*)(void *))monitor_frida_xposed, 0);
  byte_9034 = 0;
  dword_9030 = 0;
  dword_902C = 0;
  dword_9028 = 0;
  dword_9024 = 0;
  dword_9020 = 0;
  xorkey_native = 0;
  ++codecheck;
  return result;
}
```

Finally, the function `monitor_frida_xposed`  performs several security checks in order to avoid people instrumenting the application at the native level. If we take a peek at the following decompiled code, then we observe that several frameworks for dynamic binary instrumentation are checked:
```c
void __fastcall __noreturn monitor_frida_xposed(int a1)
{
  FILE *stream; // [sp+2Ch] [bp-214h]@1
  char s; // [sp+30h] [bp-210h]@2

  while ( 1 )
  {
    stream = fopen("/proc/self/maps", "r");
    if ( !stream )
      break;
    while ( fgets(&s, 512, stream) )
    {
      if ( strstr(&s, "frida") || strstr(&s, "xposed") )
      {
        _android_log_print(2, "UnCrackable3", "Tampering detected! Terminating...");
        goodbye();
      }
    }
    fclose(stream);
    usleep(500u);
  }
  _android_log_print(2, "UnCrackable3", "Error opening /proc/self/maps! Terminating...");
  goodbye();
}
```

On the DBI section, we will walk you through on how to bypass these checks by instrumenting the app in different manners. The best part is that we will use `Frida` to bypass the anti-frida checks. That's is priceless! Isn't it?


**Native anti-debugging checks:**

The Java (Dalvik) and native code are communicated through JNI calls. When the Java code is started, this loads the native code and initializes it with a bunch of bytes containing the Java secret. The native code is not obfuscated although it was slightly stripped and compiled dynamically. Therefore, we can still have symbols and strings in the clear. Notice that the following C-like code we are going to review, it has been renamed by the author depending on the interpretation of the callbacks.

It is important to mention that possibly `IDA Pro` does not detect the JNI callbacks as functions. For solving so, just go to the exports windows and make a procedure by pressing the key `P` on the export `Java_sg_vantagepoint_uncrackable3_MainActivity_init`. After that, you will also need to redefine the method signature by pressing the key `Y` when located at the function declaration of it. You can define the `JNIEnv*` objects to get better C-like code as the code shown below.

The JNI call performs anti-debugging checks, copies the `xorkey` into a global variable and increments the global counter `codecheck` to later on detect if the anti-debug checks were done fine. The JNI call `Java_sg_vantagepoint_uncrackable3_MainActivity_init` gets decompiled as follows:
```c
int *__fastcall Java_sg_vantagepoint_uncrackable3_MainActivity_init(JNIEnv *env, jobject this, char *xorkey)
{
  const char *xorkey_jni; // ST18_4@1
  int *result; // r0@1

  anti_debug();
  xorkey_jni = (const char *)_JNIEnv::GetByteArrayElements(env, xorkey, 0);
  strncpy((char *)&xorkey_native, xorkey_jni, 24u);
  _JNIEnv::ReleaseByteArrayElements(env, xorkey, xorkey_jni, 2);
  result = &codecheck;
  ++codecheck;
  return result;
}
```

Digging into the `anti_debug` function leads to the piece of code shown just below: (Functions names and variables are manually given by my interpretation)

```c
int anti_debug()
{
  __pid_t pid; // [sp+28h] [bp-18h]@2
  pthread_t newthread; // [sp+2Ch] [bp-14h]@8
  int stat_loc; // [sp+30h] [bp-10h]@3

  ::pid = fork();
  if ( ::pid )
  {
    pthread_create(&newthread, 0, (void *(*)(void *))monitor_pid, 0);
  }
  else
  {
    pid = getppid();
    if ( !ptrace(PTRACE_ATTACH, pid, 0, 0) )
    {
      waitpid(pid, &stat_loc, 0);
      ptrace(PTRACE_CONT, pid, 0, 0);
      while ( waitpid(pid, &stat_loc, 0) )
      {
        if ( (stat_loc & 127) != 127 )
          exit(0);
        ptrace(PTRACE_CONT, pid);
      }
    }
  }
  return _stack_chk_guard;
}
```

The same author of this challenge has written an amazing post explaining how to perform self-debugging technique in order to avoid tampering with the native code. The `anti_debug` function exploits the fact that only one debugger can attach to a process at any one time. To investigate how this works deeper, please take a peek at the references. I will not re-explain the same here.

Effectively, if we run the application with a debugger attached to it then we can see two threads are launched and the application crashes.
```bash
bullhead:/ # ps|grep uncrack
u0_a92    7593  563   1633840 76644 SyS_epoll_ 7f99a8fb6c S sg.vantagepoint.uncrackable3
u0_a92    7614  7593  1585956 37604 ptrace_sto 7f99b37e3c t sg.vantagepoint.uncrackable3
```

## 3. Instrumenting Dalvik bytecode with `Frida`

```java
Java.perform(function () {
    send("Placing Java hooks...");

    var sys = Java.use("java.lang.System");
    sys.exit.overload("int").implementation = function(var_0) {
        send("java.lang.System.exit(I)V  // We avoid exiting the application  :)");
    };

    send("Done Java hooks installed.");
});
```

## 4. Instrumenting native code with `Frida`

<div style="text-align:center" markdown="1">
![3](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/pthread_create.png "Cross-references to pthread_create"){: .center-image }
{:.image-caption}
*Cross-references to `pthread_create`. These xrefs lead to anti-debugging and -instrumentation functions.*
</div>

The following piece of code is a replacement for the native function `pthread_create`.
```java
// int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
var p_pthread_create = Module.findExportByName("libc.so", "pthread_create");
var pthread_create = new NativeFunction( p_pthread_create, "int", ["pointer","pointer","pointer","pointer"]);
send("NativeFunction pthread_create() replaced @ " + pthread_create);

Interceptor.replace( p_pthread_create, new NativeCallback(function (ptr0, ptr1, ptr2, ptr3) {
    send("pthread_create() overloaded");
    var ret = ptr(0);
    if (ptr1.isNull() && ptr3.isNull()) {
        send("loading fake pthread_create because ptr1 and ptr3 are equal to 0!");
    } else {
        send("loading real pthread_create()");
        ret = pthread_create(ptr0, ptr1, ptr2, ptr3);
    }

    do_native_hooks_libfoo();

    send("ret: " + ret);

}, "int", ["pointer","pointer","pointer","pointer"]));
```

Let's run our hook and see what's going on:
```bash
[20:07 edu@ubuntu hooks] > python run_usb_spawn.py
pid: 11075
[*] Intercepting ...
[!] Received: [Placing native hooks....]
[!] Received: [arch: arm64]
[!] Received: [NativeFunction pthread_create() replaced @ 0x7ef5b63170]
[!] Received: [Done with native hooks....]
[!] Received: [pthread_create() overloaded]
[!] Received: [loading real pthread_create()]
[!] Received: [p_foo is null (libfoo.so). Returning now...]
[!] Received: [ret: 0]
[!] Received: [pthread_create() overloaded]
[!] Received: [loading fake pthread_create because ptr1 and ptr3 are equal to 0!]
[!] Received: [ret: 0x0]
[!] Received: [pthread_create() overloaded]
[!] Received: [loading fake pthread_create because ptr1 and ptr3 are equal to 0!]
[!] Received: [ret: 0x0]
[!] Received: [pthread_create() overloaded]
[!] Received: [loading real pthread_create()]
[!] Received: [ret: 0]
[!] Received: [pthread_create() overloaded]
[!] Received: [loading real pthread_create()]
[!] Received: [ret: 0]
```

The `strstr` hook worked like a charm! We are now undetectable for the application. The output shown below is after spawning the application with the hooks:
```bash
[20:15 edu@ubuntu hooks] > python run_usb_spawn.py
pid: 7846
[*] Intercepting ...
[!] Received: [Placing native hooks....]
[!] Received: [arch: arm64]
[!] Received: [Done with native hooks....]
[!] Received: [strstr(frida) was patched!! 77e5d48000-77e6cfb000 r-xp 00000000 fd:00 752205    /data/local/tmp/re.frida.server/frida-agent-64.so]
[!] Received: [strstr(frida) was patched!! 77e5d48000-77e6cfb000 r-xp 00000000 fd:00 752205    /data/local/tmp/re.frida.server/frida-agent-64.so]
[!] Received: [strstr(frida) was patched!! 77e6cfc000-77e6d8e000 r--p 00fb3000 fd:00 752205    /data/local/tmp/re.frida.server/frida-agent-64.so]
[!] Received: [strstr(frida) was patched!! 77e6cfc000-77e6d8e000 r--p 00fb3000 fd:00 752205    /data/local/tmp/re.frida.server/frida-agent-64.so]
[!] Received: [strstr(frida) was patched!! 77e6d8e000-77e6def000 rw-p 01045000 fd:00 752205    /data/local/tmp/re.frida.server/frida-agent-64.so]
[!] Received: [strstr(frida) was patched!! 77e6d8e000-77e6def000 rw-p 01045000 fd:00 752205    /data/local/tmp/re.frida.server/frida-agent-64.so]
[!] Received: [strstr(frida) was patched!! 77ff497000-77ff567000 r-xp 00000000 fd:00 752212    /data/local/tmp/re.frida.server/frida-loader-64.so]
[!] Received: [strstr(frida) was patched!! 77ff497000-77ff567000 r-xp 00000000 fd:00 752212    /data/local/tmp/re.frida.server/frida-loader-64.so]
[!] Received: [strstr(frida) was patched!! 77ff568000-77ff596000 r--p 000d0000 fd:00 752212    /data/local/tmp/re.frida.server/frida-loader-64.so]
[!] Received: [strstr(frida) was patched!! 77ff568000-77ff596000 r--p 000d0000 fd:00 752212    /data/local/tmp/re.frida.server/frida-loader-64.so]
[!] Received: [strstr(frida) was patched!! 77ff596000-77ff5f0000 rw-p 000fe000 fd:00 752212    /data/local/tmp/re.frida.server/frida-loader-64.so]
[!] Received: [strstr(frida) was patched!! 77ff596000-77ff5f0000 rw-p 000fe000 fd:00 752212    /data/local/tmp/re.frida.server/frida-loader-64.so]
[!] Received: [strstr(frida) was patched!! 77e5d48000-77e6cfb000 r-xp 00000000 fd:00 752205    /data/local/tmp/re.frida.server/frida-agent-64.so]
```

**The flag:**

The following python script generates the user input required to pass the challenge:
```python
secret = "1d0811130f1749150d0003195a1d1315080e5a0017081314".decode("hex")
xorkey = "pizzapizzapizzapizzapizz"

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

user_input = xor_strings(secret,xorkey)
print "The flag is: " + user_input
```

Eventually, we got the flag:
```bash
[21:07 edu@ubuntu level3] > python getflag.py
The flag is: making owasp great again
```


<div style="text-align:center" markdown="1">
![2](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level3.png "Flag: making owasp great again"){: .center-image }
{:.image-caption}
*Flag: **making owasp great again***
</div>


**Conclusions:**
* None application is `UnCrackable` (or 100% secure).
* `Frida` rocks! We overcame pretty much all the countermeasures on our way in order to obtain the valid flag. Anti-frida techniques were bypassed by hooking with `Frida`. This allowed us to bypass the security checks in different manners and also to debug the application at runtime. Just a comment, but the author of `Frida` sometimes says that he sometimes fixes `Frida` by instrumenting it with `Frida`. This is so cool!
* Initial reverse-engineering was required before placing `Frida` hooks.
* Unlike the Dalvik code, native code can be more tough to deal with.
* Native compilers can optimize too much and therefore introduce unintended bugs or behaviors.
* Thanks a lot for the challenge Bernhard Mueller! It was so much fun to solve it. Can we expect UnCrackable Level4 to be fully anti-`Frida`? Looking forward to it!

That's all folks! Please comment the way you solved the challenge as well as give me any feedback by posting some comments on the blog. See you around!

# Extra: Compiler optimizations.

I had to rewrite the whole write-up after Bernhard Mueller and I detected problems with the compilation flags in the native library. This took me a while to rewrite but the challenge became way more attractive now. Just for your information, the two code snippets shown below are the decompilation of the main native function. Please note that all the static operations to hide the final value were optimized and removed by the compiler.


** Version 1:**

The native secret was totally visible just by decompiling the native callback `Java_sg_vantagepoint_uncrackable3_CodeCheck_bar`:
```c
signed int __fastcall Java_sg_vantagepoint_uncrackable3_CodeCheck_bar(JNIEnv *jni, jobject self, char* user_input)
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

** Version 2:**

There was a function, which I renamed to `protect_secret`, that was performing a bunch of operations to thwart attackers from statically reverse engineer the code. However, in the prologue the native secret was leaked.
```c
_DWORD *__fastcall protect_secret(_DWORD *secret)
{
  int v2; // r4@1
  _DWORD *v3; // r0@1
  int v4; // r1@2
  int v5; // r6@5
  _DWORD *v6; // r0@5
  // REDACTED
  int v17; // r4@21
  // REDACTED

  v2 = 1103515245 * dword_6004 + 12345;
  dword_6004 = 1103515245 * dword_6004 + 12345;
  v3 = malloc(8u);
  if ( v3 )
  {
    *v3 = v2 & 0x7FFFFFFF;
    v4 = 1_sub_doit__opaque_list1_1;
    if ( 1_sub_doit__opaque_list1_1 )
    {
      v3[1] = *(_DWORD *)(1_sub_doit__opaque_list1_1 + 4);
      *(_DWORD *)(v4 + 4) = v3;
    }
    else
    {
      v3[1] = v3;
      1_sub_doit__opaque_list1_1 = (int)v3;
    }
  }
  v5 = 1103515245 * v2 + 12345;
  dword_6004 = 1103515245 * v2 + 12345;
  v6 = malloc(8u);
  if ( v6 )
  {
    *v6 = v5 & 0x7FFFFFFF;
    v7 = 1_sub_doit__opaque_list1_1;
    if ( 1_sub_doit__opaque_list1_1 )
    {
      v6[1] = *(_DWORD *)(1_sub_doit__opaque_list1_1 + 4);
      *(_DWORD *)(v7 + 4) = v6;
    }
    else
    {
      v6[1] = v6;
      1_sub_doit__opaque_list1_1 = (int)v6;
    }
  }
  v8 = 1103515245 * v5 + 12345;
  dword_6004 = v8;
  v9 = malloc(8u);
  if ( v9 )
  {
    *v9 = v8 & 0x7FFFFFFF;
    v10 = 1_sub_doit__opaque_list1_1;
    if ( 1_sub_doit__opaque_list1_1 )
    {
      v9[1] = *(_DWORD *)(1_sub_doit__opaque_list1_1 + 4);
      *(_DWORD *)(v10 + 4) = v9;
    }
    else
    {
      v9[1] = v9;
      1_sub_doit__opaque_list1_1 = (int)v9;
    }
  }

  // REDACTED

  if ( result )
  {
    _aeabi_memclr(secret, 25);
    *secret = 0x1311081D;
    secret[1] = 0x1549170F;
    secret[2] = 0x1903000D;
    secret[3] = 0x15131D5A;
    secret[4] = 0x5A0E08;
    result = (_DWORD *)0x14130817;
    secret[5] = 0x14130817;
  }
  return result;
}
```


**References:**

* [Frida](https://www.frida.re/)
* [List of OWASP crackmes](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/README.md)
* [More Android Anti-Debugging Fun](http://www.vantagepoint.sg/blog/89-more-android-anti-debugging-fun)
* [Radare2 JNI init detection commit](https://github.com/radare/radare2/commit/0b4e63c73241245b09b41ad31fcac4b52614cadd)