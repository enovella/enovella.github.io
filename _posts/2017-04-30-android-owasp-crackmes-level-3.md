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

This post details a way of solving the level 3 of the Android crackmes released by the OWASP guys. Assuming you want to reproduce this write-up, let's make sure you know a bit about binary disassemblers, decompilers, bytecode and crackmes before reading this post. Anyhow, you can go further with the reading although some steps might be omitted.

**Toolbox: Choose your guns!**

The following list illustrates different tools that could be used with the same purpose to achieve the same result. Feel free to pick the ones you prefer the most:

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
        + Java bytecode:
            * `BytecodeViewer` (including various decompilers such as `Procyon`, `JD-GUI`, `CFR`,...).
            * `Jadx-gui`.
            * `JEB`.
* Dynamic binary instrumentation (DBI):
    - `Frida`.
    - `Xposed`.

My selection of tools was as such; `Frida` for performing dynamic analysis, `Hexrays` for native decompilation and `BytecodeViewer` (Procyon) for Java decompilation. The `Hexrays` decompiler was used because its reliable decompilation on ARM code. However, `Radare2` plus open-source decompilers can also do a great job.


**Before get started:**

To begin with, consider the remarks below before analyzing the APK:

* The Android phone needs to be rooted.
* There are two previous levels with less difficulty, I would first recommend you to take a peek at the other write-ups before reading this one.
* Anti-instrumentation, anti-debugging, anti-tampering and anti-rooting checks are in place both at the Java and native level. We do not need to bypass all of them but get the flag.
* The native layer is where the important code is executed. Do not be distracted with the Java bytecode.


**Possibles solutions:**

This challenge could be solved in many ways. First of all we need to know what the application does. This performs a verification of user input by verifying it against an XOR operation between a Java (`java_xor_key`) and native secret (`native_secret`) hidden within the native library. The verification is done at the native level after sending the Java secret data through the JNI bridge to the native library. The pseudo-code of the verification is as follows:

```c
if (verification(java_xor_key ^ native_secret) == user_input) {
  return 1;
}
```


Therefore, we need to extract several secrets to determine the right user input that display the message of success. The Java secret can be recovered just by decompiling the APK. The native secret needs to be recovered by a reverse engineering the code. For doing so, my initial ideas were performing:

* static reverse engineering of the Java and native code plus code emulation with `Unicorn`.
* static reverse engineering of the Java and native code plus symbolic execution by using `angr`.
* static reverse engineering plus dynamic analysis by using `Frida`.
* patching Java and native code to NOP out all the security checks using `Radare2`.


**My Solution:**

This challenge could be solved in many different ways. Though, I decided to approach it by instrumenting the Android app. For that purpose, `Frida` supports both native and Java instrumentation.

First of all, several files need to be unpacked from the APK to be reverse engineered later on. For doing that you can use `apktool` or `7zip`. Once the APK is unpacked, two files are very important to follow this post. These files are:

* `./classes.dex` contains the Java bytecode.
* `./lib/arm64-v8a/libfoo.so` is a native library that contains ARM64 assembly code. We refer to this when talking about native code during this post (feel free to use the x86/ARM32 code if preferred).

**Security checks within Uncrackable Level3:**

We find the following protections on the mobile application:
- Java anti-debugging
- Java integrity checks
- Java obfuscation (Weak)
- Java root checks
- Native anti-DBI
- Native anti-debugging
- Native integrity checks of the Java bytecode

The following security mechanisms were not found within the application:
- Java anti-DBI
- Native obfuscation (a bit of symbol stripping)
- Native root checks

## JAVA side

The following Java code snippet was obtained by decompiling the main class of the uncrackable Level3. Therefore, when the application is loaded, the MainActivity runs its method `onCreate()` which initializes itself. This code does the following:

* Verifies the native libraries against tampering.
* Initializes the native library through JNI and sends the Java secret (`"pizzapizzapizzapizzapizz"`).
* Performs rooting, debugging and tampering detection at the Java level.


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


As already mentioned above, integrity checks for native libraries and Java bytecode is identified in the following function. Notice that repackaging the Java bytecode and native code is still possible. For doing that, just by patching out the function `verifyLibs` in the Java bytecode and the function called `baz` in the native library, an attacker can bypass all the integrity checks. The function responsible for verifying libraries gets decompiled as follows:

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

**JNI calls: From Java to native code**

The main activity of the Uncrackable level 3 challenge has the interesting points to discuss:

* Hardcoded keys in the code. `xorkey` has a plaintext key, `"pizzapizzapizzapizzapizz"``` that will be used to solve the challenge.
* The loading of the native library `libfoo.so` and declaration of two native methods in the Java side: `baz()` and `init()`.
* Variables and class fields to keep track if tampering is detected.


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

    //<REDACTED>
    private native void init(byte[] xorkey) {
    }
    //<REDACTED>
 }
```


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



## Native side

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
secret = "1d0811130f1749150d0003195a1d1315080e5a0017081314".decode("hex")
xorkey = "pizzapizzapizzapizzapizz"

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

xored = xor_strings(secret,xorkey)
print "The flag is: " + xored
```

Running the script we obtain two possible flags:
```bash
[21:07 edu@ubuntu level3] > python getflag.py
The flag is: making owasp great again
```


<!-- <div style="text-align:center" markdown="1">
![2](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/owasp-level3-2.png "Flag 2"){: .center-image }
{:.image-caption}
*Flag2*
</div> -->


**References:**

* [List of OWASP crackmes](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/README.md)

