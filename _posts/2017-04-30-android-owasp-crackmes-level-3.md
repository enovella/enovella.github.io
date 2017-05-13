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
        + Java bytecode:
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


Therefore, we need to extract several secrets to determine the right user input that display the message of success. The Java secret can be recovered just by decompiling the APK. The native secret needs to be recovered by a reverse engineering the code. For doing so, my initial thoughts were performing:

* static reverse engineering of the Java and native code plus code emulation with `Unicorn`.
* static reverse engineering of the Java and native code plus symbolic execution by using `angr`.
* static reverse engineering plus dynamic analysis by using `Frida`.
* patching Java and native code to NOP out all the security checks using `Radare2`.


**My Solution:**

My final inclination was going for the binary instrumentation of the Android app at runtime. For that purpose, `Frida` is a framework that injects JavaScript to explore native apps on Windows, macOS, Linux, iOS, Android, and QNX and on top of that it is being continuously improved. What else can we ask for? Let's use `Frida` then.

**Security checks within Uncrackable Level3:**

We find the following protections on the mobile application:
- Java anti-debugging
- Java integrity checks
- Java root checks
- Native anti-DBI
- Native anti-debugging
- Native integrity checks of the Java bytecode

The following security mechanisms were not found within the application:
- Java anti-DBI
- Java obfuscation
- Native obfuscation (only a bit of symbol stripping)
- Native root checks
- Native integrity checks of the native code itself

## Java side I. Reverse-engineering Java bytecode

First of all, several files need to be unpacked from the APK to be reverse engineered later on. For doing that you can use `apktool` or `7zip`. Once the APK is unpacked, two files are very important to follow this post. These files are:

* `./classes.dex` contains the Java bytecode.
* `./lib/arm64-v8a/libfoo.so` is a native library that contains ARM64 assembly code. We refer to this when talking about native code during this post (feel free to use the x86/ARM32 code if preferred). As I was running the app in a Nexus5X, the library to reverse engineer was the compiled for ARM64 architectures.

<div style="text-align:center" markdown="1">
![1](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/package-tree.png "APK packages overview"){: .center-image }
{:.image-caption}
*APK packages overview. Decompilation of the Java bytecode (`classes.dex`)*
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

As already mentioned above, integrity checks for native libraries and Java bytecode are identified in the function `verifyLibs`. Notice that repackaging the Java bytecode and native code may be still possible. For doing that, just by patching out the function `verifyLibs` in the Java bytecode and the function `baz` in the native library, an attacker could bypass all the integrity checks and thus continue attacking the mobile app. The function responsible for verifying libraries gets decompiled as follows:

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
## Java side II. Dynamic binary instrumentation with `Frida`


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


## Native side I. Reverse-engineering native code

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

The Java and native code are communicated through JNI calls. When the Java code is started, this loads the native code and initializes it with a bunch of bytes containing the Java secret. The native code is not obfuscated although it was slightly stripped and compiled dynamically. Therefore, we can still have symbols and strings in the clear. Notice that the following C-like code we are going to review, it has been renamed by the author depending on the interpretation of the callbacks.

It is important to mention that possibly `IDA Pro` does not detect the JNI callbacks as functions. For solving so, just go to the exports windows and make a procedure by pressing the key `P` on the export `Java_sg_vantagepoint_uncrackable3_MainActivity_init`. After that, you will also need to redefine the method signature by pressing the key `Y` when located at the function declaration of it. You can define the `JNIEnv*` objects to get better C-like code as the code shown below.

The JNI call performs anti-debugging checks, copies the `xorkey` into a global variable and increment the global counter `codecheck` to later on detect if the anti-debug checks were done fine. The JNI call `Java_sg_vantagepoint_uncrackable3_MainActivity_init` gets decompiled as follows:
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


<div style="text-align:center" markdown="1">
![3](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/pthread_create.png "Cross-references to pthread_create"){: .center-image }
{:.image-caption}
*Cross-references to `pthread_create`. These xrefs lead to anti-debugging and -instrumentation functions.*
</div>





## Native side II. Dynamic binary instrumentation with `Frida`

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
*Flag: making owasp great again*
</div>


# Extra: Compiler optimizations.

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

**References:**

* [List of OWASP crackmes](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/README.md)
* [Frida](https://www.frida.re/)
* [More Android Anti-Debugging Fun](http://www.vantagepoint.sg/blog/89-more-android-anti-debugging-fun)