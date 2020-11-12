---
layout: post
title:  "Android CrackMe for R2con CTF: Radare2 Pay"
date:   2020-09-03 17:45:03 +0700
categories: [android, reverse]
---

<div style="text-align:center" markdown="1">
![0](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/r2pay.jpg "Radare2 Pay")
{:.image-caption}
*"The Radare2 community always dreamed with its decentralized and free currency to allow r2 fans to make payments in places and transfer money between r2 users. A debug version has been developed and it will be supported very soon in many stores and websites. Can you verify that this is cryptographically unbreakable?"*
</div>

**Authors:**

- [Gautam Arvind](https://twitter.com/darvincisec)
- [Eduardo Novella](https://twitter.com/enovella_)

Radare2Pay Android CrackMe aims at being similar to popular mobile payment applications such as Google Pay, the Radare2 Pay app is difficult to crack. It features layers and layers of obfuscation and protection and anti-rooting technology in order to delay attacks. The developers used white box cryptography and created their own version of Runtime Application Self-Protection (RASP) with anti-Frida protections to make it harder to recover the payment keys.

**Security mechanisms:**

We have implemented the following protections in the mobile application:
- Java root checks
- Java obfuscation
- Obfuscated Whitebox cryptography
- Manual code obfuscation though conditional tricks
- Native root checks
- Native anti-debugging
- Native inline assembly syscalls
- Native code integrity checks
- Native memory checksumming
- Native anti-DBI (Dynamic Binary Instrumentation)
- Native obfuscation
- Runtime Application Self-Protection (RASP)

**Before get started:**

Hint: Run the APK in a non-tampered device to play a bit with the app.

<div style="text-align:center" markdown="1">
![0](https://raw.githubusercontent.com/enovella/enovella.github.io/master/static/img/_posts/r2pay2.jpg "Radare2 Pay")
{:.image-caption}
*"Radare2 Pay app tokenizing a r2coin"*
</div>

**Possibles solutions:**

- [Solution bypassing protections using Frida/QBDI by Romain Thomas](https://www.romainthomas.fr/post/20-09-r2con-obfuscated-whitebox-part1 "Solution by Romain Thomas").
- [Solution whitebox key recovery using SCAMarvels by Romain Thomas](https://www.romainthomas.fr/post/20-09-r2con-obfuscated-whitebox-part2 "Solution by Romain Thomas").


**References:**

* [Radare2 Conference](https://rada.re/con)
* [Frida](https://www.frida.re/)
* [New OWASP Android Crack-Me App Sponsored by NowSecure](https://www.nowsecure.com/blog/2020/10/21/new-owasp-android-crack-me-app-sponsored-by-nowsecure)
