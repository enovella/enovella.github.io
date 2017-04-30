---
layout: post
title:  "Android OWASP crackmes: Level 3"
date:   2017-04-30 03:39:03 +0700
categories: [android, reverse]
---

Find the number of even digits in the given integer.

**Example**

* For `n = 1010`, the output should be `numberOfEvenDigits(n) = 2`.
* For `n = 123`, the output should be `numberOfEvenDigits(n) = 1`.

**Input/Output**

* [time limit] 4000ms (py)
* [input] integer n (A positive integer).

**_Constraints:_**

* 1 ≤ n ≤ 106.

* **[output] integer**

**My Solution:**

```python
def numberOfEvenDigits(n):
    return len(filter(lambda m: m.isdigit() and int(m) % 2 == 0, str(n)))
```

**Rests Tests:**

```
n: 1010
Output: 2

n: 123
Output: 1

n: 135
Output: 0
```
