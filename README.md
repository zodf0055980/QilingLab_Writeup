# QilingLab Writeup

shielder 在 2021/7/21 發布了 [QilingLab](https://www.shielder.it/blog/2021/07/qilinglab-release/) 來幫助學習 [qiling framwork](https://github.com/qilingframework/qiling) 的用法，剛好最近有用到，順手解了一下並寫了一下 writeup。

## 前情提要
[Qiling](https://github.com/qilingframework/qiling) 是一款功能強大的模擬框架，和 qemu user mode 類似，但可以做到更多功能，詳情請見他們的 [github](https://github.com/qilingframework/qiling) 和[網站](https://qiling.io/)。

他們有[官方文件](https://docs.qiling.io/en/latest/)，解此題目前建議看一下。

我所解的為 aarch64 的 [challenge](https://www.shielder.it/blog/2021/07/qilinglab-release/
)，使用的 rootfs 為 qililng 所提供的 [arm64_linux](https://github.com/qilingframework/rootfs
)。

逆向工具用 [ghidra](https://ghidra-sre.org/)，因為我沒錢買 idapro。


## First

先隨手寫個 python 用 qiling 執行 challenge binary。

```python
import sys
from qiling import *
from qiling.const import QL_VERBOSE

sys.path.append("..")


if __name__ == "__main__":
    ql = Qiling(["qilinglab-aarch64"], "rootfs/arm64_linux",verbose=QL_VERBOSE.OFF)
    ql.run()

```

可以看到結果是 binary 會不正常執行，此為正常現象，有些 Challenge 沒解完會導致錯誤或是無窮迴圈。

```
Welcome to QilingLab.
Here is the list of challenges:
Challenge 1: Store 1337 at pointer 0x1337.
Challenge 2: Make the 'uname' syscall return the correct values.
Challenge 3: Make '/dev/urandom' and 'getrandom' "collide".
Challenge 4: Enter inside the "forbidden" loop.
Challenge 5: Guess every call to rand().
Challenge 6: Avoid the infinite loop.
Challenge 7: Don't waste time waiting for 'sleep'.
Challenge 8: Unpack the struct and write at the target address.
Challenge 9: Fix some string operation to make the iMpOsSiBlE come true.
Challenge 10: Fake the 'cmdline' line file to return the right content.
Challenge 11: Bypass CPUID/MIDR_EL1 checks.

Checking which challenge are solved...
Note: Some challenges will results in segfaults and infinite loops if they aren't solved.
[x]	

[x]	x0	:	 0x0
[x]	x1	:	 0x0
[x]	x2	:	 0x1
[x]	x3	:	 0x0
[x]	x4	:	 0x0

```

## Challenge  1
把 0x1337 的位置的值改成 1337
![](https://i.imgur.com/WmHLBSY.png)

用 qiling 把該位置的 memory 讀出來，在進行改寫，要注意 align 問題。詳情請見[文件](https://docs.qiling.io/en/latest/memory/)。

```
    ql.mem.map(0x1337//4096*4096, 4096)
    ql.mem.write(0x1337,ql.pack16(1337) )

```
## Challenge 2
改掉 uname 此 sysytem call 的 return。

![](https://i.imgur.com/FelecVT.png)

可以看到他去比對 uname.sysname 和 uname.version 是否為特定值。我採用對 system call 進行 [hijack](https://docs.qiling.io/en/latest/hijack/)。

去翻 linux [文件](https://man7.org/linux/man-pages/man2/uname.2.html) 可以看到 uname 回傳的格式為 :
```
struct utsname {
               char sysname[];    /* Operating system name (e.g., "Linux") */
               char nodename[];   /* Name within "some implementation-defined
                                     network" */
               char release[];    /* Operating system release
                                     (e.g., "2.6.28") */
               char version[];    /* Operating system version */
               char machine[];    /* Hardware identifier */
           #ifdef _GNU_SOURCE
               char domainname[]; /* NIS or YP domain name */
           #endif
};
```

依照此文件把相對應的位置改掉。注意如果 release 改太小或是沒給，會噴錯。

```python
def my_syscall_uname(ql, write_buf, *args, **kw):
    buf = b'QilingOS\x00' # sysname
    ql.mem.write(write_buf, buf)
    buf = b'30000'.ljust(65, b'\x00') # important!! If not sat will `FATAL: kernel too old`
    ql.mem.write(write_buf+65*2, buf)
    buf = b'ChallengeStart'.ljust(65, b'\x00') # version
    ql.mem.write(write_buf+65*3, buf)
    regreturn = 0
    return regreturn

ql.set_syscall("uname", my_syscall_uname)
```




## Challenge 3
從`/dev/random`，從中讀取兩次，確保第一次的值和 getrandom 得到的值相同，且其中沒有第二次讀到值。

![](https://i.imgur.com/ZpxCW2z.png)

查了一下 getrandom 是一 system call。因此對 `/dev/random` 和 getrandom() 進行 [hijack](https://docs.qiling.io/en/latest/hijack/) 即可

```python
class Fake_urandom(QlFsMappedObject):
    def read(self, size):
        if(size > 1):
            return b"\x01" * size
        else:
            return b"\x02"
    def fstat(self): # syscall fstat will ignore it if return -1
        return -1
    def close(self):
        return 0

def my_syscall_getrandom(ql, write_buf, write_buf_size, flag , *args, **kw):
    buf = b"\x01" * write_buf_size
    ql.mem.write(write_buf, buf)
    regreturn = 0
    return regreturn
    
ql.add_fs_mapper('/dev/urandom', Fake_urandom())
ql.set_syscall("getrandom", my_syscall_getrandom)
```


## Challenge 4
解開無窮迴圈

![](https://i.imgur.com/BQSbfOm.png)

直接 hook `cmp` 的位置讓 reg w0 是 1 即可，位置記得要加上 pie。

```
    # 00100fd8 e0 1b 40 b9     ldr        w0,[sp, #local_8]
    # 00100fdc e1 1f 40 b9     ldr        w1,[sp, #local_4]
    # 00100fe0 3f 00 00 6b     cmp        w1,w0    <- hook         
```

```python
def hook_cmp(ql):
    ql.reg.w0 = 1
    return

base_addr = ql.mem.get_lib_base(ql.path) # get pie_base addr
ql.hook_address(hook_cmp, base_addr + 0xfe0)
```

## Challenge 5
rand() 出來的值和 0 比較要通過
![](https://i.imgur.com/HowFwVM.png)

直接 hijack rand() 讓他回傳都是 0 即可。

```python
def hook_cmp(ql):
    ql.reg.w0 = 1
    return
    
ql.set_api("rand", hook_rand)

```
# 累了之後補
## Challenge 6
![](https://i.imgur.com/wfK2XV0.png)
## Challenge 7
![](https://i.imgur.com/re9QVoa.png)
## Challenge 8
![](https://i.imgur.com/eDINYNq.png)

```
struct (0x18){ 
 ptr -> malloc (0x1e) ->  0x64206d6f646e6152
 long int = 0x3DFCD6EA00000539
 check_addr -> check;
}  
```

## Challenge 9
![](https://i.imgur.com/DmjFuFw.png)
## Challenge 10
![](https://i.imgur.com/gXu6jxO.png)
## Challenge 11
https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/MIDR-EL1--Main-ID-Register

![](https://i.imgur.com/phrLOoU.png)

## Done
![](https://i.imgur.com/THCInVp.png)

## Thanks
Thanks [MANSOUR Cyril]() release his [writeup](https://joansivion.github.io/qilinglabs/), help me alot.
