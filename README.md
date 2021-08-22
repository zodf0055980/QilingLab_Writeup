# qiling lab writeup

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
改掉 uname 此 system call 的 return。

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
進入不能進去的迴圈

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
## Challenge 6

解開無窮迴圈

![](https://i.imgur.com/wfK2XV0.png)

和 Challenge 4 同想法，hook cmp。

```python
def hook_cmp2(ql):
    ql.reg.w0 = 0
    return
    
ql.hook_address(hook_cmp2, base_addr + 0x001118)

```
## Challenge 7
不要讓他 sleep。
![](https://i.imgur.com/re9QVoa.png)
解法很多，可以 hook sleep 這個 api，或是看 sleep linux [文件](https://man7.org/linux/man-pages/man3/sleep.3.html)能知道內部處理是用 [nanosleep](https://man7.org/linux/man-pages/man2/nanosleep.2.html)，hook 他即可。

```python
def hook_sleeptime(ql):
    ql.reg.w0 = 0
    return
ql.hook_address(hook_sleeptime, base_addr + 0x1154)
```

## Challenge 8
裡面最難的一題，他是建立特殊一個結構長這個樣子。

```
struct something(0x18){ 
 string_ptr -> malloc (0x1e) ->  0x64206d6f646e6152
 long_int = 0x3DFCD6EA00000539
 check_addr -> check;
}  
```

![](https://i.imgur.com/eDINYNq.png)

由於他結構內部有 0x3DFCD6EA00000539 這個 magic byte，因此可以直接對此作搜尋並改寫內部記憶體。這邊要注意搜尋可能找到其他位置，因此前面可以加對 string_ptr 所在位置的判斷。

```python
def find_and_patch(ql, *args, **kw):
    MAGIC = 0x3DFCD6EA00000539
    magic_addrs = ql.mem.search(ql.pack64(MAGIC)) 

    # check_all_magic
    for magic_addr in magic_addrs:
        # Dump and unpack the candidate structure
        malloc1_addr = magic_addr - 8
        malloc1_data = ql.mem.read(malloc1_addr, 24)
        # unpack three unsigned long
        string_addr, _ , check_addr = struct.unpack('QQQ', malloc1_data)

        # check string data        
        if ql.mem.string(string_addr) == "Random data":
            ql.mem.write(check_addr, b"\x01")
            break
    return
    
ql.hook_address(find_and_patch, base_addr + 0x011dc)
```

另一種解法則是由於該結構在 stack 上，因此直接讀 stack 即可。

## Challenge 9

把一字串轉用[tolower](https://www.programiz.com/c-programming/library-function/ctype.h/tolower)小寫，再用 strcmp 比較。

![](https://i.imgur.com/DmjFuFw.png)

解法一樣很多種，我是 hijack tolower() 讓他啥事都不做。

```python
def hook_tolower(ql):
    return
    
ql.set_api("tolower", hook_tolower)
```

## Challenge 10

打開不存在的文件，讀取的值需要是 `qilinglab`

![](https://i.imgur.com/gXu6jxO.png)
和 Challenge 3 作法一樣，這邊要注意的是 return 要是 byte，string 會出錯。 = =

```python
class Fake_cmdline(QlFsMappedObject):

    def read(self, size):
        return b"qilinglab" # type should byte byte, string will error = =
    def fstat(self): # syscall fstat will ignore it if return -1
        return -1
    def close(self):
        return 0

ql.add_fs_mapper('/proc/self/cmdline', Fake_cmdline())
```

## Challenge 11

可以看到他從 [MIDR_EL1]( 
https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/MIDR-EL1--Main-ID-Register) 取值，而此為特殊的暫存器。

![](https://i.imgur.com/phrLOoU.png)

這邊解法是去 hook code，我選擇 hook 這段

```
# 001013ec 00 00 38 d5     mrs        x0,midr_el1
```

去搜尋所有記憶體為 `b"\x00\x00\x38\xD5"` ，讓他執行時把 x0 暫存器改寫，並更改 pc。

```python
def midr_el1_hook(ql, address, size):  
    if ql.mem.read(address, size) == b"\x00\x00\x38\xD5":
        # if any code is mrs        x0,midr_el1
        # Write the expected value to x0
        ql.reg.x0 = 0x1337 << 0x10
        # Go to next instruction
        ql.reg.arch_pc += 4
    # important !! Maybe hook library
    # see : https://joansivion.github.io/qilinglabs/
    return

ql.hook_code(midr_el1_hook)
```


## Done
![](https://i.imgur.com/THCInVp.png)

## Thanks
Thanks [MANSOUR Cyril](https://twitter.com/MansourCyril) release his [writeup](https://joansivion.github.io/qilinglabs/), help me alot.
