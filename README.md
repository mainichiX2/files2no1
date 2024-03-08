```
   ____ __     __    _    ___                ___
  / _(_) /__ _/_/__ | |  |_  |  ___  ___    <  /
 / _/ / / -_) /(_-< / / / __/  / _ \/ _ \   / / 
/_//_/_/\__/ //___//_/ /____/ /_//_/\___/  /_/  
           |_|   /_/                            
```
## Introduction
The basic purpose of the Bash shell script is to assist somebody who wants to store sensitive information in an encrypted file. In the shell, widely used programs such as GnuPG and OpenSSL are employed for encrypting and decrypting data. To use encryption tools, you only need to know the difference between symmetric and asymmetric encryption. To get more information you can visit a [blog about encryption types](https://www.ssldragon.com/blog/symmetric-asymmetric-encryption/). The menu of the shell script helps you perform all necessary steps for encrypting and decrypting file(s) and folder(s).
All unencrypted file(s) and folder(s) are deleted after the creation of the secure container.

## Script options
    Usage: ./files2no1.sh [options]
    -h|--help           Display this help message.
    -o|--overwrite      Overwrite the file with random ASCII symbols before it is removed. This is done to prevent data recovery.
                        Notice: use this option only with linux filesystems.
    -f|--flush          Flush folder from the unencrypted data. It can work together with [-o|--overwrite] option.
    -p|--panic          Clean all files and folders at the script location, including the executable script. 
                        It can work together with [-o|--overwrite] option.
                        Notice: The current option does not require your agreement and will be executed immediately.
    The OpenSSL symmetric ciphers list is extensive, but not every cipher is compatible with encrypting TAR files.
        Please choose ciphers with the postfix '-cbc'.
    The OpenSSL command reminder for generating asymmetric key pairs:
        openssl req -x509 -newkey rsa:4096 -keyout <privatekey.pem> -out <public.pem> -days <numeric>
    The GnuPG command reminder for generating asymmetric key pairs:
        gpg --full-generate-key | gpg --gen-key
