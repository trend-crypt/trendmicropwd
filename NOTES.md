# Crypt Methods

## PWD DLL Decrypt

While there is code for this format, it is (probably poorly) copied over from Luigi's program but completely untested. I have not seen any use of it in my limited experience with Trend products. If you need to decrypt these kinds of passwords, I suggest using Luigi's program.

## !CRYPT!

Uses a static key derived from two static strings, meaning any strings encrypted with this method can be decrypted without additional information. May decrypt to plaintext strings or hashes, usually MD5.

Messages encrypted with this method have length restrictions. If the encrypted data is longer than this, the data is broken up into chunks and encrypted separately then concatenated together with an excalamation mark (`!`) as a separator. An example can be seen in the `samples.txt` file. Luigi's original program does not handle these and only decrypts the first chunk. This script will decrypt them each then concatenate the result.

## !CRYPTEX! / !CRYPTEX3!

Uses a standard encryption algorithm (AES 256 CBC) but with a static key and IV. Therefore, any strings encrypted with this method can be decrypted without additional information. may decrypt to plaintext strings or hashes, usually MD5.

According to Luigi's website, other hash types may be used (perhaps in `!CRYPTEX3!` strings), but that should have no impact on the decryption done by his tool or this script.

## !CRYPTCSTEX!

Uses a standard encryption algorithm (AES 256 CBC) but with a static IV. The key is derived from the agent's installation date and time. The date and time is hashed using SHA-1. The first 32 characters of the hash (as a hex string) are used as the key.

If you have access to a host with Trend installed, the install date and time is stored in a registry key and can be retrieved with the following commands:
* On 32-bit systems: `reg query HKLM\Software\TrendMicro\Installation\DE /v InstallDateTime`
* On 64-bit systems: `req query HKLM\Software\Wow6432Node\TrendMicro\Installation\DE /v InstallDateTime`

Unlike other crypto methods used here, `!CRYPTCSTEX!` strings are base64-encoded after being encrypted.

### Usage Notes

This script expects an `InstallDateTime` key-value pair in the password file to decrypt strings using this method. The date and time should be in the format of `YYYYMMDD00hhmmss` (note the two zeroes in the middle). This should be added before any `!CRYPTCSTEX!` strings.

If your passwords file contains `!CRYPTCSTEX!` strings from multiple hosts, new `InstallDateTime` values can be added to the file above each new est of `!CRYPTCSTEX!` strings. See the `samples.txt` file for an example of this.

### Bruteforcing

Because of the limited set of values used to derive a key, I've also created a script that can brute force the key for a given `!CRYPTCSTEX!` string. Set the `AGE` value at the top of the script to an epoch time before you believe the Trend server was installed. Run the script in the same fashion as the main script using a file of encrypted strings as an argument. The script will extract the first `!CRYPTCSTEX!` string it sees and then attempt to brute force it.

The bruteforce script is not very intelligent because it does not take very long to go through several years of dates and times, so I did not bother to optimize it. Going through a year's worth of dates and times only takes me about 10 minutes. If time is your concern, feel free to adjust the code yourself.

Likewise, the script does not stop after finding one possible datetime value. This is mostly out of laziness, but the script only checks that the decrypted value is comprised of ASCII printable characters, and I did not want to assume no other value could decrypt a string to match this criteria. It seems very unlikely, but I'm not a cryptography expert. Just kill the script once you've found a value you're happy with.

## !CRYPTNG! / !CRYPTNGS!

Uses a standard encryption algorithm (AES 256 CBC) but this time the key and IV are not static. Instead, these values are stored in the registry and protected with DPAPI. This script only supports decrypting these strings once the key and IV are known. It will not decrypt any DPAPI blobs.

The protected key data can be retrieved with the following commands (key and IV, respectively):
* On 32-bit systems:
  * `reg query HKLM\Software\TrendMicro\OfficeScan\service\Information\Data /v skos`
  * `reg query HKLM\Software\TrendMicro\OfficeScan\service\Information\Data /v skos_s`
* On 64-bit systems:
  * `req query HKLM\Software\Wow6432Node\TrendMicro\OfficeScan\service\Information\Data /v skos`
  * `req query HKLM\Software\Wow6432Node\TrendMicro\OfficeScan\service\Information\Data /v skos_s`

### Usage Notes

This scripts expects a `skos` key-value pair in the password file to decrypt strings using this method. The values should be converted to hex strings and appended together to form a 48 character string similar to many other encrypted password strings in the file. This should be added before any `!CRYPTNG!` or `!CRYPTNGS!` strings.

### Special Note

It may be possible that a `skos` entry that is _not_ protected by DPAPI can be found in configuration files like the main `ofcscan.ini` file in the format of a 48 character hex string. It's possible that this is the key and IV, concatenated together, unprotected. This value can be copied into your passwords file as-is to be used with this script. This is also the reason for this specific format of the key when decrypting these strings.

### DPAPI (Untested)

The `skos` and `skos_s` registry values are DPAPI blobs just as those discussed in depth [here](https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/) and are protected with the host's system key.

However, the DPAPI protection does also require some additional data used as part of DPAPI's [optional data](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata#parameters) parameter.
* The optional data: `Lbq60rEfC39XnWpJ Gy83OlK9Se7MaTh1W `
* NULL bytes terminate each of these strings for a total length of 0x23 bytes
* I've never actually done any work with DPAPI before, so I'm not entirely sure how this works. In case things fail, also try swapping the order of the strings.

## !CRYPTAA!

Don't ask. I saw it once in a session cookie for a completely different Trend Micro product. I know nothing about it.
