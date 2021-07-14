# ce-login
Ce-Login depends on the following libraries and should be installed on build machine:

libcrypto, libssl, json-c (celogin_cli)

To build the ce-login utility run these commands:
```
meson setup -Dlib=false -Dbin=true build
ninja -C build
```

There is support to build either the cli utility, static lib or shared lib.

The options can be configured on setup or afterwards with the 'meson configure' command

Set any of the options to 'true' to build desired target
```
meson configure -Dlib=[true | false] -Dbin=[true | false] -Ddefault_library=[shared | static] build
```
Default configuration is:
```
-Dlib=true -Dbin=false -Ddefault_library=static
```
As defined by meson_options.txt

Running unit tests:
```
meson setup -Dlib=false -Dbin=true build
ninja -C build
cd build
meson test
```

Example creation of pub/priv keys for this utility:

Create the RSA Private Key
```
openssl genrsa -out rsaprivkey.pem 2048
```
Get public key
```
openssl rsa -in rsaprivkey.pem -pubout -outform DER -out rsapubkey.der
```
Get private key
```
openssl rsa -in rsaprivkey.pem -outform DER -out rsaprivkey.der
```

Example usage of this utility:

Create ACF:
```
./celogin_cli create \
                --machine 'P10,dev,12345' \
                --sourceFileName "none" \
                --password "0penBmc123" \
                --expirationDate "2025-12-25" \
                --requestId "1234" \
                --pkey ../p10-celogin-lab-pkey.der \
                --output ./service.acf \
```

Verify ACF:
```
./celogin_cli verify \
                --hsfFile ./service.acf \
                --publicKeyFile ../p10-celogin-lab-pub.der \
                --password "0penBmc123" \
                --serialNumber "12345"
```

Decode ACF - Decodes and prints contents of ACF:
```
./celogin_cli decode \
                --hsfFile ./service.acf \
                --publicKeyFile ../p10-celogin-lab-pub.der
```

Supported keyword value pairs:

machine: [ ProcessorGeneration (P10), ServiceAuthority (ce | dev), SerialNumber ( "UNSET" | bmc serial number )]\
requestId: [unrestricted]\
sourceFileName: [unrestricted]\
expirationDate: [yyyy-mm-dd format only]\
password: [unrestricted]
