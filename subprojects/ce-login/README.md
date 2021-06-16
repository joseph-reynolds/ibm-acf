# ce-login
Ce-Login depends on the following libraries and should be installed on build machine:
libcrypto, libssl, lsl, jsonc

To build the ce-login utility run these commands:
meson setup build
meson configure -Dso=false -Dstatic=false -Dbin=true build
ninja -C build

To build only the ce-login shared library run these command:
meson setup build
meson configure -Dso=true -Dstatic=false -Dbin=false build
ninja -C build


Example creation of pub/priv keys for this utility:

Create the RSA Private Key
openssl genrsa -out rsaprivkey.pem 2048
Get public key
openssl rsa -in rsaprivkey.pem -pubout -outform DER -out rsapubkey.der
Get private key
openssl rsa -in rsaprivkey.pem -outform DER -out rsaprivkey.der

Example usage of this utility:

Create ACF:
./celogin_cli create --processingType "P" --sourceFileName "none" --serialNumber "0000000000000000" \
                     --frameworkEc "PWR10D" --password "password" --expirationDate "2025-12-25" \
                     --requestId "1234" --pkey ../p10-celogin-lab-pkey.der --output ./ACFFile.bin --verbose
RC: 0
217

Verify ACF:
./celogin_cli verify --hsfFile $CWD/scratch/acf.bin --publicKeyFile ../p10-celogin-lab-pub.der \
                     --password "password" --serialNumber "0000000000000000"

Decode ACF - Decodes and prints contents of ACF:
run decode --hsfFile ./ACFFile.bin  --publicKeyFile ../p10-celogin-lab-pub.der

Supported keyword value pairs:

framworkEC:[PWR10D,PWR10S]
processingType:[P]
serialNumber:[ string of digits or UNSET keyword]
requestId:[unrestricted]
sourceFileName:[unrestricted]
expirationDate:[yyyy-mm-dd format only]
password:[unrestricted]
