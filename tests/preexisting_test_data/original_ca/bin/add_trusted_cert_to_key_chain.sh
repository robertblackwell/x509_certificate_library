
# install a trusted certificate into the keychain from the command line
# can be PEM or DER format

sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $1
