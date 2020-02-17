
# install a trusted certificate into the keychain from the command line
# can be PEM or DER format

sudo security import -t agg -f pkcs12 -d -r trustRoot -k /Library/Keychains/System.keychain $1
