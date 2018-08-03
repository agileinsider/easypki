[![Build
Status](https://travis-ci.org/agileinsider/easypki.svg?branch=master)](https://travis-ci.org/agileinsider/easypki)
[![codecov](https://codecov.io/gh/agileinsider/easypki/branch/master/graph/badge.svg)](https://codecov.io/gh/agileinsider/easypki)

easypki
======

Easy Public Key Infrastructure intends to provide most of the components needed
to manage a PKI, so you can either use the API in your automation, or use the
CLI.  Based on the original google version but updated to use elliptical curves / SHA256

# API

[![godoc](https://godoc.org/github.com/agileinsider/easypki?status.svg)](https://godoc.org/github.com/agileinsider/easypki)

For the latest API:

```
import "github.com/agileinsider/easypki"
```

# CLI

Current implementation of the CLI uses the local store and uses a structure
compatible with openssl, so you are not restrained.

```
# Get the CLI:
go get github.com/agileinsider/easypki/cmd/ecpki


# You can also pass the following through arguments if you do not want to use
# env variables.
export PKI_ROOT=/tmp/pki
export PKI_ORGANIZATION="Acme Inc."
export PKI_ORGANIZATIONAL_UNIT=IT
export PKI_COUNTRY=US
export PKI_LOCALITY="Agloe"
export PKI_PROVINCE="New York"

mkdir $PKI_ROOT

# Create the root CA:
ecpki create --filename root --ca "Acme Inc. Certificate Authority"

# In the following commands, ca-name corresponds to the filename containing
# the CA.

# Create a server certificate for blog.acme.com and www.acme.com:
ecpki create --ca-name root --dns blog.acme.com --dns www.acme.com www.acme.com

# Create an intermediate CA:
ecpki create --ca-name root --filename intermediate --intermediate "Acme Inc. - Internal CA"

# Create a wildcard certificate for internal use, signed by the intermediate ca:
ecpki create --ca-name intermediate --dns "*.internal.acme.com" "*.internal.acme.com"

# Create a client certificate:
ecpki create --ca-name intermediate --client --email bob@acme.com bob@acme.com

# Revoke the www certificate.
ecpki revoke $PKI_ROOT/root/certs/www.acme.com.crt

# Generate a CRL expiring in 1 day (PEM Output on stdout):
ecpki crl --ca-name root --expire 1
```
You will find the generated certificates in `$PKI_ROOT/ca_name/certs/` and
private keys in `$PKI_ROOT/ca_name/keys/`

For more info about available flags, checkout out the help `ecpki -h`.

# Disclaimer

This is forked and heavily hacked from something that was not an official Google product.
