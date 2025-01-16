## How To use the PKCS#11 provider

### Configuration via openssl.cnf

Once you have installed the module you need to change OpenSSL's configuration to
be able to load the provider and a pkcs#11 driver.
The specific pkcs#11 driver name will depend on what token you are using.

In openssl.cnf add the following section:

```
[pkcs11_sect]
module = /path/to/pkcs11.so
pkcs11-module-path = /path/to/pkcs11-driver.so
activate = 1
```
Optionally add a path to a file containing the user's PIN:
```
pkcs11-module-token-pin = file:/path/to/userpin.txt
```
If a user PIN is not provided it should be requested interactively by most
openssl utilities.

Some pkcs11-drivers accept/require an initialization string (for example NSS
softokn), if that is needed add it as follow:
```
pkcs11-module-init-args = <initialization string here>
```

Once the section is properly constructed add the following statement to the
provider section. If a provider section does not exist make sure to create one
with all the needed providers (at least the default provider will be needed - 
remember to activate it, otherwise the _openssl_ command will not behave 
correctly):

```
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1
```

See CONFIG(5OSSL) manpage for more information on the openssl.cnf file.

### Driver specification via environment variable

In some cases it may be preferable to specify the pkcs11-driver module via an
environment variable instead of via openssl.cnf file. This may be useful when
the system can use multiple different tokens and the user/admin wants to start
different applications pointing them at distinct tokens.

If this is preferred, remove the pkcs11-module-path directive from openssl.cnf
and instead insure the driver is specified via the PKCS11_PROVIDER_MODULE
environment variable.

Example:
```
$ export PKCS11_PROVIDER_MODULE=/path/to/pkcs11-driver.so
$ openssl pkey -in pkcs11:id=%01 -pubin -pubout -text
```

### Specifying keys

When the pkcs11-provider is in use keys are specified using pkcs11 URIs as
defined in RFC7512. In general keys are either identified by a percent-encoded
binary ID, or by a label (called "object" in pkcs11 URIs). The command 
`pkcs11-tool --module /path/to/pkcs11-driver.so --list-objects` can be used to
find identifiers for your keys.

Example:
```
pkcs11:object=my-rsa-key;type=public
```

A pkcs11 URI can also specify a User PIN used to unlock the key, this can be
used instead of storing the PIN in the openssl.cnf file or using interactive
prompting.

### Key generation

On some tokens it is possible to create on the token using openssl
with non-standard parameters. Nevertheless, we recommend using tools working
with pkcs11 directly such as p11tool.
