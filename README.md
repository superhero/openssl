# OpenSSL

## Overview

`@superhero/openssl` is a Node.js library that simplifies the creation and management of TLS certificates wrapping OpenSSL CLI as a child process. It provides an API to generate root, intermediate, end-entity and hybrid certificates, with configuration options for altered use cases. The library also supports verification of certificate chains at various levels of strength.

## Installation

Install the package using npm:

```bash
npm install @superhero/openssl
```

Ensure that OpenSSL is installed and accessible in your system's PATH.

## Features

- Generate self-signed, root, intermediate, and end-entity (leaf) certificates.
- Support for hybrid certificates.
- Flexible configuration for certificate parameters, including algorithms, extensions, and subject attributes.
- Verification of certificates with customizable strength levels.
- Password protection for private keys.
- DNS and IP restrictions for certificates.
- etc...

## Usage

### Basic Example

Create a self-signed hybrid certificate:

```javascript
import OpenSSL from '@superhero/openssl';

const openssl = new OpenSSL();

const certificate = await openssl.hybrid();
console.log(certificate); // { cert, key, text, meta }
```

### Generate a Root Certificate

```javascript
const rootCA = await openssl.root();
```

### Create an Intermediate CA

```javascript
const intermediateCA = await openssl.intermediate(rootCA);
```

### Generate an End-Entity Certificate

```javascript
const leafCert = await openssl.leaf(intermediateCA, { dns: ['example.com'] });
```

### Verify a Certificate Chain

```javascript
const verified = await openssl.verify(leafCert, rootCA, intermediateCA);
console.log(`Verification status: ${verified}`);
```

### Use Password-Protected Private Keys

```javascript
const certificate = await openssl.hybrid({ password: 'password' });
```

### Use an Alternative Algorithm

By default, the certificate generated will use algorithm: `Ed25519`.

```javascript
const certificate = await openssl.hybrid({ algorithm: OpenSSL.ALGO.EdDSAEd448 });
```

### Use an Alternative Hash

By default, the certificate generated will use hash: `SHA256`.

```javascript
const certificate = await openssl.hybrid({ algorithm: OpenSSL.HASH.SHA512 });
```

## Configuration

### Config Object

The `Config` object allows detailed customization of certificates. Below are key properties:

- **algorithm**: Specify the algorithm (`RSA:2048`, `ECDSA:P-256`, etc.).
- **hash**: Define the hash algorithm (`sha256`, `sha384`, etc.).
- **days**: Validity period of the certificate.
- **subject**: Define subject attributes like `CN`, `O`, `C`, etc.
- **dns**: List of domain names for the certificate.
- **ip**: List of IP addresses for the certificate.
- **password**: Password for encrypting private keys.
- **extensions**: Add specific X.509 extensions like `basicConstraints`, `subjectAltName`, etc.

For full details, see the inline documentation in the source code.

### Supported Algorithms

- RSA (2048, 4096 bits)
- ECDSA (P-256, P-384, P-521)
- EdDSA (Ed25519, Ed448)

> [!NOTE]
> It's possible to alter the supported algorithms by simply adding to the `OpenSSL.ALGO` structure.

### Supported Hashes

- SHA1
- SHA224
- SHA256
- SHA384
- SHA512

> [!NOTE]
> It's possible to alter the supported hashes by simply adding to the `OpenSSL.HASH` structure.

### Running Tests

To run the tests, execute:

```bash
npm test
```

### Test Coverage

```
▶ @superhero/openssl
  ✔ Create a Hybrid Self-Signed Certificate (CA) (87.969186ms)
  ✔ Create Root Anchor Certificate Authority (CA) (40.667514ms)
  ✔ Create Intermediate Certificate Authority (CA) from a Root CA (65.759514ms)
  ✔ Create End-Entity Certificate (leaf) from a Root CA (63.916151ms)
  ✔ Create End-Entity Certificate (leaf) from an Intermediate CA (84.138971ms)
  ✔ Create Server End-Entity Certificate (leaf) (88.82563ms)
  ✔ Create Client End-Entity Certificate (leaf) (86.057993ms)
  ✔ Password Protected Private Key (112.056798ms)
  ✔ Password Protected Private Key (different input and output) (110.907526ms)
  ✔ DNS Restricted Certificate (102.647465ms)
  ✔ IP Restricted Certificate (105.181923ms)

  ▶ Different Algorithm and Hash Combinations
    ✔ RSA:2048 SHA1 (403.021609ms)
    ℹ VERIFY LVL:0:BASIC
    ✔ RSA:2048 SHA224 (483.182539ms)
    ℹ VERIFY LVL:2:AVERAGE
    ✔ RSA:2048 SHA256 (400.399147ms)
    ℹ VERIFY LVL:2:AVERAGE
    ✔ RSA:2048 SHA384 (342.325613ms)
    ℹ VERIFY LVL:2:AVERAGE
    ✔ RSA:2048 SHA512 (287.548281ms)
    ℹ VERIFY LVL:2:AVERAGE
    ✔ RSA:4096 SHA1 (3128.963791ms)
    ℹ VERIFY LVL:0:BASIC
    ✔ RSA:4096 SHA224 (3616.371228ms)
    ℹ VERIFY LVL:2:AVERAGE
    ✔ RSA:4096 SHA256 (1443.261141ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ RSA:4096 SHA384 (2890.999781ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ RSA:4096 SHA512 (1435.414523ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ ECDSA:P-256 SHA1 (185.233739ms)
    ℹ VERIFY LVL:0:BASIC
    ✔ ECDSA:P-256 SHA224 (162.734969ms)
    ℹ VERIFY LVL:1:WEAK
    ✔ ECDSA:P-256 SHA256 (157.594275ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ ECDSA:P-256 SHA384 (157.088086ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ ECDSA:P-256 SHA512 (158.156195ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ ECDSA:P-384 SHA1 (162.866576ms)
    ℹ VERIFY LVL:0:BASIC
    ✔ ECDSA:P-384 SHA224 (160.590359ms)
    ℹ VERIFY LVL:1:WEAK
    ✔ ECDSA:P-384 SHA256 (162.255488ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ ECDSA:P-384 SHA384 (160.708701ms)
    ℹ VERIFY LVL:4:STRONG
    ✔ ECDSA:P-384 SHA512 (160.348996ms)
    ℹ VERIFY LVL:4:STRONG
    ✔ ECDSA:P-521 SHA1 (162.938906ms)
    ℹ VERIFY LVL:0:BASIC
    ✔ ECDSA:P-521 SHA224 (161.97703ms)
    ℹ VERIFY LVL:2:AVERAGE
    ✔ ECDSA:P-521 SHA256 (164.781055ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ ECDSA:P-521 SHA384 (164.679174ms)
    ℹ VERIFY LVL:4:STRONG
    ✔ ECDSA:P-521 SHA512 (172.449647ms)
    ℹ VERIFY LVL:5:ROBUST
    ✔ EdDSA:Ed25519 SHA1 (165.041081ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ EdDSA:Ed25519 SHA224 (158.007169ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ EdDSA:Ed25519 SHA256 (157.974071ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ EdDSA:Ed25519 SHA384 (161.319262ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ EdDSA:Ed25519 SHA512 (154.722881ms)
    ℹ VERIFY LVL:3:STANDARD
    ✔ EdDSA:Ed448 SHA1 (155.4482ms)
    ℹ VERIFY LVL:4:STRONG
    ✔ EdDSA:Ed448 SHA224 (155.423545ms)
    ℹ VERIFY LVL:4:STRONG
    ✔ EdDSA:Ed448 SHA256 (154.603686ms)
    ℹ VERIFY LVL:4:STRONG
    ✔ EdDSA:Ed448 SHA384 (156.128255ms)
    ℹ VERIFY LVL:4:STRONG
    ✔ EdDSA:Ed448 SHA512 (155.360286ms)
    ℹ VERIFY LVL:4:STRONG
  ✔ Different Algorithm and Hash Combinations (18462.27014ms)
✔ @superhero/openssl (19412.498389ms)

tests 46
suites 2
pass 46

----------------------------------------------------------------------------------------------------------------
file            | line % | branch % | funcs % | uncovered lines
----------------------------------------------------------------------------------------------------------------
index.js        |  90.32 |    82.35 |   97.30 | 119-124 158-163 205-210 253-258 283-288 308-313 422-427 452-457
index.test.js   | 100.00 |   100.00 |  100.00 | 
----------------------------------------------------------------------------------------------------------------
all files       |  94.19 |    89.29 |   98.04 | 
----------------------------------------------------------------------------------------------------------------
```

## License

This project is licensed under the MIT License.

## Contributing

Feel free to submit issues or pull requests for improvements or additional features.
