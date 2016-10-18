# Lightfactor UAF Authentication Library

lightfactor-uaf is a [FIDO UAF 1.0 compliant](https://fidoalliance.org/specifications/overview/) library that provides register, deregister, authenticate and transaction confirmation support for UAF operations.  It is designed to be used in conjunction with lightfactor-engine which provides HTTPS server connectivity to the library.

Lightfactor Identity Engine (the combination of lightfactor-uaf and lightfactor-engine) participated in the August 2016 FIDO Interop event and was [certified](https://fidoalliance.org/certification/fido-certified/) by FIDO in September 2016.  It has been load-tested against a free-tier AWS instance and can support 200 simultaneous UAF operations in that configuration.

This library was designed and built with an emphasis on scalability and simplicity with regard to installation, dependencies, architecture, etc. It is offered here, in Open Source form, to educate, drive further adoption of FIDO, and expand the FIDO ecosystem. No warranty is offered or implied.

Source code review is appreciated, and contributions are welcomed and encouraged.

Check us out at https://lightfactor.co.

## Features

To support FIDO UAF operations, it offers the following features:

* Generation of UAF protocol requests in JSON, including cryptographic challenges
* Verification of UAF protocol responses in JSON, including cryptographic signatures
* Generation of transaction confirmation text and images

## Requirements

* This package was written for use in [Node.js](https://nodejs.org/en/).
* This library *must be* incorporated into a server in order to be used by UAF clients.

## Installation

```shell
npm install lightfactor-uaf
```

## Usage

For detailed usage, see lightfactor-engine/routes/uaf.js.

## TODO

* Move to a real testing framework.
* Enhance transaction confirmation image and generation process.
* Improve process for extracting public key from presented certificate.
* Improve handling of arrays of assertions, transactions, etc.
* Use a FIPS-validated crypto library.

## License

[GNU AGPLv3](http://www.gnu.org/licenses/agpl-3.0.txt)
