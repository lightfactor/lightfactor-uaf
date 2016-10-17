
/*

    Copyright © 2016, Lightfactor, LLC.
    Created by Dave Atherton.

    This file is part of lightfactor-uaf.

    lightfactor-uaf is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    lightfactor-uaf is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

*/

var crypto = require('crypto');
var EC = require('elliptic').ec;
var forge = require('node-forge');
var Constants = require("./constants");
var util = require("./util");
var ursa = require('ursa');


function getKeyFromAssertionBuffer(assertionKeyBuffer, algKey) {

  var algKeyOperations = {};                                                    // TODO: if ECC keys are ever larger than 64 bytes, 0x100 and 0x101 will break... are they?

  // example:
  // BC8JFfD+A9Umi9sfK/w6H5409QUqjLsBP/5ZLROxhCyUbV8kdB1dCGJEMLy3XI25UZM2zPwTjaet8D0225o8xKY=

  algKeyOperations[Constants.UAF_ALG_KEY_ECC_X962_RAW] = function() {           // 0x100 (256)
    var key = {
      algEncPub: Constants.UAF_ALG_KEY_ECC_X962_RAW,
      oid: [
        "1.2.840.10045.2.1",                                                    // EC Public Key
        "1.2.840.10045.3.1.7"                                                   // SEC-2 recommended elliptic curve domain - secp256r1
      ],
      data: {
        publicKey: assertionKeyBuffer.toString('base64'),
        raw: assertionKeyBuffer.toString('base64')
      }
    };
    return key;
  };

  // example:
  // MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEakxqllb9thmxMnU/WoJsDMGJzcMdvW33FRBWo8FWn3fKrobJj/EipWYdLk1fe77v01SdtXMO0C0EHfltAjY5aQ==

  algKeyOperations[Constants.UAF_ALG_KEY_ECC_X962_DER] = function() {           // 0x101 (257)
    var keyString = assertionKeyBuffer.toString('binary');
    var rootObj = forge.asn1.fromDer(keyString);
    var publicKeyObj = rootObj.value[1];
    var publicKeyBuffer = Buffer.from(publicKeyObj.value, 'binary').slice(1);   // remove leading 0x00, leaving 0x04 + 64 byte key
    var key = {
      algEncPub: Constants.UAF_ALG_KEY_ECC_X962_DER,
      oid: [
        forge.asn1.derToOid(rootObj.value[0].value[0].value),
        forge.asn1.derToOid(rootObj.value[0].value[1].value)
      ],
      data: {
//        publicKeyBuffer: publicKeyBuffer,
        publicKey: publicKeyBuffer.toString('base64'),
        raw: assertionKeyBuffer.toString('base64')
      }
    }
    return key;
  };

  // example:
  // y3f61poYNsNBXL2M/otXx+AenSuP0XFGP8YC9/gPM5QP//IpplUkEQsjXZkp4IDCIh4hA4H2Tz3VNfqAN+Wa/0oZtry1XbyI+1afvbrb4uILSWu2UYAYz5tVFyd6YyzlyQb4D/k287fHi3Pc7xOjyuNhlgiFUVE6CmGZ5yLlayFaG+Pk02SxgpbQk1vsW15AXhiXTdIW2dHBOcdQoApvDFVxejznFF4Dpahx1gKscrv/VhrnOV6DdU3WWLaPCmtz5XW2aGslzvXa7zEKhKWSlFPxeZ9fWMdKk6sCyDq5pKHyN10/I5CzC61+DfCG7VCwxWOFTndfaoRYv5p0a9OAuwEAAQ==

  algKeyOperations[Constants.UAF_ALG_KEY_RSA_2048_PSS_RAW] = function() {       // 0x102 (258)
    var modulusBuffer = assertionKeyBuffer.slice(0, 256);
    var exponentBuffer = assertionKeyBuffer.slice(256);
    var key = {
      algEncPub: Constants.UAF_ALG_KEY_RSA_2048_PSS_RAW,
      oid: [ "1.2.840.113549.1.1.10" ],                                         // RSASSA-PSS
      data: {
//        modulusBuffer: modulusBuffer,
//        exponentBuffer: exponentBuffer,
        modulus: modulusBuffer.toString('base64'),
        exponent: exponentBuffer.toString('base64'),
        raw: assertionKeyBuffer.toString('base64'),
      }
    };
    return key;
  };


  // example:
  // MIIBCgKCAQEAnQIQMoNB7OZ3zlzQhLygWVeU+w4OmJbiawGwfQE80tuEptL0SdS/IO2aMlhdh8vy1l4hZsviohwzdkYtXKen7/3j3QyG+kE3KAeiyVMvHVSNSIh682ZhoeRTaiYFLpxbGhVw7jC5CCGzv7BrxoPLs5etlS5WVe87Mti+Zk26hO9KgZaj458T5MISNI7OHjJ7DetVKe7SqG9QOdAVf3UVJonf+Hd0RnUwu+Dl0CTUheNiUiCZ5Y/0LHNJIjvj7HvblOIQQpSzgSkFVT+W/Lj7qZMfw9KBCmk0obooNrEub/iuLTC4MLk2qKAyOs7Kn6aP1/6HBu5FXNcBjzF/1WcxuQIDAQAB

  algKeyOperations[Constants.UAF_ALG_KEY_RSA_2048_PSS_DER] = function() {       // 0x103 (259)
    var keyString = assertionKeyBuffer.toString('binary');
    var keyObj = forge.asn1.fromDer(keyString);
    var modulusBuffer = Buffer.from(keyObj.value[0].value, 'binary');           // value[0].type should be asn1.Type.INTEGER (2)
    var exponentBuffer = Buffer.from(keyObj.value[1].value, 'binary');          // value[1].type should be asn1.Type.INTEGER (2)
    var key = {
      algEncPub: Constants.UAF_ALG_KEY_RSA_2048_PSS_DER,
      objectOid: [ "1.2.840.113549.1.1.10" ],                                   // RSASSA-PSS
      data: {
        modulus: modulusBuffer.toString('base64'),
        exponent: exponentBuffer.toString('base64'),
        raw: assertionKeyBuffer.toString('base64'),
      }
    };
    return key;                                                                 // TODO: enforce input structure before return
  };

  return algKeyOperations[algKey]();                                            // should never fail, as we've validated algKey values prior to here

}


function getKeyfromCertificateBuffer(certificateBuffer) {                       // see https://lapo.it/asn1js/ for help navigating

  var certificateString = certificateBuffer.toString('binary');
  var rootObj = forge.asn1.fromDer(certificateString);

  // look for ECC key first

  var objects = findAsn1ObjectInAsn1Object(rootObj, [ [0, 5], [ 0, 6 ] ], function(asn1Object) {
    try {
      if (asn1Object.value[0].value[0].type !== 6) return;                      // looking for asn1.Type.OID (public key type)
      if (asn1Object.value[0].value[1].type !== 6) return;                      // looking for asn1.Type.OID (curve)
      if (asn1Object.value[1].type !== 3) return;                               // looking for asn1.Type.BITSTRING (key)

      var oid = [
        forge.asn1.derToOid(asn1Object.value[0].value[0].value),
        forge.asn1.derToOid(asn1Object.value[0].value[1].value)
      ];
      if (oid[0] !== "1.2.840.10045.2.1") return;
      if (oid[1] !== "1.2.840.10045.3.1.7" && oid[1] !== "1.3.132.0.10") return;

      var key = {
        algEncPub: Constants.UAF_ALG_KEY_ECC_X962_RAW,
        oid: oid,
        data: {
          publicKey: Buffer.from(asn1Object.value[1].value, 'binary').slice(1).toString('base64')  // ignore leading 0x00
        }
      }

      return key;
    }
    catch(error) {
      if (!(error instanceof TypeError)) throw error;
      return;
    }
  });

  if (objects[0]) return objects[0];                                            // TODO: do we really only want to just use first one always? same applies below...

  // look for RSASSA-PSS if no ECC key found

  var objects = findAsn1ObjectInAsn1Object(rootObj, [ [0, 5], [0, 6] ], function(asn1Object) {
    try {
      if (asn1Object.value[0].value[0].type !== 6) return;                      // looking for asn1.Type.OID (public key type)
      if (asn1Object.value[1].type !== 3) return;                               // looking for asn1.Type.BITSTRING (key)

      var oid = [
        forge.asn1.derToOid(asn1Object.value[0].value[0].value)
      ];

      if (oid[0] !== "1.2.840.113549.1.1.1") return;

      var key = {
        algEncPub: Constants.UAF_ALG_KEY_RSA_2048_PSS_RAW,
        oid: oid,
        data: {
          modulus: Buffer.from(asn1Object.value[1].value[0].value[0].value, 'binary').toString('base64'),
          exponent: Buffer.from(asn1Object.value[1].value[0].value[1].value, 'binary').toString('base64')
        }
      };

      return key;
    }
    catch(error) {
      if (!(error instanceof TypeError)) throw error;
      return;
    }
  });

  if (objects[0]) return objects[0];

  else {
    console.log(certificateBuffer.toString('base64'));
    throw new util.UAFError("No public key found in attestation certificate.", 1498, null);;
  }

};


function getSignatureFromAssertionBuffer(signatureBuffer, algSign) {

  var algSignOperations = {};

  algSignOperations[Constants.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW] = function() {                   // 0x01
    return signatureBuffer;
  };

  algSignOperations[Constants.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER] = function() {                   // 0x02
    var signatureString = signatureBuffer.toString('binary');
    var rootObj = forge.asn1.fromDer(signatureString);

    var rObj = rootObj.value[0];
    var r = Buffer.from(rObj.value, 'binary');
    if (r.length === 33 && r[0] === 0x00) r = r.slice(1);                       // ignore leading 0x00 if present (see http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long)
    var sObj = rootObj.value[1];
    var s = Buffer.from(sObj.value, 'binary');
    if (s.length === 33 && s[0] === 0x00) s = s.slice(1);                       // see above

    var signatureBufferCooked = Buffer.concat([r, s], 64);

    return signatureBufferCooked;
  };

  algSignOperations[Constants.UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW] = function() {                        // 0x03
    return signatureBuffer;
  };

  algSignOperations[Constants.UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER] = function() {                        // 0x04
    rootObj = forge.asn1.fromDer(signatureBuffer.toString('binary'));
    signatureBufferCooked = Buffer.from(rootObj.value, 'binary');

    return signatureBufferCooked;
  };

  algSignOperations[Constants.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW] =                                // 0x05
    algSignOperations[Constants.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW];

  algSignOperations[Constants.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER] =                                // 0x06
    algSignOperations[Constants.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER]

  return algSignOperations[algSign]();                                          // should never fail, as we've validated algSign values prior to here

}

function getVerifyMethodForKey(algSign) {

  if (algSign === Constants.UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW || algSign === Constants.UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER) {

    function verifySignatureRSASSAPSS(dataBuffer, signatureBuffer) {

      var modulusBuffer = Buffer.from(this.data.modulus, 'base64');
      var exponentBuffer = Buffer.from(this.data.exponent, 'base64');
      var key = ursa.createPublicKeyFromComponents(modulusBuffer, exponentBuffer);
      var usePssPadding = true;
      var saltLength = 32;
      var check = key.hashAndVerify("sha256", dataBuffer, signatureBuffer, null, usePssPadding, saltLength);

      return check;

    }

    return verifySignatureRSASSAPSS;

  }

  else {

    var ec;

    if (algSign === Constants.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW || algSign === Constants.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER) {
      ec = new EC('p256');                                                      // "SEC 2" recommended elliptic curve domain - secp256r1
    }
    else if (algSign === Constants.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW || algSign === Constants.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER) {
      ec = new EC('secp256k1');                                                 // "SEC 2" recommended elliptic curve domain - secp256k1
    }
    else return;

    function verifySignatureECC(dataBuffer, signatureBuffer) {                      // TODO: make this more elegant versus if/else/else

      if (this.oid[0] !== '1.2.840.10045.2.1')                                      // somehow ended here even though key is not for ECC
        throw new util.UAFError(`Unsupported ECC OID: ${this.oid[0]}.`, 1498, null);

      if (this.oid[1] !== '1.2.840.10045.3.1.7' && this.oid[1] !== '1.3.132.0.10')
        throw new util.UAFError(`Unsupported ECC curve in key, OID: ${this.oid[1]}.`, 1498, null);

      var signedDataHash = crypto.createHash('SHA256').update(dataBuffer).digest();
      var key = ec.keyFromPublic(Buffer.from(this.data.publicKey, 'base64'));
      var ecSignature = {
        r: signatureBuffer.slice(0, 32).toString('hex'),
        s: signatureBuffer.slice(32, 64).toString('hex')
      };

      var check = key.verify(signedDataHash, ecSignature);

      return check;

    }

    return verifySignatureECC;

  }

}

module.exports = {
  getKeyFromAssertionBuffer: getKeyFromAssertionBuffer,
  getKeyfromCertificateBuffer: getKeyfromCertificateBuffer,
  getSignatureFromAssertionBuffer: getSignatureFromAssertionBuffer,
  getVerifyMethodForKey: getVerifyMethodForKey
};

function findAsn1ObjectInAsn1Object(rootAsn1Object, locationHints, filter) {

  var found = [];

  for (let location of locationHints) {
    let currentAsn1Object = rootAsn1Object;
    try {
      var obj;
      for (let step of location) { currentAsn1Object = currentAsn1Object.value[step]; }
      if (obj = filter(currentAsn1Object)) { found.push(obj); }
    }
    catch(error) {
      if (!(error instanceof TypeError)) throw error;
      continue;
    }
  }

  return found;

}
