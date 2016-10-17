
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

var https = require('https');
var crypto = require('crypto');
var EC = require('elliptic').ec;
var ec = new EC('p384');                    // see https://tools.ietf.org/html/rfc7519#section-8 and look at header, alg: 'ES256'
var forge = require('node-forge');
var pki = forge.pki;
var asn1 = forge.asn1;

// see https://tools.ietf.org/html/rfc7519
// see also https://jwt.io/introduction/ for some tools and helpful information

var fidoMdsRoot = "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoXDTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4imsrfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYwHwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAwZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciWDcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XUYjdBz56jSA=="

var options = {
    hostname: "mds.fidoalliance.org",
    port: 443,
    path: "/",
    method: "GET",
    secureProtocol: 'TLSv1_2_method',
  	rejectUnauthorized: true
};

var buf = null;
var bufTmp = null;

var req = https.request(options, function(res) {

  var length = parseInt(res.headers['content-length']);
  buf = Buffer.alloc(length);
  bufTmp = buf;

	res.setEncoding('utf8');

	res.on('data', (chunk) => {
    bufTmp.write(chunk);
    bufTmp = bufTmp.slice(chunk.length);
	});

  res.on('end', () => {

    var firstIndex = buf.indexOf('.');
    var headerBuf = Buffer.from(buf.slice(0, firstIndex).toString(), 'base64');
    var header = JSON.parse(headerBuf);

    var secondIndex = buf.indexOf('.', firstIndex + 1);
    var payloadBuf = Buffer.from(buf.slice(firstIndex + 1, secondIndex).toString(), 'base64');
    var payload = JSON.parse(payloadBuf);

    var signatureBuf = Buffer.from(buf.slice(secondIndex + 1).toString(), 'base64');

    console.log(`first: ${firstIndex}, second: ${secondIndex}`);
    console.log("Header:");
    console.log(header);
    console.log("Payload:");
    console.log({ nextUpdate: payload.nextUpdate, no: payload.no, entryCount: payload.entries.length });
    console.log(`Signature (${signatureBuf.length} bytes):`);
    console.log(signatureBuf);
console.log(signatureBuf.toString('base64'));

    var rootObject = forge.asn1.fromDer(Buffer.from(fidoMdsRoot, 'base64').toString('binary'));
    var pubKeyObject = rootObject.value[0].value[6].value;
//console.log(pubKeyObject);
//console.log(forge.asn1.derToOid(pubKeyObject[0].value[0].value));
//console.log(forge.asn1.derToOid(pubKeyObject[0].value[1].value));
    var pubKey = Buffer.from(pubKeyObject[1].value, 'binary').slice(1);

console.log("extracted by nodejs");
console.log(pubKey);
console.log(pubKey.length);

    var testKeyString = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4imsrfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSos";
    var testKey = Buffer.from(testKeyString, 'base64');
console.log("extracted by openssl");
console.log(testKey);
console.log(testKey.length);

    var signedData = buf.slice(0, secondIndex);               // header.payload from original buffer
    var signedDataHash = crypto.createHash('SHA256').update(signedData).digest();
    var key = ec.keyFromPublic(pubKey);
    var ecSignature = {
      r: signatureBuf.slice(0, 32).toString('hex'),
      s: signatureBuf.slice(32, 64).toString('hex')
    };

    var value = key.verify(signedDataHash, ecSignature);

    console.log(value);

  });

});

//req.write(body);

req.end();

req.on('error', function(e) {
	console.error(e);
});
