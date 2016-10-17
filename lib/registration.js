
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

var uafCrypto = require("./uafcrypto");


function getRegistrationRequestTemplate() {
  return {
    uafRequest: [
      {
        header: {
          upv: {
            major: 1,
            minor: 0
          },
          op: 'Reg'
        }
      }
    ]
  };
}

function getDeregistrationRequestTemplate() {
  return {
    uafRequest: [
      {
        header: {
          upv: {
            major: 1,
            minor: 0
          },
          op: 'Dereg'
        }
      }
    ]
  };
}

function getAttestationPubKey(assertion) {                                      // TODO: error handling

  if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL)
    return uafCrypto.getKeyfromCertificateBuffer(assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_ATTESTATION_CERT.b);

  else if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE)
    return uafCrypto.getKeyFromAssertionBuffer(
      assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_PUB_KEY.b,
      assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.algEncPub);

}


module.exports = {
  getRegistrationRequestTemplate: getRegistrationRequestTemplate,
  getDeregistrationRequestTemplate: getDeregistrationRequestTemplate,
  getAttestationPubKey: getAttestationPubKey
};
