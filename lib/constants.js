
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

_e = module.exports;

_e.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW =      0x01;
_e.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER =      0x02;
_e.UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW =           0x03;
_e.UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER =           0x04;
_e.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW =      0x05;
_e.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER =      0x06;

_e.UAF_ALG_SIGN = [
  _e.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW,
  _e.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER,
  _e.UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW,
  _e.UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER,
  _e.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW,
  _e.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER
];


_e.UAF_ALG_KEY_ECC_X962_RAW =                     0x100;              // 256
_e.UAF_ALG_KEY_ECC_X962_DER =                     0x101;              // 257
_e.UAF_ALG_KEY_RSA_2048_PSS_RAW =                 0x102;              // 258
_e.UAF_ALG_KEY_RSA_2048_PSS_DER =                 0x103;              // 259

_e.UAF_ALG_KEY = [
  _e.UAF_ALG_KEY_ECC_X962_RAW,
  _e.UAF_ALG_KEY_ECC_X962_DER,
  _e.UAF_ALG_KEY_RSA_2048_PSS_RAW,
  _e.UAF_ALG_KEY_RSA_2048_PSS_DER
];


_e.TAG_UAFV1_REG_ASSERTION =                      0x3E01;             // 15873
_e.TAG_UAFV1_AUTH_ASSERTION =                     0x3E02;             // 15874

_e.TAG_ASSERTION = [
  _e.TAG_UAFV1_REG_ASSERTION,
  _e.TAG_UAFV1_AUTH_ASSERTION
];


_e.TAG_UAFV1_KRD =                                0x3E03;             // 15875
_e.TAG_UAFV1_SIGNED_DATA =                        0x3E04;             // 15876

_e.TAG_ASSERTION_DATA = [
  _e.TAG_UAFV1_KRD,
  _e.TAG_UAFV1_SIGNED_DATA
];


_e.TAG_ATTESTATION_CERT =                         0x2E05;             // 11781
_e.TAG_SIGNATURE =                                0x2E06;             // 11782
_e.TAG_KEYID =                                    0x2E09;             // 11785
_e.TAG_FINAL_CHALLENGE =                          0x2E0A;             // 11786
_e.TAG_AAID =                                     0x2E0B;             // 11787
_e.TAG_PUB_KEY =                                  0x2E0C;             // 11788
_e.TAG_COUNTERS =                                 0x2E0D;             // 11789
_e.TAG_ASSERTION_INFO =                           0x2E0E;             // 11790
_e.TAG_AUTHENTICATOR_NONCE =                      0x2E0F;             // 11791
_e.TAG_TRANSACTION_CONTENT_HASH =                 0x2E10;             // 11792


_e.TAG_ATTESTATION_BASIC_FULL =                   0x3E07;             // 15879
_e.TAG_ATTESTATION_BASIC_SURROGATE =              0x3E08;             // 15880

_e.UAF_TAG_ATTESTATION = [
  _e.TAG_ATTESTATION_BASIC_FULL,
  _e.TAG_ATTESTATION_BASIC_SURROGATE
];


_e.AUTHENTICATION_MODE = [
  0x01,
  0x02
];

const tags = {};

tags["3E01"] = tags[15873] = "TAG_UAFV1_REG_ASSERTION";
tags["3E02"] = tags[15874] = "TAG_UAFV1_AUTH_ASSERTION";
tags["3E03"] = tags[15875] = "TAG_UAFV1_KRD";
tags["3E04"] = tags[15876] = "TAG_UAFV1_SIGNED_DATA";
tags["3E07"] = tags[15879] = "TAG_ATTESTATION_BASIC_FULL";
tags["3E08"] = tags[15880] = "TAG_ATTESTATION_BASIC_SURROGATE";

tags["2E05"] = tags[11781] = "TAG_ATTESTATION_CERT";
tags["2E06"] = tags[11782] = "TAG_SIGNATURE";
tags["2E09"] = tags[11785] = "TAG_KEYID";
tags["2E0A"] = tags[11786] = "TAG_FINAL_CHALLENGE";
tags["2E0B"] = tags[11787] = "TAG_AAID";
tags["2E0C"] = tags[11788] = "TAG_PUB_KEY";
tags["2E0D"] = tags[11789] = "TAG_COUNTERS";
tags["2E0E"] = tags[11790] = "TAG_ASSERTION_INFO";
tags["2E0F"] = tags[11791] = "TAG_AUTHENTICATOR_NONCE";
tags["2E10"] = tags[11792] = "TAG_TRANSACTION_CONTENT_HASH";

_e.tags = tags;
