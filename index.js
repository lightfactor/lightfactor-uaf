
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

var uafRegistration = require("./lib/registration");
var uafAuthentication = require("./lib/authentication");
var uafResponse = require("./lib/response");
var uafTransaction = require("./lib/transaction");
var util = require("./lib/util");
var Constants = require("./lib/constants");
var uafCrypto = require("./lib/uafcrypto");

// TODO: wire up actual status codes per FIDO spec

function getRegistrationRequest(appID, policy, authenticators, username, obj) {
// TODO: enforce parameter validity
  var result = uafRegistration.getRegistrationRequestTemplate();

  result.uafRequest[0].header.appID = appID;
  result.uafRequest[0].header.serverData = util.toWebsafeBase64(crypto.randomBytes(32));        // TODO: do something meaningful with this field
  result.uafRequest[0].challenge = util.toWebsafeBase64(crypto.randomBytes(32));
  result.uafRequest[0].username = username;

  if (authenticators && authenticators.length > 0) {
    var matchCriteria = {
      aaid: authenticators.map(authenticator => authenticator.data.aaid),
      keyIDs: authenticators.map(authenticator => authenticator.data.keyID)
    };
    if (policy.disallowed) policy.disallowed.push(matchCriteria);
    else policy.disallowed = [ matchCriteria ];
  }

  result.uafRequest[0].policy = policy;

  obj.uafRequest = result.uafRequest;

  return obj;

}

function getAuthenticationRequest(appID, policy, transaction, authenticators, metadata, obj) {
// TODO: enforce parameter validity
// TODO: use authenticator tcDisplayPNGCharacteristics to override metadata, if present.
  var result = uafAuthentication.getAuthenticationRequestTemplate();

  result.uafRequest[0].header.appID = appID;
  result.uafRequest[0].header.serverData = util.toWebsafeBase64(crypto.randomBytes(32));        // TODO: do something with this field
  result.uafRequest[0].challenge = util.toWebsafeBase64(crypto.randomBytes(32));

  if (authenticators && authenticators.length > 0) {
    policy.accepted = [[ {
        aaid: authenticators.map(authenticator => authenticator.data.aaid),
        keyIDs: authenticators.map(authenticator => authenticator.data.keyID)
    } ]];
  }

  result.uafRequest[0].policy = policy;

  if (transaction) {

    var contentType = metadata.tcDisplayContentType;
    var transactionObject = { contentType: contentType };

    switch (contentType) {
      case "text/plain":
        transactionObject.content = util.toWebsafeBase64(Buffer.from(transaction));
        break;
      case "image/png":
        var tcDisplayPNGCharacteristics = metadata.tcDisplayPNGCharacteristics[0];
        var transactionImageBuffer = uafTransaction.createImageFromText(transaction, tcDisplayPNGCharacteristics.width, tcDisplayPNGCharacteristics.height).toBuffer();
        transactionObject.content = util.toWebsafeBase64(transactionImageBuffer);
        transactionObject.tcDisplayPNGCharacteristics = tcDisplayPNGCharacteristics;
        break;
      default:
        throw new util.UAFError(`Invalid metadata.tcDisplayContentType: ${contentType}.`, 1498, null);
    }

    result.uafRequest[0].transaction = [ transactionObject ];

  }

  obj.uafRequest = result.uafRequest;

  return obj;

}

function getDeregistrationRequest(appID, authenticators, obj) {
// TODO: enforce parameter validity
  result = uafRegistration.getDeregistrationRequestTemplate();

  result.uafRequest[0].header.appID = appID;

  if (authenticators && authenticators.length > 0) {
    result.uafRequest[0].authenticators = authenticators.map(authenticator => authenticator.data);
  }

  obj.uafRequest = result.uafRequest;

  return obj;

}


function validateAndUnwrapResponse(op, appID, facetIDArray, response) {

  function overrideResponseSchema(schema) {
    schema.properties.header.properties.op.enum = op;
    schema.properties.header.properties.appID.constant = appID;
  }
  var result = validateResponse(response, overrideResponseSchema);
  if (result.error) throw result.error;

  function overrideFCParamsSchema(schema) {
    schema.properties.appID.constant = appID;
    schema.properties.facetID.enum = facetIDArray;
  }
  var fcParamsResult = getValidFCParamsFromResponse(response, overrideFCParamsSchema);
  if (fcParamsResult.error) throw fcParamsResult.error;

  var assertionResult = getAssertionFromValidResponse(response);
  if (assertionResult.error) throw(assertionResult.error);

  return {
    fcParams: fcParamsResult.value,
    assertionObject: assertionResult.value
  }

}


function verifyRegistrationAssertion(assertionObject, metadata, obj) {

  function checkMetadata(assertion, metadata) {
    if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_AAID.s !== metadata.aaid)
      throw new util.UAFError("Assertion failed metadata AAID check.", 1498, null);
    if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.authenticatorVersion < metadata.authenticatorVersion)
      throw new util.UAFError("Assertion failed metadata authenticatorVersion check.", 1498, null);
    if (assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.algEncSign !== metadata.authenticationAlgorithm)
      throw new util.UAFError("Assertion failed metadata authenticationAlgorithm check.", 1498, null);

    var i = 0;
    for (attestationType of metadata.attestationTypes) if (assertion.TAG_UAFV1_REG_ASSERTION[Constants.tags[attestationType]]) i++;
    if (i === 0) throw new util.UAFError("Assertion failed metadata attestationType check.", 1498, null);
  }

  var assertion = assertionObject.assertion;
  var assertionBuffer = assertionObject.assertionBuffer;
  var metadataValid = checkMetadata(assertionObject.assertion, metadata);
  var attestationPubKeyObject = uafRegistration.getAttestationPubKey(assertion);        // TODO: verify certificate chain, also to include metadata
  var attestationObject = assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL
    || assertion.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE;
  var algEncSign = assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.algEncSign;
  var signature = uafCrypto.getSignatureFromAssertionBuffer(attestationObject.TAG_SIGNATURE.b, algEncSign);
  var endIndex = assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.l + 4 + 4;                                    // note: length does given does NOT include T and L of TLV
  var signedData = assertionBuffer.slice(4, endIndex);

  var verify = uafCrypto.getVerifyMethodForKey(algEncSign);
  var check = verify.call(attestationPubKeyObject, signedData, signature);

  if (!check) throw new util.UAFError("Registration signature verification failed.", 1498, null);

  var pubKeyObject = uafCrypto.getKeyFromAssertionBuffer(assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_PUB_KEY.b,
    assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.algEncPub);

  obj.registrationData = {
    pubKeyObject: pubKeyObject,
    keyID: assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_KEYID.s,
    signatureCounter: assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_COUNTERS.signatureCounter,
    authenticatorVersion: assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.authenticatorVersion,
    aaid: assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_AAID.s
  };

  if (assertionObject.tcDisplayPNGCharacteristics) obj.registrationData.tcDisplayPNGCharacteristics = assertionObject.tcDisplayPNGCharacteristics;
  if (assertionObject.exts) obj.registrationData.exts = assertionObject.exts;

  return obj;

}


function verifyAuthenticationAssertion(assertionObject, transaction, authenticator, metadata, obj) {

  var publicKeyObject = authenticator.data.pubKeyObject;
  var signatureCounter = authenticator.data.signatureCounter;

  function checkMetadata(assertion, metadata) {
    if (assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_AAID.s !== metadata.aaid)
      throw new util.UAFError("Assertion failed metadata AAID check.", 1498, null);
    if (assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.authenticatorVersion < metadata.authenticatorVersion)
      throw new util.UAFError("Assertion failed metadata authenticatorVersion check.", 1498, null);
    if (assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.algEncSign !== metadata.authenticationAlgorithm)
      throw new util.UAFError("Assertion failed metadata authenticationAlgorithm check.", 1498, null);

    if (signatureCounter === 0) signatureCounter = -1;        // combined with next statement: if a.sC = 0, assertion.sc >= 0; if a.sC > 0, assertion.sc > a.sC
    if (!(assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_COUNTERS.signatureCounter > signatureCounter))
      throw new util.UAFError("Assertion failed authenticator signatureCounter check.", 1498, null);
  }

  var assertion = assertionObject.assertion;
  var assertionBuffer = assertionObject.assertionBuffer;
  var metadataValid = checkMetadata(assertionObject.assertion, metadata);
  var algEncSign = assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.algEncSign;
  var signature = uafCrypto.getSignatureFromAssertionBuffer(assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE.b, algEncSign);
  var endIndex = assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.l + 4 + 4;                                    // length does given does NOT include T and L of TLV
  var signedData = assertionBuffer.slice(4, endIndex);

  var verify = uafCrypto.getVerifyMethodForKey(algEncSign);
  var value = verify.call(publicKeyObject, signedData, signature);
  if (!value) throw new util.UAFError("Authentication signature verification failed.", 1498, null);

  if (assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.authenticationMode == 0x02) {
    if (!transaction) throw new util.UAFError("Missing transaction for Auth mode 0x02.", 1498, null);
    var rawTransaction = Buffer.from(transaction, 'base64');
    var transactionHash = crypto.createHash('SHA256').update(rawTransaction).digest();
    var check = transactionHash.equals(assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH.b);
    if (!check) throw new util.UAFError("Transaction hash verification failed.", 1498, null);
  }

  return obj;

}


module.exports = {
  uafResponse: uafResponse,
  uafRegistration: uafRegistration,
  uafAuthentication: uafAuthentication,

  getRegistrationRequest: getRegistrationRequest,
  getAuthenticationRequest: getAuthenticationRequest,
  getDeregistrationRequest: getDeregistrationRequest,

  validateAndUnwrapResponse: validateAndUnwrapResponse,

  verifyRegistrationAssertion: verifyRegistrationAssertion,
  verifyAuthenticationAssertion: verifyAuthenticationAssertion,

  statusCodes: statusCodes
}

function validateResponse(response, overrideFunction) {

  try {
    var responseValid = uafResponse.validateWithSchemaWithOverride(response, uafResponse.getResponseSchema(), overrideFunction);
    return { error: null, value: responseValid };
  }
  catch (error) {
    if (error instanceof util.UAFError) return { error: error, value: null };
    else throw error;
  }

}

function getValidFCParamsFromResponse(response, overrideFunction) {                                    // NOTE: add AJV keyword for Buffer.from(base64).length test

  try {
    var fcParams = JSON.parse(Buffer.from(response.fcParams, 'base64'));
    var fcParamsValid = uafResponse.validateWithSchemaWithOverride(fcParams, uafResponse.getFCParamsSchema(), overrideFunction);
    var challengeBuffer = Buffer.from(fcParams.challenge, 'base64');
    if (challengeBuffer.length > 64 || challengeBuffer.length < 8)
      throw new util.UAFError("UAF response validation failed", 1498, validate.errors);
    return { error: null, value: fcParams };
  }
  catch (error) {
    if (error instanceof util.UAFError) return { error: error, value: null };
    else throw error;
  }

}

function getAssertionFromValidResponse(response) {

  try {
    var assertionBuffer = Buffer.from(response.assertions[0].assertion, 'base64');                // TODO: deal properly with whole array
    var assertion = uafResponse.parseAssertion(assertionBuffer);
    var schema = uafResponse.getAssertionSchema();
    var assertionValid = uafResponse.validateWithSchemaWithOverride(assertion, schema, null);

    var fcHash = crypto.createHash('SHA256').update(response.fcParams).digest();                  // TODO: SHA256 looks to be the only one supported at this point... will change implementation if that changes
    if (assertion.TAG_UAFV1_REG_ASSERTION)
      var finalChallenge = assertion.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_FINAL_CHALLENGE.b;
    else if (assertion.TAG_UAFV1_AUTH_ASSERTION)
      var finalChallenge = assertion.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_FINAL_CHALLENGE.b;
    var test = finalChallenge.equals(fcHash);                                          // per spec Protocol 3.4.6.5, must be true
    if (!test) throw new util.UAFError("TAG_FINAL_CHALLENGE is NOT equal to hash of fcParams", 1498, null);

    var value = {
      assertion: assertion,
      assertionBuffer: assertionBuffer,
      tcDisplayPNGCharacteristics: response.assertions[0].tcDisplayPNGCharacteristics,
      exts: response.assertions[0].exts
    };

    return { error: null, value: value };
  }
  catch (error) {
    if (error instanceof util.UAFError) return { error: error, value: null };
    else throw error;
  }

}

// status codes
//  (see see https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-client-api-transport-v1.0-ps-20141208.html#uaf-status-codes)

var statusCodes = {
  "1200": { message: "OK.", explanation: "Operation completed." },
  "1202": { message: "Accepted.", explanation: "Message accepted, but not completed at this time. The RP may need time to process the attestation, run risk scoring, etc. The server should not send an authenticationToken with a 1202 response." },
  "1400": { message: "Bad Request.", explanation: "The server did not understand the message." },
  "1401": { message: "Unauthorized.", explanation: "The userid must be authenticated to perform this operation, or this KeyID is not associated with this UserID." },
  "1403": { message: "Forbidden.", explanation: "The userid is not allowed to perform this operation. Client should not retry." },
  "1404": { message: "Not Found.", explanation: "" },
  "1408": { message: "Request Timeout.", explanation: "" },
  "1480": { message: "Unknown AAID.", explanation: "The server was unable to locate authoritative metadata for the AAID." },
  "1481": { message: "Unknown KeyID.", explanation: "The server was unable to locate a registration for the given UserID and KeyID combination. This error indicates that there is an invalid registration on the user's device. It is recommended that FIDO UAF Client deletes the key from local device when this error is received." },
  "1490": { message: "Channel Binding Refused.", explanation: "The server refused to service the request due to a missing or mismatched channel binding(s)." },
  "1491": { message: "Request Invalid.", explanation: "The server refused to service the request because the request message nonce was unknown, expired or the server has previously serviced a message with the same nonce and user ID." },
  "1492": { message: "Unacceptable Authenticator.", explanation: "The authenticator is not acceptable according to the server's policy, for example, because the capability registry used by the server reported different capabilities than client-side discovery." },
  "1493": { message: "Revoked Authenticator.", explanation: "The authenticator is considered revoked by the server." },
  "1494": { message: "Unacceptable Key.", explanation: "The key used is unacceptable. Perhaps it is on a list of known weak keys or uses insecure parameter choices." },
  "1495": { message: "Unacceptable Algorithm.", explanation: "The server believes the authenticator to be capable of using a stronger mutually-agreeable algorithm than was presented in the request." },
  "1496": { message: "Unacceptable Attestation.", explanation: "The attestation(s) provided were not accepted by the server." },
  "1497": { message: "Unacceptable Client Capabilities.", explanation: "The server was unable or unwilling to use required capabilities provided supplementally to the authenticator by the client software." },
  "1498": { message: "Unacceptable Content.", explanation: "There was a problem with the contents of the message and the server was unwilling or unable to process it." },
  "1500": { message: "Internal Server Error", explanation: "" }
};
