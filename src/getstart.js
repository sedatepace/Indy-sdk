"use strict";

const indy = require('indy-sdk');
const util = require('./util');
const assert = require('assert');

async function run() {

    console.log("gettingStarted.js -> started");

    let poolName = 'pool1';
    console.log(`Open Pool Ledger: ${poolName}`);
    let poolGenesisTxnPath = await util.getPoolGenesisTxnPath(poolName);
    let poolConfig = {
        "genesis_txn": poolGenesisTxnPath
    };
    try {
        await indy.createPoolLedgerConfig(poolName, poolConfig);
    } catch(e) {
        if(e.message !== "PoolLedgerConfigAlreadyExistsError") {
            throw e;
        }
    }

    await indy.setProtocolVersion(2)

    let poolHandle = await indy.openPoolLedger(poolName);

    console.log("==============================");
    console.log("=== Getting Trust Anchor credentials for CA  ==");
    console.log("------------------------------");

    console.log("\"Sovrin Steward\" -> Create wallet");
    let stewardWalletConfig = {'id': 'stewardWalletName'}
    let stewardWalletCredentials = {'key': 'steward_key'}
    try {
        await indy.createWallet(stewardWalletConfig, stewardWalletCredentials)
    } catch(e) {
        if(e.message !== "WalletAlreadyExistsError") {
            throw e;
        }
    }

    let stewardWallet = await indy.openWallet(stewardWalletConfig, stewardWalletCredentials);

    console.log("\"Sovrin Steward\" -> Create and store in Wallet DID from seed");
    let stewardDidInfo = {
        'seed': '000000000000000000000000Steward1'
    };

    let [stewardDid,] = await indy.createAndStoreMyDid(stewardWallet, stewardDidInfo);

    console.log("==============================");
    console.log("== Getting Trust Anchor credentials - CA Onboarding  ==");
    console.log("------------------------------");

    let CAWalletConfig = {'id': 'CAWallet'}
    let CAWalletCredentials = {'key': 'CA_key'}
    let [CAWallet, stewardCAKey, CAStewardDid, CAStewardKey] = await onboarding(poolHandle, "Sovrin Steward", stewardWallet, stewardDid, "CA", null, CAWalletConfig, CAWalletCredentials);

    console.log("==============================");
    console.log("== Getting Trust Anchor credentials - CA getting Verinym  ==");
    console.log("------------------------------");

    let CADid = await getVerinym(poolHandle, "Sovrin Steward", stewardWallet, stewardDid,
        stewardCAKey, "CA", CAWallet, CAStewardDid,
        CAStewardKey, 'TRUST_ANCHOR');

    
    console.log("==============================");
    console.log("== Getting Trust Anchor credentials - Faber Onboarding  ==");
    console.log("------------------------------");

    let faberWalletConfig = {'id': 'faberWallet'}
    let faberWalletCredentials = {'key': 'faber_key'}
    let [faberWallet, stewardFaberKey, faberStewardDid, faberStewardKey] = await onboarding(poolHandle, "Sovrin Steward", stewardWallet, stewardDid, "Faber", null, faberWalletConfig, faberWalletCredentials);

    console.log("==============================");
    console.log("== Getting Trust Anchor credentials - Faber getting Verinym  ==");
    console.log("------------------------------");

    let faberDid = await getVerinym(poolHandle, "Sovrin Steward", stewardWallet, stewardDid, stewardFaberKey,
        "Faber", faberWallet, faberStewardDid, faberStewardKey, 'TRUST_ANCHOR');

    console.log("\"CA\" -> Create \"membership\" Schema");
    let [membershipSchemaId, membershipSchema] = await indy.issuerCreateSchema(CADid, 'membership', '1.2',
        ['name', 'age', 'id', 'pw','verkey']);
    console.log("\"CA\" -> Send \"membership\" Schema to Ledger");
    await sendSchema(poolHandle, CAWallet, CADid, membershipSchema);
    
    console.log("==============================");
    console.log("== Getting Trust Anchor credentials - Thrift Onboarding  ==");
    console.log("------------------------------");

    let thriftWalletConfig = {'id': 'thriftWallet'}
    let thriftWalletCredentials = {'key': 'thrift_key'}
    let [thriftWallet, stewardThriftKey, thriftStewardDid, thriftStewardKey] = await onboarding(poolHandle, "Sovrin Steward", stewardWallet, stewardDid, "Thrift", null, thriftWalletConfig, thriftWalletCredentials);

    console.log("==============================");
    console.log("== Getting Trust Anchor credentials - Thrift getting Verinym  ==");
    console.log("------------------------------");

    let thriftDid = await getVerinym(poolHandle, "Sovrin Steward", stewardWallet, stewardDid, stewardThriftKey,
        "Thrift", thriftWallet, thriftStewardDid, thriftStewardKey, 'TRUST_ANCHOR');

    console.log("==============================");
    console.log("=== Faber Credential Definition Setup ==");
    console.log("------------------------------");

    console.log("\"Faber\" -> Get \"membership\" Schema from Ledger");
    [, membershipSchema] = await getSchema(poolHandle, faberDid, membershipSchemaId);

    console.log("\"Faber\" -> Create and store in Wallet \"Faber membership\" Credential Definition");
    let [fabermembershipCredDefId, fabermembershipCredDefJson] = await indy.issuerCreateAndStoreCredentialDef(faberWallet, faberDid, membershipSchema, 'TAG1', 'CL', '{"support_revocation": false}');

    console.log("\"Faber\" -> Send  \"Faber membership\" Credential Definition to Ledger");
    await sendCredDef(poolHandle, faberWallet, faberDid, fabermembershipCredDefJson);

        
    console.log("==============================");
    console.log("=== Getting membership with Faber ==");
    console.log("==============================");
    console.log("== Getting membership with Faber - Onboarding ==");
    console.log("------------------------------");

    let aliceWalletConfig = {'id': 'aliceWallet'}
    let aliceWalletCredentials = {'key': 'alice_key'}
    let [aliceWallet, faberAliceKey, aliceFaberDid, aliceFaberKey, faberAliceConnectionResponse] = await onboarding(poolHandle, "Faber", faberWallet, faberDid, "Alice", null, aliceWalletConfig, aliceWalletCredentials);

    console.log("==============================");
    console.log("== Getting membership with Faber - Getting membership Credential ==");
    console.log("------------------------------");

    console.log("\"Faber\" -> Create \"membership\" Credential Offer for Alice");
    let membershipCredOfferJson = await indy.issuerCreateCredentialOffer(faberWallet, fabermembershipCredDefId);

    console.log("\"Faber\" -> Get key for Alice did");
    let aliceFaberVerkey = await indy.keyForDid(poolHandle, faberWallet, faberAliceConnectionResponse['did']);

    console.log("\"Faber\" -> Authcrypt \"membership\" Credential Offer for Alice");
    let authcryptedmembershipCredOffer = await indy.cryptoAuthCrypt(faberWallet, faberAliceKey, aliceFaberVerkey, Buffer.from(JSON.stringify(membershipCredOfferJson),'utf8'));

    console.log("\"Faber\" -> Send authcrypted \"membership\" Credential Offer to Alice");

    console.log("\"Alice\" -> Authdecrypted \"membership\" Credential Offer from Faber");
    let [faberAliceVerkey, authdecryptedmembershipCredOfferJson, authdecryptedmembershipCredOffer] = await authDecrypt(aliceWallet, aliceFaberKey, authcryptedmembershipCredOffer);

    console.log("\"Alice\" -> Create and store \"Alice\" Master Secret in Wallet");
    let aliceMasterSecretId = await indy.proverCreateMasterSecret(aliceWallet, null);

    console.log("\"Alice\" -> Get \"Faber membership\" Credential Definition from Ledger");
    let fabermembershipCredDef;
    [fabermembershipCredDefId, fabermembershipCredDef] = await getCredDef(poolHandle, aliceFaberDid, authdecryptedmembershipCredOffer['cred_def_id']);

    console.log("\"Alice\" -> Create \"membership\" Credential Request for Faber");
    let [membershipCredRequestJson, membershipCredRequestMetadataJson] = await indy.proverCreateCredentialReq(aliceWallet, aliceFaberDid, authdecryptedmembershipCredOfferJson, fabermembershipCredDef, aliceMasterSecretId);

    console.log("\"Alice\" -> Authcrypt \"membership\" Credential Request for Faber");
    let authcryptedmembershipCredRequest = await indy.cryptoAuthCrypt(aliceWallet, aliceFaberKey, faberAliceVerkey, Buffer.from(JSON.stringify(membershipCredRequestJson),'utf8'));

    console.log("\"Alice\" -> Send authcrypted \"membership\" Credential Request to Faber");

    console.log("\"Faber\" -> Authdecrypt \"membership\" Credential Request from Alice");
    let authdecryptedmembershipCredRequestJson;
    [aliceFaberVerkey, authdecryptedmembershipCredRequestJson] = await authDecrypt(faberWallet, faberAliceKey, authcryptedmembershipCredRequest);

    console.log("\"Faber\" -> Create \"membership\" Credential for Alice");
    // note that encoding is not standardized by Indy except that 32-bit integers are encoded as themselves. IS-786
    let membershipCredValues = {
        "name": {"raw": "Alice", "encoded": "1139481716457488690172217916278103335"},
        "age": {"raw": "22", "encoded": "22"},
        "id": {"raw": "ty0621", "encoded": "12434523576212321"},
        "pw": {"raw": "paw123", "encoded": "2213454313412354"},
        "verkey": {"raw": "7TYfekw4GUagBnBVCqPjiC", "encoded": "3124141231422543541"},
    };

    let [membershipCredJson] = await indy.issuerCreateCredential(faberWallet, membershipCredOfferJson, authdecryptedmembershipCredRequestJson, membershipCredValues, null, -1);

    console.log("\"Faber\" -> Authcrypt \"membership\" Credential for Alice");
    let authcryptedmembershipCredJson = await indy.cryptoAuthCrypt(faberWallet, faberAliceKey, aliceFaberVerkey, Buffer.from(JSON.stringify(membershipCredJson),'utf8'));

    console.log("\"Faber\" -> Send authcrypted \"membership\" Credential to Alice");

    console.log("\"Alice\" -> Authdecrypted \"membership\" Credential from Faber");
    let [, authdecryptedmembershipCredJson] = await authDecrypt(aliceWallet, aliceFaberKey, authcryptedmembershipCredJson);

    console.log("\"Alice\" -> Store \"membership\" Credential from Faber");
    await indy.proverStoreCredential(aliceWallet, null, membershipCredRequestMetadataJson,
        authdecryptedmembershipCredJson, fabermembershipCredDef, null);


    console.log("==============================");
    console.log("=== Apply for the loan with Thrift ==");
    console.log("==============================");
    console.log("== Apply for the loan with Thrift - Onboarding ==");
    console.log("------------------------------");

    let thriftAliceKey, aliceThriftDid, aliceThriftKey, thriftAliceConnectionResponse;
    [aliceWallet, thriftAliceKey, aliceThriftDid, aliceThriftKey, thriftAliceConnectionResponse] = await onboarding(poolHandle, "Thrift", thriftWallet, thriftDid,
        "Alice", aliceWallet, aliceWalletConfig, aliceWalletCredentials);

    console.log("==============================");
    console.log("== Apply for the loan with Thrift - Job-Certificate proving  ==");
    console.log("------------------------------");

    console.log("\"Thrift\" -> Create \"login\" Proof Request");
    let nonce = await indy.generateNonce()
    let loginProofRequestJson = {
        'nonce': nonce,
        'name': 'login',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'id',
                'restrictions': [{'cred_def_id': fabermembershipCredDefId}]
            },
            'attr2_referent': {
                'name': 'pw',
                'restrictions': [{'cred_def_id': fabermembershipCredDefId}]
            },
            'attr3_referent': {
                'name': 'verkey',
                'restrictions': [{'cred_def_id': fabermembershipCredDefId}]
            }
        
        }
    };

    console.log("\"Thrift\" -> Get key for Alice did");
    let aliceThriftVerkey = await indy.keyForDid(poolHandle, thriftWallet, thriftAliceConnectionResponse['did']);

    console.log("\"Thrift\" -> Authcrypt \"login\" Proof Request for Alice");
    let authcryptedloginProofRequestJson = await indy.cryptoAuthCrypt(thriftWallet, thriftAliceKey, aliceThriftVerkey,Buffer.from(JSON.stringify(loginProofRequestJson),'utf8'));

    console.log("\"Thrift\" -> Send authcrypted \"login\" Proof Request to Alice");

    console.log("\"Alice\" -> Authdecrypt \"login\" Proof Request from Thrift");
    let [thriftAliceVerkey, authdecryptedloginProofRequestJson] = await authDecrypt(aliceWallet, aliceThriftKey, authcryptedloginProofRequestJson);

    console.log("\"Alice\" -> Get credentials for \"login\" Proof Request");

    let searchForJloginProofRequest = await indy.proverSearchCredentialsForProofReq(aliceWallet, authdecryptedloginProofRequestJson, null)

    let credentials = await indy.proverFetchCredentialsForProofReq(searchForJloginProofRequest, 'attr1_referent', 100)
    let credForAttr1 = credentials[0]['cred_info'];

    await indy.proverFetchCredentialsForProofReq(searchForJloginProofRequest, 'attr2_referent', 100)
    credForPredicate1 = credentials[0]['cred_info'];

    await indy.proverFetchCredentialsForProofReq(searchForJloginProofRequest, 'attr3_referent', 100)
    let credForPredicate2 = credentials[0]['cred_info'];

    await indy.proverCloseCredentialsSearchForProofReq(searchForJloginProofRequest)

    let credsForloginProof = {};
    credsForloginProof[`${credForAttr1['referent']}`] = credForAttr1;
    credsForloginProof[`${credForAttr2['referent']}`] = credForAttr2;
    credsForloginProof[`${credForAttr3['referent']}`] = credForAttr3;

    [schemasJson, credDefsJson, revocStatesJson] = await proverGetEntitiesFromLedger(poolHandle, aliceThriftDid, credsForloginProof, 'Alice');

    console.log("\"Alice\" -> Create \"login\" Proof");
    let loginRequestedCredsJson = {
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {'cred_id': credForAttr1['referent'], 'revealed': true},
            'attr1_referent': {'cred_id': credForAttr2['referent'], 'revealed': true},
            'attr1_referent': {'cred_id': credForAttr3['referent'], 'revealed': true}
        }
    };
    let aliceloginProofJson = await indy.proverCreateProof(aliceWallet, authdecryptedloginProofRequestJson,
        loginRequestedCredsJson, aliceMasterSecretId, schemasJson,
        credDefsJson, revocStatesJson);

    console.log("\"Alice\" -> Authcrypt \"login\" Proof for Thrift");
    let authcryptedAliceloginProofJson = await indy.cryptoAuthCrypt(aliceWallet, aliceThriftKey, thriftAliceVerkey,Buffer.from(JSON.stringify(aliceloginProofJson),'utf8'));

    console.log("\"Alice\" -> Send authcrypted \"login\" Proof to Thrift");

    console.log("\"Thrift\" -> Authdecrypted \"login\" Proof from Alice");
    let authdecryptedAliceloginProofJson, authdecryptedAliceloginProof;
    [, authdecryptedAliceloginProofJson, authdecryptedAliceloginProof] = await authDecrypt(thriftWallet, thriftAliceKey, authcryptedAliceloginProofJson);

    console.log("\"Thrift\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger required for Proof verifying");

    let revocDefsJson;
    [schemasJson, credDefsJson, revocDefsJson, revocRegsJson] = await verifierGetEntitiesFromLedger(poolHandle, thriftDid,
        authdecryptedAliceloginProof['identifiers'], 'Thrift');

    console.log("\"Thrift\" -> Verify \"login\" Proof from Alice");
    assert('Permanent' === authdecryptedAliceloginProof['requested_proof']['revealed_attrs']['attr1_referent']['raw']);

    assert(await indy.verifierVerifyProof(loginProofRequestJson, authdecryptedAliceloginProofJson, schemasJson, credDefsJson, revocDefsJson, revocRegsJson));

    console.log("==============================");

    console.log("==============================");
    console.log("== Apply for the loan with Thrift - membership and Job-Certificate proving  ==");
    console.log("------------------------------");

    console.log("\"Thrift\" -> Create \"login-KYC\" Proof Request");
    nonce = await indy.generateNonce()
    let loginKycProofRequestJson = {
        'nonce': nonce,
        'name': 'login-KYC',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {'name': 'id'},
            'attr2_referent': {'name': 'pw'},
            'attr3_referent': {'name': 'verkey'}
        },
        'requested_predicates': {}
    };

    console.log("\"Thrift\" -> Get key for Alice did");
    aliceThriftVerkey = await indy.keyForDid(poolHandle, thriftWallet, thriftAliceConnectionResponse['did']);

    console.log("\"Thrift\" -> Authcrypt \"login-KYC\" Proof Request for Alice");
    let authcryptedloginKycProofRequestJson = await indy.cryptoAuthCrypt(thriftWallet, thriftAliceKey, aliceThriftVerkey,Buffer.from(JSON.stringify(loginKycProofRequestJson),'utf8'));

    console.log("\"Thrift\" -> Send authcrypted \"login-KYC\" Proof Request to Alice");

    console.log("\"Alice\" -> Authdecrypt \"login-KYC\" Proof Request from Thrift");
    let authdecryptedloginKycProofRequestJson;
    [thriftAliceVerkey, authdecryptedloginKycProofRequestJson] = await authDecrypt(aliceWallet, aliceThriftKey, authcryptedloginKycProofRequestJson);

    console.log("\"Alice\" -> Get credentials for \"login-KYC\" Proof Request");

    let searchForloginKycProofRequest = await indy.proverSearchCredentialsForProofReq(aliceWallet, authdecryptedloginKycProofRequestJson, null)

    credentials = await indy.proverFetchCredentialsForProofReq(searchForloginKycProofRequest, 'attr1_referent', 100)
    credForAttr1 = credentials[0]['cred_info'];

    credentials = await indy.proverFetchCredentialsForProofReq(searchForloginKycProofRequest, 'attr2_referent', 100)
    credForAttr2 = credentials[0]['cred_info'];

    credentials = await indy.proverFetchCredentialsForProofReq(searchForloginKycProofRequest, 'attr3_referent', 100)
    credForAttr3 = credentials[0]['cred_info'];

    await indy.proverCloseCredentialsSearchForProofReq(searchForloginKycProofRequest)

    let credsForloginKycProof = {};
    credsForloginKycProof[`${credForAttr1['referent']}`] = credForAttr1;
    credsForloginKycProof[`${credForAttr2['referent']}`] = credForAttr2;
    credsForloginKycProof[`${credForAttr3['referent']}`] = credForAttr3;

    [schemasJson, credDefsJson, revocStatesJson] = await proverGetEntitiesFromLedger(poolHandle, aliceThriftDid, credsForloginKycProof, 'Alice');

    console.log("\"Alice\" -> Create \"login-KYC\" Proof");

    let loginKycRequestedCredsJson = {
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {'cred_id': credForAttr1['referent'], 'revealed': true},
            'attr2_referent': {'cred_id': credForAttr2['referent'], 'revealed': true},
            'attr3_referent': {'cred_id': credForAttr3['referent'], 'revealed': true}
        },
        'requested_predicates': {}
    };

    let aliceloginKycProofJson = await indy.proverCreateProof(aliceWallet, authdecryptedloginKycProofRequestJson,
        loginKycRequestedCredsJson, aliceMasterSecretId,
        schemasJson, credDefsJson, revocStatesJson);

    console.log("\"Alice\" -> Authcrypt \"login-KYC\" Proof for Thrift");
    let authcryptedAliceloginKycProofJson = await indy.cryptoAuthCrypt(aliceWallet, aliceThriftKey, thriftAliceVerkey,Buffer.from(JSON.stringify(aliceloginKycProofJson),'utf8'));

    console.log("\"Alice\" -> Send authcrypted \"login-KYC\" Proof to Thrift");

    console.log("\"Thrift\" -> Authdecrypted \"login-KYC\" Proof from Alice");
    let authdecryptedAliceloginKycProof;
    [, authdecryptedAliceloginKycProof] = await authDecrypt(thriftWallet, thriftAliceKey, authcryptedAliceloginKycProofJson);

    console.log("\"Thrift\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger required for Proof verifying");

    [schemasJson, credDefsJson, revocDefsJson, revocRegsJson] = await verifierGetEntitiesFromLedger(poolHandle, thriftDid, authdecryptedAliceloginKycProof['identifiers'], 'Thrift');

    console.log("\"Thrift\" -> Verify \"login-KYC\" Proof from Alice");
    assert('Alice' === authdecryptedAliceloginKycProof['requested_proof']['revealed_attrs']['attr1_referent']['raw']);
    assert('Garcia' === authdecryptedAliceloginKycProof['requested_proof']['revealed_attrs']['attr2_referent']['raw']);
    assert('123-45-6789' === authdecryptedAliceloginKycProof['requested_proof']['revealed_attrs']['attr3_referent']['raw']);

    assert(await indy.verifierVerifyProof(loginKycProofRequestJson, authdecryptedAliceloginKycProof, schemasJson, credDefsJson, revocDefsJson, revocRegsJson));

    console.log("==============================");

    console.log(" \"Sovrin Steward\" -> Close and Delete wallet");
    await indy.closeWallet(stewardWallet);
    await indy.deleteWallet(stewardWalletConfig, stewardWalletCredentials);

    console.log("\"CA\" -> Close and Delete wallet");
    await indy.closeWallet(CAWallet);
    await indy.deleteWallet(CAWalletConfig, CAWalletCredentials);

    console.log("\"Faber\" -> Close and Delete wallet");
    await indy.closeWallet(faberWallet);
    await indy.deleteWallet(faberWalletConfig, faberWalletCredentials);

    console.log("\"Thrift\" -> Close and Delete wallet");
    await indy.closeWallet(thriftWallet);
    await indy.deleteWallet(thriftWalletConfig, thriftWalletCredentials);

    console.log("\"Alice\" -> Close and Delete wallet");
    await indy.closeWallet(aliceWallet);
    await indy.deleteWallet(aliceWalletConfig, aliceWalletCredentials);

    console.log("Close and Delete pool");
    await indy.closePoolLedger(poolHandle);
    await indy.deletePoolLedgerConfig(poolName);

    console.log("Getting started -> done")
    
}


async function onboarding(poolHandle, From, fromWallet, fromDid, to, toWallet, toWalletConfig, toWalletCredentials) {
    console.log(`\"${From}\" > Create and store in Wallet \"${From} ${to}\" DID`);
    let [fromToDid, fromToKey] = await indy.createAndStoreMyDid(fromWallet, {});

    console.log(`\"${From}\" > Send Nym to Ledger for \"${From} ${to}\" DID`);
    await sendNym(poolHandle, fromWallet, fromDid, fromToDid, fromToKey, null);

    console.log(`\"${From}\" > Send connection request to ${to} with \"${From} ${to}\" DID and nonce`);
    let connectionRequest = {
        did: fromToDid,
        nonce: 123456789
    };

    if (!toWallet) {
        console.log(`\"${to}\" > Create wallet"`);
        try {
            await indy.createWallet(toWalletConfig, toWalletCredentials);
        } catch(e) {
            if(e.message !== "WalletAlreadyExistsError") {
                throw e;
            }
        }
        toWallet = await indy.openWallet(toWalletConfig, toWalletCredentials);
    }

    console.log(`\"${to}\" > Create and store in Wallet \"${to} ${From}\" DID`);
    let [toFromDid, toFromKey] = await indy.createAndStoreMyDid(toWallet, {});

    console.log(`\"${to}\" > Get key for did from \"${From}\" connection request`);
    let fromToVerkey = await indy.keyForDid(poolHandle, toWallet, connectionRequest.did);

    console.log(`\"${to}\" > Anoncrypt connection response for \"${From}\" with \"${to} ${From}\" DID, verkey and nonce`);
    let connectionResponse = JSON.stringify({
        'did': toFromDid,
        'verkey': toFromKey,
        'nonce': connectionRequest['nonce']
    });
    let anoncryptedConnectionResponse = await indy.cryptoAnonCrypt(fromToVerkey, Buffer.from(connectionResponse, 'utf8'));

    console.log(`\"${to}\" > Send anoncrypted connection response to \"${From}\"`);

    console.log(`\"${From}\" > Anondecrypt connection response from \"${to}\"`);
    let decryptedConnectionResponse = JSON.parse(Buffer.from(await indy.cryptoAnonDecrypt(fromWallet, fromToKey, anoncryptedConnectionResponse)));

    console.log(`\"${From}\" > Authenticates \"${to}\" by comparision of Nonce`);
    if (connectionRequest['nonce'] !== decryptedConnectionResponse['nonce']) {
        throw Error("nonces don't match!");
    }

    console.log(`\"${From}\" > Send Nym to Ledger for \"${to} ${From}\" DID`);
    await sendNym(poolHandle, fromWallet, fromDid, decryptedConnectionResponse['did'], decryptedConnectionResponse['verkey'], null);

    return [toWallet, fromToKey, toFromDid, toFromKey, decryptedConnectionResponse];
}

async function getVerinym(poolHandle, From, fromWallet, fromDid, fromToKey, to, toWallet, toFromDid, toFromKey, role) {
    console.log(`\"${to}\" > Create and store in Wallet \"${to}\" new DID"`);
    let [toDid, toKey] = await indy.createAndStoreMyDid(toWallet, {});

    console.log(`\"${to}\" > Authcrypt \"${to} DID info\" for \"${From}\"`);
    let didInfoJson = JSON.stringify({
        'did': toDid,
        'verkey': toKey
    });
    let authcryptedDidInfo = await indy.cryptoAuthCrypt(toWallet, toFromKey, fromToKey, Buffer.from(didInfoJson, 'utf8'));

    console.log(`\"${to}\" > Send authcrypted \"${to} DID info\" to ${From}`);

    console.log(`\"${From}\" > Authdecrypted \"${to} DID info\" from ${to}`);
    let [senderVerkey, authdecryptedDidInfo] =
        await indy.cryptoAuthDecrypt(fromWallet, fromToKey, Buffer.from(authcryptedDidInfo));

    let authdecryptedDidInfoJson = JSON.parse(Buffer.from(authdecryptedDidInfo));
    console.log(`\"${From}\" > Authenticate ${to} by comparision of Verkeys`);
    let retrievedVerkey = await indy.keyForDid(poolHandle, fromWallet, toFromDid);
    if (senderVerkey !== retrievedVerkey) {
        throw Error("Verkey is not the same");
    }

    console.log(`\"${From}\" > Send Nym to Ledger for \"${to} DID\" with ${role} Role`);
    await sendNym(poolHandle, fromWallet, fromDid, authdecryptedDidInfoJson['did'], authdecryptedDidInfoJson['verkey'], role);

    return toDid;
}

async function sendNym(poolHandle, walletHandle, Did, newDid, newKey, role) {
    let nymRequest = await indy.buildNymRequest(Did, newDid, newKey, null, role);
    await indy.signAndSubmitRequest(poolHandle, walletHandle, Did, nymRequest);
}

async function sendSchema(poolHandle, walletHandle, Did, schema) {
    // schema = JSON.stringify(schema); // FIXME: Check JSON parsing
    let schemaRequest = await indy.buildSchemaRequest(Did, schema);
    await indy.signAndSubmitRequest(poolHandle, walletHandle, Did, schemaRequest)
}

async function sendCredDef(poolHandle, walletHandle, did, credDef) {
    let credDefRequest = await indy.buildCredDefRequest(did, credDef);
    await indy.signAndSubmitRequest(poolHandle, walletHandle, did, credDefRequest);
}

async function getSchema(poolHandle, did, schemaId) {
    let getSchemaRequest = await indy.buildGetSchemaRequest(did, schemaId);
    let getSchemaResponse = await indy.submitRequest(poolHandle, getSchemaRequest);
    return await indy.parseGetSchemaResponse(getSchemaResponse);
}

async function getCredDef(poolHandle, did, schemaId) {
    let getCredDefRequest = await indy.buildGetCredDefRequest(did, schemaId);
    let getCredDefResponse = await indy.submitRequest(poolHandle, getCredDefRequest);
    return await indy.parseGetCredDefResponse(getCredDefResponse);
}

async function proverGetEntitiesFromLedger(poolHandle, did, identifiers, actor) {
    let schemas = {};
    let credDefs = {};
    let revStates = {};

    for(let referent of Object.keys(identifiers)) {
        let item = identifiers[referent];
        console.log(`\"${actor}\" -> Get Schema from Ledger`);
        let [receivedSchemaId, receivedSchema] = await getSchema(poolHandle, did, item['schema_id']);
        schemas[receivedSchemaId] = receivedSchema;

        console.log(`\"${actor}\" -> Get Claim Definition from Ledger`);
        let [receivedCredDefId, receivedCredDef] = await getCredDef(poolHandle, did, item['cred_def_id']);
        credDefs[receivedCredDefId] = receivedCredDef;

        if (item.rev_reg_seq_no) {
            // TODO Create Revocation States
        }
    }

    return [schemas, credDefs, revStates];
}


async function verifierGetEntitiesFromLedger(poolHandle, did, identifiers, actor) {
    let schemas = {};
    let credDefs = {};
    let revRegDefs = {};
    let revRegs = {};

    for(let referent of Object.keys(identifiers)) {
        let item = identifiers[referent];
        console.log(`"${actor}" -> Get Schema from Ledger`);
        let [receivedSchemaId, receivedSchema] = await getSchema(poolHandle, did, item['schema_id']);
        schemas[receivedSchemaId] = receivedSchema;

        console.log(`"${actor}" -> Get Claim Definition from Ledger`);
        let [receivedCredDefId, receivedCredDef] = await getCredDef(poolHandle, did, item['cred_def_id']);
        credDefs[receivedCredDefId] = receivedCredDef;

        if (item.rev_reg_seq_no) {
            // TODO Get Revocation Definitions and Revocation Registries
        }
    }

    return [schemas, credDefs, revRegDefs, revRegs];
}

async function authDecrypt(walletHandle, key, message) {
    let [fromVerkey, decryptedMessageJsonBuffer] = await indy.cryptoAuthDecrypt(walletHandle, key, message);
    let decryptedMessage = JSON.parse(decryptedMessageJsonBuffer);
    let decryptedMessageJson = JSON.stringify(decryptedMessage);
    return [fromVerkey, decryptedMessageJson, decryptedMessage];
}

if (require.main.filename == __filename) {
    run()
}

module.exports = {
    run
}