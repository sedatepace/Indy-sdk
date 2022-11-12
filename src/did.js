const express = require('express');
const cookieParser = require('cookie-parser')
const path = require('path');
// const session = require('express-session');
const flash = require('connect-flash');
const cors = require('cors');

const app = express();


///////////////////////////

var exec = require("child_process").exec;

const indy = require('indy-sdk');
const util = require('./util');
const assert = require('assert');


const log = console.log

function assertEquals(expected, value) {
    if (expected != value) {
        log("Assertion error ! Expected : '" + expected + "' / Current value : '" + value + "'")
        return false;
    }
    return true;
}



///////////////////////////


app.use(cors());
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.set('port', process.env.PORT || 8001);

app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(flash());


app.use('/:id/:verkey', async (req, res)=>{
    console.log("ok");
        await del();

    let out = await run2(req.params.id, req.params.verkey);
    // let out = {verkey:true};
    console.log(out);
    res.send(out);

})

async function del(){
    await exec("rm -rf /home/netcc/.indy_client/", function (err, stdout, stderr) {

        console.log(stdout);
        console.log(stderr);
        console.log(err);
    });
}


app.use((req, res, next)=>{
    const err = new Error('Not Found');
    err.status = 404;
    next(err);
});

app.listen(app.get('port'), ()=>{
    console.log(app.get('port'), '번 포트에서 대기 중');

});


    async function run (name){
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
        console.log("=== Getting Trust Anchor credentials for Faber, Acme, Thrift and Government  ==");
        console.log("------------------------------");
    
        console.log("\"Sovrin Steward\" -> Create wallet");
        let stewardWalletConfig = {'id': name}  //이름 
        // let stewardWalletConfig = {'id': name }  이름 
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
        console.log("== Getting Trust Anchor credentials - Government Onboarding  ==");
        console.log("------------------------------");
    
        let governmentWalletConfig = {'id': 'governmentWallet'}
        let governmentWalletCredentials = {'key': 'government_key'}
        let [governmentWallet, stewardGovernmentKey, governmentStewardDid, governmentStewardKey] = await onboarding(poolHandle, "Sovrin Steward", stewardWallet, stewardDid, "Government", null, governmentWalletConfig, governmentWalletCredentials);
    
        console.log("==============================");
        console.log("== Getting Trust Anchor credentials - Government getting Verinym  ==");
        console.log("------------------------------");
    
        let governmentDid = await getVerinym(poolHandle, "Sovrin Steward", stewardWallet, stewardDid,
            stewardGovernmentKey, "Government", governmentWallet, governmentStewardDid,
            governmentStewardKey, 'TRUST_ANCHOR');
    
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
    
        console.log("==============================");
        console.log("== Getting Trust Anchor credentials - Acme Onboarding  ==");
        console.log("------------------------------");
    
        let acmeWalletConfig = {'id': 'acmeWallet'}
        let acmeWalletCredentials = {'key': 'acme_key'}
        let [acmeWallet, stewardAcmeKey, acmeStewardDid, acmeStewardKey] = await onboarding(poolHandle, "Sovrin Steward", stewardWallet, stewardDid, "Acme", null, acmeWalletConfig, acmeWalletCredentials);
    
        console.log("==============================");
        console.log("== Getting Trust Anchor credentials - Acme getting Verinym  ==");
        console.log("------------------------------");
    
        let acmeDid = await getVerinym(poolHandle, "Sovrin Steward", stewardWallet, stewardDid, stewardAcmeKey,
            "Acme", acmeWallet, acmeStewardDid, acmeStewardKey, 'TRUST_ANCHOR');
    
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
    
    
    }
    

    
async function run2(web_id, verkey) {

    log("anoncredsRevocation.js -> started")

    log("Anoncreds Revocation sample -> started")

    const issuerDid = 'NcYxiDXkpYi6ov5FcYDi1e'
    const proverDid = 'VsKV7grR1BUE29mG2Fm2kX'

    // Set protocol version 2 to work with Indy Node 1.4
    await indy.setProtocolVersion(2)
0
    // 1. Create Issuer Wallet and Get Wallet Handle
    const issuerWalletConfig = {"id": "issuer_wallet"}
    const issuerWalletCredentials = {"key": "issuer_wallet_key"}
    await indy.createWallet(issuerWalletConfig, issuerWalletCredentials)
    const issuerWallet = await indy.openWallet(issuerWalletConfig, issuerWalletCredentials)
    log({issuerWallet})

    // 2. Create Prover Wallet and Get Wallet Handle
    const proverWalletConfig = {"id": "prover_wallet"}
    const proverWalletCredentials = {"key": "issuer_wallet_key"}
    await indy.createWallet(proverWalletConfig, proverWalletCredentials)
    const proverWallet = await indy.openWallet(proverWalletConfig, proverWalletCredentials)
    log({proverWallet})

    // 3. Issuer create Credential Schema
    const schemaName = 'gvt'
    const schemaVersion = '1.0'
    const schemaAttributes = '["age", "sex", "height", "name","verkey","id"]'
    const [schemaId, schema] = await indy.issuerCreateSchema(issuerDid, schemaName, schemaVersion, schemaAttributes)
    log({schemaId})
    log({schema})

    
    const credDefTag = 'cred_def_tag'
    const credDefType = 'CL'
    const credDefConfig = {"support_revocation": true}
    const [credDefId, credDef] = await indy.issuerCreateAndStoreCredentialDef(issuerWallet, issuerDid,
                                                                    schema, credDefTag, credDefType, credDefConfig)
    log({credDefId})
    log({credDef})

    // 5. Issuer create Revocation Registry
    const tailsWriterConfig = {'base_dir': util.getPathToIndyClientHome() + "/tails", 'uri_pattern': ''}
    const tailsWriter = await indy.openBlobStorageWriter('default', tailsWriterConfig)
    const rvocRegDefTag = 'cred_def_tag'
    const rvocRegDefConfig = {"max_cred_num": 5, 'issuance_type': 'ISSUANCE_ON_DEMAND'}
    const [revRegId, revRegDef, _] = await indy.issuerCreateAndStoreRevocReg(issuerWallet, issuerDid,
                                                undefined, rvocRegDefTag, credDefId, rvocRegDefConfig, tailsWriter)
    log({revRegId})
    log({revRegDef})

    // 6. Prover create Master Secret
    const masterSecretId = await indy.proverCreateMasterSecret(proverWallet, undefined)
    log({masterSecretId})

    //  7. Issuer create Credential Offer
    const credOffer = await indy.issuerCreateCredentialOffer(issuerWallet, credDefId)
    log({credOffer})

    // 8. Prover create Credential Request
    const [credReq, credReqMetadata] = await indy.proverCreateCredentialReq(proverWallet, proverDid,
                                                                credOffer, credDef, masterSecretId)
    log({credReq})

    // 9. Issuer open Tails reader
    const blobStorageReaderHandle = await indy.openBlobStorageReader('default', tailsWriterConfig)
    log({blobStorageReaderHandle})

    // 10. Issuer create Credential
    const credValues = {
        "sex": {"raw": "male", "encoded": "5944657099558967239210949258394887428692050081607692519917050"},
        "name": {"raw": "Alex", "encoded": "1139481716457488690172217916278103335"},
        "verkey": {"raw": "2413fb3709b05939f04cf2e92f7d0897fc2596f9ad0b8a9ea855c7bfebaae892", "encoded": "1139481716457488690172217916278103335"},
        "id": {"raw": "ssp", "encoded": "1232455"},
        "height": {"raw": "175", "encoded": "175"},
        "age": {"raw": "28", "encoded": "28"}
       
    }

    const [cred, revId, revRegDelta] = await indy.issuerCreateCredential(issuerWallet, credOffer, credReq,
                                                                credValues, revRegId, blobStorageReaderHandle)

    // 11. Prover store Credential
    await indy.proverStoreCredential(proverWallet, undefined, credReqMetadata, cred, credDef, revRegDef)

    // 11. Prover gets Credentials for Proof Request
    const nonce = await indy.generateNonce()
    const proofReq = {
        'nonce': nonce,
        'name': 'proof_req_1',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {'name': 'name'},
            'attr2_referent': {'name': 'verkey'},
            'attr3_referent': {'name': 'id'}
        },
        'requested_predicates': {
            'predicate1_referent': {'name': 'age', 'p_type': '>=', 'p_value': 18},
        },
        "non_revoked": {"from": 80, "to": 100}
    }

    const search_handle = await indy.proverSearchCredentialsForProofReq(proverWallet, proofReq, undefined)

    // Prover gets Credentials for attr1_referent
    const credentialsForAttr1 = await indy.proverFetchCredentialsForProofReq(search_handle, 'attr1_referent', 10)
    log({credentialsForAttr1})
    const credForAttribute = credentialsForAttr1[0]['cred_info']

    const credentialsForAttr2 = await indy.proverFetchCredentialsForProofReq(search_handle, 'attr2_referent', 10)
    log({credentialsForAttr2})
    const credForAttribute2 = credentialsForAttr2[0]['cred_info']

    const credentialsForAttr3 = await indy.proverFetchCredentialsForProofReq(search_handle, 'attr2_referent', 10)
    log({credentialsForAttr3})
    const credForAttribute3 = credentialsForAttr2[0]['cred_info']

    // Prover gets Credentials for predicate1_referent
    const credentialsForPredicate1 = await indy.proverFetchCredentialsForProofReq(search_handle, 'predicate1_referent', 10)
    log({credentialsForPredicate1})
    const credForPredicate = credentialsForPredicate1[0]['cred_info']

    await indy.proverCloseCredentialsSearchForProofReq(search_handle)

    // 12. Prover creates revocation state
    const timestamp = 100
    const revState = await indy.createRevocationState(blobStorageReaderHandle, revRegDef, revRegDelta, timestamp, revId)
    log({revState})

    // 13. Prover create Proof for Proof Request
    const requestedCredentials = {
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {
                'cred_id': credForAttribute['referent'], 'revealed': true, 'timestamp': timestamp
            },
            'attr2_referent': {
                'cred_id': credForAttribute2['referent'], 'revealed': true, 'timestamp': timestamp
            },
            'attr3_referent': {
                'cred_id': credForAttribute3['referent'], 'revealed': true, 'timestamp': timestamp
            },
        },
        'requested_predicates': {
            'predicate1_referent': {'cred_id': credForPredicate['referent'], 'timestamp': timestamp},
            // 'predicate2_referent': {'cred_id': credForPredicate['referent'], 'timestamp': timestamp}

        }
    }

    const schemas = {}
    schemas[schemaId] = schema
    const credDefs = {}
    credDefs[credDefId] = credDef
    const revocStates = {}
    revocStates[revRegId] = {}
    revocStates[revRegId][timestamp] = revState

    const proof = await indy.proverCreateProof(proverWallet, proofReq, requestedCredentials, masterSecretId,
                                                    schemas, credDefs, revocStates)
    log({proof})

    let name = assertEquals('Alex', proof['requested_proof']['revealed_attrs']['attr1_referent']['raw'])
    let verkey1 = assertEquals(verkey, proof['requested_proof']['revealed_attrs']['attr2_referent']['raw'])
    let id  = assertEquals(web_id, proof['requested_proof']['revealed_attrs']['attr3_referent']['raw'])

    // 12. Verifier verify proof
    const revocRefDefs = {}
    revocRefDefs[revRegId] = revRegDef
    const revocRegs = {}
    revocRegs[revRegId] = {}
    revocRegs[revRegId][timestamp] = revRegDelta

    const verified = await indy.verifierVerifyProof(proofReq, proof, schemas, credDefs, revocRefDefs, revocRegs)
    log({verified})
    log({name,verkey1,id  })

    // 13. Close and delete Issuer wallet
    await indy.closeWallet(issuerWallet)
    await indy.deleteWallet(issuerWalletConfig, issuerWalletCredentials)

    // 14. Close and delete Prover wallet
    await indy.closeWallet(proverWallet)
    await indy.deleteWallet(proverWalletConfig, proverWalletCredentials)

    log("Anoncreds Revocation sample -> completed")
    let result = {
        verkey:verkey1 ,id
    }
    return {name, verkey:verkey1, id};
}
    
    /**
     * 블록체인 함수 
     */

    
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
