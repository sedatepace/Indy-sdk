const indy = require('indy-sdk')
const util = require('./util')

const log = console.log

function assertEquals(expected, value) {
    if (expected != value) {
        log("Assertion error ! Expected : '" + expected + "' / Current value : '" + value + "'")
        return false;
    }
    return true;
}

async function run() {

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
        "verkey": {"raw": "467bbfd0b5d5e518a43eaa874abdfff4563a70a30c3638b71fe53abe8d29087b", "encoded": "1139481716457488690172217916278103335"},
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
    let verkey1 = assertEquals('467bbfd0b5d5e518a43eaa874abdfff4563a70a30c3638b71fe53abe8d29087b', proof['requested_proof']['revealed_attrs']['attr2_referent']['raw'])
    let id  = assertEquals('ssp1', proof['requested_proof']['revealed_attrs']['attr3_referent']['raw'])

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
}

if (require.main.filename == __filename) {
    run()
}

module.exports = {
    run
}
