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
    // Steward WALLET 생성

    let stewardWallet = await indy.openWallet(stewardWalletConfig, stewardWalletCredentials);

    console.log("\"Sovrin Steward\" -> Create and store in Wallet DID from seed");
    let stewardDidInfo = {
        'seed': '000000000000000000000000Steward1'
    };
    // Steward DID 생성
    let [stewardDid,] = await indy.createAndStoreMyDid(stewardWallet, stewardDidInfo);

    console.log("==============================");
    console.log("== Getting Trust Anchor credentials - CA Onboarding  ==");
    console.log("------------------------------");

    let CAWalletConfig = {'id': 'CAWallet'}
    let CAWalletCredentials = {'key': 'CA_key'}
    let [CAWallet, stewardCAKey, CAStewardDid, CAStewardKey] = await onboarding(poolHandle, "Sovrin Steward", stewardWallet, stewardDid, "CA", null, CAWalletConfig, CAWalletCredentials);
    //CA WALLET 생성

    console.log("==============================");
    console.log("== Getting Trust Anchor credentials - CA getting Verinym  ==");
    console.log("------------------------------");

    let CADid = await getVerinym(poolHandle, "Sovrin Steward", stewardWallet, stewardDid,
        stewardCAKey, "CA", CAWallet, CAStewardDid,
        CAStewardKey, 'TRUST_ANCHOR');

    return; 
