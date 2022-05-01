const newXym = require("symbol-sdk");
const { sha3_256} = require('js-sha3');
const request = require('request');
const crypto = require("crypto");
const converter = require("./node_modules/symbol-sdk/src/utils/converter")
const encoder = require("./encorder")

// const node = "http://154.12.242.37:3000"
const node = "http://2.dusan.gq:3000"

const facade = new newXym.facade.SymbolFacade("testnet");
const key = new newXym.CryptoTypes.PrivateKey("***")
const account = new newXym.facade.SymbolFacade.KeyPair(key)
const signerPublicKey = Buffer.from(account.publicKey.bytes).toString("hex").toUpperCase();

const now = Date.now();
const eadj = 1637848847;
const deadline = BigInt(now - eadj*1000 + 60*60*6*1000 - 60*1000);//deadlineを導出

const feeMultiPlier = 100;

const remoteAccount = accountGenerator();
const vrfAccount = accountGenerator()
const targetNodeKey = "0E5459F1981C1D47EFC0DC62B51275ED24AE37843BB6863537B739556B66773E";
const ephemeralAccount = accountGenerator();

function accountGenerator(){
	const key = new newXym.CryptoTypes.PrivateKey(crypto.randomBytes(32).toString("hex").toUpperCase())
	return new newXym.facade.SymbolFacade.KeyPair(key)
}

const emVrfKeyTransaction = facade.transactionFactory.createEmbedded({
    type: 'vrf_key_link_transaction',
	signerPublicKey: signerPublicKey,
    linkedPublicKey: converter.uint8ToHex(vrfAccount.publicKey.bytes),
	linkAction: 1 //unlink:0 link: 1
});

const emAccountKeyTransaction = facade.transactionFactory.createEmbedded({
    type: 'account_key_link_transaction',
    signerPublicKey: signerPublicKey,
    linkedPublicKey: converter.uint8ToHex(remoteAccount.publicKey.bytes),
    linkAction: 1 //unlink:0 link: 1
});
const emNodeKeyTransaction = facade.transactionFactory.createEmbedded({
    type: 'node_key_link_transaction',
    signerPublicKey: signerPublicKey,
    linkedPublicKey: targetNodeKey,
    linkAction: 1 //unlink:0 link: 1
});

const delegatePersistentMessage = "FE2A8061577301E2" + //委任メッセージ作成("FE2A8061577301E2"
		 converter.uint8ToHex(ephemeralAccount.publicKey.bytes) + //+ ワンタイム公開鍵 
		 encoder.encode(converter.uint8ToHex(ephemeralAccount.privateKey.bytes), targetNodeKey, converter.uint8ToHex(remoteAccount.privateKey.bytes) + converter.uint8ToHex(vrfAccount.privateKey.bytes), true).toUpperCase(); //EncryptedMessage(ワンタイム秘密鍵,targetNode)
 const emPersistentTransaction = facade.transactionFactory.createEmbedded({
    type: 'transfer_transaction',
    signerPublicKey: signerPublicKey,
    recipientAddress: "TCUZ3TAEMUX63IQXDV74UI5HHOB3HJBLUGVNFVA",
});
emPersistentTransaction.message = converter.hexToUint8(delegatePersistentMessage);
const aggregateComplete = facade.transactionFactory.create({
	type: 'aggregate_complete_transaction',
	signerPublicKey: signerPublicKey,
	deadline: deadline,
	transactions: [
		emVrfKeyTransaction, 
		emAccountKeyTransaction, 
		emNodeKeyTransaction, 
		emPersistentTransaction
	]
});

aggregateComplete.fee.value = BigInt(aggregateComplete.size * feeMultiPlier); //SetMaxFeeの役割を果たします

console.log(aggregateComplete)
const signature = facade.signTransaction(new newXym.facade.SymbolFacade.KeyPair(key), aggregateComplete);
const jsonPayload = facade.transactionFactory.constructor.attachSignature(aggregateComplete, signature);
console.log(jsonPayload);
anounceTX(JSON.parse(jsonPayload).payload);

const payload = stringToUint8Array(JSON.parse(jsonPayload).payload);
const sig = payload.slice(8,8+64);
const pub = payload.slice(8+64,8+64+32)
const gene = stringToUint8Array("7FCCD304802016BEBBCD342A332F91FF1F3BB5E902988B352697BE245F48E836");
const tx = payload.slice(8 + 64 + 32 + 4);
const hasher = sha3_256.create();
hasher.update(sig);
hasher.update(pub);
hasher.update(gene);
hasher.update(tx);
const hash = new Uint8Array(hasher.arrayBuffer())
console.log(node +"/transactionStatus/"+uint8ToString(hash))

function stringToUint8Array(str){
  const buf = Buffer.from(str,"hex");
  return bufferToUint8Array(buf);
}
function bufferToUint8Array(buf) {
  const view = new Uint8Array(buf.length);
  for (let i = 0; i < buf.length; ++i) {
      view[i] = buf[i];
  }
  return view;
}

function uint8ToString(uint8arr){
  return Buffer.from(uint8arr).toString("hex").toUpperCase();
}

function anounceTX(signed){
  console.log(node+"/transactions")
  var options = {
    uri: node+"/transactions",
  headers: {
    "Content-type": "application/json",
  },
  json: {
    "payload": signed
  }
  };
  request.put(options, function(error, response, body){
    console.log(body);
  });

}
