const newXym = require("symbol-sdk");
const { sha3_256 } = require('js-sha3');
const request = require('request');
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

const emTransaction = facade.transactionFactory.createEmbedded({
    type: 'transfer_transaction',
	signerPublicKey: signerPublicKey,
    recipientAddress: 'TAEVDDC5TXMJ5ICMRZ6A52DT6NYCQ7U3MBODEWA',
	message:'test'
});
emTransaction.message = new Uint8Array([0, ...emTransaction.message]);
const emTransaction2 = facade.transactionFactory.createEmbedded({
    type: 'transfer_transaction',
    signerPublicKey: signerPublicKey,
    recipientAddress: 'TAEVDDC5TXMJ5ICMRZ6A52DT6NYCQ7U3MBODEWA',
    message: 'test'
});
emTransaction2.message = new Uint8Array([0, ...emTransaction2.message]);
const aggregateComplete = facade.transactionFactory.create({
	type: 'aggregate_complete_transaction',
	signerPublicKey: signerPublicKey,
	deadline: deadline,
	transactions: [emTransaction,emTransaction2]
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
