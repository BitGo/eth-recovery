const _ = require('lodash');
const sjcl = require('./sjcl.min');
let ethAbi = function() {};
let ethUtil = function() {};
const bitcoin = require('bitgo-bitcoinjs-lib');

try {
  ethAbi = require('ethereumjs-abi');
  ethUtil = require('ethereumjs-util');
} catch (e) {
  // ethereum currently not supported
}
function ethSignMsgHash(msgHash, privKey) {
  const signatureInParts = ethUtil.ecsign(new Buffer(ethUtil.stripHexPrefix(msgHash), 'hex'), new Buffer(privKey, 'hex'));

  // Assemble strings from r, s and v
  const r = ethUtil.setLengthLeft(signatureInParts.r, 32).toString('hex');
  const s = ethUtil.setLengthLeft(signatureInParts.s, 32).toString('hex');
  const v = ethUtil.stripHexPrefix(ethUtil.intToHex(signatureInParts.v));

  // Concatenate the r, s and v parts to make the signature string
  return ethUtil.addHexPrefix(r.concat(s, v));
};

/**
 * Evaluates whether an address string is valid for this coin
 * @param address
 */
function isValidAddress(address) {
  return ethUtil.isValidAddress(ethUtil.addHexPrefix(address));
};

/**
 * Get transfer operation for coin
 * @param recipient recipient info
 * @param expireTime expiry time
 * @param contractSequenceId sequence id
 * @returns {Array} operation array
 */
function getOperation(recipient, expireTime, contractSequenceId) {
  return [
    ['address', 'uint', 'string', 'uint', 'uint'],
    [
      new ethUtil.BN(ethUtil.stripHexPrefix(recipient.address), 16),
      recipient.amount,
      ethUtil.stripHexPrefix(recipient.data) || '',
      expireTime,
      contractSequenceId
    ]
  ];
};

function getOperationSha3ForExecuteAndConfirm(recipients, expireTime, contractSequenceId) {
  if (!recipients || !Array.isArray(recipients)) {
    throw new Error('expecting array of recipients');
  }

  // Right now we only support 1 recipient
  if (recipients.length !== 1) {
    throw new Error('must send to exactly 1 recipient');
  }

  if (!_.isNumber(expireTime)) {
    throw new Error('expireTime must be number of seconds since epoch');
  }

  if (!_.isNumber(contractSequenceId)) {
    throw new Error('contractSequenceId must be number');
  }

  // Check inputs
  recipients.forEach(function(recipient) {
    if (!_.isString(recipient.address) || !ethUtil.isValidAddress(ethUtil.addHexPrefix(recipient.address))) {
      throw new Error('Invalid address: ' + recipient.address);
    }

    if (recipient.data && !_.isString(recipient.data)) {
      throw new Error('Data for recipient ' + recipient.address + ' - should be of type hex string');
    }
  });

  const recipient = recipients[0];
  return ethUtil.bufferToHex(ethAbi.soliditySHA3(...getOperation(recipient, expireTime, contractSequenceId)));
};

/**
 * Assemble keychain and half-sign prebuilt transaction
 * @param params
 * - txPrebuild
 * - prv
 * @returns {{txHex}}
 */
function signTransaction(params) {
  const userPrv = params.prv;
  const EXPIRETIME_DEFAULT = 60 * 60 * 24 * 7; // This signature will be valid for 1 week

  const secondsSinceEpoch = Math.floor((new Date().getTime()) / 1000);
  const expireTime = params.expireTime || secondsSinceEpoch + EXPIRETIME_DEFAULT;

  const operationHash = getOperationSha3ForExecuteAndConfirm(params.recipients, expireTime, params.nextContractSequenceId);
  const signature = ethSignMsgHash(operationHash, xprvToEthPrivateKey(userPrv));

  const txParams = {
    recipients: params.recipients,
    expireTime: expireTime,
    contractSequenceId: params.nextContractSequenceId,
    sequenceId: params.sequenceId,
    operationHash: operationHash,
    signature: signature
  };
  console.dir(txParams);
};

function xprvToEthPrivateKey(xprv) {
  const hdNode = bitcoin.HDNode.fromBase58(xprv);
  const ethPrivateKey = hdNode.keyPair.d.toBuffer();
  return ethUtil.setLengthLeft(ethPrivateKey, 32).toString('hex');
};

// node index.js <nextContractSequenceId> <destinationAddress> <amount> <password> <box B>
if (!process.argv[2] || !process.argv[3] ||
   !process.argv[4] || !process.argv[5]) {
  console.log('Invalid params');
  process.exit();
}
const nextContractSequenceId = parseInt(process.argv[2], 10);
var params = {};
params.recipients = [{
  address: process.argv[3],
  amount: process.argv[4]
}];
params.nextContractSequenceId = nextContractSequenceId;
params.prv = sjcl.decrypt(process.argv[5], process.argv[6]);
signTransaction(params);
