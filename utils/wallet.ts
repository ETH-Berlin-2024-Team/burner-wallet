import { ethers } from 'ethers';
import { ec as EC } from 'elliptic';

const ec = new EC('secp256k1');

export function createBurnerWallet() {
  const wallet = ethers.Wallet.createRandom();
  return wallet;
}

export function encryptMessage(publicKey: string, message: string) {
  const pubKey = ec.keyFromPublic(publicKey.slice(2), 'hex'); // Remove the '0x' prefix from the public key
  const msg = Buffer.from(message, 'utf8');
  const encrypted = pubKey.encrypt(msg);
  return JSON.stringify(encrypted);
}

export function decryptMessage(privateKey: string, encryptedMessage: string) {
  const privKey = ec.keyFromPrivate(privateKey.slice(2), 'hex'); // Remove the '0x' prefix from the private key
  const encrypted = JSON.parse(encryptedMessage);
  const decrypted = privKey.decrypt(encrypted);
  return Buffer.from(decrypted).toString('utf8');
}
