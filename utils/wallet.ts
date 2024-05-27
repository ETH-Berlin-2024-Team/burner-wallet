import { ethers } from 'ethers';
import { ec as EC } from 'elliptic';
import crypto from 'crypto';

const ec = new EC('secp256k1');

export function createBurnerWallet() {
  const wallet = ethers.Wallet.createRandom();
  return wallet;
}

export function getPublicKeyFromPrivateKey(privateKey: string): string {
  const keyPair = ec.keyFromPrivate(privateKey.slice(2), 'hex'); // Remove the '0x' prefix from the private key
  return '0x' + keyPair.getPublic(true, 'hex'); // Get the compressed public key in hex format
}

export function encryptMessage(publicKey: string, message: string) {
  const pubKey = ec.keyFromPublic(publicKey.slice(2), 'hex'); // Remove the '0x' prefix from the public key

  // Generate ephemeral key pair
  const ephemeralKeyPair = ec.genKeyPair();
  const sharedSecret = ephemeralKeyPair.derive(pubKey.getPublic());

  // Use the shared secret to derive a symmetric key
  const sharedSecretHex = sharedSecret.toString(16);
  const symmetricKey = crypto.createHash('sha256').update(sharedSecretHex).digest();

  // Encrypt the message using AES
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
  let encryptedMessage = cipher.update(message, 'utf8', 'hex');
  encryptedMessage += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return JSON.stringify({
    ephemeralPublicKey: ephemeralKeyPair.getPublic(true, 'hex'),
    iv: iv.toString('hex'),
    encryptedMessage,
    authTag,
  });
}

export function decryptMessage(privateKey: string, encryptedData: string) {
  const privKey = ec.keyFromPrivate(privateKey.slice(2), 'hex'); // Remove the '0x' prefix from the private key
  const { ephemeralPublicKey, iv, encryptedMessage, authTag } = JSON.parse(encryptedData);

  // Reconstruct the ephemeral public key
  const ephemeralPubKey = ec.keyFromPublic(ephemeralPublicKey, 'hex');

  // Derive the shared secret
  const sharedSecret = privKey.derive(ephemeralPubKey.getPublic());

  // Use the shared secret to derive a symmetric key
  const sharedSecretHex = sharedSecret.toString(16);
  const symmetricKey = crypto.createHash('sha256').update(sharedSecretHex).digest();

  // Decrypt the message using AES
  const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf8');
  decryptedMessage += decipher.final('utf8');

  return decryptedMessage;
}
