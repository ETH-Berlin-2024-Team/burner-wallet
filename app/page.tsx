"use client";

import React, { useState } from 'react';
import { ethers } from 'ethers';
import { createBurnerWallet, encryptMessage, decryptMessage } from '../utils/wallet';

const Home: React.FC = () => {
  const [wallet, setWallet] = useState<ethers.Wallet | null>(null);
  const [message, setMessage] = useState('');
  const [encryptedMessage, setEncryptedMessage] = useState('');
  const [decryptedMessage, setDecryptedMessage] = useState('');

  const handleCreateWallet = () => {
    const newWallet = createBurnerWallet();
    setWallet(newWallet);
  };

  const handleEncryptMessage = () => {
    if (wallet && message) {
      const publicKey = wallet.publicKey;
      const encrypted = encryptMessage(publicKey, message);
      setEncryptedMessage(encrypted);
    }
  };

  const handleDecryptMessage = () => {
    if (wallet && encryptedMessage) {
      const decrypted = decryptMessage(wallet.privateKey, encryptedMessage);
      setDecryptedMessage(decrypted);
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <h1>Burner Wallet</h1>
      <button onClick={handleCreateWallet}>Create Burner Wallet</button>
      {wallet && (
        <div style={{ marginTop: '20px' }}>
          <h2>Wallet Details</h2>
          <p><strong>Address:</strong> {wallet.address}</p>
          <p><strong>Public Key:</strong> {wallet.publicKey}</p>
          <p><strong>Private Key:</strong> {wallet.privateKey}</p>
          <div style={{ marginTop: '20px' }}>
            <h2>Encrypt Message</h2>
            <input
              type="text"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Enter message"
              style={{ width: '300px' }}
            />
            <button onClick={handleEncryptMessage}>Encrypt</button>
            {encryptedMessage && (
              <div>
                <p><strong>Encrypted Message:</strong> {encryptedMessage}</p>
              </div>
            )}
          </div>
          <div style={{ marginTop: '20px' }}>
            <h2>Decrypt Message</h2>
            <button onClick={handleDecryptMessage}>Decrypt</button>
            {decryptedMessage && (
              <div>
                <p><strong>Decrypted Message:</strong> {decryptedMessage}</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default Home;
