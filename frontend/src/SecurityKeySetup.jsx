import React, { useState } from 'react';
import { set, get } from 'idb-keyval';

const SecurityKeySetup = () => {
  const [message, setMessage] = useState('');
  const [userId, setUserId] = useState('phdang');
  const [decryptedData, setDecryptedData] = useState('');

  const base64ToArrayBuffer = (base64) => {
    try {
      if (typeof base64 !== 'string') throw new Error('Input must be a string');
      let base64Padded = base64.replace(/-/g, '+').replace(/_/g, '/');
      const paddingNeeded = (4 - (base64Padded.length % 4)) % 4;
      base64Padded += '='.repeat(paddingNeeded);
      const binary = window.atob(base64Padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    } catch (error) {
      console.error('Base64 Decode Error:', error);
      throw error;
    }
  };

  const arrayBufferToBase64 = (buffer) => {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return window.btoa(binary);
  };

  const arrayBufferToBase64url = (buffer) => {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return window.btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  };

  const exportPublicKeyAsPem = async (publicKey) => {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    const base64 = arrayBufferToBase64(exported);
    return `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
  };

  const generateKeyPair = async () => {
    return await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );
  };

  const decryptData = async (encryptedDataObj, privateKey, uId) => {
    const { encryptedData, encryptedAesKey, iv, authTag, masterIv, encryptedMasterKeys } = encryptedDataObj;
    const encryptedMasterKey = encryptedMasterKeys[uId];

    const masterKey = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      base64ToArrayBuffer(encryptedMasterKey)
    );

    const importedMasterKey = await window.crypto.subtle.importKey(
      'raw',
      masterKey,
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );

    const aesKey = await window.crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: base64ToArrayBuffer(masterIv) },
      importedMasterKey,
      base64ToArrayBuffer(encryptedAesKey)
    );

    const importedAesKey = await window.crypto.subtle.importKey(
      'raw',
      aesKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToArrayBuffer(iv),
        tagLength: 128,
      },
      importedAesKey,
      new Uint8Array([...new Uint8Array(base64ToArrayBuffer(encryptedData)), ...new Uint8Array(base64ToArrayBuffer(authTag))])
    );

    return new TextDecoder().decode(decrypted);
  };

  const handleRegister = async () => {
    setMessage('Generating key pair...');
    try {
      const { publicKey, privateKey } = await generateKeyPair();
      const publicKeyPem = await exportPublicKeyAsPem(publicKey);

      setMessage('Fetching registration options...');
      const response = await fetch(`http://localhost:3000/register-options?userId=${userId}`);
      if (!response.ok) throw new Error(await response.text());
      const options = await response.json();

      options.challenge = base64ToArrayBuffer(options.challenge);
      options.user.id = base64ToArrayBuffer(options.user.id);

      setMessage('Please authenticate...');
      const credential = await navigator.credentials.create({ publicKey: options });

      const publicKeyCredential = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        response: {
          attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
          clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
        },
        type: credential.type,
        userId,
        publicKey: publicKeyPem,
      };

      await set(`privateKey_${userId}`, await window.crypto.subtle.exportKey('pkcs8', privateKey));
      await set(`credentialId_${userId}`, credential.id);

      setMessage('Registering with server...');
      const verification = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(publicKeyCredential),
      });
      if (!verification.ok) throw new Error(await verification.text());
      const result = await verification.json();

      if (result.success) {
        setMessage('Registration successful!');
      } else {
        setMessage('Registration failed');
      }
    } catch (error) {
      console.error('Registration Error:', error);
      setMessage(`Error: ${error.message}`);
    }
  };

  const handleAuthenticate = async () => {
    setMessage('Fetching authentication options...');
    setDecryptedData('');
    try {
      const response = await fetch(`http://localhost:3000/auth-options?userId=${userId}`);
      if (!response.ok) throw new Error(await response.text());
      const options = await response.json();

      options.challenge = base64ToArrayBuffer(options.challenge);
      options.allowCredentials = options.allowCredentials.map(cred => ({
        ...cred,
        id: base64ToArrayBuffer(cred.id),
      }));

      setMessage('Please authenticate...');
      const credential = await navigator.credentials.get({ publicKey: options });

      const authCredential = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        response: {
          authenticatorData: arrayBufferToBase64url(credential.response.authenticatorData),
          clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
          signature: arrayBufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? arrayBufferToBase64url(credential.response.userHandle) : null,
        },
        type: credential.type,
        userId,
      };

      setMessage('Verifying authentication...');
      const verification = await fetch('http://localhost:3000/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(authCredential),
      });
      if (!verification.ok) throw new Error(await verification.text());
      const result = await verification.json();

      if (result.success) {
        const privateKeyRaw = await get(`privateKey_${userId}`);
        if (!privateKeyRaw) throw new Error('Private key not found. Please register first.');
        const privateKey = await window.crypto.subtle.importKey(
          'pkcs8',
          privateKeyRaw,
          { name: 'RSA-OAEP', hash: 'SHA-256' },
          false,
          ['decrypt']
        );
        const decrypted = await decryptData(result.encryptedData, privateKey, userId);
        setMessage('Authentication successful!');
        setDecryptedData(decrypted);
        console.log('Decrypted Data:', JSON.parse(decrypted));
      } else {
        setMessage('Authentication failed');
      }
    } catch (error) {
      console.error('Authentication Error:', error);
      setMessage(`Error: ${error.message}`);
    }
  };

  const handleAddUser = async (newUserId) => {
    setMessage(`Adding access for ${newUserId}...`);
    try {
      // Generate a new key pair for the new user
      const { publicKey, privateKey } = await generateKeyPair();
      const newPublicKeyPem = await exportPublicKeyAsPem(publicKey);
      console.log('Generated Public Key for', newUserId, ':', newPublicKeyPem);

      // Fetch registration options for the new user
      setMessage(`Fetching registration options for ${newUserId}...`);
      const response = await fetch(`http://localhost:3000/register-options?userId=${newUserId}`);
      if (!response.ok) throw new Error(await response.text());
      const options = await response.json();

      options.challenge = base64ToArrayBuffer(options.challenge);
      options.user.id = base64ToArrayBuffer(options.user.id);

      // Prompt WebAuthn registration (biometric/password)
      setMessage(`Please authenticate for ${newUserId}...`);
      const credential = await navigator.credentials.create({ publicKey: options });

      const publicKeyCredential = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        response: {
          attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
          clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
        },
        type: credential.type,
        userId: newUserId,
        publicKey: newPublicKeyPem,
      };

      // Store the new user's private key and credential ID
      await set(`privateKey_${newUserId}`, await window.crypto.subtle.exportKey('pkcs8', privateKey));
      await set(`credentialId_${newUserId}`, credential.id);

      // Register the new user with WebAuthn
      setMessage(`Registering ${newUserId} with server...`);
      const verification = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(publicKeyCredential),
      });
      if (!verification.ok) throw new Error(await verification.text());
      const registerResult = await verification.json();

      if (!registerResult.success) {
        throw new Error('Failed to register new user');
      }

      // Add access for the new user
      setMessage(`Adding access for ${newUserId} to encrypted data...`);
      const addAccessResponse = await fetch('http://localhost:3000/add-user-access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newUserId, newPublicKey: newPublicKeyPem }),
      });
      if (!addAccessResponse.ok) throw new Error(await addAccessResponse.text());
      const addAccessResult = await addAccessResponse.json();

      if (addAccessResult.success) {
        setMessage(`Successfully added access for ${newUserId}!`);
        const privateKeyRaw = await get(`privateKey_${newUserId}`);
        if (!privateKeyRaw) throw new Error('Private key not found. Please register first.');
        const privateKey = await window.crypto.subtle.importKey(
          'pkcs8',
          privateKeyRaw,
          { name: 'RSA-OAEP', hash: 'SHA-256' },
          false,
          ['decrypt']
        );
        const decrypted = await decryptData(addAccessResult.encryptedData, privateKey, newUserId);
        setMessage('Authentication successful!');
        setDecryptedData(decrypted);
        setUserId(newUserId);
        console.log('Decrypted Data:', JSON.parse(decrypted));
      } else {
        setMessage('Failed to add user access');
      }
    } catch (error) {
      console.error('Add User Error:', error);
      setMessage(`Error: ${error.message}`);
    }
  };

  return (
    <div>
      <h2>Secure Data Setup</h2>
      <button onClick={handleRegister}>Register</button>
      <button onClick={handleAuthenticate}>Authenticate</button>
      <button onClick={() => handleAddUser('userB')}>
        Add User B
      </button>
      <p>{message}</p>
      {decryptedData && <p>Decrypted Data: {decryptedData}</p>}
    </div>
  );
};

export default SecurityKeySetup;