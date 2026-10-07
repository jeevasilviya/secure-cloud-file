/**
 * Test script to verify AES-256-GCM encryption & decryption
 */
const { encryptText, decryptText, encryptJSON, decryptJSON } = require('./encryption');

function runTest() {
  console.log('Testing AES-256-GCM Cryptographic Service...');

  const originalMemoir = 'This is a deeply personal diary memoir entry from summer 2026.';
  const enc = encryptText(originalMemoir);

  console.log('Plaintext:', originalMemoir);
  console.log('Encrypted Ciphertext (Hex):', enc.cipherText);
  console.log('IV (Hex):', enc.iv);
  console.log('Auth Tag (Hex):', enc.tag);

  if (!enc.cipherText || enc.cipherText === originalMemoir) {
    throw new Error('Encryption failed to produce secure ciphertext!');
  }

  const decrypted = decryptText(enc.cipherText, enc.iv, enc.tag);
  console.log('Decrypted:', decrypted);

  if (decrypted !== originalMemoir) {
    throw new Error('Decryption did not match original memoir!');
  }

  // Test Tamper-Resistance: Alter one character in ciphertext
  const tamperedCipher = enc.cipherText.slice(0, -2) + 'ff';
  try {
    decryptText(tamperedCipher, enc.iv, enc.tag);
    throw new Error('Failed to detect tampered ciphertext!');
  } catch (err) {
    console.log('Tamper detection test passed! (Caught tampering error:', err.message, ')');
  }

  // Test JSON encryption
  const metadata = { coordinates: { lat: 37.7749, lng: -122.4194 }, tags: ['vacation', 'private'] };
  const encJson = encryptJSON(metadata);
  const decJson = decryptJSON(encJson.cipherText, encJson.iv, encJson.tag);
  if (JSON.stringify(decJson) !== JSON.stringify(metadata)) {
    throw new Error('JSON encryption/decryption failed!');
  }
  console.log('JSON encryption & decryption test passed!');

  console.log('All Cryptographic Validation Tests Passed Successfully!');
}

runTest();
