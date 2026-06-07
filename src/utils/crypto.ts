import CryptoJS from 'crypto-js';

// In a real scenario, this key should be securely exchanged (e.g., via RSA/Diffie-Hellman)
// For this enterprise iteration, we use a pre-shared key for the payload wrapper.
const E2EE_SHARED_KEY = import.meta.env.VITE_E2EE_KEY || 'SECURAI_ENTERPRISE_E2EE_V1_SECRET_KEY';

export const encryptPayload = (data: unknown): string => {
  const jsonStr = JSON.stringify(data);
  return CryptoJS.AES.encrypt(jsonStr, E2EE_SHARED_KEY).toString();
};

export const decryptPayload = <T = unknown>(ciphertext: string): T | null => {
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, E2EE_SHARED_KEY);
    const decryptedStr = bytes.toString(CryptoJS.enc.Utf8);
    return JSON.parse(decryptedStr) as T;
  } catch (error) {
    console.error('E2EE Decryption Failed:', error);
    return null;
  }
};
