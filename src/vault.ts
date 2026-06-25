/**
 * Encrypted vault for env-secure.
 * Uses AES-256-GCM to encrypt/decrypt secrets with a user-provided passphrase.
 *
 * Vault format:
 *   {
 *     version: 1,
 *     created: ISO timestamp,
 *     salt: base64 (32 bytes),
 *     entries: Array<{ key: string, value: encrypted-base64, iv: base64, tag: base64 }>
 *   }
 */

import { randomBytes, createCipheriv, createDecipheriv, createHash, scryptSync } from 'crypto';
import { writeFileSync, readFileSync, existsSync, unlinkSync } from 'fs';
import { join } from 'path';
import chalk from 'chalk';
import { ScanResult } from './scanner.js';
import { printVaultCreated } from './logger.js';

const VAULT_VERSION = 1;
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32;
const TAG_LENGTH = 16;

export interface VaultEntry {
  key: string;
  value: string; // base64-encoded encrypted value
  iv: string;    // base64-encoded IV
  tag: string;   // base64-encoded auth tag
}

export interface VaultData {
  version: number;
  created: string;
  salt: string; // base64-encoded salt
  entries: VaultEntry[];
}

/**
 * Derive an encryption key from a passphrase + salt using scrypt.
 */
function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, KEY_LENGTH);
}

/**
 * Encrypt a plaintext value. Returns { encrypted, iv, tag }.
 */
function encrypt(plaintext: string, key: Buffer): { encrypted: string; iv: string; tag: string } {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf-8'),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();
  return {
    encrypted: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
  };
}

/**
 * Decrypt a ciphertext value. Returns the plaintext.
 */
function decrypt(encrypted: string, ivBase64: string, tagBase64: string, key: Buffer): string {
  const iv = Buffer.from(ivBase64, 'base64');
  const tag = Buffer.from(tagBase64, 'base64');
  const encryptedBuf = Buffer.from(encrypted, 'base64');

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  return decipher.update(encryptedBuf) + decipher.final('utf-8');
}

/**
 * Prompt for a passphrase (silent input).
 * Falls back to interactive prompt via stdin.
 */
function promptPassphrase(promptText: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(chalk.dim(promptText));
    
    const stdin = process.stdin as NodeJS.ReadStream;
    const isRaw = stdin.isRaw;
    
    if (stdin.setRawMode) {
      stdin.setRawMode(true);
    }
    stdin.resume();

    let input = '';
    const onData = (data: Buffer) => {
      const char = data.toString();
      if (char === '\r' || char === '\n') {
        stdin.removeListener('data', onData);
        stdin.pause();
        if (stdin.setRawMode && isRaw !== undefined) {
          try { stdin.setRawMode(isRaw); } catch {}
        }
        process.stdout.write('\n');
        resolve(input);
      } else if (char === '\x7f' || char === '\b') {
        if (input.length > 0) {
          input = input.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else {
        input += char;
        process.stdout.write('*');
      }
    };

    stdin.on('data', onData);
  });
}

/**
 * Get passphrase from env var, CLI flag, or prompt.
 */
async function getPassphrase(passphrase?: string, confirmPrompt: string = 'Enter vault passphrase: '): Promise<string> {
  // Priority: 1) env var 2) passed param 3) interactive prompt
  const envPassphrase = process.env['ENV_VAULT_PASSPHRASE'];
  if (envPassphrase) return envPassphrase;
  if (passphrase) return passphrase;
  return promptPassphrase(confirmPrompt);
}

/**
 * Get a passphrase with confirmation (for creating a new vault).
 */
async function getPassphraseWithConfirm(passphrase?: string): Promise<string> {
  const envPassphrase = process.env['ENV_VAULT_PASSPHRASE'];
  if (envPassphrase) return envPassphrase;
  if (passphrase) return passphrase;
  
  const p1 = await getPassphrase(undefined, 'Enter new vault passphrase: ');
  const p2 = await getPassphrase(undefined, 'Confirm passphrase: ');
  
  if (p1 !== p2) {
    process.stdout.write(chalk.red('\n  ✖ Passphrases do not match\n'));
    return getPassphraseWithConfirm(passphrase);
  }
  
  if (p1.length < 8) {
    process.stdout.write(chalk.yellow('\n  ⚠ Passphrase should be at least 8 characters\n'));
    return getPassphraseWithConfirm(passphrase);
  }
  
  return p1;
}

/**
 * Create a new encrypted vault from scan results.
 */
export async function createVault(
  results: ScanResult[],
  outputDir: string,
  passphrase?: string
): Promise<string> {
  // Deduplicate entries by env var name
  const envMap = new Map<string, string>();
  for (const r of results) {
    if (r.pattern.envVar) {
      const existing = envMap.get(r.pattern.envVar);
      if (!existing) {
        // Extract the value from the snippet
        const value = extractValueFromSnippet(r.snippet);
        envMap.set(r.pattern.envVar, value);
      }
    }
  }

  const pp = await getPassphraseWithConfirm(passphrase);
  const salt = randomBytes(SALT_LENGTH);
  const key = deriveKey(pp, salt);

  const entries: VaultEntry[] = [];
  for (const [envKey, envValue] of envMap) {
    const enc = encrypt(envValue, key);
    entries.push({
      key: envKey,
      value: enc.encrypted,
      iv: enc.iv,
      tag: enc.tag,
    });
  }

  const vaultData: VaultData = {
    version: VAULT_VERSION,
    created: new Date().toISOString(),
    salt: salt.toString('base64'),
    entries,
  };

  const outputPath = join(outputDir, '.env.vault.enc');
  writeFileSync(outputPath, JSON.stringify(vaultData, null, 2), 'utf-8');

  printVaultCreated(outputPath);
  return outputPath;
}

/**
 * Decrypt a vault file and return the plaintext entries.
 * Returns a Map<envVarName, value>.
 */
export async function decryptVault(
  vaultPath: string,
  passphrase?: string
): Promise<Map<string, string>> {
  if (!existsSync(vaultPath)) {
    throw new Error(`Vault file not found: ${vaultPath}`);
  }

  const vaultData: VaultData = JSON.parse(readFileSync(vaultPath, 'utf-8'));

  if (vaultData.version !== VAULT_VERSION) {
    throw new Error(`Unsupported vault version: ${vaultData.version}`);
  }

  const pp = await getPassphrase(passphrase);
  const salt = Buffer.from(vaultData.salt, 'base64');
  const key = deriveKey(pp, salt);

  const result = new Map<string, string>();
  for (const entry of vaultData.entries) {
    try {
      const plaintext = decrypt(entry.value, entry.iv, entry.tag, key);
      result.set(entry.key, plaintext);
    } catch {
      process.stdout.write(chalk.yellow(`  ⚠ Failed to decrypt entry: ${entry.key}\n`));
    }
  }

  return result;
}

/**
 * Generate a .env file from a decrypted vault.
 */
export function writeEnvFromVault(envMap: Map<string, string>, outputDir: string): string {
  const lines: string[] = [];
  for (const [key, value] of envMap) {
    lines.push(`${key}=${value}`);
  }

  const outputPath = join(outputDir, '.env.vault-decrypted');
  writeFileSync(outputPath, lines.join('\n'), 'utf-8');
  return outputPath;
}

/**
 * Extract a value from the snippet found during scanning.
 * Heuristic: look for the value after = or : in the snippet.
 */
function extractValueFromSnippet(snippet: string): string {
  // Try to find a value pattern
  const eqMatch = snippet.match(/['"]([A-Za-z0-9_\-\.]{20,})['"]/);
  if (eqMatch) return eqMatch[1];

  // Try after = sign
  const eqSign = snippet.match(/=\s*['"]?([A-Za-z0-9_\-\.\/+=]{10,})['"]?/);
  if (eqSign) return eqSign[1];

  // Return the whole line
  return snippet;
}
