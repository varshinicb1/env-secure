#!/usr/bin/env node

/**
 * env-secure — Scan your codebase for leaked secrets, keys, and tokens.
 * CLI entry point with full Command + CI mode support.
 */

import { Command } from 'commander';
import { resolve } from 'path';
import { printBanner, log, ICONS } from './logger.js';
import { scanDirectory, ScanStats } from './scanner.js';
import { renderReport, renderJSON, renderCIMatrix } from './reporter.js';
import { extractEnvEntries, writeEnvExample, mergeWithExisting } from './env-generator.js';
import { createVault, decryptVault, writeEnvFromVault } from './vault.js';
import chalk from 'chalk';
import { existsSync } from 'fs';

const isCi = process.env['CI'] === 'true' || process.env['CI'] === '1' || !process.stdin.isTTY;

const program = new Command();

program
  .name('env-secure')
  .description('🔍 Scan codebases for leaked API keys, passwords, and tokens — generate .env.example + encrypted vault')
  .version('1.0.0');

// Core options
program
  .option('--ci', 'Non-interactive mode (auto-detected in CI environments)')
  .option('-y, --yes', 'Alias for --ci');

// Scan options
program
  .option('--scan', 'Run security scan (default action if no other action specified)')
  .option('--dir <path>', 'Directory to scan', '.')
  .option('--min-confidence <level>', 'Minimum confidence level: high|medium|low', 'low')
  .option('--entropy-threshold <n>', 'Entropy threshold for detection (default: 3.5)', parseFloat, 3.5)
  .option('--exclude <paths>', 'Comma-separated paths to exclude')
  .option('--include <paths>', 'Comma-separated paths to include (only scan these)');

// Output options
program
  .option('--json', 'Output results as JSON')
  .option('--ci-matrix', 'Output as GitHub Actions-compatible markdown table')
  .option('--quiet', 'Suppress banner and detailed output')
  .option('--group-by <mode>', 'Group results by: severity|category|file', 'severity');

// Action options
program
  .option('--env', 'Generate .env.example from discovered secrets')
  .option('--vault', 'Create encrypted vault of discovered secrets')
  .option('--vault-pass <passphrase>', 'Passphrase for vault encryption/decryption')
  .option('--vault-decrypt <path>', 'Decrypt a vault file to .env.vault-decrypted')
  .option('--merge', 'Merge with existing .env.example if present')
  .option('--output <dir>', 'Output directory for generated files', '.');

program.action(async (options) => {
  printBanner();

  const ci = options.ci || options.yes || isCi;
  const rootDir = resolve(options.dir);

  // Handle vault decryption
  if (options.vaultDecrypt) {
    if (!existsSync(options.vaultDecrypt)) {
      log('error', `Vault file not found: ${options.vaultDecrypt}`);
      process.exit(1);
    }
    log('info', `Decrypting vault: ${options.vaultDecrypt}`);
    log('info', ci ? 'Using CI mode (passphrase from ENV_VAULT_PASSPHRASE or --vault-pass)' : 'Enter passphrase when prompted');
    
    const envMap = await decryptVault(options.vaultDecrypt, options.vaultPass);
    const outPath = writeEnvFromVault(envMap, options.output);
    log('success', `Decrypted ${envMap.size} entries to: ${outPath}`);
    process.exit(0);
  }

  // Determine actions
  const doScan = options.scan || true; // scan is always on unless vault-decrypt
  const doEnv = options.env || ci;
  const doVault = options.vault || false;

  if (doScan) {
    log('scan', `Scanning ${chalk.cyan(rootDir)} for secrets...`);

    const excludePaths = options.exclude ? options.exclude.split(',').map((s: string) => s.trim()) : undefined;
    const includePaths = options.include ? options.include.split(',').map((s: string) => s.trim()) : undefined;

    const startTime = Date.now();
    const scanResult = scanDirectory(rootDir, {
      minConfidence: options.minConfidence as 'high' | 'medium' | 'low',
      excludePaths,
      includePaths,
      entropyThreshold: options.entropyThreshold,
    });
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1) + 's';
    const { results, stats } = scanResult;
    const statsWithElapsed: ScanStats = { ...stats, elapsed };

    if (options.json) {
      process.stdout.write(renderJSON(results, statsWithElapsed));
      return;
    }

    if (options.ciMatrix) {
      process.stdout.write(renderCIMatrix(results, statsWithElapsed));
      log('info', `\nScan completed in ${chalk.dim(elapsed)}`);
      if (stats.high > 0) {
        log('warn', `${stats.high} high-confidence secrets found — review and fix before committing`);
      }
      return;
    }

    // Render full report
    const reportOptions = {
      showSnippets: !options.quiet,
      groupBy: options.groupBy as 'severity' | 'category' | 'file',
    };
    renderReport(results, statsWithElapsed, reportOptions);

    // Generate .env.example
    if (doEnv && results.length > 0) {
      log('info', `\n${ICONS.key} Generating .env.example...`);
      const entries = extractEnvEntries(results);
      const finalEntries = options.merge
        ? mergeWithExisting(entries, resolve(rootDir, '.env.example'))
        : entries;
      const envPath = writeEnvExample(finalEntries, options.output);
      log('success', `Generated: ${chalk.cyan(envPath)}`);
    }

    // Create encrypted vault
    if (doVault && results.length > 0) {
      let pp: string | undefined;
      if (!ci) {
        log('info', `\n${ICONS.lock} Creating encrypted vault...`);
      } else {
        pp = options.vaultPass || process.env['ENV_VAULT_PASSPHRASE'];
        if (!pp) {
          log('error', '--vault-pass required for vault creation in CI mode (or set ENV_VAULT_PASSPHRASE)');
          process.exit(1);
        }
      }
      await createVault(results, options.output, pp);
    }
  }

  // Quick summary for CI
  if (ci) {
    log('success', 'Scan complete');
  }
});

program.parse(process.argv);
