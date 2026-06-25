/**
 * Terminal UI utilities for env-secure.
 * Colored output, spinners, and banner display.
 */

import chalk from 'chalk';

export type LogLevel = 'info' | 'success' | 'warn' | 'error' | 'muted' | 'scan';

export const ICONS = {
  info: chalk.blue('ℹ'),
  success: chalk.green('✔'),
  warn: chalk.yellow('⚠'),
  error: chalk.red('✖'),
  muted: chalk.dim('·'),
  bullet: chalk.dim('•'),
  arrow: chalk.dim('→'),
  lock: chalk.yellow('🔒'),
  key: chalk.cyan('🔑'),
  scan: chalk.magenta('🔍'),
  shield: chalk.green('🛡️'),
  file: chalk.blue('📄'),
  folder: chalk.cyan('📁'),
  alert: chalk.red('🚨'),
};

export function log(level: LogLevel, message: string): void {
  const icon = ICONS[level] || '';
  const ts = chalk.dim(new Date().toLocaleTimeString());
  process.stdout.write(`${ts} ${icon}  ${message}\n`);
}

export function logFindings(severity: 'high' | 'medium' | 'low', count: number, file: string, line: number, snippet: string): void {
  const color = severity === 'high' ? chalk.red : severity === 'medium' ? chalk.yellow : chalk.dim;
  const badge = severity === 'high' ? chalk.bgRed.white(' HIGH ') : severity === 'medium' ? chalk.bgYellow.black(' MED  ') : chalk.bgGray.white(' LOW  ');
  process.stdout.write(`  ${badge} ${color(count.toString().padStart(3))}  ${chalk.dim(file)}:${chalk.yellow(line.toString())}\n`);
  if (snippet) {
    process.stdout.write(`       ${chalk.dim(snippet.trimEnd())}\n`);
  }
}

export function printBanner(): void {
  const banner = `
${chalk.cyan.bold('  ╔══════════════════════════════════════════════╗')}
${chalk.cyan.bold('  ║')}    ${chalk.green.bold('🔍  ENV-SECURE  v1.0.0')}              ${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ║')}    ${chalk.dim('Scan codebases for leaked secrets,')}    ${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ║')}    ${chalk.dim('generate .env.example, encrypt vault.')}  ${chalk.cyan.bold('║')}
${chalk.cyan.bold('  ╚══════════════════════════════════════════════╝')}
`;
  process.stdout.write(banner);
}

export function printSummary(stats: {
  totalFiles: number;
  totalSecrets: number;
  high: number;
  medium: number;
  low: number;
  envVars: number;
  elapsed: string;
}): void {
  const color = stats.high > 0 ? chalk.red : stats.medium > 0 ? chalk.yellow : chalk.green;
  process.stdout.write(`\n${chalk.bold('  📊  Scan Summary')}\n`);
  process.stdout.write(`  ${chalk.dim('────────────────────────────────────────────')}\n`);
  process.stdout.write(`  ${ICONS.folder}  Files scanned:     ${chalk.bold(stats.totalFiles.toString())}\n`);
  process.stdout.write(`  ${ICONS.alert}  Secrets found:     ${color.bold(stats.totalSecrets.toString())}\n`);
  process.stdout.write(`  ${chalk.bgRed.white(' HIGH ')}  Critical:         ${chalk.red.bold(stats.high.toString())}\n`);
  process.stdout.write(`  ${chalk.bgYellow.black(' MED  ')}  Medium:           ${chalk.yellow.bold(stats.medium.toString())}\n`);
  process.stdout.write(`  ${chalk.bgGray.white(' LOW  ')}  Low:              ${chalk.dim(stats.low.toString())}\n`);
  process.stdout.write(`  ${ICONS.key}  Env vars extracted: ${chalk.bold(stats.envVars.toString())}\n`);
  process.stdout.write(`  ⏱️   Time:             ${chalk.dim(stats.elapsed)}\n`);
  process.stdout.write(`  ${chalk.dim('────────────────────────────────────────────')}\n`);
}

export function printVaultCreated(path: string): void {
  process.stdout.write(`\n  ${ICONS.lock}  ${chalk.green.bold('Encrypted vault created')}\n`);
  process.stdout.write(`  ${chalk.dim('  Location:')} ${chalk.cyan(path)}\n`);
  process.stdout.write(`  ${chalk.dim('  Algorithm:')} AES-256-GCM\n`);
  process.stdout.write(`  ${chalk.yellow('  ⚠ Keep this file safe and do not commit it to git!')}\n`);
}

export function printEnvExample(path: string): void {
  process.stdout.write(`\n  ${ICONS.file}  ${chalk.green.bold('.env.example generated')}\n`);
  process.stdout.write(`  ${chalk.dim('  Location:')} ${chalk.cyan(path)}\n`);
  process.stdout.write(`  ${chalk.dim('  Tip: Fill in')} ${chalk.yellow('your_values_here')} ${chalk.dim('with real credentials')}\n`);
}

export function printNoSecrets(): void {
  process.stdout.write(`\n  ${ICONS.shield}  ${chalk.green.bold('No secrets found — your codebase looks clean!')}\n`);
  process.stdout.write(`  ${chalk.dim('  This is a good sign. Run')} ${chalk.cyan('env-secure --scan --vault')}\n`);
  process.stdout.write(`  ${chalk.dim('  to create an encrypted vault of your environment.')}\n`);
}

export function printWarning(message: string): void {
  process.stdout.write(`\n  ${ICONS.warn}  ${chalk.yellow(message)}\n`);
}
