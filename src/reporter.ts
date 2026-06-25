/**
 * Pretty-printed scan results reporter for env-secure.
 * Groups findings by severity and category, with color-coded output.
 */

import chalk from 'chalk';
import { ScanResult, ScanStats } from './scanner.js';
import { logFindings, printSummary, printNoSecrets } from './logger.js';
import { ICONS } from './logger.js';

export interface ReportOptions {
  showSnippets?: boolean;
  groupBy?: 'severity' | 'category' | 'file';
}

/**
 * Render the full scan report to stdout.
 */
export function renderReport(results: ScanResult[], stats: ScanStats, options: ReportOptions = {}): void {
  const { showSnippets = true, groupBy = 'severity' } = options;

  if (results.length === 0) {
    printNoSecrets();
    return;
  }

  if (groupBy === 'severity') {
    renderBySeverity(results, showSnippets);
  } else if (groupBy === 'category') {
    renderByCategory(results, showSnippets);
  } else {
    renderByFile(results, showSnippets);
  }

  printSummary({
    totalFiles: stats.totalFiles,
    totalSecrets: results.length,
    high: stats.high,
    medium: stats.medium,
    low: stats.low,
    envVars: extractEnvVarCount(results),
    elapsed: stats.elapsed,
  });
}

function extractEnvVarCount(results: ScanResult[]): number {
  const envSet = new Set<string>();
  for (const r of results) {
    if (r.pattern.envVar) envSet.add(r.pattern.envVar);
  }
  return envSet.size;
}

function renderBySeverity(results: ScanResult[], showSnippets: boolean): void {
  const high = results.filter(r => r.pattern.confidence === 'high');
  const medium = results.filter(r => r.pattern.confidence === 'medium');
  const low = results.filter(r => r.pattern.confidence === 'low');

  if (high.length > 0) {
    process.stdout.write(`\n  ${chalk.bgRed.white(' HIGH SEVERITY ')}  ${chalk.red(`${high.length} secrets found`)}\n`);
    process.stdout.write(`  ${chalk.dim('────────────────────────────────────────────')}\n`);
    for (const r of high) renderFinding(r, showSnippets);
  }

  if (medium.length > 0) {
    process.stdout.write(`\n  ${chalk.bgYellow.black(' MEDIUM SEVERITY ')}  ${chalk.yellow(`${medium.length} secrets found`)}\n`);
    process.stdout.write(`  ${chalk.dim('────────────────────────────────────────────')}\n`);
    for (const r of medium) renderFinding(r, showSnippets);
  }

  if (low.length > 0) {
    process.stdout.write(`\n  ${chalk.bgGray.white(' LOW SEVERITY ')}  ${chalk.dim(`${low.length} secrets found`)}\n`);
    process.stdout.write(`  ${chalk.dim('────────────────────────────────────────────')}\n`);
    for (const r of low) renderFinding(r, showSnippets);
  }
}

function renderByCategory(results: ScanResult[], showSnippets: boolean): void {
  const grouped = new Map<string, ScanResult[]>();
  for (const r of results) {
    const cat = r.pattern.category || 'Other';
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(r);
  }

  for (const [category, items] of grouped) {
    const severityColor = items.some(r => r.pattern.confidence === 'high') ? chalk.red :
      items.some(r => r.pattern.confidence === 'medium') ? chalk.yellow : chalk.dim;
    process.stdout.write(`\n  ${severityColor.bold(`📂 ${category}`)}  ${chalk.dim(`(${items.length} findings)`)}`);
    for (const r of items) renderFinding(r, showSnippets);
  }
}

function renderByFile(results: ScanResult[], showSnippets: boolean): void {
  const grouped = new Map<string, ScanResult[]>();
  for (const r of results) {
    if (!grouped.has(r.file)) grouped.set(r.file, []);
    grouped.get(r.file)!.push(r);
  }

  for (const [file, items] of grouped) {
    const severityColor = items.some(r => r.pattern.confidence === 'high') ? chalk.red :
      items.some(r => r.pattern.confidence === 'medium') ? chalk.yellow : chalk.dim;
    process.stdout.write(`\n  ${chalk.cyan('📄')} ${severityColor.bold(file)}  ${chalk.dim(`(${items.length} findings)`)}`);
    for (const r of items) renderFindingInline(r, showSnippets);
  }
}

function renderFinding(r: ScanResult, showSnippets: boolean): void {
  const severity = r.pattern.confidence;
  const color = severity === 'high' ? chalk.red : severity === 'medium' ? chalk.yellow : chalk.dim;
  const badge = severity === 'high' ? chalk.bgRed.white('!') : severity === 'medium' ? chalk.bgYellow.black('~') : chalk.bgGray.white('·');

  process.stdout.write(`\n  ${badge} ${color.bold(r.pattern.name)}`);
  process.stdout.write(`\n     ${chalk.dim('File:')}   ${chalk.cyan(r.file)}:${chalk.yellow(r.line.toString())}`);
  if (r.entropy > 0) {
    process.stdout.write(`\n     ${chalk.dim('Entropy:')} ${r.entropy > 5 ? chalk.red(r.entropy.toString()) : r.entropy > 4 ? chalk.yellow(r.entropy.toString()) : chalk.dim(r.entropy.toString())}`);
  }
  if (r.pattern.envVar) {
    process.stdout.write(`\n     ${chalk.dim('Env:')}    ${chalk.green(r.pattern.envVar)}`);
  }
  if (showSnippets && r.snippet) {
    const masked = maskSecret(r.snippet);
    process.stdout.write(`\n     ${chalk.dim('Code:')}  ${color(masked)}`);
  }
  process.stdout.write('\n');
}

function renderFindingInline(r: ScanResult, showSnippets: boolean): void {
  const color = r.pattern.confidence === 'high' ? chalk.red : r.pattern.confidence === 'medium' ? chalk.yellow : chalk.dim;
  process.stdout.write(`\n    ${color('→')} ${color.bold(r.pattern.name)} ${chalk.dim(`L${r.line}`)}`);
  if (showSnippets && r.snippet) {
    const masked = maskSecret(r.snippet);
    process.stdout.write(`  ${color(masked)}`);
  }
}

/**
 * Mask the actual secret value in the snippet for safety in reports.
 */
export function maskSecret(snippet: string): string {
  return snippet.replace(
    /(['"])([A-Za-z0-9_\-]{20,})(['"])/g,
    (_, open, mid, close) => {
      if (/^[A-Za-z0-9_\-]{20,}$/.test(mid)) {
        const visible = mid.slice(0, 6);
        return `${open}${visible}...${close}`;
      }
      return `${open}${mid}${close}`;
    }
  ).replace(
    /([A-Za-z0-9_\-]{20,})/g,
    (match) => {
      if (match.length >= 20) {
        return match.slice(0, 6) + '...';
      }
      return match;
    }
  );
}

/**
 * Generate a machine-readable JSON report.
 */
export function renderJSON(results: ScanResult[], stats: ScanStats): string {
  return JSON.stringify({
    version: '1.0.0',
    scanned: {
      files: stats.totalFiles,
    },
    summary: {
      total: stats.totalSecrets,
      high_confidence: stats.high,
      medium_confidence: stats.medium,
      low_confidence: stats.low,
    },
    findings: results.map(r => ({
      file: r.file,
      line: r.line,
      column: r.column,
      type: r.pattern.name,
      category: r.pattern.category,
      confidence: r.pattern.confidence,
      env_var: r.pattern.envVar || null,
      entropy: r.entropy,
    })),
  }, null, 2);
}

/**
 * Generate a summary table for CI/CD output.
 */
export function renderCIMatrix(results: ScanResult[], stats: ScanStats): string {
  const lines: string[] = [];
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| 🔴 High   | ${stats.high} |`);
  lines.push(`| 🟡 Medium | ${stats.medium} |`);
  lines.push(`| ⚪ Low    | ${stats.low} |`);
  lines.push(`| **Total** | **${stats.totalSecrets}** |`);
  lines.push('');
  
  if (stats.high > 0) {
    const maxShow = Math.min(5, results.filter(r => r.pattern.confidence === 'high').length);
    lines.push('**Top findings:**');
    for (const r of results.filter(r => r.pattern.confidence === 'high').slice(0, maxShow)) {
      lines.push(`- \`${r.file}:${r.line}\` — ${r.pattern.name}`);
    }
  }

  return lines.join('\n');
}
