/**
 * File scanner engine for env-secure.
 * Recursive file scanning with gitignore awareness, binary detection, and entropy analysis.
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative, extname } from 'path';
import { PATTERNS, SecretPattern, getPatterns } from './patterns.js';

export interface ScanResult {
  file: string;
  line: number;
  column: number;
  pattern: SecretPattern;
  snippet: string;
  entropy: number;
}

export interface ScanStats {
  totalFiles: number;
  totalSecrets: number;
  high: number;
  medium: number;
  low: number;
  elapsed: string;
}

const DEFAULT_IGNORE = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'out',
  'target', 'vendor', '.cache', '__pycache__', '.venv',
  '.env', '.env.local', '.env.production', '.env.development',
  '*.pyc', '*.pyo', '*.class', '*.jar', '*.war',
  '*.dll', '*.exe', '*.so', '*.dylib', '*.bin',
  '*.png', '*.jpg', '*.jpeg', '*.gif', '*.svg', '*.ico',
  '*.woff', '*.woff2', '*.ttf', '*.eot', '*.mp4', '*.mp3',
  '*.zip', '*.tar', '*.gz', '*.rar', '*.7z',
  '*.pdf', '*.doc', '*.docx', '*.xls', '*.xlsx',
  '.gitignore', '.gitattributes', '.DS_Store',
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb',
  '*.min.js', '*.min.css', '*.bundle.js',
  '*.map', '.terraform', '.serverless',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp', '.webp',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp4', '.mp3', '.avi', '.mov', '.wav', '.flac', '.ogg',
  '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm',
  '.o', '.a', '.lib', '.obj',
  '.pyc', '.pyo', '.class', '.jar', '.war',
  '.DS_Store',
]);

const MAX_FILE_SIZE = 1_048_576; // 1MB
const TEXT_FILE_CHUNK = 1024;

function isBinaryContent(buffer: Buffer): boolean {
  const checkLen = Math.min(buffer.length, TEXT_FILE_CHUNK);
  for (let i = 0; i < checkLen; i++) {
    if (buffer[i] === 0x00) return true;
  }
  return false;
}

function loadGitignore(rootDir: string): Set<string> {
  const ignorePatterns = new Set<string>(DEFAULT_IGNORE);
  try {
    const content = readFileSync(join(rootDir, '.gitignore'), 'utf-8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const pattern = trimmed.replace(/^\.?\//, '').replace(/\/$/, '');
      if (pattern) ignorePatterns.add(pattern);
    }
  } catch {
    // No .gitignore found
  }
  return ignorePatterns;
}

function shouldIgnore(relativePath: string, ignorePatterns: Set<string>): boolean {
  const parts = relativePath.replace(/\\/g, '/').split('/');
  const name = parts[parts.length - 1];

  for (const pattern of ignorePatterns) {
    if (parts.some(p => p === pattern || p.endsWith(pattern))) return true;
    if (pattern.startsWith('*.')) {
      const ext = pattern.slice(1);
      if (name.endsWith(ext)) return true;
    }
    if (relativePath.replace(/\\/g, '/').startsWith(pattern.replace(/\\/g, '/'))) return true;
  }
  return false;
}

function calculateEntropy(s: string): number {
  if (!s || s.length < 3) return 0;
  const len = s.length;
  const freq = new Map<string, number>();
  for (const char of s) freq.set(char, (freq.get(char) || 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function getLineColumn(content: string, index: number): { line: number; column: number } {
  const before = content.slice(0, index);
  const lines = before.split('\n');
  return {
    line: lines.length,
    column: (lines[lines.length - 1]?.length || 0) + 1,
  };
}

function getSnippet(content: string, index: number, matchLength: number): string {
  const lineStart = content.lastIndexOf('\n', index);
  const lineEnd = content.indexOf('\n', index + matchLength);
  const start = lineStart === -1 ? 0 : lineStart + 1;
  const end = lineEnd === -1 ? content.length : lineEnd;
  const line = content.slice(start, end);
  const trimmed = line.trim();
  if (trimmed.length > 120) {
    const matchIdx = line.indexOf(content.slice(index, index + matchLength));
    const ctxStart = Math.max(0, matchIdx - 40);
    const ctxEnd = Math.min(line.length, matchIdx + matchLength + 40);
    return (ctxStart > 0 ? '...' : '') + line.slice(ctxStart, ctxEnd).trim() + (ctxEnd < line.length ? '...' : '');
  }
  return trimmed;
}

export interface ScanOptions {
  minConfidence?: 'high' | 'medium' | 'low';
  includePaths?: string[];
  excludePaths?: string[];
  entropyThreshold?: number;
  verbose?: boolean;
}

function deduplicateResults(results: ScanResult[]): ScanResult[] {
  if (results.length === 0) return [];
  const grouped = new Map<string, ScanResult[]>();
  for (const r of results) {
    const key = r.file;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(r);
  }
  const deduped: ScanResult[] = [];
  for (const [, group] of grouped) {
    group.sort((a, b) => a.line - b.line);
    const merged: ScanResult[] = [];
    for (const r of group) {
      const last = merged[merged.length - 1];
      if (last && Math.abs(last.line - r.line) <= 3 && last.pattern.name === r.pattern.name) {
        if (r.entropy > last.entropy) merged[merged.length - 1] = r;
      } else {
        merged.push(r);
      }
    }
    deduped.push(...merged);
  }
  const severityOrder = { high: 0, medium: 1, low: 2 };
  deduped.sort((a, b) => {
    const sevDiff = (severityOrder[a.pattern.confidence] || 0) - (severityOrder[b.pattern.confidence] || 0);
    if (sevDiff !== 0) return sevDiff;
    return a.file.localeCompare(b.file) || a.line - b.line;
  });
  return deduped;
}

export function scanDirectory(dir: string, options: ScanOptions = {}): { results: ScanResult[]; stats: ScanStats } {
  const {
    minConfidence = 'low',
    includePaths,
    excludePaths = [],
    entropyThreshold = 3.5,
  } = options;

  const patterns = getPatterns(minConfidence);
  const ignorePatterns = loadGitignore(dir);
  const results: ScanResult[] = [];
  let totalFiles = 0;

  function walk(currentDir: string): void {
    let entries: string[];
    try {
      entries = readdirSync(currentDir);
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      const relPath = relative(dir, fullPath).replace(/\\/g, '/');

      if (shouldIgnore(relPath, ignorePatterns)) continue;
      if (includePaths && !includePaths.some(p => relPath.startsWith(p))) continue;
      if (excludePaths.some(p => relPath.startsWith(p))) continue;

      let stat: ReturnType<typeof statSync>;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }

      if (stat.isDirectory()) {
        walk(fullPath);
        continue;
      }

      if (stat.size > MAX_FILE_SIZE) continue;

      const ext = extname(entry).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;

      totalFiles++;

      let content: Buffer;
      try {
        content = readFileSync(fullPath);
      } catch {
        continue;
      }

      if (isBinaryContent(content)) continue;

      const text = content.toString('utf-8');

      // Reset all regex lastIndex before pre-filter
      for (const p of patterns) p.regex.lastIndex = 0;

      // Quick pre-filter: check if any pattern matches or common indicators exist
      const hasPotentialSecret = patterns.some(p => {
        try {
          p.regex.lastIndex = 0;
          return p.regex.test(text);
        } catch {
          return false;
        }
      });

      const hasIndicator = /[A-Z][A-Z0-9_]{3,}_KEY|_SECRET|_TOKEN|_PASSWORD|-----BEGIN|mongodb:|postgres:|redis:|Bearer\s+|sk_live|sk_test|AKIA|AIza|ghp_|xoxb-|SG\./i.test(text);

      if (!hasPotentialSecret && !hasIndicator) continue;

      // Reset before scan loop
      for (const p of patterns) p.regex.lastIndex = 0;

      // Scan each pattern
      for (const pattern of patterns) {
        try {
          pattern.regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          let matchCount = 0;

          while ((match = pattern.regex.exec(text)) !== null) {
            if (matchCount >= 20) break;
            matchCount++;

            const matchStr = match[0];
            const entropy = calculateEntropy(matchStr);

            if (entropy < entropyThreshold) continue;

            // Skip false positives
            if (
              matchStr.startsWith('YOUR_') || matchStr.startsWith('your-') ||
              matchStr.includes('xxxxxxxx') || matchStr.includes('123456') ||
              matchStr.includes('placeholder') ||
              matchStr === 'true' || matchStr === 'false' || matchStr === 'null' || matchStr === 'undefined'
            ) continue;

            const pos = getLineColumn(text, match.index);
            const snippet = getSnippet(text, match.index, matchStr.length);

            results.push({
              file: relPath,
              line: pos.line,
              column: pos.column,
              pattern,
              snippet,
              entropy: Math.round(entropy * 100) / 100,
            });

            pattern.regex.lastIndex = match.index + match[0].length;
          }
        } catch {
          // Skip patterns that throw
        }
      }
    }
  }

  walk(dir);

  const deduped = deduplicateResults(results);

  const stats: ScanStats = {
    totalFiles,
    totalSecrets: deduped.length,
    high: deduped.filter(r => r.pattern.confidence === 'high').length,
    medium: deduped.filter(r => r.pattern.confidence === 'medium').length,
    low: deduped.filter(r => r.pattern.confidence === 'low').length,
    elapsed: '0s',
  };

  return { results: deduped, stats };
}

export function extractEnvVars(results: ScanResult[]): Map<string, { key: string; value: string }> {
  const envMap = new Map<string, { key: string; value: string }>();
  for (const result of results) {
    if (result.pattern.envVar && !envMap.has(result.pattern.envVar)) {
      envMap.set(result.pattern.envVar, {
        key: result.pattern.envVar,
        value: 'your_value_here',
      });
    }
  }
  return envMap;
}
