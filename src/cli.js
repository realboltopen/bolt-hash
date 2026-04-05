#!/usr/bin/env node

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const readline = require('readline/promises');
const { builtinModules } = require('module');
const fse = require('fs-extra');
const fg = require('fast-glob');
const ts = require('typescript');
const JavaScriptObfuscator = require('javascript-obfuscator');
const chalk = require('chalk');
const { spawn } = require('child_process');
const { version } = require('../package.json');

const CODE_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.cts', '.mts', '.tsx', '.jsx']);
const TYPESCRIPT_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts']);
const NODE_ENTRY_EXTENSIONS = new Set(['.js', '.cjs', '.mjs']);
const PYTHON_ENTRY_EXTENSIONS = new Set(['.py']);
const GITHUB_URL = 'https://github.com/realboltopen/bolt-hash';
const BUILTIN_MODULES = new Set([
  ...builtinModules,
  ...builtinModules.map((moduleName) => moduleName.startsWith('node:') ? moduleName.slice(5) : `node:${moduleName}`)
]);

// ── Supported frameworks (free edition) ──────────────────────────────────────
// bolt-hash (free) supports: Node.js + TypeScript server-side projects
//   (Express, Fastify, NestJS, Koa, Hapi, etc.)
// NOT supported: React, Vue, Nuxt, Angular, Next.js (SSR), Vite, CRA, SvelteKit
// Use bolt for SPA / SSR / full-stack framework support.
const UNSUPPORTED_FRAMEWORK_DEPS = new Map([
  ['react',              'React (use bolt)'],
  ['react-dom',          'React (use bolt)'],
  ['next',               'Next.js (use bolt)'],
  ['nuxt',               'Nuxt (use bolt)'],
  ['@nuxt/core',         'Nuxt (use bolt)'],
  ['vue',                'Vue.js (use bolt)'],
  ['@vue/core',          'Vue.js (use bolt)'],
  ['@angular/core',      'Angular (use bolt)'],
  ['@sveltejs/kit',      'SvelteKit (use bolt)'],
  ['vite',               'Vite (use bolt)'],
  ['create-react-app',   'CRA (use bolt)'],
  ['gatsby',             'Gatsby (use bolt)'],
  ['remix',              'Remix (use bolt)'],
  ['@remix-run/node',    'Remix (use bolt)'],
  ['astro',              'Astro (use bolt)'],
  ['svelte',             'Svelte (use bolt)'],
  ['solid-js',           'SolidJS (use bolt)'],
]);

/**
 * Check the source directory's package.json for unsupported frameworks.
 * Returns { supported: true } or { supported: false, framework: string, dep: string }
 */
function detectFramework(sourceDir) {
  const pkgPath = path.join(sourceDir, 'package.json');
  if (!fs.existsSync(pkgPath)) return { supported: true };
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch { return { supported: true }; }
  const allDeps = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {}),
    ...(pkg.peerDependencies || {})
  };
  for (const [dep, framework] of UNSUPPORTED_FRAMEWORK_DEPS) {
    if (dep in allDeps) {
      return { supported: false, framework, dep };
    }
  }
  return { supported: true };
}

const CORE_EXCLUDES = [
  '**/node_modules/**',
  '**/.git/**',
  '**/.svn/**',
  '**/.hg/**',
  '**/.env',
  '**/.env.*',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/.nuxt/**'
];

const SENSITIVE_ENV_KEY_REGEX = /(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|CLIENT_SECRET|JWT|DB_URL|DATABASE_URL|CONNECTION_STRING|LICENSE_KEY|SMTP_PASS|SMTP_PASSWORD|WEBHOOK_SECRET)$/i;
const SENSITIVE_ENV_VALUE_REGEX = /(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{10,})/;

async function main() {
  printBanner();

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  let sourceDir;
  let outputDir;
  let extraExcludeText;
  let cleanOutput;
  let signManifest;
  let manifestSigningSecret;

  try {
    const sourceInput = await askText(rl, 'Source directory to protect', process.cwd());
    sourceDir = path.resolve(sourceInput.trim());
    if (!(await isDirectory(sourceDir))) {
      throw new Error(`Invalid source directory: ${sourceDir}`);
    }

    // ── Framework check ──────────────────────────────────────────────────────
    const fwCheck = detectFramework(sourceDir);
    if (!fwCheck.supported) {
      console.log('');
      console.log(chalk.yellow(`⚠  Unsupported framework detected: ${chalk.bold(fwCheck.framework)}`));
      console.log(chalk.yellow(`   Detected dependency: ${chalk.bold(fwCheck.dep)}`));
      console.log(chalk.yellow('   bolt (free) supports server-side Node.js/TypeScript only.'));
      console.log(chalk.yellow('   For SPA/SSR frameworks, use bolt.'));
      console.log('');
      const proceed = await askConfirm(rl, 'Continue anyway (obfuscation only, no integrity guarantee)?', false);
      if (!proceed) {
        throw new Error(`Aborted: ${fwCheck.framework} is not supported by bolt (free edition)`);
      }
    }

    const outputInput = await askText(rl, 'Output directory', path.join(sourceDir, 'protected_output'));
    outputDir = path.resolve(outputInput.trim());

    extraExcludeText = await askText(rl, 'Extra excludes (comma-separated globs, leave empty to skip)', '');
    signManifest = await askConfirm(rl, 'Enable signed manifest protection (recommended)', true);
    if (signManifest) {
      manifestSigningSecret = await askText(rl, 'Manifest signing secret (leave empty to auto-generate)', '');
      if (!manifestSigningSecret || !manifestSigningSecret.trim()) {
        // Auto-generate a secret and print it so the user can save it
        manifestSigningSecret = crypto.randomBytes(32).toString('hex');
        console.log('');
        console.log(chalk.green('✅ Auto-generated signing secret:'));
        console.log(chalk.cyan(`   ${manifestSigningSecret}`));
        console.log(chalk.yellow('   ⚠  Save this secret — you will need it to run   bolt start'));
        console.log(chalk.yellow('   Set it via: export BOLT_HASH_SECRET=<secret>  or supply when prompted on start'));
        console.log('');
      } else {
        manifestSigningSecret = manifestSigningSecret.trim();
      }
    } else {
      manifestSigningSecret = '';
    }
    cleanOutput = await askConfirm(rl, `Clean output directory before building? (${outputDir})`, true);
  } finally {
    rl.close();
  }

  const extraExcludes = parseCommaList(extraExcludeText);
  const ignorePatterns = [...CORE_EXCLUDES, ...extraExcludes];

  await warnSensitiveEnvFiles(sourceDir);

  if (isSubPath(outputDir, sourceDir)) {
    const relativeOutput = normalizeSlashes(path.relative(sourceDir, outputDir));
    if (relativeOutput && relativeOutput !== '.') {
      ignorePatterns.push(`${relativeOutput}/**`);
    }
  }

  if (cleanOutput) {
    await fse.emptyDir(outputDir);
  } else {
    await fse.ensureDir(outputDir);
  }

  const startedAt = Date.now();
  const result = await protectProject({
    sourceDir,
    outputDir,
    ignorePatterns,
    manifestSigningSecret
  });

  const elapsedMs = Date.now() - startedAt;

  console.log('');
  console.log(chalk.green('✅ Protection complete.'));
  console.log(chalk.cyan(`- Total files scanned : ${result.totalFiles}`));
  console.log(chalk.cyan(`- Code files protected : ${result.codeFiles}`));
  console.log(chalk.cyan(`- Asset files copied  : ${result.assetFiles}`));
  console.log(chalk.cyan(`- Manifest signed     : ${result.manifestSigned ? 'yes' : 'no'}`));
  console.log(chalk.cyan(`- Hash manifest       : ${path.join(outputDir, '__bolt_manifest.json')}`));
  console.log(chalk.cyan(`- Integrity checker   : ${path.join(outputDir, '__bolt_integrity.js')}`));
  console.log(chalk.cyan(`- Elapsed             : ${elapsedMs}ms`));
  console.log('');
  console.log(chalk.yellow('Warning: Any modification to a protected output file will cause the application to crash at startup.'));
  console.log(chalk.yellow('To run with integrity check: cd into the output directory, then run  bolt start  or  bolt run <script>'));
}

async function warnSensitiveEnvFiles(sourceDir) {
  const envFiles = await fg(['**/.env', '**/.env.*'], {
    cwd: sourceDir,
    dot: true,
    onlyFiles: true,
    unique: true,
    followSymbolicLinks: false,
    ignore: ['**/.env.example', '**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**', '**/.next/**', '**/.nuxt/**', '**/protected_output/**']
  });

  const findings = [];
  for (const relativePath of envFiles) {
    const absPath = path.join(sourceDir, relativePath);
    let content = '';
    try {
      const stat = await fse.stat(absPath);
      if (stat.size > 256 * 1024) continue;
      content = await fse.readFile(absPath, 'utf8');
    } catch {
      continue;
    }

    const keyHits = new Set();
    for (const line of content.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
      if (!match) continue;
      const key = match[1];
      const value = match[2] || '';
      if (SENSITIVE_ENV_KEY_REGEX.test(key)) keyHits.add(key);
      if (value && SENSITIVE_ENV_VALUE_REGEX.test(value)) keyHits.add(`${key} (value-pattern)`);
    }

    if (keyHits.size > 0) {
      findings.push({
        filePath: normalizeSlashes(relativePath),
        keys: Array.from(keyHits).slice(0, 6)
      });
    }
  }

  if (findings.length === 0) return;

  console.log('');
  console.log(chalk.bgYellow.black.bold(' ⚠ SENSITIVE .ENV CONTENT DETECTED '));
  console.log(chalk.yellow('Potential secret keys were found in project .env files during hashing/protection.'));
  findings.slice(0, 5).forEach((item) => {
    console.log(chalk.yellow(`  - ${item.filePath}: ${item.keys.join(', ')}`));
  });
  if (findings.length > 5) {
    console.log(chalk.yellow(`  ...and ${findings.length - 5} more file(s).`));
  }
  console.log(chalk.cyan('  Hardening guide: https://hash.boltopen.com/production-hardening'));
  console.log(chalk.cyan('  Secret handling: https://hash.boltopen.com/docs#secrets-handling'));
  console.log(chalk.yellow('  Recommendation: keep secrets in vault/CI secret store and inject at runtime.'));
  console.log('');
}

function printBanner() {
  console.log(chalk.bold.blue('\u2500'.repeat(72)));
  console.log(chalk.bold.cyan('     \u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557    \u2588\u2588\u2557  \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557  \u2588\u2588\u2557'));
  console.log(chalk.bold.cyan('     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551  \u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d    \u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551  \u2588\u2588\u2551'));
  console.log(chalk.bold.cyan('     \u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551       \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551'));
  console.log(chalk.bold.cyan('     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551       \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551'));
  console.log(chalk.bold.cyan('     \u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551       \u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2551'));
  console.log(chalk.bold.cyan('     \u255a\u2550\u2550\u2550\u2550\u2550\u255d  \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d       \u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d'));
  console.log(chalk.bold.blue(`v${version}  \u2022  `) + chalk.bold.cyan('FREE') + chalk.bold.blue('  \u2022  Powered by BoltOpen'));
  console.log(chalk.blue('Website       : https://hash.boltopen.com'));
  console.log(chalk.blue('Docs          : https://hash.boltopen.com/docs'));
  console.log(chalk.blue('Upgrade       : https://hash.boltopen.com/pricing'));
  console.log(chalk.blue('Open Source   : https://github.com/realboltopen/bolt-hash'));
  console.log(chalk.bold.blue('\u2500'.repeat(72)));
}

async function askText(rl, label, defaultValue) {
  const answer = await rl.question(`${label}${defaultValue ? ` [${defaultValue}]` : ''}: `);
  const trimmed = answer.trim();
  if (!trimmed) {
    return defaultValue || '';
  }

  return trimmed;
}

async function askConfirm(rl, label, defaultValue) {
  const defaultHint = defaultValue ? 'Y/n' : 'y/N';
  const answer = await rl.question(`${label} [${defaultHint}]: `);
  const normalized = answer.trim().toLowerCase();

  if (!normalized) {
    return defaultValue;
  }

  return ['y', 'yes'].includes(normalized);
}

async function protectProject({ sourceDir, outputDir, ignorePatterns, manifestSigningSecret }) {
  const sourceFiles = await fg('**/*', {
    cwd: sourceDir,
    onlyFiles: true,
    dot: true,
    unique: true,
    followSymbolicLinks: false,
    ignore: ignorePatterns
  });

  const sortedFiles = sourceFiles
    .map((filePath) => normalizeSlashes(filePath))
    .sort((left, right) => left.localeCompare(right));

  const plan = sortedFiles.map((relativeInputPath) => {
    const extension = path.extname(relativeInputPath).toLowerCase();
    const isCodeFile = CODE_EXTENSIONS.has(extension);
    const relativeOutputPath = isCodeFile
      ? withJsExtension(relativeInputPath)
      : relativeInputPath;

    return {
      relativeInputPath,
      relativeOutputPath,
      isCodeFile
    };
  });

  const sourceToOutputMap = new Map(
    plan.map((item) => [normalizeRelativePath(item.relativeInputPath), normalizeRelativePath(item.relativeOutputPath)])
  );
  const outputFilesSet = new Set(plan.map((item) => normalizeSlashes(item.relativeOutputPath)));
  const pathAliasConfig = loadTsConfigPathAliases(sourceDir);
  const integrityScriptContent = buildIntegrityScript();
  const integrityScriptHash = hashText(integrityScriptContent);

  for (const fileItem of plan) {
    const srcPath = path.join(sourceDir, fileItem.relativeInputPath);
    const outPath = path.join(outputDir, fileItem.relativeOutputPath);

    await fse.ensureDir(path.dirname(outPath));

    if (!fileItem.isCodeFile) {
      await fse.copyFile(srcPath, outPath);
      continue;
    }

    const rawCode = await fse.readFile(srcPath, 'utf8');
    const transpiledCode = transpileToCommonJs(rawCode, srcPath);
    const rewrittenCode = rewriteRelativeImportExtensions(transpiledCode);
    const aliasRewrittenCode = rewriteTsconfigPathAliases({
      code: rewrittenCode,
      sourceDir,
      relativeOutputPath: fileItem.relativeOutputPath,
      sourceToOutputMap,
      pathAliasConfig
    });
    validateLocalSpecifiers(aliasRewrittenCode, fileItem.relativeOutputPath, outputFilesSet);
    const obfuscatedCode = obfuscateCode(aliasRewrittenCode);
    const wrappedCode = createByteEncodedWrapper(obfuscatedCode, fileItem.relativeOutputPath, integrityScriptHash);

    await fse.writeFile(outPath, wrappedCode, 'utf8');
  }

  const manifest = {
    algorithm: 'sha256',
    generatedAt: new Date().toISOString(),
    files: {},
    systemFiles: {
      '__bolt_integrity.js': integrityScriptHash
    }
  };

  for (const fileItem of plan) {
    if (!fileItem.isCodeFile) {
      continue;
    }
    const outPath = path.join(outputDir, fileItem.relativeOutputPath);
    manifest.files[normalizeSlashes(fileItem.relativeOutputPath)] = await hashFile(outPath);
  }

  if (manifestSigningSecret) {
    manifest.signatureAlgorithm = 'hmac-sha256';
    manifest.signature = signManifestData(manifest, manifestSigningSecret);
    manifest.signed = true;
  } else {
    manifest.signed = false;
  }

  await fse.writeJson(path.join(outputDir, '__bolt_manifest.json'), manifest, { spaces: 2 });
  await fse.writeFile(path.join(outputDir, '__bolt_integrity.js'), integrityScriptContent, 'utf8');

  await patchOutputPackageJson(outputDir);

  return {
    totalFiles: plan.length,
    codeFiles: plan.filter((item) => item.isCodeFile).length,
    assetFiles: plan.filter((item) => !item.isCodeFile).length,
    manifestSigned: !!manifest.signed
  };
}

function createManifestPayload(manifest) {
  return JSON.stringify({
    algorithm: manifest.algorithm,
    generatedAt: manifest.generatedAt,
    files: manifest.files || {},
    systemFiles: manifest.systemFiles || {}
  });
}

function signManifestData(manifest, secret) {
  const payload = createManifestPayload(manifest);
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function timingSafeEqualHex(leftHex, rightHex) {
  const left = Buffer.from(String(leftHex || ''), 'hex');
  const right = Buffer.from(String(rightHex || ''), 'hex');
  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function isManifestSigned(manifest) {
  return !!(
    manifest
    && typeof manifest.signature === 'string'
    && manifest.signature.trim().length > 0
    && manifest.signatureAlgorithm === 'hmac-sha256'
  );
}

function verifyManifestSignature(manifest, secret) {
  if (!isManifestSigned(manifest)) {
    return true;
  }

  if (!secret || !secret.trim()) {
    return false;
  }

  const expectedSignature = signManifestData(manifest, secret.trim());
  return timingSafeEqualHex(expectedSignature, manifest.signature);
}

function loadTsConfigPathAliases(sourceDir) {
  const tsConfigPath = path.join(sourceDir, 'tsconfig.json');
  if (!fs.existsSync(tsConfigPath)) {
    return {
      baseUrlAbs: sourceDir,
      rules: []
    };
  }

  const readResult = ts.readConfigFile(tsConfigPath, ts.sys.readFile);
  if (readResult.error || !readResult.config) {
    return {
      baseUrlAbs: sourceDir,
      rules: []
    };
  }

  const compilerOptions = readResult.config.compilerOptions || {};
  const baseUrlAbs = path.resolve(sourceDir, compilerOptions.baseUrl || '.');
  const pathsConfig = compilerOptions.paths && typeof compilerOptions.paths === 'object'
    ? compilerOptions.paths
    : {};

  const rules = Object.entries(pathsConfig)
    .filter(([, targets]) => Array.isArray(targets) && targets.length > 0)
    .map(([aliasPattern, targets]) => ({
      aliasPattern,
      aliasRegex: aliasPatternToRegex(aliasPattern),
      targets: targets.map((targetPath) => normalizeSlashes(String(targetPath)))
    }));

  return {
    baseUrlAbs,
    rules
  };
}

function aliasPatternToRegex(aliasPattern) {
  const escapedPattern = escapeRegExp(aliasPattern).replace(/\\\*/g, '(.+?)');
  return new RegExp(`^${escapedPattern}$`);
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function rewriteTsconfigPathAliases({
  code,
  sourceDir,
  relativeOutputPath,
  sourceToOutputMap,
  pathAliasConfig
}) {
  if (!pathAliasConfig || !Array.isArray(pathAliasConfig.rules) || pathAliasConfig.rules.length === 0) {
    return code;
  }

  const parsedSpecifiers = parseModuleSpecifiers(code, relativeOutputPath);
  if (parsedSpecifiers.length === 0) {
    return code;
  }

  const replacements = [];

  for (const entry of parsedSpecifiers) {
    const specifier = entry.value;

    if (isRelativeSpecifier(specifier) || BUILTIN_MODULES.has(specifier)) {
      continue;
    }

    const resolvedAliasOutputPath = resolveAliasSpecifierToOutputPath({
      specifier,
      sourceDir,
      sourceToOutputMap,
      pathAliasConfig
    });

    if (!resolvedAliasOutputPath) {
      if (matchesAnyAliasRule(specifier, pathAliasConfig.rules)) {
        throw new Error(
          `Cannot resolve tsconfig path alias: '${specifier}' (in: ${relativeOutputPath})`
        );
      }

      continue;
    }

    const rewrittenSpecifier = toRelativeSpecifier(relativeOutputPath, resolvedAliasOutputPath);
    if (rewrittenSpecifier !== specifier) {
      replacements.push({
        start: entry.start,
        end: entry.end,
        value: rewrittenSpecifier
      });
    }
  }

  return applyStringReplacements(code, replacements);
}

function resolveAliasSpecifierToOutputPath({ specifier, sourceDir, sourceToOutputMap, pathAliasConfig }) {
  for (const rule of pathAliasConfig.rules) {
    const matched = specifier.match(rule.aliasRegex);
    if (!matched) {
      continue;
    }

    const wildcardValues = matched.slice(1);
    for (const targetPattern of rule.targets) {
      let wildcardIndex = 0;
      const resolvedTarget = targetPattern.replace(/\*/g, () => wildcardValues[wildcardIndex++] || '');
      const absoluteInputBase = path.resolve(pathAliasConfig.baseUrlAbs, resolvedTarget);
      const relativeInputBase = normalizeRelativePath(path.relative(sourceDir, absoluteInputBase));

      const resolvedOutput = resolveInputBaseToOutputPath(relativeInputBase, sourceToOutputMap);
      if (resolvedOutput) {
        return resolvedOutput;
      }
    }
  }

  return null;
}

function resolveInputBaseToOutputPath(inputBasePath, sourceToOutputMap) {
  const normalizedBase = normalizeRelativePath(inputBasePath);
  const codeExtCandidates = ['.ts', '.tsx', '.mts', '.cts', '.js', '.cjs', '.mjs', '.jsx'];
  const rawExtCandidates = ['.json', '.node'];

  const candidates = [
    normalizedBase,
    ...codeExtCandidates.map((ext) => `${normalizedBase}${ext}`),
    ...rawExtCandidates.map((ext) => `${normalizedBase}${ext}`),
    ...codeExtCandidates.map((ext) => `${normalizedBase}/index${ext}`),
    ...rawExtCandidates.map((ext) => `${normalizedBase}/index${ext}`)
  ];

  for (const candidate of candidates) {
    const normalizedCandidate = normalizeRelativePath(candidate);
    if (sourceToOutputMap.has(normalizedCandidate)) {
      return sourceToOutputMap.get(normalizedCandidate);
    }
  }

  return null;
}

function toRelativeSpecifier(fromOutputPath, toOutputPath) {
  const fromDir = path.posix.dirname(normalizeSlashes(fromOutputPath));
  let relativePath = normalizeSlashes(path.posix.relative(fromDir, normalizeSlashes(toOutputPath)));

  if (!relativePath.startsWith('.')) {
    relativePath = `./${relativePath}`;
  }

  return relativePath;
}

function matchesAnyAliasRule(specifier, rules) {
  return rules.some((rule) => rule.aliasRegex.test(specifier));
}

function validateLocalSpecifiers(code, relativeOutputPath, outputFilesSet) {
  const staticSpecifiers = collectStaticSpecifiers(code, relativeOutputPath);
  if (staticSpecifiers.size === 0) {
    return;
  }

  const baseDir = path.posix.dirname(normalizeSlashes(relativeOutputPath));

  for (const specifier of staticSpecifiers) {
    if (!isRelativeSpecifier(specifier)) {
      continue;
    }

    const normalizedSpecifier = normalizeSlashes(specifier);
    const resolvedBase = normalizeSlashes(path.posix.normalize(path.posix.join(baseDir, normalizedSpecifier)));

    if (isPotentiallyResolved(resolvedBase, outputFilesSet)) {
      continue;
    }

    throw new Error(
      `Local import/require cannot be resolved after build: '${specifier}' (in: ${relativeOutputPath})`
    );
  }
}

function collectStaticSpecifiers(code, fileLabel = 'inline.js') {
  const specifiers = new Set();
  const parsedSpecifiers = parseModuleSpecifiers(code, fileLabel);

  for (const entry of parsedSpecifiers) {
    if (entry.value) {
      specifiers.add(entry.value);
    }
  }

  return specifiers;
}

function parseModuleSpecifiers(code, fileLabel = 'inline.js') {
  const sourceFile = ts.createSourceFile(
    fileLabel,
    code,
    ts.ScriptTarget.ES2020,
    true,
    ts.ScriptKind.JS
  );

  const entries = [];

  function captureSpecifier(literalNode) {
    if (!literalNode || !ts.isStringLiteralLike(literalNode)) {
      return;
    }

    entries.push({
      value: literalNode.text,
      start: literalNode.getStart(sourceFile) + 1,
      end: literalNode.getEnd() - 1
    });
  }

  function visit(node) {
    if (ts.isImportDeclaration(node) && node.moduleSpecifier) {
      captureSpecifier(node.moduleSpecifier);
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
      captureSpecifier(node.moduleSpecifier);
    } else if (ts.isCallExpression(node) && node.arguments.length === 1) {
      const argumentNode = node.arguments[0];
      if (ts.isStringLiteralLike(argumentNode)) {
        if (ts.isIdentifier(node.expression) && node.expression.text === 'require') {
          captureSpecifier(argumentNode);
        }

        if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
          captureSpecifier(argumentNode);
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);

  return entries;
}

function applyStringReplacements(input, replacements) {
  if (!replacements || replacements.length === 0) {
    return input;
  }

  let output = input;
  const sortedReplacements = [...replacements].sort((left, right) => right.start - left.start);

  for (const replacement of sortedReplacements) {
    output = `${output.slice(0, replacement.start)}${replacement.value}${output.slice(replacement.end)}`;
  }

  return output;
}

function isRelativeSpecifier(specifier) {
  return specifier.startsWith('./') || specifier.startsWith('../');
}

function isPotentiallyResolved(resolvedBasePath, outputFilesSet) {
  const candidates = new Set([
    resolvedBasePath,
    `${resolvedBasePath}.js`,
    `${resolvedBasePath}.cjs`,
    `${resolvedBasePath}.mjs`,
    `${resolvedBasePath}.json`,
    `${resolvedBasePath}.node`,
    `${resolvedBasePath}/index.js`,
    `${resolvedBasePath}/index.cjs`,
    `${resolvedBasePath}/index.mjs`,
    `${resolvedBasePath}/index.json`,
    `${resolvedBasePath}/index.node`
  ]);

  for (const candidate of candidates) {
    if (outputFilesSet.has(candidate)) {
      return true;
    }
  }

  return false;
}

function transpileToCommonJs(code, filePath) {
  const result = ts.transpileModule(code, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2020,
      module: ts.ModuleKind.CommonJS,
      moduleResolution: ts.ModuleResolutionKind.Node10,
      esModuleInterop: true,
      allowSyntheticDefaultImports: true,
      resolveJsonModule: true,
      sourceMap: false,
      inlineSourceMap: false,
      removeComments: false,
      skipLibCheck: true
    },
    fileName: filePath,
    reportDiagnostics: true
  });

  if (result.diagnostics && result.diagnostics.length > 0) {
    const critical = result.diagnostics.filter((diag) => diag.category === ts.DiagnosticCategory.Error);
    if (critical.length > 0) {
      const message = critical
        .map((diag) => ts.flattenDiagnosticMessageText(diag.messageText, '\n'))
        .join('\n');
      throw new Error(`TypeScript/JavaScript transpile error in ${filePath}:\n${message}`);
    }
  }

  return result.outputText;
}

function rewriteRelativeImportExtensions(code) {
  const parsedSpecifiers = parseModuleSpecifiers(code, 'rewrite.js');
  const replacements = [];

  for (const entry of parsedSpecifiers) {
    if (!isRelativeSpecifier(entry.value)) {
      continue;
    }

    const replacedSpecifier = entry.value.replace(/\.(ts|tsx|mts|cts|mjs|cjs|jsx)$/i, '.js');
    if (replacedSpecifier !== entry.value) {
      replacements.push({
        start: entry.start,
        end: entry.end,
        value: replacedSpecifier
      });
    }
  }

  return applyStringReplacements(code, replacements);
}

function obfuscateCode(code) {
  const result = JavaScriptObfuscator.obfuscate(code, {
    compact: true,
    simplify: true,
    target: 'node',
    renameGlobals: false,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayShuffle: true,
    stringArrayThreshold: 0.75,
    transformObjectKeys: true,
    selfDefending: false,
    sourceMap: false,
    numbersToExpressions: true,
    deadCodeInjection: false,
    controlFlowFlattening: false,
    unicodeEscapeSequence: false,
    identifierNamesGenerator: 'hexadecimal'
  });

  return result.getObfuscatedCode();
}

function createByteEncodedWrapper(obfuscatedCode, relativeOutputPath, integrityScriptExpectedHash) {
  const bytesText = Array.from(Buffer.from(obfuscatedCode, 'utf8')).join(',');
  const integrityImport = getIntegrityImportPath(relativeOutputPath);

  return `'use strict';\nconst fs = require('fs');\nconst crypto = require('crypto');\nconst __boltIntegrityPath = require.resolve('${integrityImport}');\nconst __boltIntegrityActualHash = crypto.createHash('sha256').update(fs.readFileSync(__boltIntegrityPath)).digest('hex');\nif (__boltIntegrityActualHash !== '${integrityScriptExpectedHash}') {\n  throw new Error('[BOLT-INTEGRITY] Integrity checker file was modified: ' + __boltIntegrityPath);\n}\nconst __boltIntegrity = require('${integrityImport}');\n__boltIntegrity.verify();\nconst __boltBytes = [${bytesText}];\nconst __boltSource = Buffer.from(__boltBytes).toString('utf8');\nmodule._compile(__boltSource, __filename);\n`;
}

function getIntegrityImportPath(relativeOutputPath) {
  const fromDir = path.dirname(relativeOutputPath);
  let relativePath = normalizeSlashes(path.relative(fromDir, '__bolt_integrity.js'));

  if (!relativePath.startsWith('.')) {
    relativePath = `./${relativePath}`;
  }

  return relativePath;
}

function buildIntegrityScript() {
  return `'use strict';\nconst fs = require('fs');\nconst path = require('path');\nconst crypto = require('crypto');\n\nconst manifest = require('./__bolt_manifest.json');\nlet checked = false;\n\nfunction sha256(filePath) {\n  const content = fs.readFileSync(filePath);\n  return crypto.createHash('sha256').update(content).digest('hex');\n}\n\nfunction createManifestPayload(data) {\n  return JSON.stringify({\n    algorithm: data.algorithm,\n    generatedAt: data.generatedAt,\n    files: data.files || {},\n    systemFiles: data.systemFiles || {}\n  });\n}\n\nfunction timingSafeEqualHex(leftHex, rightHex) {\n  const left = Buffer.from(String(leftHex || ''), 'hex');\n  const right = Buffer.from(String(rightHex || ''), 'hex');\n  if (left.length !== right.length) {\n    return false;\n  }\n\n  return crypto.timingSafeEqual(left, right);\n}\n\nfunction verifyManifestSignature() {\n  const hasSignature = !!(manifest && manifest.signature && manifest.signatureAlgorithm === 'hmac-sha256');\n  if (!hasSignature) {\n    return;\n  }\n\n  const signingSecret = process.env.BOLT_HASH_SECRET || '';\n  if (!signingSecret) {\n    crash('Manifest is signed but BOLT_HASH_SECRET is missing');\n  }\n\n  const expectedSignature = crypto.createHmac('sha256', signingSecret).update(createManifestPayload(manifest)).digest('hex');\n  if (!timingSafeEqualHex(expectedSignature, manifest.signature)) {\n    crash('Manifest signature mismatch. The manifest may have been forged.');\n  }\n}\n\nfunction crash(message) {\n  const finalMessage = '[BOLT-INTEGRITY] ' + message;\n  console.error(finalMessage);\n  throw new Error(finalMessage);\n}\n\nfunction verifyEntries(entries) {\n  for (const [relativeFile, expectedHash] of Object.entries(entries || {})) {\n    const absoluteFile = path.join(__dirname, relativeFile);\n\n    if (!fs.existsSync(absoluteFile)) {\n      crash('Missing protected file: ' + relativeFile);\n    }\n\n    const actualHash = sha256(absoluteFile);\n    if (actualHash !== expectedHash) {\n      crash('File has been modified or corrupted: ' + relativeFile);\n    }\n  }\n}\n\nfunction verify() {\n  if (checked) {\n    return;\n  }\n\n  checked = true;\n  verifyManifestSignature();\n  verifyEntries(manifest && manifest.files ? manifest.files : {});\n  verifyEntries(manifest && manifest.systemFiles ? manifest.systemFiles : {});\n}\n\nmodule.exports = { verify };\n`;
}

async function hashFile(filePath) {
  const fileBuffer = await fse.readFile(filePath);
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

function hashText(text) {
  return crypto.createHash('sha256').update(Buffer.from(String(text), 'utf8')).digest('hex');
}

function withJsExtension(relativePath) {
  const parsed = path.parse(relativePath);
  return normalizeSlashes(path.join(parsed.dir, `${parsed.name}.js`));
}

function parseCommaList(text) {
  return text
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => item.replace(/\\+/g, '/'));
}

function normalizeSlashes(inputPath) {
  return inputPath.split(path.sep).join('/');
}

function normalizeRelativePath(inputPath) {
  const normalized = normalizeSlashes(path.posix.normalize(String(inputPath || '')));
  if (normalized === '.') {
    return '';
  }

  return normalized.replace(/^\.\//, '');
}

function isSubPath(targetPath, parentPath) {
  const relativePath = path.relative(parentPath, targetPath);
  return !!relativePath && !relativePath.startsWith('..') && !path.isAbsolute(relativePath);
}

async function isDirectory(dirPath) {
  try {
    const stats = await fse.stat(dirPath);
    return stats.isDirectory();
  } catch (error) {
    return false;
  }
}

async function readOutputPackageJson(packageJsonPath) {
  if (!fs.existsSync(packageJsonPath)) {
    return null;
  }

  try {
    return JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  } catch (error) {
    return null;
  }
}

function detectDefaultStartInput(cwd) {
  const candidates = [
    'index.js',
    'main.js',
    'server.js',
    'src/index.js',
    'src/main.js',
    'src/server.js',
    'main.py',
    'app.py',
    'src/main.py',
    'src/app.py'
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(path.join(cwd, candidate))) {
      return normalizeSlashes(candidate);
    }
  }

  return '';
}

async function promptStartCommandInput(cwd, defaultStartInput) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    const userInput = await askText(
      rl,
      `No start script in package.json at ${cwd}. Enter a startup command or main file (supports args)`,
      defaultStartInput
    );

    if (!userInput || !userInput.trim()) {
      throw new Error('A startup command is required when package.json has no scripts.start');
    }

    return userInput.trim();
  } finally {
    rl.close();
  }
}

function normalizeStartCommandInput(inputText) {
  const trimmed = String(inputText || '').trim();
  if (!trimmed) {
    throw new Error('Startup command cannot be empty');
  }

  const tokenMatch = trimmed.match(/^("[^"]+"|'[^']+'|\S+)([\s\S]*)$/);
  if (!tokenMatch) {
    return trimmed;
  }

  const rawToken = tokenMatch[1];
  const rest = tokenMatch[2] || '';
  const plainToken = stripSurroundingQuotes(rawToken);
  const ext = path.extname(plainToken).toLowerCase();

  if (TYPESCRIPT_EXTENSIONS.has(ext)) {
    const jsToken = plainToken.replace(/\.(ts|tsx|mts|cts)$/i, '.js');
    const renderedToken = quoteIfNeeded(jsToken);
    return `node ${renderedToken}${rest}`.trim();
  }

  if (NODE_ENTRY_EXTENSIONS.has(ext)) {
    return `node ${rawToken}${rest}`.trim();
  }

  if (PYTHON_ENTRY_EXTENSIONS.has(ext)) {
    return `python ${rawToken}${rest}`.trim();
  }

  return trimmed;
}

function stripSurroundingQuotes(text) {
  if (!text || text.length < 2) {
    return text;
  }

  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith('\'') && text.endsWith('\''))) {
    return text.slice(1, -1);
  }

  return text;
}

function quoteIfNeeded(text) {
  if (/\s/.test(text)) {
    return `"${text.replace(/"/g, '\\"')}"`;
  }

  return text;
}

function appendArgsToShellCommand(baseCommand, extraArgs) {
  if (!Array.isArray(extraArgs) || extraArgs.length === 0) {
    return baseCommand;
  }

  const renderedArgs = extraArgs.map((arg) => quoteIfNeeded(String(arg)));
  return `${baseCommand} ${renderedArgs.join(' ')}`.trim();
}

async function runScript(scriptName, extraArgs) {
  printBanner();

  const cwd = process.cwd();
  const manifestPath = path.join(cwd, '__bolt_manifest.json');

  if (!fs.existsSync(manifestPath)) {
    throw new Error(
      `No __bolt_manifest.json found in the current directory (${cwd}).\n` +
      `Run 'bolt' first to protect your project, then run this command from the output directory.`
    );
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const files = manifest && manifest.files ? manifest.files : {};
  const systemFiles = manifest && manifest.systemFiles ? manifest.systemFiles : {};
  const totalFiles = Object.keys(files).length + Object.keys(systemFiles).length;

  let runtimeSigningSecret = process.env.BOLT_HASH_SECRET || '';
  if (isManifestSigned(manifest)) {
    if (!runtimeSigningSecret) {
      runtimeSigningSecret = await askForRuntimeSigningSecret();
    }

    if (!verifyManifestSignature(manifest, runtimeSigningSecret)) {
      throw new Error('[BOLT-INTEGRITY] Manifest signature mismatch. The manifest may have been forged.');
    }
  } else {
    console.log(chalk.yellow('Warning: Manifest is not signed. Re-hashing attacks are possible. Rebuild with signed manifest protection enabled.'));
  }

  console.log(chalk.cyan(`Verifying integrity of ${totalFiles} protected file(s)...`));

  for (const [relativeFile, expectedHash] of [...Object.entries(files), ...Object.entries(systemFiles)]) {
    const absoluteFile = path.join(cwd, relativeFile);

    if (!fs.existsSync(absoluteFile)) {
      throw new Error(`[BOLT-INTEGRITY] Missing protected file: ${relativeFile}`);
    }

    const content = fs.readFileSync(absoluteFile);
    const actualHash = crypto.createHash('sha256').update(content).digest('hex');
    if (actualHash !== expectedHash) {
      throw new Error(`[BOLT-INTEGRITY] File has been modified or corrupted: ${relativeFile}`);
    }
  }

  console.log(chalk.green(`✅ Integrity verified (${totalFiles} file(s)). Launching '${scriptName}'...`));
  console.log('');

  if (scriptName === 'start') {
    const packageJsonPath = path.join(cwd, 'package.json');
    const packageJson = await readOutputPackageJson(packageJsonPath);
    const hasStartScript = !!(
      packageJson
      && packageJson.scripts
      && typeof packageJson.scripts === 'object'
      && typeof packageJson.scripts.start === 'string'
      && packageJson.scripts.start.trim().length > 0
    );

    if (!hasStartScript) {
      const defaultStartInput = detectDefaultStartInput(cwd);
      const userInput = await promptStartCommandInput(cwd, defaultStartInput);
      const normalizedCommand = normalizeStartCommandInput(userInput);
      const fullCommand = appendArgsToShellCommand(normalizedCommand, extraArgs);

      console.log(chalk.cyan(`No 'scripts.start' found. Running custom command: ${fullCommand}`));

      const _isWin = process.platform === 'win32';
      // Split command string into argv tokens (handles quoted args).
      const _rawParts = fullCommand.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [fullCommand];
      const _cmdParts = _rawParts.map((tok) => {
        if (tok.length >= 2) {
          if (tok[0] === '"' && tok[tok.length - 1] === '"') return tok.slice(1, -1).replace(/\\"/g, '"');
          if (tok[0] === "'" && tok[tok.length - 1] === "'") return tok.slice(1, -1).replace(/\\'/g, "'");
        }
        return tok;
      });
      // Use cmd /c on Windows (avoids DEP0190: shell:true + args array).
      const _spawnCmd = _isWin ? 'cmd' : _cmdParts[0];
      const _spawnArgs = _isWin ? ['/c', ..._cmdParts] : _cmdParts.slice(1);

      const customChild = spawn(_spawnCmd, _spawnArgs, {
        cwd,
        stdio: 'inherit',
        env: {
          ...process.env,
          ...(isManifestSigned(manifest) ? { BOLT_HASH_SECRET: runtimeSigningSecret } : {})
        },
        shell: false
      });

      customChild.on('error', (err) => {
        console.error(chalk.red(`❌ Failed to launch custom start command: ${err.message}`));
        process.exit(1);
      });

      customChild.on('exit', (code) => {
        process.exit(code ?? 0);
      });

      return;
    }
  }

  const npmArgs = scriptName === 'start'
    ? ['start', ...extraArgs]
    : ['run', scriptName, ...extraArgs];
  // On Windows use cmd /c to launch npm without shell:true + args (avoids DEP0190).
  const _win = process.platform === 'win32';
  const _spawnCmd = _win ? 'cmd' : 'npm';
  const _spawnArgs = _win ? ['/c', 'npm', ...npmArgs] : npmArgs;

  const child = spawn(_spawnCmd, _spawnArgs, {
    cwd,
    stdio: 'inherit',
    env: {
      ...process.env,
      ...(isManifestSigned(manifest) ? { BOLT_HASH_SECRET: runtimeSigningSecret } : {})
    },
    shell: false
  });

  child.on('error', (err) => {
    console.error(chalk.red(`❌ Failed to launch npm script: ${err.message}`));
    process.exit(1);
  });

  child.on('exit', (code) => {
    process.exit(code ?? 0);
  });
}

async function patchOutputPackageJson(outputDir) {
  const pkgPath = path.join(outputDir, 'package.json');
  if (!(await fse.pathExists(pkgPath))) {
    return;
  }

  const pkg = await fse.readJson(pkgPath);
  if (!pkg.scripts || typeof pkg.scripts !== 'object') {
    return;
  }

  let modified = false;
  for (const [key, value] of Object.entries(pkg.scripts)) {
    if (typeof value === 'string') {
      const updated = value.replace(/\.(ts|tsx|mts|cts)(?=[\s"'`]|$)/g, '.js');
      if (updated !== value) {
        pkg.scripts[key] = updated;
        modified = true;
      }
    }
  }

  if (modified) {
    await fse.writeJson(pkgPath, pkg, { spaces: 2 });
  }
}

async function askForRuntimeSigningSecret() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    const secret = await askText(rl, 'Manifest is signed. Enter BOLT_HASH_SECRET to continue', '');
    if (!secret || !secret.trim()) {
      throw new Error('BOLT_HASH_SECRET is required for signed manifests');
    }

    return secret.trim();
  } finally {
    rl.close();
  }
}

// ======= Help =======
function showHelp() {
  printBanner();
  console.log('');
  console.log(chalk.white('Commands:'));
  console.log(chalk.cyan('  bolt                        Protect project (obfuscate + SHA-256 manifest)'));
  console.log(chalk.cyan('  bolt start                  Run protected project with integrity check'));
  console.log(chalk.cyan('  bolt run <script>           Run npm script with integrity check'));
  console.log(chalk.cyan('  bolt help | bolt -h         Show this help'));
  console.log('');
  console.log(chalk.white('Protect workflow:'));
  console.log(chalk.cyan('  cd my-app'));
  console.log(chalk.cyan('  bolt                        TUI: choose source dir, output dir, signing secret'));
  console.log(chalk.cyan('  cd protected_output'));
  console.log(chalk.cyan('  bolt start                  Verify SHA-256 integrity + HMAC signature, then launch'));
  console.log('');
  console.log(chalk.white('Manifest signing secret  (1 key — lock on protect, unlock on start):'));
  console.log(chalk.cyan('  Auto-generated on first `bolt` run. Copy and keep it safe.'));
  console.log(chalk.cyan('  Required by `bolt start` to verify the HMAC-signed manifest.'));
  console.log(chalk.cyan('  Supply via:  BOLT_HASH_SECRET=<hex>  (env var — skips prompt)'));
  console.log(chalk.cyan('  Or enter it interactively when `bolt start` prompts.'));
  console.log(chalk.cyan('  Without a secret the manifest is unsigned: tampering is detectable'));
  console.log(chalk.cyan('  via SHA-256 but not cryptographically authenticated (HMAC skipped).'));
  console.log('');
  console.log(chalk.white('Environment variables:'));
  console.log(chalk.cyan('  BOLT_HASH_SECRET=<hex>      Manifest signing secret (overrides prompt)'));
  console.log('');
  console.log(chalk.white('Supported project types (free edition):'));
  console.log(chalk.cyan('  Node.js + TypeScript server-side (Express, Fastify, NestJS, Koa, Hapi, ...)'));
  console.log(chalk.yellow('  SPA/SSR frameworks (React, Vue, Nuxt, Next.js) → upgrade to Premium'));
  console.log('');
  console.log(chalk.white('Upgrade to Premium for:'));
  console.log(chalk.cyan('  License key management + heartbeat kill timer + anti-cheat'));
  console.log(chalk.cyan('  BGit version control  (bolt commit / bolt pull / bolt log)'));
  console.log(chalk.cyan('  SPA/SSR dist integrity  (bolt protect-dist + bolt start-spa)'));
  console.log(chalk.cyan('  CI/CD integration + monthly build quota tracking'));
  console.log(chalk.cyan('  \u2192 https://hash.boltopen.com/pricing'));
  console.log('');
}

if (require.main === module) {
  const [, , subcommand, ...subArgs] = process.argv;

  if (subcommand === 'start') {
    runScript('start', subArgs).catch((error) => {
      console.error(chalk.red(`\u274c Error: ${error.message}`));
      process.exit(1);
    });
  } else if (subcommand === 'run' && subArgs.length > 0) {
    const [scriptName, ...restArgs] = subArgs;
    runScript(scriptName, restArgs).catch((error) => {
      console.error(chalk.red(`\u274c Error: ${error.message}`));
      process.exit(1);
    });
  } else if (subcommand === 'help' || subcommand === '-h' || subcommand === '--help') {
    showHelp();
  } else if (subcommand && subcommand !== 'protect') {
    console.error(chalk.red(`\u274c Unknown command: ${subcommand}`));
    console.error(chalk.yellow('Run `bolt help` or `bolt -h` to see available commands.'));
    process.exit(1);
  } else {
    main().catch((error) => {
      console.error(chalk.red(`\u274c Error: ${error.message}`));
      process.exit(1);
    });
  }
}

module.exports = {
  protectProject,
  transpileToCommonJs,
  rewriteRelativeImportExtensions,
  createByteEncodedWrapper,
  buildIntegrityScript,
  runScript,
  patchOutputPackageJson,
  detectFramework
};
