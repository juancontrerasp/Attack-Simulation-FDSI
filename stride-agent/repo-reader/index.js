/**
 * ST-01.1 - Lector de repositorio y extractor de contexto
 */

const fs = require('fs');
const path = require('path');

const ALLOWED_EXTENSIONS = new Set([
  '.java', '.js', '.ts', '.py',
  '.yml', '.yaml', '.json', '.properties',
  '.sh', '.md', '.env.example'
]);

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'out', 'build', 'dist',
  'target', '.gradle', '__pycache__', '.idea', '.vscode',
  'cache'  // evita incluir entradas de cache del propio agente
]);

const IGNORED_FILES = new Set([
  '.env', 'passwords.txt', 'package-lock.json',
  'yarn.lock', 'pnpm-lock.yaml',
  'threats-output.json', 'threats-compare-output.json'
]);

// Patrones de nombre de archivo a ignorar (suffix)
const IGNORED_SUFFIXES = ['-output.json'];

const MAX_CONTEXT_CHARS = 200000;
const MAX_FILE_CHARS = 10000;

function shouldIgnoreFile(filePath) {
  const fileName = path.basename(filePath);
  if (IGNORED_FILES.has(fileName)) return true;
  if (IGNORED_SUFFIXES.some(s => fileName.endsWith(s))) return true;
  if (fileName.startsWith('.') && fileName !== '.env.example') return true;
  return false;
}

function shouldIgnoreDir(dirName) {
  return IGNORED_DIRS.has(dirName);
}

function hasAllowedExtension(filePath) {
  if (filePath.endsWith('.env.example')) return true;
  const ext = path.extname(filePath).toLowerCase();
  return ALLOWED_EXTENSIONS.has(ext);
}

function walkDir(dirPath, depth = 0) {
  if (depth > 5) return [];

  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return [];
  }

  let files = [];
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (!shouldIgnoreDir(entry.name)) {
        files = files.concat(walkDir(fullPath, depth + 1));
      }
      continue;
    }

    if (!entry.isFile()) continue;
    if (shouldIgnoreFile(fullPath)) continue;
    if (!hasAllowedExtension(fullPath)) continue;
    files.push(fullPath);
  }

  return files;
}

function readFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    if (content.length > MAX_FILE_CHARS) {
      return content.slice(0, MAX_FILE_CHARS) + '\n... [archivo truncado por tamano]';
    }
    return content;
  } catch {
    return null;
  }
}

function buildStructureTree(repoPath, depth = 0, prefix = '') {
  if (depth > 3) return '';

  let entries;
  try {
    entries = fs.readdirSync(repoPath, { withFileTypes: true });
  } catch {
    return '';
  }

  const visibleEntries = entries.filter(entry => {
    if (entry.name.startsWith('.')) return false;
    if (entry.isDirectory() && shouldIgnoreDir(entry.name)) return false;
    return true;
  });

  let tree = '';
  visibleEntries.forEach((entry, index) => {
    const isLast = index === visibleEntries.length - 1;
    const connector = isLast ? '└── ' : '├── ';
    tree += `${prefix}${connector}${entry.name}\n`;

    if (entry.isDirectory() && depth < 2) {
      const nextPrefix = prefix + (isLast ? '    ' : '│   ');
      tree += buildStructureTree(path.join(repoPath, entry.name), depth + 1, nextPrefix);
    }
  });

  return tree;
}

function readRepository(repoPath) {
  const absolutePath = path.resolve(repoPath);
  if (!fs.existsSync(absolutePath)) {
    throw new Error(`El directorio no existe: ${absolutePath}`);
  }

  const structure = buildStructureTree(absolutePath);
  const allFiles = walkDir(absolutePath);

  const fileContents = [];
  let totalChars = 0;

  for (const filePath of allFiles) {
    if (totalChars >= MAX_CONTEXT_CHARS) break;
    const content = readFile(filePath);
    if (content === null) continue;

    const roomLeft = MAX_CONTEXT_CHARS - totalChars;
    const safeContent = content.length > roomLeft
      ? content.slice(0, roomLeft) + '\n... [contexto truncado por limite global]'
      : content;

    fileContents.push({
      path: path.relative(absolutePath, filePath),
      content: safeContent
    });

    totalChars += safeContent.length;
  }

  return {
    repoPath: absolutePath,
    repoName: path.basename(absolutePath),
    structure,
    files: fileContents,
    totalFiles: fileContents.length,
    totalChars,
    readAt: new Date().toISOString()
  };
}

function buildArchitectureContext(repoContext) {
  let context = '';
  context += `## Repositorio: ${repoContext.repoName}\n\n`;
  context += '### Estructura de carpetas\n';
  context += '```\n' + repoContext.structure + '```\n\n';
  context += '### Archivos de codigo fuente\n\n';

  for (const file of repoContext.files) {
    const ext = path.extname(file.path).slice(1) || 'text';
    context += `#### ${file.path}\n`;
    context += '```' + ext + '\n';
    context += file.content + '\n';
    context += '```\n\n';
  }

  return context;
}

module.exports = {
  readRepository,
  buildArchitectureContext,
  MAX_CONTEXT_CHARS
};
