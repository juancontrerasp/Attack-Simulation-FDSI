/**
 * ST-11.1 - Detección automática del stack tecnológico del repositorio
 */

const fs = require('fs');
const path = require('path');

const LANGUAGE_EXTENSIONS = {
  '.java': 'Java',
  '.js': 'Node.js',
  '.ts': 'Node.js',
  '.py': 'Python',
  '.rb': 'Ruby',
  '.go': 'Go',
  '.cs': 'C#',
  '.php': 'PHP'
};

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'out', 'build', 'dist', 'target',
  '.gradle', '__pycache__', 'cache', '.venv', 'venv', '.mvn', 'coverage'
]);

function countExtensions(repoPath, counts = {}) {
  let entries;
  try { entries = fs.readdirSync(repoPath); } catch { return counts; }

  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry)) continue;
    const full = path.join(repoPath, entry);
    let stat;
    try { stat = fs.statSync(full); } catch { continue; }

    if (stat.isDirectory()) {
      countExtensions(full, counts);
    } else {
      const ext = path.extname(entry).toLowerCase();
      if (ext) counts[ext] = (counts[ext] || 0) + 1;
    }
  }
  return counts;
}

function detectLanguage(extCounts) {
  const langScores = {};
  for (const [ext, count] of Object.entries(extCounts)) {
    const lang = LANGUAGE_EXTENSIONS[ext];
    if (lang) langScores[lang] = (langScores[lang] || 0) + count;
  }
  if (Object.keys(langScores).length === 0) return null;
  return Object.entries(langScores).sort((a, b) => b[1] - a[1])[0][0];
}

function detectFromPackageJson(repoPath) {
  const candidates = [
    path.join(repoPath, 'package.json'),
    ...findFilesNamed(repoPath, 'package.json', 2)
  ];

  for (const pkgPath of candidates) {
    if (!fs.existsSync(pkgPath)) continue;
    let pkg;
    try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')); } catch { continue; }

    const deps = Object.keys({
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {})
    });

    const framework = detectNodeFramework(deps);
    const database = detectDatabase(deps, []);
    const auth = detectAuth(deps, []);

    if (framework || database || auth) {
      return { framework, database, auth };
    }
  }
  return { framework: null, database: null, auth: null };
}

function detectNodeFramework(deps) {
  if (deps.some(d => d === 'express')) return 'Express';
  if (deps.some(d => d === 'fastify')) return 'Fastify';
  if (deps.some(d => d === 'koa')) return 'Koa';
  if (deps.some(d => d === 'nestjs' || d === '@nestjs/core')) return 'NestJS';
  if (deps.some(d => d === 'hapi' || d === '@hapi/hapi')) return 'Hapi';
  return null;
}

function detectDatabase(deps, fileContents) {
  const all = [...deps, ...fileContents.join(' ').split(/\s+/)];
  const joined = all.join(' ').toLowerCase();
  if (/(mongoose|mongodb)/.test(joined)) return 'MongoDB';
  if (/(sequelize|mariadb|mysql2|mysql)/.test(joined)) return 'MySQL';
  if (/(pg|postgres|postgresql)/.test(joined)) return 'PostgreSQL';
  if (/(sqlite|better-sqlite)/.test(joined)) return 'SQLite';
  if (/(redis|ioredis)/.test(joined)) return 'Redis';
  if (/(hibernate|jdbc|spring-data-jpa|jpa)/.test(joined)) return 'JPA/Hibernate';
  if (/(djang.*database|psycopg2|mysqlclient)/.test(joined)) return 'Django ORM';
  return null;
}

function detectAuth(deps, fileContents) {
  const joined = [...deps, ...fileContents].join(' ').toLowerCase();
  if (/(jsonwebtoken|jwt|jose)/.test(joined)) return 'JWT';
  if (/(passport)/.test(joined)) return 'Passport.js';
  if (/(spring-security|spring.security)/.test(joined)) return 'Spring Security';
  if (/(keycloak)/.test(joined)) return 'Keycloak';
  if (/(oauth2|oauth)/.test(joined)) return 'OAuth2';
  if (/(djangorestframework-simplejwt|rest_framework.authtoken)/.test(joined)) return 'Django JWT';
  return null;
}

function detectFromPomXml(repoPath) {
  const candidates = [
    path.join(repoPath, 'pom.xml'),
    ...findFilesNamed(repoPath, 'pom.xml', 2)
  ];

  for (const pomPath of candidates) {
    if (!fs.existsSync(pomPath)) continue;
    const content = fs.readFileSync(pomPath, 'utf-8').toLowerCase();

    const framework = detectJavaFramework(content);
    const database = detectDatabase([], [content]);
    const auth = detectAuth([], [content]);

    if (framework || database || auth) {
      return { framework, database, auth };
    }
  }
  return null;
}

function detectJavaFramework(content) {
  if (/spring-boot/.test(content)) return 'Spring Boot';
  if (/spring-framework|spring-webmvc/.test(content)) return 'Spring MVC';
  if (/quarkus/.test(content)) return 'Quarkus';
  if (/micronaut/.test(content)) return 'Micronaut';
  if (/jakartaee|javaee|javax\.ws\.rs/.test(content)) return 'Jakarta EE';
  return null;
}

function detectFromRequirementsTxt(repoPath) {
  const candidates = [
    path.join(repoPath, 'requirements.txt'),
    ...findFilesNamed(repoPath, 'requirements.txt', 2)
  ];

  for (const reqPath of candidates) {
    if (!fs.existsSync(reqPath)) continue;
    const content = fs.readFileSync(reqPath, 'utf-8').toLowerCase();

    const framework = detectPythonFramework(content);
    const database = detectDatabase([], [content]);
    const auth = detectAuth([], [content]);

    if (framework || database || auth) {
      return { framework, database, auth };
    }
  }
  return null;
}

function detectPythonFramework(content) {
  if (/django/.test(content)) return 'Django';
  if (/flask/.test(content)) return 'Flask';
  if (/fastapi/.test(content)) return 'FastAPI';
  if (/tornado/.test(content)) return 'Tornado';
  return null;
}

function findFilesNamed(dir, name, maxDepth, depth = 0) {
  if (depth >= maxDepth) return [];
  const results = [];
  let entries;
  try { entries = fs.readdirSync(dir); } catch { return results; }

  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry)) continue;
    const full = path.join(dir, entry);
    let stat;
    try { stat = fs.statSync(full); } catch { continue; }
    if (stat.isDirectory()) {
      results.push(...findFilesNamed(full, name, maxDepth, depth + 1));
    } else if (entry === name) {
      results.push(full);
    }
  }
  return results;
}

function computeConfidence(language, framework, database, auth) {
  let score = 0;
  if (language) score += 40;
  if (framework) score += 30;
  if (database) score += 20;
  if (auth) score += 10;
  if (score >= 80) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function detectStack(repoPath) {
  const extCounts = countExtensions(repoPath);
  const language = detectLanguage(extCounts);

  let framework = null;
  let database = null;
  let auth = null;

  if (language === 'Node.js') {
    const pkg = detectFromPackageJson(repoPath);
    framework = pkg.framework;
    database = pkg.database;
    auth = pkg.auth;
  } else if (language === 'Java') {
    const pom = detectFromPomXml(repoPath);
    if (pom) { framework = pom.framework; database = pom.database; auth = pom.auth; }
    if (!framework && !database && !auth) {
      const pkg = detectFromPackageJson(repoPath);
      framework = framework || pkg.framework;
      database = database || pkg.database;
      auth = auth || pkg.auth;
    }
  } else if (language === 'Python') {
    const req = detectFromRequirementsTxt(repoPath);
    if (req) { framework = req.framework; database = req.database; auth = req.auth; }
  } else {
    const pkg = detectFromPackageJson(repoPath);
    const pom = detectFromPomXml(repoPath);
    const req = detectFromRequirementsTxt(repoPath);
    framework = (pkg && pkg.framework) || (pom && pom.framework) || (req && req.framework) || null;
    database = (pkg && pkg.database) || (pom && pom.database) || (req && req.database) || null;
    auth = (pkg && pkg.auth) || (pom && pom.auth) || (req && req.auth) || null;
  }

  const stackProfile = {
    language: language || null,
    framework: framework || null,
    database: database || null,
    auth: auth || null,
    confidence: computeConfidence(language, framework, database, auth)
  };

  return stackProfile;
}

module.exports = { detectStack };
