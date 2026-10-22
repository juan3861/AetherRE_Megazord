/**
 * AetherRE — Real Acorn-Powered ESTree AST Deobfuscation Worker (.cjs).
 *
 * Uses acorn (the production parser behind Webpack, Rollup, ESLint)
 * to parse code into an ESTree AST, avoiding any regex or brace-counting heuristics.
 */

const fs = require('fs');
let acorn;
try {
  acorn = require('acorn');
} catch (e) {
  acorn = require('C:/Users/juanp/node_modules/acorn/dist/acorn.js');
}

function isMinified(name) {
  if (!name || typeof name !== 'string') return false;
  return /^(?:[a-zA-Z]|_[a-zA-Z]|[a-zA-Z0-9]{1,2}|sub_[0-9a-fA-F]+|_0x[0-9a-fA-F]+)$/.test(name);
}

function inferSemanticName(bodyStrings, bodyCalls, originalName) {
  const allStr = bodyStrings.join(' ').toLowerCase();
  const allCalls = bodyCalls.join(' ').toLowerCase();

  if (allStr.includes('enoent') || allCalls.includes('cwd') || allCalls.includes('directory')) {
    return 'validateDirectory';
  }
  if (allStr.includes('--debug') || allStr.includes('verbose')) {
    return 'checkDebugFlags';
  }
  if (allStr.includes('permission') || allStr.includes('bypass')) {
    return 'checkPermissionMode';
  }
  if (allStr.includes('sha256') || allCalls.includes('hash') || allCalls.includes('crypto')) {
    return 'computeHash';
  }
  if (allCalls.includes('log') || allCalls.includes('warn') || allCalls.includes('error')) {
    return 'logMessage';
  }
  if (allCalls.includes('read') || allCalls.includes('stat') || allCalls.includes('fs.')) {
    return 'readResource';
  }
  return `helper_${originalName}`;
}

function extractLiteralsAndCalls(node, strings, calls) {
  if (!node || typeof node !== 'object') return;

  if (node.type === 'Literal') {
    if (typeof node.value === 'string' && node.value.length >= 3) {
      strings.push(node.value);
    }
  } else if (node.type === 'CallExpression') {
    if (node.callee && node.callee.type === 'Identifier') {
      calls.push(node.callee.name);
    } else if (node.callee && node.callee.type === 'MemberExpression' && node.callee.property && node.callee.property.name) {
      calls.push(node.callee.property.name);
    }
  }

  for (const key of Object.keys(node)) {
    if (key === 'parent') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        extractLiteralsAndCalls(item, strings, calls);
      }
    } else if (child && typeof child === 'object') {
      extractLiteralsAndCalls(child, strings, calls);
    }
  }
}

function deobfuscateSource(sourceCode) {
  let ast;
  try {
    ast = acorn.parse(sourceCode, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      ranges: true,
      locations: true,
    });
  } catch (err) {
    try {
      ast = acorn.parse(sourceCode, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        ranges: true,
        locations: true,
      });
    } catch (scriptErr) {
      return {
        success: false,
        error: scriptErr.message,
        functions_renamed: 0,
        renamed_map: {},
        code: sourceCode,
      };
    }
  }

  const functionNodes = [];
  const exportedNames = new Set();

  function walk(node) {
    if (!node || typeof node !== 'object') return;

    if (node.type === 'ExportNamedDeclaration') {
      if (node.specifiers) {
        for (const spec of node.specifiers) {
          if (spec.exported && spec.exported.name) {
            exportedNames.add(spec.exported.name);
          }
        }
      }
      if (node.declaration && node.declaration.id && node.declaration.id.name) {
        exportedNames.add(node.declaration.id.name);
      }
    }

    if (node.type === 'FunctionDeclaration' && node.id) {
      functionNodes.push(node);
    } else if (node.type === 'FunctionExpression' && node.id) {
      functionNodes.push(node);
    }

    for (const key of Object.keys(node)) {
      if (key === 'parent') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) walk(item);
      } else if (child && typeof child === 'object') {
        walk(child);
      }
    }
  }

  walk(ast);

  const replacements = [];
  const renamedMap = {};
  const usedNames = new Set();

  for (const fnNode of functionNodes) {
    const origName = fnNode.id.name;
    if (!isMinified(origName)) continue;

    const strings = [];
    const calls = [];
    extractLiteralsAndCalls(fnNode.body, strings, calls);

    let suggested = inferSemanticName(strings, calls, origName);
    if (usedNames.has(suggested)) {
      suggested = `${suggested}_${origName}`;
    }
    usedNames.add(suggested);
    renamedMap[origName] = suggested;

    replacements.push({
      start: fnNode.id.start,
      end: fnNode.id.end,
      newText: suggested,
    });
  }

  replacements.sort((a, b) => b.start - a.start);

  let newCode = sourceCode;
  for (const rep of replacements) {
    newCode = newCode.slice(0, rep.start) + rep.newText + newCode.slice(rep.end);
  }

  return {
    success: true,
    total_functions_analyzed: functionNodes.length,
    functions_renamed: Object.keys(renamedMap).length,
    renamed_map: renamedMap,
    code: newCode,
  };
}

function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.error('Usage: node acorn_ast_worker.cjs <input_file> [output_file]');
    process.exit(1);
  }

  const inputFile = args[0];
  const outputFile = args[1];

  const source = fs.readFileSync(inputFile, 'utf-8');
  const result = deobfuscateSource(source);

  if (outputFile) {
    fs.writeFileSync(outputFile, result.code, 'utf-8');
  }

  console.log(JSON.stringify({
    success: result.success,
    total_functions_analyzed: result.total_functions_analyzed,
    functions_renamed: result.functions_renamed,
    renamed_map: result.renamed_map,
    error: result.error,
  }));
}

if (require.main === module) {
  main();
}

module.exports = { deobfuscateSource };
