/**
 * AetherRE Webcrack Worker (CJS)
 * Unpacks Webpack/Browserify bundles, un-flattens control flow, and deobfuscates JS arrays.
 */

const fs = require('fs');
const path = require('path');
const { webcrack } = require('../node_modules/webcrack');

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.error(JSON.stringify({
      success: false,
      error: "Usage: node webcrack_worker.cjs <input_js_path> <output_dir>"
    }));
    process.exit(1);
  }

  const inputPath = path.resolve(args[0]);
  const outputDir = path.resolve(args[1]);

  if (!fs.existsSync(inputPath)) {
    console.error(JSON.stringify({
      success: false,
      error: `Input file does not exist: ${inputPath}`
    }));
    process.exit(1);
  }

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const rawCode = fs.readFileSync(inputPath, 'utf-8');
  const startTime = Date.now();

  try {
    const result = await webcrack(rawCode, {
      unpack: true,
      jsx: true,
      deobfuscate: true,
      unminify: false,
      mangle: false,
    });

    const elapsedMs = Date.now() - startTime;
    const deobfuscatedPath = path.join(outputDir, 'deobfuscated.js');
    fs.writeFileSync(deobfuscatedPath, result.code, 'utf-8');

    let isBundle = false;
    let bundleType = "none";
    let moduleCount = 0;
    const moduleList = [];

    if (result.bundle) {
      isBundle = true;
      bundleType = result.bundle.type || "unknown";
      
      // Save all extracted modules into outputDir/modules/
      const modulesDir = path.join(outputDir, 'modules');
      await result.save(outputDir);

      if (result.bundle.modules) {
        for (const [id, mod] of result.bundle.modules) {
          moduleCount++;
          moduleList.push({
            id: String(id),
            path: mod.path || `module_${id}.js`,
            size: (mod.code || '').length,
          });
        }
      }
    }

    const manifest = {
      success: true,
      input_path: inputPath,
      output_dir: outputDir,
      elapsed_ms: elapsedMs,
      original_size: rawCode.length,
      deobfuscated_size: result.code.length,
      is_bundle: isBundle,
      bundle_type: bundleType,
      module_count: moduleCount,
      modules: moduleList,
    };

    const manifestPath = path.join(outputDir, 'webcrack_manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');

    console.log(JSON.stringify(manifest));
    process.exit(0);

  } catch (err) {
    console.error(JSON.stringify({
      success: false,
      error: err.stack || err.message,
    }));
    process.exit(1);
  }
}

main();
