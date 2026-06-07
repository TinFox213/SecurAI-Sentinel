import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rootDir = __dirname;
const outputFilename = 'ARCHIVED_DOCUMENTATION.md';
const outputPath = path.join(rootDir, outputFilename);

const skipFiles = [
  'README.md',
  'START_HERE.md',
  'QUICKSTART.md',
  'QUICK_START.md',
  'APPLICATION_OVERVIEW.md',
  outputFilename
];

console.log('Starting markdown consolidation...');

const files = fs.readdirSync(rootDir);
const mdFiles = files.filter(file => file.endsWith('.md') && !skipFiles.includes(file) && fs.statSync(path.join(rootDir, file)).isFile());

let combinedContent = '# Sentinel-Flows Archived Documentation\n\nThis document contains the consolidated contents of various previous phase guides, mission reports, and documentation artifacts.\n\n';

for (const file of mdFiles) {
  const filePath = path.join(rootDir, file);
  console.log(`Reading ${file}...`);
  const content = fs.readFileSync(filePath, 'utf-8');
  
  combinedContent += `\n\n---\n\n## Source File: ${file}\n\n`;
  combinedContent += content;
  
  try {
    fs.unlinkSync(filePath);
    console.log(`Deleted original file: ${file}`);
  } catch (err) {
    console.error(`Failed to delete ${file}:`, err);
  }
}

fs.writeFileSync(outputPath, combinedContent, 'utf-8');
console.log(`Successfully combined ${mdFiles.length} files into ${outputFilename}.`);
