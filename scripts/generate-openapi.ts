import fs from 'fs';
import path from 'path';

const source = path.join(__dirname, '../openapi/openapi.json');
const target = path.join(__dirname, '../openapi.json');

fs.copyFileSync(source, target);
console.log('OpenAPI spec copied to openapi.json');
