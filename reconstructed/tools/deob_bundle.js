#!/usr/bin/env node
// Lightweight helper used while reconstructing rel/*.js. It decodes the common
// numeric base36/string-builder patterns seen in the release bundles.
const fs = require('fs');

if (process.argv.length < 4) {
  console.error('usage: node reconstructed/tools/deob_bundle.js <input.js> <output.js>');
  process.exit(2);
}

let s = fs.readFileSync(process.argv[2], 'utf8');
const q = JSON.stringify;
function b36hex(hex) {
  let n = BigInt(hex);
  if (n === 0n) return '0';
  const digits = '0123456789abcdefghijklmnopqrstuvwxyz';
  let out = '';
  while (n > 0n) {
    out = digits[Number(n % 36n)] + out;
    n /= 36n;
  }
  return out;
}

let old;
do {
  old = s;
  s = s.replace(/(\d+)\.\.toString\(36\)\.toLowerCase\(\)\.split\(""\)\.map\(function\((\w+)\)\{return String\.fromCharCode\(\2\.charCodeAt\(\)\+(-?\d+)\)\}\)\.join\(""\)/g,
    (_m, num, _v, shift) => q(Number(num).toString(36).toLowerCase().split('').map(c => String.fromCharCode(c.charCodeAt(0) + Number(shift))).join('')));
  s = s.replace(/(\d+)\.\.toString\(36\)\.toLowerCase\(\)/g,
    (_m, num) => q(Number(num).toString(36).toLowerCase()));
  s = s.replace(/\((0x[0-9a-fA-F]+)\)\.toString\(36\)\.toLowerCase\(\)/g,
    (_m, hex) => q(b36hex(hex)));
  s = s.replace(/function\(\)\{var (\w+)=Array\.prototype\.slice\.call\(arguments\),(\w+)=\1\.shift\(\);return \1\.reverse\(\)\.map\(function\(\w+,(\w+)\)\{return String\.fromCharCode\(\w+-\2-(\d+)-\3\)\}\)\.join\(""\)\}\(([-\d,]+)\)/g,
    (_m, _arr, _baseName, _idx, off, args) => {
      const nums = args.split(',').map(Number);
      const base = nums.shift();
      const rev = nums.reverse();
      let out = '';
      for (let i = 0; i < rev.length; i++) out += String.fromCharCode(rev[i] - base - Number(off) - i);
      return q(out);
    });
  s = s.replace(/"([^"]*)"\+"([^"]*)"/g, (_m, a, b) => q(a + b));
} while (s !== old);

fs.writeFileSync(process.argv[3], s);
