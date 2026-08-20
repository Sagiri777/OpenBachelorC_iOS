mkdir tmp\reconstructed
call npx frida-compile -S reconstructed\script\java\index.ts -o tmp\reconstructed\java.js
call npx frida-compile -S reconstructed\script\native\index.ts -o tmp\reconstructed\native.js
call npx frida-compile -S reconstructed\script\extra\index.ts -o tmp\reconstructed\extra.js
call npx frida-compile -S reconstructed\script\trainer\index.ts -o tmp\reconstructed\trainer.js
pause
