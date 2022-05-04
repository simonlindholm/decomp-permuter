const fs = require('fs')

const lines = fs.readFileSync(process.argv[2]).toString().split('\n')

let lastBlrLine = -1

for (let index = 7; index < lines.length; index++) {
    const opcode = lines[index].split('\t')[2].split(' ')[0]
    if (opcode == "blr") lastBlrLine = index
    if (opcode == ".long") break
}

const output = lines.slice(0, lastBlrLine + 1).join('\n')
fs.writeFileSync(process.argv[3], output + '\n\n')