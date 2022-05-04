const fs = require('fs')

const lines = fs.readFileSync(process.argv[2]).toString().split('\n')

const final_bytes = []

const hex2bin = (hex) => {
    return (parseInt(hex, 16).toString(2)).padStart(8, '0')
}


//// Note: OBJDump leaves 2 blank lines at the end by default
//// Option to ignore epilogue lines, TODO make this auto detect 
const ignoreBottomLines = parseInt(process.argv[4])

lines.slice(7, lines.length-2-ignoreBottomLines).forEach(line => {
    const bytes = line.split('\t')[1]
    const first_byte = bytes.split(' ')[0]
    const second_byte = bytes.split(' ')[1]

    const first_byte_bin_string = hex2bin(first_byte)

    const opcode = parseInt(first_byte_bin_string.substring(0, 6), 2)
    
    if (opcode == 18) { //bl
        final_bytes.push(`${48}`)
    } else if (opcode == 14 || opcode == 15) {   /// addi, li, addis, lis
        final_bytes.push(`${first_byte} ${second_byte}`)
    } else {
        final_bytes.push(bytes)
    }
})

fs.writeFileSync(process.argv[3], final_bytes.join('\n'))
