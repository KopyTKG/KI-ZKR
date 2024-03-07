import { iCypher } from '@/interface/iCypher'
import { randomBytes } from 'crypto'
import { Buffer } from 'buffer'

// klic je 128b
/*
    4x8b na rundu

    8 rund + 1 opakovani (9 rund)
*/

// blok je 64b a deli se na 4x16b

class IDEA implements iCypher {
 generateKey(): string {
  const buffer = randomBytes(16)
  return buffer.toString('base64')
 }
 // Function to rotate bits left
 private rotateLeft(bits: number[], count: number): number[] {
  const length = bits.length
  const result = new Array(length)
  for (let i = 0; i < length; ++i) {
   result[i] = bits[(i + count) % length]
  }
  return result
 }

 // Function to convert base64 string to a binary array
 private base64ToBinaryArray(base64: string): number[] {
  const binaryString = Buffer.from(base64, 'base64').toString('binary')
  const binaryArray = []
  for (let i = 0; i < binaryString.length; i++) {
   const charCode = binaryString.charCodeAt(i)
   for (let j = 7; j >= 0; --j) {
    binaryArray.push((charCode >> j) & 1)
   }
  }
  return binaryArray
 }
 private removeCommas(array: string): string[]  {
    const arr = array.split("")
    return arr.map(subkey => subkey.replace(/,/g, ""));
  };
  
 // Function to generate IDEA subkeys from base64 encoded 128-bit key
 private generateIDEASubkeys(base64Key: string): number[] {
  let binaryKey = this.base64ToBinaryArray(base64Key)
  const subkeys: number[] = []

  for (let i = 0; i < 6.5; ++i) {
   // 6 full cycles + 1 half cycle for 52 subkeys
   for (let j = 0; j < 8 && subkeys.length < 52; ++j) {
    const startBit = j * 16
    const subkeyBits = binaryKey.slice(startBit, startBit + 16)
    const subkeyInt = parseInt(subkeyBits.join("").toString(), 2)
    subkeys.push(subkeyInt)
   }
   // Rotate the whole key by 25 bits to the left for the next cycle
   binaryKey = this.rotateLeft(binaryKey, 25)
  }

  return subkeys
 }
 private algorithm(key: string, data: string): number[] {
    const segments = this.generateIDEASubkeys(key)


    const blocks: number[] = [];
        // Split 'base' into blocks of 2 characters each
        for (let i = 0; i < data.length; i += 2) {
            const block = data.substring(i, i + 2);
            const code1 = block.charCodeAt(0);
            const code2 = block.charCodeAt(1);
        
            // Combine the two codes into a 16-bit integer
            // Shift the first character's code 8 bits to the left and OR it with the second character's code
            const combinedInt = (code1 << 8) | code2;

            blocks.push(combinedInt);
        }
    for (let i = 0; i < 8; i++) {
        // layer 1
        blocks[0] = blocks[0] * segments[(8*i)]
        blocks[1] = blocks[1] + segments[(8*i) + 1]
        blocks[2] = blocks[2] + segments[(8*i) + 2]
        blocks[3] = blocks[3] * segments[(8*i) + 3]
        //layer 2
        const middle: number[] = []
        middle.push(blocks[0] ^ blocks[2])
        middle.push(blocks[1] ^ blocks[3])
        //layer 3
        middle[0] = middle[0] * segments[(8*i) + 5]
        middle[1] = middle[0] + middle[1]
        middle[1] = middle[1] * segments[(8*i) + 6]
        middle[0] = middle[0] + middle[1]
        //layer 4
        blocks[0] = blocks[0] ^ middle[1]
        blocks[1] = blocks[1] ^ middle[0]
        blocks[2] = blocks[2] ^ middle[1]
        blocks[3] = blocks[3] ^ middle[0]
        
        // swap
        const tmp = blocks[1]
        blocks[1] =  blocks[2]
        blocks[2] = tmp

    }


    // layer 1
    blocks[0] = blocks[0] * segments[(8*7)]
    blocks[1] = blocks[1] + segments[(8*7) + 1]
    blocks[2] = blocks[2] + segments[(8*7) + 2]
    blocks[3] = blocks[3] * segments[(8*7) + 3]

    let newBase = ''
    blocks.forEach((chars) => {    
        const code1 = (chars >> 8) & 0xFF;
        // Extract the second character's code by masking out the first 8 bits
        const code2 = chars & 0xFF;
        
        // Convert ASCII codes back to characters and concatenate them
        const char1 = String.fromCharCode(code1);
        const char2 = String.fromCharCode(code2);
        
        newBase += char1 + char2;
    })

    return blocks
     }
 
 encode(key: string, data: string): string {
  // Define the size of each chunk in characters, assuming ASCII encoding (8 characters = 64 bits)
  const chunkSize = 8;
  // Initialize an array to hold the chunks
  const chunks: string[] = [];
  // Loop through the string, slicing it into chunks of the specified size
  for (let i = 0; i < data.length; i += chunkSize) {
      const chunk = data.slice(i, i + chunkSize);
      chunks.push(chunk);
  }

  while(chunks[chunks.length-1].length < 8) {
    chunks[chunks.length-1] += "0"
  }
  let encodedString = ""
  chunks.forEach((chunk) => {
        const str = this.algorithm(key, chunk)
        console.log(str)
  })
  return encodedString
 }

 decode(key: string, data: string): string {
  throw new Error('Not implemented')
 }
}

export default IDEA
