import { iCypher } from '@/interface/iCypher'
import { randomBytes } from 'crypto'
import { Buffer } from 'buffer'
import { log } from 'console'

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
 private removeCommas(array: string): string[] {
  const arr = array.split('')
  return arr.map((subkey) => subkey.replace(/,/g, ''))
 }

 // Function to generate IDEA subkeys from base64 encoded 128-bit key
 private generateIDEASubkeys(base64Key: string): number[] {
  let binaryKey = this.base64ToBinaryArray(base64Key)
  const subkeys: number[] = []

  for (let i = 0; i < 6.5; ++i) {
   // 6 full cycles + 1 half cycle for 52 subkeys
   for (let j = 0; j < 8 && subkeys.length < 52; ++j) {
    const startBit = j * 16
    const subkeyBits = binaryKey.slice(startBit, startBit + 16)
    const subkeyInt = parseInt(subkeyBits.join('').toString(), 2)
    subkeys.push(subkeyInt)
   }
   // Rotate the whole key by 25 bits to the left for the next cycle
   binaryKey = this.rotateLeft(binaryKey, 25)
  }

  return subkeys
 }
 private algorithm(key: string, data: string) {
  const segments = this.generateIDEASubkeys(key)
  let base = data.padEnd(8, 'X')

  const blocks: number[] = []
  // Split 'base' into blocks of 2 characters each
  for (let i = 0; i < data.length; i += 2) {
   const block = base.substring(i, i + 2)
   const code1 = block.charCodeAt(0)
   const code2 = block.charCodeAt(1)

   // Combine the two codes into a 16-bit integer
   // Shift the first character's code 8 bits to the left and OR it with the second character's code
   const combinedInt = (code1 << 8) | code2

   blocks.push(combinedInt)
  }
  for (let i = 0; i < 8; i++) {
   const index = 6 * i
   // layer 1
   blocks[0] = blocks[0] * segments[index]
   blocks[1] = blocks[1] + segments[index + 1]
   blocks[2] = blocks[2] + segments[index + 2]
   blocks[3] = blocks[3] * segments[index + 3]
   //layer 2
   const middle: number[] = []
   middle.push(blocks[0] ^ blocks[2])
   middle.push(blocks[1] ^ blocks[3])
   //layer 3
   middle[0] = middle[0] * segments[index + 4]
   middle[1] = middle[0] + middle[1]
   middle[1] = middle[1] * segments[index + 5]
   middle[0] = middle[0] + middle[1]
   //layer 4
   blocks[0] = blocks[0] ^ middle[1]
   blocks[1] = blocks[1] ^ middle[0]
   blocks[2] = blocks[2] ^ middle[1]
   blocks[3] = blocks[3] ^ middle[0]

   // swap
   const tmp = blocks[1]
   blocks[1] = blocks[2]
   blocks[2] = tmp
  }

  // layer 8.5
  blocks[0] = blocks[0] * segments[6 * 7]
  blocks[1] = blocks[1] + segments[6 * 7 + 1]
  blocks[2] = blocks[2] + segments[6 * 7 + 2]
  blocks[3] = blocks[3] * segments[6 * 7 + 3]

  let newBase = ''
  blocks.forEach((chars) => {
   const code1 = (chars >> 8) & 0xff
   // Extract the second character's code by masking out the first 8 bits
   const code2 = chars & 0xff

   // Convert ASCII codes back to characters and concatenate them
   const char1 = String.fromCharCode(code1)
   const char2 = String.fromCharCode(code2)

   newBase += char1 + char2
  })

  return newBase
 }

 encode(key: string, data: string): string {
  // Define the size of each chunk in characters, assuming ASCII encoding (8 characters = 64 bits)
  const chunkSize = 8
  // Initialize an array to hold the chunks
  const chunks: string[] = []
  // Loop through the string, slicing it into chunks of the specified size
  for (let i = 0; i < data.length; i += chunkSize) {
   const chunk = data.slice(i, i + chunkSize)
   chunks.push(chunk)
  }

  let encoded = ''
  chunks.forEach((chunk) => {
   encoded += this.algorithm(key, chunk)
  })

  const encodedString = btoa(encoded)
  return encodedString
 }

 decode(key: string, base64Data: string): string {
  // Decode the Base64 input
  const data = atob(base64Data)

  // Placeholder for the decoded output
  let decoded = ''

  // Assuming 'generateIDEASubkeys' function generates an array of subkeys
  const segments = this.generateIDEASubkeys(key)

  // Placeholder: Process to divide 'data' into chunks corresponding to the encoding process
  // This should match how the data was chunked and encoded in the encode function
  // Define the size of each chunk in characters, assuming ASCII encoding (8 characters = 64 bits)
  const chunkSize = 8
  // Initialize an array to hold the chunks
  const chunks: string[] = []
  // Loop through the string, slicing it into chunks of the specified size
  for (let i = 0; i < data.length; i += chunkSize) {
   const chunk = data.slice(i, i + chunkSize)
   chunks.push(chunk)
  }

  log(chunks)

  chunks.forEach((chunk) => {
   // Convert the chunk back to 16-bit blocks, similar to the initial step in the encryption process
   const blocks: any[] = [] // Convert 'chunk' into 16-bit blocks

   // Reverse the final layer 1 operations from the encryption
   // layer 8.5
   blocks[0] = blocks[0] / segments[6 * 7]
   blocks[1] = blocks[1] - segments[6 * 7 + 1]
   blocks[2] = blocks[2] - segments[6 * 7 + 2]
   blocks[3] = blocks[3] / segments[6 * 7 + 3]
   // Placeholder: Apply inverse operations (subtraction and multiplicative inverse) using the final round subkeys

   // Reverse the rounds, ensuring to swap blocks back to their original positions before each round's inversion
   for (let i = 7; i >= 0; i--) {
    // Iterate rounds in reverse order
    const index = 6 * i

    // Placeholder: Invert layer 4 operations using XOR
    const middle: number[] = []
    middle.push(blocks[1] ^ blocks[3])
    middle.push(blocks[0] ^ blocks[2])

    // Placeholder: Invert layer 3 operations (considering the multiplicative inverse and subtraction)
    middle[0] = middle[0] - middle[1]
    middle[0] = middle[0] / segments[index + 4]
    middle[1] = middle[0] - middle[1]
    middle[1] = middle[1] / segments[index + 5]
    // Placeholder: Invert layer 2 operations using XOR
    blocks[0] = blocks[0] ^ middle[1]
    blocks[1] = blocks[1] ^ middle[0]
    blocks[2] = blocks[2] ^ middle[1]
    blocks[3] = blocks[3] ^ middle[0]

    // Placeholder: Invert layer 1 operations (subtraction and multiplicative inverse) using the subkeys for this round
    blocks[0] = blocks[0] / segments[index]
    blocks[1] = blocks[1] - segments[index + 1]
    blocks[2] = blocks[2] - segments[index + 2]
    blocks[3] = blocks[3] / segments[index + 3]
    // Swap blocks back to their positions before this round's original swap
    // swap
    const tmp = blocks[1]
    blocks[1] = blocks[2]
    blocks[2] = tmp
    log(blocks)
   }

   // Convert the blocks back into characters
   blocks.forEach((block) => {
    const char1 = String.fromCharCode((block >> 8) & 0xff)
    const char2 = String.fromCharCode(block & 0xff)
    decoded += char1 + char2
   })
  })

  return decoded
 }
}

export default IDEA
