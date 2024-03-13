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

 // Function to calculate modular inverse (handles potential non-invertible cases)
 private modInverse(a: number, m: number): number | null {
    if (a < 0 || a >= m || m <= 1) {
      throw new Error('Invalid input for modular inverse');
    }
  
    // Extended Euclidean Algorithm for modular inverse
    let m0 = m;
    let y = 0;
    let x = 1;
  
    if (m === 1) {
      return 0;
    }
  
    while (a > 1) {
      // q is the quotient
      const q = Math.floor(a / m);
      let t = m;
  
      m = a % m;
      a = t;
      t = y;
      y = x - q * y;
      x = t;
    }
  
    if (x < 0) {
      x += m0;
    }
  
    return x;
  }
  
  // Function to generate decryption subkeys from encryption subkeys
  private generateDecryptionSubkeys(encryptionSubkeys: number[]): number[] {
    const decryptionSubkeys: number[] = new Array(encryptionSubkeys.length);
  
    // Handle multiplicative keys (every other subkey)
    for (let i = 0; i < 52; i += 6) {
      const multiplicativeKey = encryptionSubkeys[i];
      // Check if modular inverse exists (avoid division by zero)
      if (multiplicativeKey === 0) {
        throw new Error('Multiplicative key cannot be zero');
      }
      decryptionSubkeys[i] = this.modInverse(multiplicativeKey, 65536) || 0; // Handle non-invertible cases
      decryptionSubkeys[i + 3] = this.modInverse(encryptionSubkeys[i + 3], 65536) || 0;
    }
  
    // Handle additive keys (remaining subkeys)
    for (let i = 1; i < 52; i += 6) {
      decryptionSubkeys[i] = (65536 - encryptionSubkeys[i]) % 65536;
      decryptionSubkeys[i + 1] = (65536 - encryptionSubkeys[i + 1]) % 65536;
    }
  
    // Handle the final output transformation
    decryptionSubkeys[48] = this.modInverse(encryptionSubkeys[48], 65536) || 0;
    decryptionSubkeys[49] = (65536 - encryptionSubkeys[49]) % 65536;
    decryptionSubkeys[50] = (65536 - encryptionSubkeys[50]) % 65536;
    decryptionSubkeys[51] = this.modInverse(encryptionSubkeys[51], 65536) || 0;
  
    // Reverse the subkeys for decryption
    return decryptionSubkeys.reverse();
  }
  

 private Plus(a: number, b: number): number {
  return (a + b) % 65536
 }

 private Multiply(a: number, b: number): number {
  // Ensure 'a' is not 0; if it is, use 65536 (since 0 * b % 65536 will always be 0, which is not useful for encryption)
  if (a === 0) a = 65536
  if (b === 0) b = 65536
  return (a * b) % 65537
 }
 private inverseMod2ToThe16(n: number): number | null {
  if (typeof n !== 'number' || n < 0) {
   throw new Error('n must be a non-negative number')
  }

  const modulo = 1 << 16
  n = n % modulo // Ensure 'n' is within the modulus range

  let t = 0
  let newT = 1
  let r = modulo
  let newR = n

  while (newR !== 0) {
   const quotient = Math.floor(r / newR)

   ;[t, newT] = [newT, t - quotient * newT]
   ;[r, newR] = [newR, r - quotient * newR]
  }

  // No inverse exists if 'r' is greater than 1 (i.e., 'n' and 'modulo' are not coprime)
  if (r > 1) return null // Indicate no inverse exists

  // Adjust 't' to be positive
  if (t < 0) t += modulo

  return t
 }

 private algorithm(segments: number[], data: string) {
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
   const k1 = segments[index] === 0 ? 65536 : segments[index]
   const k2 = segments[index + 1]
   const k3 = segments[index + 2]
   const k4 = segments[index + 3] === 0 ? 65536 : segments[index + 3]
   const k5 = segments[index + 4] === 0 ? 65536 : segments[index + 4]
   const k6 = segments[index + 5] === 0 ? 65536 : segments[index + 5]

   // layer 1
   blocks[0] = this.Multiply(blocks[0], k1)
   blocks[3] = this.Multiply(blocks[3], k4)
   blocks[1] = this.Plus(blocks[1], k2)
   blocks[2] = this.Plus(blocks[2], k3)
   //layer 2
   const middle: number[] = []
   middle.push(blocks[0] ^ blocks[2])
   middle.push(blocks[1] ^ blocks[3])
   //layer 3
   middle[0] = this.Multiply(middle[0], k5)
   middle[0] = this.Plus(middle[0], middle[1])
   middle[1] = this.Plus(middle[0], middle[1])
   middle[1] = this.Multiply(middle[1], k6)
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
  blocks[1] = this.Plus(blocks[1], segments[6 * 7 + 1])
  blocks[2] = this.Plus(blocks[2], segments[6 * 7 + 2])
  blocks[0] = this.Multiply(blocks[0], segments[6 * 7])
  blocks[3] = this.Multiply(blocks[3], segments[6 * 7 + 3])

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
  const segments = this.generateIDEASubkeys(key)

  chunks.forEach((chunk) => {
   encoded += this.algorithm(segments, chunk)
  })

  const encodedString = btoa(encoded)
  return encodedString
 }

 decode(key: string, data: string): string {
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

  const gen = this.generateIDEASubkeys(key)
  const segments = this.generateDecryptionSubkeys(gen)

  chunks.forEach((chunk) => {
   encoded += this.algorithm(segments, chunk)
  })

  //   const encodedString = atob(encoded)
  return encoded
 }
}

export default IDEA
