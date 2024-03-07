interface iCypher {
    generateKey(): string
    encode(key: string, data: string): string
    decode(key: string, data: string): string
}


export type {
    iCypher
}