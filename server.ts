
import IDEA from "./src/classes/idea";

const idea = new IDEA()

// const key = idea.generateKey()
const key ="i/ELBfPOjppw17m9CQYaQg=="
console.log(key)
const encoded = idea.encode(key, "a")
console.log(encoded)
const decoded = idea.decode(key, encoded)
console.log(decoded)