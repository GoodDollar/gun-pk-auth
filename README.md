## Gun SEA determinisic authentication

webcrypto doesnt allow to generate keys based on a seed, so we use `elliptic` for that
SEA user/password login is not reliable.
You can use this package to generate a deterministic SEA keypair for your user based on your existing login method.

This is perfect for dapps(web3) that are based on private keys or some secret signed data by the user private key.
Both a private key and a signature can be used as seed to deterministically generate SEA key pair.

### Installation
`yarn add @gooddollar/gun-pk-auth`
or
`npm i @gooddollar/gun-pk-auth`

### Examples

a seed can be a private key "0x012345678901234567890123456789123456"

```
import { genDeterministicKeyPair, genDeterministicSEAPair, gunAuth} from '@gooddollar/gun-pk-auth'

//helper to generate keypair in JWK format
const jwk = genDeterministicKeyPair(<someseed>)

//generate same key in SEA format
const seaPair = genDeterministicSEAPair(<someseed>)

//use the generated seaPair to do regular gun auth
gun.auth(null, seaPair, <some callabck>)

//or use gunAuth helper to do gun authentication based on promises
const userIs = await gunAuth(gun, <someseed>)
```
