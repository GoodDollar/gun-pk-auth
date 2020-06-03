## Gun SEA determinisic authentication

SEA user/password login is not reliable.
You can use this package to generate a deterministic SEA keypair for your user based on your existing login method.

This is perfect for dapps(web3) that are based on private keys or some secret signed data by the user private key.
Both a private key and a signature can be used as seed to deterministically generate SEA key pair.

### API

a seed can be a private key "0x012345678901234567890123456789123456"

```
import { genDeterministicKeyPair, genDeterministicSEAPair, gunAuth} from '@gooddollar/gun-pk-auth'

//helper to generate keypair in JWK format
const jwk = genDeterministicKeyPair(<someseed>)
const seaPair = genDeterministicSEAPair(<someseed>)
//regular gun auth
gun.auth(null, seaPair, <some callabck>)

//promise gun auth helper
const userIs = await gunAuth(gun, <someseed>)
```
