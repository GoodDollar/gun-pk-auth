import elliptic from "elliptic";

const tob64u = (str) => {
  return str.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};

/**
 * generates an ecdsa keypair based on curve p256 and export as jwk
 */
export const genDeterministicKeyPair = (seed) => {
  const ec = new elliptic.ec("p256");
  // Generate keys
  const keyPair = ec.genKeyPair({ entropy: seed });
  const priv = keyPair.getPrivate();
  const pub = keyPair.getPublic();
  const x = pub.getX();
  const y = pub.getY();
  let jwk = {
    kty: "EC",
    crv: "P-256",
    x: tob64u(x.toArrayLike(Buffer).toString("base64")),
    y: tob64u(y.toArrayLike(Buffer).toString("base64")),
    d: tob64u(priv.toArrayLike(Buffer).toString("base64")),
  };
  return jwk;
};

/**
 * convert jwk to SEA keypair format
 * notice that in SEA it generates different keypairs for signing and decrypting but here we use same keypair
 * in future  possible to derive another keypair from seed
 */
export const genDeterministicSEAPair = (seed) => {
  const jwk = genDeterministicKeyPair(seed);
  const seaPair = {
    pub: jwk.x + "." + jwk.y,
    priv: jwk.d,
    epriv: jwk.d,
    epub: jwk.x + "." + jwk.y,
  };
  return seaPair;
};

/**
 *
 * @param {Gun} gunInstance an instance of Gun()
 * @param {string} seed at least 192bits seeds, possible to use ethereum private key as string "0x..."
 * @returns Promise<user().is> on success or rejects with error
 */

export const gunAuth = async (gunInstance, seed) => {
  const user = gunInstance.user();
  const login = new Promise((res, rej) => {
    user.auth(genDeterministicSEAPair(seed), (authres) => {
      if (authres.err) rej(authres.err);
      else res(authres);
    });
  });
  await login;
  user.put({ epub: user.is.epub, pub: user.is.pub });
  return user.is;
};
