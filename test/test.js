import Gun from "gun";
import SEA from "gun/sea";
import { assert } from "chai";
import * as pkAuth from "../src/gun-pk-auth";
describe("deterministic pk auth", () => {
  let gun;
  before(() => {
    gun = Gun({ localStorage: false, multicast: false, axe: false });
  });

  // test a functionality
  it("should create jwk keypair", () => {
    const keypair = pkAuth.genDeterministicKeyPair("0x012345678901234567890123456789123456");
    assert.containsAllKeys(keypair, ["d", "y", "x"]);
    assert.isString(keypair.d);
    assert.isString(keypair.y);
    assert.isString(keypair.x);
  });

  it("should create different keypair for different seeds", () => {
    const keypair = pkAuth.genDeterministicKeyPair("0x012345678901234567890123456789123456");
    const keypair2 = pkAuth.genDeterministicKeyPair("0x012345678901234567890123456789123457");
    assert.notDeepEqual(keypair, keypair2);
  });

  it("should create same keypair for same seed", () => {
    const keypair = pkAuth.genDeterministicKeyPair("0x012345678901234567890123456789123456");
    const keypair2 = pkAuth.genDeterministicKeyPair("0x012345678901234567890123456789123456");
    assert.deepEqual(keypair, keypair2);
  });

  it("should create SEA keypair", () => {
    const keypair = pkAuth.genDeterministicKeyPair("0x012345678901234567890123456789123456");
    const seapair = pkAuth.genDeterministicSEAPair("0x012345678901234567890123456789123456");
    assert.equal(keypair.d, seapair.priv);
    assert.equal(keypair.x + "." + keypair.y, seapair.pub);
  });

  it("should authenticate with SEA", async () => {
    const keypair = pkAuth.genDeterministicKeyPair("0x012345678901234567890123456789123456");
    const loggedin = await pkAuth.gunAuth(gun, "0x012345678901234567890123456789123456");
    assert.equal(keypair.d, gun.user()._.sea.priv);
    assert.equal(keypair.x + "." + keypair.y, loggedin.pub);
    const profile = await gun.get("~" + loggedin.pub).then();
    assert.containsAllKeys(profile, ["epub", "pub"]);
  }).timeout(5000);
});
