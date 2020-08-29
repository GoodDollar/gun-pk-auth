import Gun from "@gooddollar/gun";
import SEA from "@gooddollar/gun/sea";
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

  it("should pad correctly", () => {
    const keypair = pkAuth.genDeterministicKeyPair("0a303bdb819a251f41bfc646a54f90b340d22d9d523ee12cd092dd1090e0cd926e8a6a5e4a8e4489"); //this seed creates a 31 bytes x value
    assert.containsAllKeys(keypair, ["d", "y", "x"]);
    assert.lengthOf(Buffer.from(keypair.d,"base64").toString("hex"),64);
    assert.lengthOf(Buffer.from(keypair.y,"base64").toString("hex"),64);
    assert.lengthOf(Buffer.from(keypair.x,"base64").toString("hex"),64);
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
  }).timeout(10000);
});
