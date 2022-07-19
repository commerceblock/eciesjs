import { PrivateKey, PublicKey } from "./keys";
import {
  aesDecrypt,
  aesEncrypt,
  decodeHex,
  getValidSecret,
  remove0x,
} from "./utils";
import { UNCOMPRESSED_PUBLIC_KEY_SIZE } from "./consts";
var Buffer = require('buffer/').Buffer  // note: the trailing slash is important!

export function encrypt(receiverRawPK: string | Buffer, msg: Buffer): Buffer {
  const ephemeralKey = new PrivateKey();

  

  const receiverPK =
    receiverRawPK instanceof Buffer
      ? new PublicKey(receiverRawPK as Buffer)
      : PublicKey.fromHex(receiverRawPK as string);

  const aesKey = ephemeralKey.encapsulate(receiverPK);
  const encrypted = aesEncrypt(aesKey, msg);
  return Buffer.concat([ephemeralKey.publicKey.uncompressed, encrypted]);
}

export function decrypt(receiverRawSK: string | Buffer, msg: Buffer): Buffer {
  const receiverSK =
    receiverRawSK instanceof Buffer
      ? new PrivateKey(receiverRawSK as Buffer)
      : PrivateKey.fromHex(receiverRawSK as string);

  const senderPubkey = new PublicKey(
    msg.slice(0, UNCOMPRESSED_PUBLIC_KEY_SIZE)
  );
  const encrypted = msg.slice(UNCOMPRESSED_PUBLIC_KEY_SIZE);
  const aesKey = senderPubkey.decapsulate(receiverSK);
  return aesDecrypt(aesKey, encrypted);
}

export { PrivateKey, PublicKey } from "./keys";

export const utils = {
  aesDecrypt,
  aesEncrypt,
  decodeHex,
  getValidSecret,
  remove0x,
};
