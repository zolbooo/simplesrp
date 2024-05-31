export function byteArrayToHexString(byteArray: Uint8Array): string {
  return [...byteArray].map((b) => b.toString(16).padStart(2, "0")).join("");
}
export function byteArrayToBigInt(byteArray: Uint8Array): bigint {
  return BigInt("0x" + byteArrayToHexString(byteArray));
}

export function hexStringToByteArray(hexString: string): Uint8Array {
  if (hexString.length % 2 !== 0) {
    hexString = "0" + hexString;
  }
  const byteArray = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < byteArray.length; i++) {
    byteArray[i] = parseInt(hexString.slice(i * 2, i * 2 + 2), 16);
  }
  return byteArray;
}
