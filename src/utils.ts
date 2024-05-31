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

export function padData(data: Uint8Array, N: Uint8Array): Uint8Array {
  const paddedData = new Uint8Array(N.length);
  paddedData.set(data, length - data.length);
  paddedData.set(
    Array.from({ length: N.length - data.length }).map(() => 0),
    0
  );
  return paddedData;
}

export function generateRandomExponent(mod: bigint): bigint {
  const modSize = Math.floor(mod.toString(2).length / 8);
  while (true) {
    const randomBytes = crypto.getRandomValues(new Uint8Array(modSize));
    const derivedRandom = BigInt("0x" + byteArrayToHexString(randomBytes));
    // (mod - 1) because Fermat's little theorem
    const result = derivedRandom % (mod - 1n);
    if (result > 1n) {
      return result;
    }
  }
}
