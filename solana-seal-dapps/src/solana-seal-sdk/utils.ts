// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex, toHex } from "@mysten/bcs";
import { UserError } from "./error";
import { isValidSuiObjectId } from "@mysten/sui/utils";

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error("Invalid input");
  }
  return xorUnchecked(a, b);
}

export function xorUnchecked(a: Uint8Array, b: Uint8Array): Uint8Array {
  return a.map((ai, i) => ai ^ b[i]);
}

/**
 * Create a full ID concatenating DST || package ID || inner ID.
 * @param dst - The domain separation tag.
 * @param packageId - The package ID.
 * @param innerId - The inner ID (hex string, with or without 0x prefix).
 * @returns The full ID.
 */
export function createFullId(
  dst: Uint8Array,
  packageId: string,
  innerId: string
): string {
  if (!isValidSuiObjectId(packageId)) {
    throw new UserError(`Invalid package ID ${packageId}`);
  }
  // console.log("createFullId - Input:", {
  //   dst: Buffer.from(dst).toString('hex'),
  //   packageId,
  //   innerId,
  //   dstLength: dst.length
  // });
  
  const packageIdBytes = fromHex(packageId);
  
  // Handle hex IDs consistently with backend
  // Remove 0x prefix if present and convert hex string to bytes
  const cleanInnerId = innerId.startsWith('0x') ? innerId.slice(2) : innerId;
  const innerIdBytes = fromHex(cleanInnerId);
  
  // console.log("createFullId - Bytes:", {
  //   packageIdBytes: Buffer.from(packageIdBytes).toString('hex'),
  //   innerIdBytes: Buffer.from(innerIdBytes).toString('hex'),
  //   dstBytes: Buffer.from(dst).toString('hex')
  // });
  
  // Create the full ID by concatenating:
  // 1. DST length (1 byte)
  // 2. DST bytes
  // 3. Package ID bytes
  // 4. Inner ID bytes
  const fullId = flatten([
    new Uint8Array([dst.length]),
    dst,
    packageIdBytes,
    innerIdBytes,
  ]);
  
  const result = toHex(fullId);
  // console.log("createFullId - Result:", {
  //   fullId: result,
  //   fullIdBytes: Buffer.from(fullId).toString('hex'),
  //   fullIdLength: fullId.length
  // });
  
  return result;
}

/**
 * Flatten an array of Uint8Arrays into a single Uint8Array.
 *
 * @param arrays - An array of Uint8Arrays to flatten.
 * @returns A single Uint8Array containing all the elements of the input arrays in the given order.
 */
export function flatten(arrays: Uint8Array[]): Uint8Array {
  const length = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(length);
  arrays.reduce((offset, array) => {
    result.set(array, offset);
    return offset + array.length;
  }, 0);
  return result;
}

/** Count the number of occurrences of a value in an array. */
export function count<T>(array: T[], value: T): number {
  return array.reduce((count, item) => (item === value ? count + 1 : count), 0);
}

/**
 * A simple class to represent a version number of the form x.y.z.
 */
export class Version {
  major: number;
  minor: number;
  patch: number;

  constructor(version: string) {
    // Very basic version parsing. Assumes version is in the format x.y.z where x, y, and z are non-negative integers.
    const parts = version.split(".").map(Number);
    if (
      parts.length !== 3 ||
      parts.some((part) => isNaN(part) || !Number.isInteger(part) || part < 0)
    ) {
      throw new UserError(`Invalid version format: ${version}`);
    }
    this.major = parts[0];
    this.minor = parts[1];
    this.patch = parts[2];
  }

  // Compare this version with another version. True if this version is older than the other version.
  older_than(other: Version): boolean {
    if (this.major !== other.major) {
      return this.major < other.major;
    } else if (this.minor !== other.minor) {
      return this.minor < other.minor;
    }
    return this.patch < other.patch;
  }
}
