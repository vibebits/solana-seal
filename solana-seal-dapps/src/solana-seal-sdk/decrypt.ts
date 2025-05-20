// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex } from '@mysten/bcs';
import { combine as externalCombine } from 'shamir-secret-sharing';

import type { EncryptedObject } from './bcs';
import type { G1Element } from './bls12381';
import { G2Element } from './bls12381';
import { AesGcm256, Hmac256Ctr } from './dem';
import { InvalidCiphertextError, UnsupportedFeatureError } from './error';
import { BonehFranklinBLS12381Services, DST } from './ibe';
import { deriveKey, KeyPurpose } from './kdf';
import type { KeyCacheKey } from './types';
import { createFullId, flatten } from './utils';

export interface DecryptOptions {
	encryptedObject: typeof EncryptedObject.$inferType;
	keys: Map<KeyCacheKey, G1Element>;
}

/**
 * Decrypt the given encrypted bytes with the given cached secret keys for the full ID.
 * It's assumed that fetchKeys has been called to fetch the secret keys for enough key servers
 * otherwise, this will throw an error.
 *
 * @returns - The decrypted plaintext corresponding to ciphertext.
 */
export async function decrypt({ encryptedObject, keys }: DecryptOptions): Promise<Uint8Array> {
	if (!encryptedObject.encryptedShares.BonehFranklinBLS12381) {
		throw new UnsupportedFeatureError('Encryption mode not supported');
	}

	console.log('decrypt.ts - Input:', {
		encryptedObjectId: encryptedObject.id,
		encryptedObjectPackageId: encryptedObject.packageId,
		encryptedObjectThreshold: encryptedObject.threshold,
		encryptedObjectServices: encryptedObject.services,
		keysSize: keys.size,
		keysEntries: Array.from(keys.entries()).map(([key, value]) => ({
			key,
			valueLength: value.toBytes().length
		}))
	});

	const fullId = createFullId(DST, encryptedObject.packageId, encryptedObject.id);
	console.log('decrypt.ts - Full ID:', fullId);

	// Get the indices of the service whose keys are in the keystore.
	const inKeystore = encryptedObject.services
		.map((_, i) => i)
		.filter((i) => keys.has(`${fullId}:${encryptedObject.services[i][0]}`));

	console.log('decrypt.ts - Keys in keystore:', {
		inKeystore,
		inKeystoreLength: inKeystore.length,
		requiredThreshold: encryptedObject.threshold
	});

	if (inKeystore.length < encryptedObject.threshold) {
		throw new Error('Not enough shares. Please fetch more keys.');
	}

	const encryptedShares = encryptedObject.encryptedShares.BonehFranklinBLS12381.encryptedShares;
	if (encryptedShares.length !== encryptedObject.services.length) {
		throw new InvalidCiphertextError(
			`Mismatched shares ${encryptedShares.length} and services ${encryptedObject.services.length}`,
		);
	}

	const nonce = G2Element.fromBytes(encryptedObject.encryptedShares.BonehFranklinBLS12381.nonce);

	// Decrypt each share.
	const shares = inKeystore.map((i) => {
		const [objectId, index] = encryptedObject.services[i];
		// Use the index as the unique info parameter to allow for multiple shares per key server.
		const share = BonehFranklinBLS12381Services.decrypt(
			nonce,
			keys.get(`${fullId}:${objectId}`)!,
			encryptedShares[i],
			fromHex(fullId),
			[objectId, index],
		);
		// The Shamir secret sharing library expects the index/x-coordinate to be at the end of the share.
		return { index, share };
	});

	// Combine the decrypted shares into the key.
	const baseKey = await combine(shares);

	const demKey = deriveKey(KeyPurpose.DEM, baseKey);

	if (encryptedObject.ciphertext.Aes256Gcm) {
		return AesGcm256.decrypt(demKey, encryptedObject.ciphertext);
	} else if (encryptedObject.ciphertext.Hmac256Ctr) {
		return Hmac256Ctr.decrypt(demKey, encryptedObject.ciphertext);
	} else if (encryptedObject.ciphertext.Plain) {
		// In case `Plain` mode is used, return the key.
		return demKey;
	} else {
		throw new InvalidCiphertextError('Invalid ciphertext type');
	}
}

/**
 * Helper function that combines the shares into the key.
 * @param shares - The shares to combine.
 * @returns - The combined key.
 */
async function combine(shares: { index: number; share: Uint8Array }[]): Promise<Uint8Array> {
	if (shares.length === 0) {
		throw new Error('Invalid shares length');
	} else if (shares.length === 1) {
		// The Shamir secret sharing library expects at least two shares.
		// If there is only one and the threshold is 1, the reconstructed secret is the same as the share.
		return Promise.resolve(shares[0].share);
	}

	// The Shamir secret sharing library expects the index/x-coordinate to be at the end of the share
	return externalCombine(
		shares.map(({ index, share }) => flatten([share, new Uint8Array([index])])),
	);
}
