// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { EncryptedObject } from './bcs';
import { G1Element, G2Element } from './bls12381';
import { decrypt } from './decrypt';
import type { EncryptionInput } from './dem';
import { AesGcm256, Hmac256Ctr } from './dem';
import { DemType, encrypt, KemType } from './encrypt';
import {
	InconsistentKeyServersError,
	InvalidKeyServerError,
	InvalidThresholdError,
	toMajorityError,
} from './error';
import { BonehFranklinBLS12381Services, DST } from './ibe';
import {
	BonehFranklinBLS12381DerivedKey,
	KeyServerType,
	retrieveKeyServers,
	verifyKeyServer,
} from './key-server';
import type { DerivedKey, KeyServer } from './key-server';
import { fetchKeysForAllIds } from './keys';
import type { SessionKey } from './session-key';
import type { KeyCacheKey, SealCompatibleClient } from './types';
import { createFullId, count } from './utils';

/**
 * Configuration options for initializing a SealClient
 * @property serverObjectIds: Array of object IDs for the key servers to use.
 * @property verifyKeyServers: Whether to verify the key servers' authenticity.
 * 	 Should be false if servers are pre-verified (e.g., getAllowlistedKeyServers).
 * 	 Defaults to true.
 * @property timeout: Timeout in milliseconds for network requests. Defaults to 10 seconds.
 */

export interface SealClientExtensionOptions {
	serverObjectIds: string[];
	verifyKeyServers?: boolean;
	timeout?: number;
}

export interface SealClientOptions extends SealClientExtensionOptions {
	suiClient: SealCompatibleClient;
}

export class SealClient {
	#suiClient: SealCompatibleClient;
	#serverObjectIds: string[];
	#verifyKeyServers: boolean;
	#keyServers: Promise<KeyServer[]> | null = null;
	// A caching map for: fullId:object_id -> partial key.
	#cachedKeys = new Map<KeyCacheKey, G1Element>();
	#timeout: number;

	constructor(options: SealClientOptions) {
		this.#suiClient = options.suiClient;
		this.#serverObjectIds = options.serverObjectIds;
		this.#verifyKeyServers = options.verifyKeyServers ?? true;
		this.#timeout = options.timeout ?? 10_000;
	}

	static experimental_asClientExtension(options: SealClientExtensionOptions) {
		return {
			name: 'seal' as const,
			register: (client: SealCompatibleClient) => {
				return new SealClient({
					suiClient: client,
					...options,
				});
			},
		};
	}

	/**
	 * Return an encrypted message under the identity.
	 *
	 * @param kemType - The type of KEM to use.
	 * @param demType - The type of DEM to use.
	 * @param threshold - The threshold for the TSS encryption.
	 * @param packageId - the packageId namespace.
	 * @param id - the identity to use.
	 * @param data - the data to encrypt.
	 * @param aad - optional additional authenticated data.
	 * @returns The bcs bytes of the encrypted object containing all metadata and the 256-bit symmetric key that was used to encrypt the object.
	 * 	Since the symmetric key can be used to decrypt, it should not be shared but can be used e.g. for backup.
	 */
	async encrypt({
		kemType = KemType.BonehFranklinBLS12381DemCCA,
		demType = DemType.AesGcm256,
		threshold,
		packageId,
		id,
		data,
		aad = new Uint8Array(),
	}: {
		kemType?: KemType;
		demType?: DemType;
		threshold: number;
		packageId: string;
		id: string;
		data: Uint8Array;
		aad?: Uint8Array;
	}) {
		// TODO: Verify that packageId is first version of its package (else throw error).
		return encrypt({
			keyServers: await this.getKeyServers(),
			kemType,
			threshold,
			packageId,
			id,
			encryptionInput: this.#createEncryptionInput(demType, data, aad),
		});
	}

	#createEncryptionInput(type: DemType, data: Uint8Array, aad: Uint8Array): EncryptionInput {
		switch (type) {
			case DemType.AesGcm256:
				return new AesGcm256(data, aad);
			case DemType.Hmac256Ctr:
				return new Hmac256Ctr(data, aad);
		}
	}

	/**
	 * Decrypt the given encrypted bytes using cached keys.
	 * Calls fetchKeys in case one or more of the required keys is not cached yet.
	 * The function throws an error if the client's key servers are not a subset of
	 * the encrypted object's key servers (including the same weights) or if the
	 * threshold cannot be met.
	 *
	 * @param data - The encrypted bytes to decrypt.
	 * @param sessionKey - The session key to use.
	 * @param txBytes - The transaction bytes to use (that calls seal_approve* functions).
	 * @returns - The decrypted plaintext corresponding to ciphertext.
	 */
	async decrypt({
		data,
		sessionKey,
		txBytes,
	}: {
		data: Uint8Array;
		sessionKey: SessionKey;
		txBytes: Uint8Array;
	}) {
		const encryptedObject = EncryptedObject.parse(data);

		this.#validateEncryptionServices(
			encryptedObject.services.map((s) => s[0]),
			encryptedObject.threshold,
		);

		await this.fetchKeys({
			ids: [encryptedObject.id],
			txBytes,
			sessionKey,
			threshold: encryptedObject.threshold,
		});

		console.log('done fetchKeys');

		return decrypt({ encryptedObject, keys: this.#cachedKeys });
	}

	#validateEncryptionServices(services: string[], threshold: number) {
		// Check that the client's key servers are a subset of the encrypted object's key servers.
		// TODO: fix this check to allow for non-equal weights.
		if (
			services.some((objectId) => {
				const countInClient = count(this.#serverObjectIds, objectId);
				return countInClient > 0 && countInClient !== count(services, objectId);
			})
		) {
			throw new InconsistentKeyServersError(
				`Client's key servers must be a subset of the encrypted object's key servers`,
			);
		}
		// Check that the threshold can be met with the client's key servers.
		if (threshold > this.#serverObjectIds.length) {
			throw new InvalidThresholdError(
				`Invalid threshold ${threshold} for ${this.#serverObjectIds.length} servers`,
			);
		}
	}

	async getKeyServers() {
		if (!this.#keyServers) {
			this.#keyServers = this.#loadKeyServers().catch((error) => {
				this.#keyServers = null;
				throw error;
			});
		}

		return this.#keyServers;
	}

	async #loadKeyServers(): Promise<KeyServer[]> {
		const keyServers = await retrieveKeyServers({
			objectIds: this.#serverObjectIds,
			client: this.#suiClient,
		});

		if (keyServers.length === 0) {
			throw new InvalidKeyServerError('No key servers found');
		}

		if (this.#verifyKeyServers) {
			await Promise.all(
				keyServers.map(async (server) => {
					if (!(await verifyKeyServer(server, this.#timeout))) {
						throw new InvalidKeyServerError(`Key server ${server.objectId} is not valid`);
					}
				}),
			);
		}

		return keyServers;
	}

	/**
	 * Fetch keys from the key servers and update the cache.
	 *
	 * It is recommended to call this function once for all ids of all encrypted objects if
	 * there are multiple, then call decrypt for each object. This avoids calling fetchKey
	 * individually for each decrypt.
	 *
	 * @param ids - The ids of the encrypted objects.
	 * @param txBytes - The transaction bytes to use (that calls seal_approve* functions).
	 * @param sessionKey - The session key to use.
	 * @param threshold - The threshold for the TSS encryptions. The function returns when a threshold of key servers had returned keys for all ids.
	 */
	async fetchKeys({
		ids,
		txBytes,
		sessionKey,
		threshold,
	}: {
		ids: string[];
		txBytes: Uint8Array;
		sessionKey: SessionKey;
		threshold: number;
	}) {
		// console.log('fetchKeys - Input:', {
		// 	ids,
		// 	txBytesLength: txBytes.length,
		// 	sessionKeyAddress: sessionKey.getAddress(),
		// 	threshold
		// });

		const keyServers = await this.getKeyServers();
		// console.log('fetchKeys - Key servers:', {
		// 	count: keyServers.length,
		// 	serverIds: keyServers.map(s => s.objectId)
		// });

		if (threshold > keyServers.length || threshold < 1 || keyServers.length < 1) {
			throw new InvalidThresholdError(
				`Invalid threshold ${threshold} for ${keyServers.length} servers`,
			);
		}

		let completedServerCount = 0;
		const remainingKeyServers = new Set<KeyServer>();
		const fullIds = ids.map((id) => {
			const fullId = createFullId(DST, sessionKey.getPackageId(), id);
			// console.log('fetchKeys - Creating full ID:', {
			// 	id,
			// 	idHex: Buffer.from(id).toString('hex'),
			// 	packageId: sessionKey.getPackageId(),
			// 	fullId,
			// 	fullIdHex: Buffer.from(fullId).toString('hex')
			// });
			return fullId;
		});
		console.log('fetchKeys - Full IDs:', fullIds);

		// Count a server as completed if it has keys for all fullIds.
		// Duplicated key server ids will be counted towards the threshold.
		for (const server of keyServers) {
			if (fullIds.every((fullId) => this.#cachedKeys.has(`${fullId}:${server.objectId}`))) {
				completedServerCount++;
				console.log('fetchKeys - Server already has keys:', server.objectId);
			} else {
				remainingKeyServers.add(server);
				console.log('fetchKeys - Server needs keys:', server.objectId);
			}
		}

		// console.log('fetchKeys - Initial state:', {
		// 	completedServerCount,
		// 	remainingServers: remainingKeyServers.size
		// });

		// Return early if we have enough keys from cache.
		if (completedServerCount >= threshold) {
			console.log('fetchKeys - Enough keys in cache, returning early');
			return;
		}

		// Check server validities.
		for (const server of remainingKeyServers) {
			if (server.keyType !== KeyServerType.BonehFranklinBLS12381) {
				throw new InvalidKeyServerError(
					`Server ${server.objectId} has invalid key type: ${server.keyType}`,
				);
			}
		}

		const cert = await sessionKey.getCertificate();
		const signedRequest = await sessionKey.createRequestParams(txBytes);

		console.log('fetchKeys - Request params:', {
			certificate: cert,
			requestSignature: signedRequest.requestSignature,
			decryptionKeyLength: signedRequest.decryptionKey.length
		});

		const controller = new AbortController();
		const errors: Error[] = [];

		const keyFetches = [...remainingKeyServers].map(async (server) => {
			try {
				// console.log('fetchKeys - Fetching keys from server:', {
				// 	serverUrl: server.url,
				// 	serverId: server.objectId
				// });

				const allKeys = await fetchKeysForAllIds(
					server.url,
					signedRequest.requestSignature,
					txBytes,
					signedRequest.decryptionKey,
					cert,
					this.#timeout,
					controller.signal,
				);

				// console.log('fetchKeys - Received keys from server:', {
				// 	serverId: server.objectId,
				// 	keysCount: allKeys.length,
				// 	receivedIds: allKeys.map(k => k.fullId)
				// });

				// Check validity of the keys and add them to the cache.
				const receivedIds = new Set<string>();
				for (const { fullId, key } of allKeys) {
					// console.log('check validity', {fullId, key})
					const keyElement = G1Element.fromBytes(key);
					const isValid = BonehFranklinBLS12381Services.verifyUserSecretKey(
							keyElement,
							fullId,
							G2Element.fromBytes(server.pk),
					);

					// console.log('fetchKeys - Validating key:', {
					// 	fullId,
					// 	isValid,
					// 	keyLength: key.length
					// });

					if (!isValid) {
						console.warn('Received invalid key from key server ' + server.objectId);
						continue;
					}
					this.#cachedKeys.set(`${fullId}:${server.objectId}`, keyElement);
					receivedIds.add(fullId);
				}

				// Check if all the receivedIds are consistent with the requested fullIds.
				// If so, consider the key server got all keys and mark as completed.
				const hasAllKeys = fullIds.every((fullId) => receivedIds.has(fullId));
				// console.log('fetchKeys - Server key status:', {
				// 	serverId: server.objectId,
				// 	hasAllKeys,
				// 	receivedIds: Array.from(receivedIds),
				// 	expectedIds: fullIds,
				// 	// receivedIdsHex: Array.from(receivedIds).map(id => Buffer.from(id).toString('hex')),
				// 	// expectedIdsHex: fullIds.map(id => Buffer.from(id).toString('hex')),
				// 	comparison: fullIds.map(id => ({
				// 		id,
				// 		idHex: Buffer.from(id).toString('hex'),
				// 		received: receivedIds.has(id)
				// 	}))
				// });

				if (hasAllKeys) {
					completedServerCount++;
					console.log('fetchKeys - Server completed:', {
						serverId: server.objectId,
						completedServerCount,
						threshold
					});

					// Return early if the completed servers is more than the threshold.
					if (completedServerCount >= threshold) {
						console.log('fetchKeys - Threshold reached, aborting remaining requests');
						controller.abort();
					}
				}
			} catch (error) {
				console.error('fetchKeys - Error fetching from server:', {
					serverId: server.objectId,
					error: error instanceof Error ? error.message : String(error)
				});

				if (!controller.signal.aborted) {
					errors.push(error as Error);
				}
				// If there are too many errors that the threshold is not attainable, return early with error.
				if (remainingKeyServers.size - errors.length < threshold - completedServerCount) {
					console.error('fetchKeys - Too many errors, cannot reach threshold');
					controller.abort(error);
				}
			}
		});

		await Promise.allSettled(keyFetches);

		if (completedServerCount < threshold) {
			throw toMajorityError(errors);
		}
	}

	/**
	 * Get derived keys from the given services.
	 *
	 * @param id - The id of the encrypted object.
	 * @param txBytes - The transaction bytes to use (that calls seal_approve* functions).
	 * @param sessionKey - The session key to use.
	 * @param threshold - The threshold.
	 * @returns - Derived keys for the given services that are in the cache as a "service object ID" -> derived key map. If the call is succesful, exactly threshold keys will be returned.
	 */
	async getDerivedKeys({
		kemType = KemType.BonehFranklinBLS12381DemCCA,
		id,
		txBytes,
		sessionKey,
		threshold,
	}: {
		kemType?: KemType;
		id: string;
		txBytes: Uint8Array;
		sessionKey: SessionKey;
		threshold: number;
	}): Promise<Map<string, DerivedKey>> {
		switch (kemType) {
			case KemType.BonehFranklinBLS12381DemCCA:
				const keyServers = await this.getKeyServers();
				if (threshold > this.#serverObjectIds.length) {
					throw new InvalidThresholdError(
						`Invalid threshold ${threshold} for ${this.#serverObjectIds.length} servers`,
					);
				}
				await this.fetchKeys({
					ids: [id],
					txBytes,
					sessionKey,
					threshold,
				});

				// After calling fetchKeys, we can be sure that there are at least `threshold` of the required keys in the cache.
				// It is also checked there that the KeyServerType is BonehFranklinBLS12381 for all services.

				const fullId = createFullId(DST, sessionKey.getPackageId(), id);

				const derivedKeys = new Map<string, DerivedKey>();
				let servicesAdded = 0;
				for (const keyServer of keyServers) {
					// The code below assumes that the KeyServerType is BonehFranklinBLS12381.
					const cachedKey = this.#cachedKeys.get(`${fullId}:${keyServer.objectId}`);
					if (cachedKey) {
						derivedKeys.set(keyServer.objectId, new BonehFranklinBLS12381DerivedKey(cachedKey));
						if (++servicesAdded === threshold) {
							// We have enough keys, so we can stop.
							break;
						}
					}
				}
				return derivedKeys;
		}
	}
}
