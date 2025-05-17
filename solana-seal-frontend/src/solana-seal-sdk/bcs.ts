// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex, toHex } from '@mysten/bcs';
import { bcs } from '@mysten/sui/bcs';

export const IBEEncryptions = bcs.enum('IBEEncryptions', {
	BonehFranklinBLS12381: bcs.struct('BonehFranklinBLS12381', {
		nonce: bcs.bytes(96),
		encryptedShares: bcs.vector(bcs.bytes(32)),
		encryptedRandomness: bcs.bytes(32),
	}),
});

export const Ciphertext = bcs.enum('Ciphertext', {
	Aes256Gcm: bcs.struct('Aes256Gcm', {
		blob: bcs.vector(bcs.U8),
		aad: bcs.option(bcs.vector(bcs.U8)),
	}),
	Hmac256Ctr: bcs.struct('Hmac256Ctr', {
		blob: bcs.vector(bcs.U8),
		aad: bcs.option(bcs.vector(bcs.U8)),
		mac: bcs.bytes(32),
	}),
	Plain: bcs.struct('Plain', {}),
});

/**
 * The encrypted object format. Should be aligned with the Rust implementation.
 */
export const EncryptedObject = bcs.struct('EncryptedObject', {
	version: bcs.U8,
	packageId: bcs.Address,
	id: bcs.vector(bcs.U8).transform({
		output: (val) => toHex(new Uint8Array(val)),
		input: (val: string) => fromHex(val),
	}),
	services: bcs.vector(bcs.tuple([bcs.Address, bcs.U8])),
	threshold: bcs.U8,
	encryptedShares: IBEEncryptions,
	ciphertext: Ciphertext,
});

/**
 * The Move struct for the KeyServer object.
 */
export const KeyServerMove = bcs.struct('KeyServer', {
	id: bcs.Address,
	name: bcs.string(),
	url: bcs.string(),
	keyType: bcs.u8(),
	pk: bcs.vector(bcs.u8()),
});
