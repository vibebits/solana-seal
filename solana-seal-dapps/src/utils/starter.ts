export async function getFullEncryptionId(encryptionId: string) {
    return Buffer.from(encryptionId).toString('hex');
}