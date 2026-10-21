import type { IEncrypter } from '@ostro/contracts/encryption/encrypter';
import '@ostro/support/helpers';
import EncrypterContract from '@ostro/contracts/encryption/encrypter';
import RuntimeException from '@ostro/support/exceptions/runtimeException';
import DecryptException from './decryptException';
import crypto from 'crypto';
import { is_json, isset } from '@ostro/support/function';

interface EncryptionPayload {
    iv: string;
    value: string;
    mac: string;
    [key: string]: unknown;
}

class Encrypter extends EncrypterContract implements IEncrypter {
    protected $key: string;
    protected $cipher: string;

    /**
     * Create a new Encrypter instance.
     *
     * @param key - Encryption key
     * @param cipher - Cipher algorithm name
     */
    constructor($key: string, $cipher: string = 'AES-128-CBC') {
        super();
        if (this.supported($key, $cipher)) {
            this.$key = $key;
            this.$cipher = $cipher;
        } else {
            throw new RuntimeException('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');
        }
    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param key - Encryption key
     * @param cipher - Cipher algorithm
     * @returns True if combination is supported
     */
    public supported($key: string, $cipher: string): boolean {
        const $length = $key.length;
        return ($cipher === 'AES-128-CBC' && $length === 16) ||
            ($cipher === 'AES-192-CBC' && $length === 24) ||
            ($cipher === 'AES-256-CBC' && $length === 32);
    }

    /**
     * Get the length of the encryption key.
     *
     * @returns Length of key
     */
    public getKeyLength(): number {
        return this.$key.length;
    }

    /**
     * Generate a new random IV key.
     *
     * @returns Buffer containing random bytes
     */
    public generateKey(): Buffer {
        return crypto.randomBytes(16);
    }

    /**
     * Encrypt the given value.
     *
     * @typeParam T - Type of the value being encrypted
     * @param value - Value to encrypt
     * @param serialize - Whether to JSON serialize the value
     * @returns Base64 encoded payload
     */
    public encrypt<T = unknown>($value: T, $serialize: boolean = true): string {
        const iv: Buffer = this.generateKey();
        const cipher = crypto.createCipheriv(this.$cipher, this.$key, iv);
        const serializedValue: string = ($serialize ? JSON.stringify($value) : $value) as string;
        const encrypted: string = Buffer.concat([cipher.update(serializedValue, 'utf-8'), cipher.final()]).toString('base64');

        return Buffer.from(JSON.stringify({
            iv: iv.toString('base64'),
            value: encrypted,
            mac: this.$cipher
        })).toString('base64');
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param value - String value to encrypt
     * @returns Base64 encoded payload
     */
    public encryptString($value: string): string {
        return this.encrypt($value, false);
    }

    /**
     * Decrypt the given payload.
     *
     * @typeParam T - Expected return type
     * @param payload - Base64 encoded payload string or object
     * @param unserialize - Whether to parse JSON result
     * @returns Decrypted value
     */
    public decrypt<T = unknown>($payload: string | Record<string, any>, $unserialize: boolean = true): T {
        const payloadObj = this.getJsonPayload($payload);
        const $iv = Buffer.from(payloadObj['iv'], 'base64');
        const decipher = crypto.createDecipheriv(this.$cipher, this.$key, $iv);
        const $decrypted = Buffer.concat([decipher.update(Buffer.from(payloadObj['value'], 'base64')), decipher.final()]).toString();
        return ($unserialize ? JSON.parse($decrypted) : $decrypted) as T;
    }

    /**
     * Get the JSON array from the given raw payload.
     *
     * @param payload - Base64 payload string or payload object
     * @returns Parsed payload object
     */
    public getJsonPayload($payload: any): EncryptionPayload {
        try {
            $payload = JSON.parse(Buffer.from($payload, 'base64').toString());
        } catch (e) {
            throw new DecryptException('The payload is invalid.');
        }

        if (!this.validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }

        return $payload as EncryptionPayload;
    }

    /**
     * Verify that the encryption payload is valid.
     *
     * @param payload - Payload object to validate
     * @returns True if valid payload
     */
    public validPayload($payload: any): boolean {
        return is_json($payload) && isset($payload['iv'], $payload['value'], $payload['mac']) &&
            Buffer.from($payload['iv'], 'base64').length === 16;
    }

    /**
     * Get the encryption key.
     *
     * @returns Key string
     */
    public getKey(): string {
        return this.$key;
    }
}

export default Encrypter;