import Encrypter from '../src/encrypter';
import DecryptException from '../src/decryptException';
import RuntimeException from '@ostro/support/exceptions/runtimeException';
import CryptoHasher from '../src/cryptoHasher';
import BcryptHasher from '../src/bcryptHasher';
import HashManager from '../src/hashManager';
import EncryptionServiceProvider from '../src/encryptionServiceProvider';
import MissingAppKeyException from '../src/missingAppKeyException';
import Container from '@ostro/container';
import crypto from 'crypto';
import bcrypt from 'bcrypt';


describe('@ostro/encryption Unit Tests', () => {

    describe('Encrypter', () => {
        const key16 = '1234567890123456';
        const key24 = '123456789012345678901234';
        const key32 = '12345678901234567890123456789012';

        test('instantiates with supported ciphers and key lengths', () => {
            const enc128 = new Encrypter(key16, 'AES-128-CBC');
            expect(enc128.getKey()).toBe(key16);
            expect(enc128.getKeyLength()).toBe(16);

            const enc192 = new Encrypter(key24, 'AES-192-CBC');
            expect(enc192.getKeyLength()).toBe(24);

            const enc256 = new Encrypter(key32, 'AES-256-CBC');
            expect(enc256.getKeyLength()).toBe(32);
        });

        test('throws RuntimeException on unsupported key length or cipher', () => {
            expect(() => new Encrypter('shortkey', 'AES-128-CBC')).toThrow(RuntimeException);
            expect(() => new Encrypter(key16, 'DES-EDE3-CBC')).toThrow(RuntimeException);
        });

        test('encrypt and decrypt serialized objects and primitives', () => {
            const enc = new Encrypter(key16, 'AES-128-CBC');
            const data = { user: 'Alice', age: 30, permissions: ['read', 'write'] };

            const encrypted = enc.encrypt(data);
            expect(typeof encrypted).toBe('string');
            expect(encrypted).not.toContain('Alice');

            const decrypted = enc.decrypt(encrypted);
            expect(decrypted).toEqual(data);
        });

        test('encryptString and decrypt string payloads', () => {
            const enc = new Encrypter(key32, 'AES-256-CBC');
            const secret = 'super-secret-plain-text';

            const encrypted = enc.encryptString(secret);
            const decrypted = enc.decrypt(encrypted, false);
            expect(decrypted).toBe(secret);
        });

        test('decrypt throws DecryptException on invalid payload or tampered payload', () => {
            const enc = new Encrypter(key16, 'AES-128-CBC');

            // invalid base64 json
            const invalidPayload = Buffer.from('invalid-json').toString('base64');
            expect(() => enc.decrypt(invalidPayload)).toThrow(DecryptException);

            // payload missing required keys or invalid iv length
            const incompletePayload = Buffer.from(JSON.stringify({ iv: 'short', value: 'xyz' })).toString('base64');
            expect(() => enc.decrypt(incompletePayload)).toThrow(DecryptException);
        });
    });

    describe('CryptoHasher', () => {
        test('make and check passwords with default and custom rounds', () => {
            const hasher = new CryptoHasher({ rounds: 16 });
            expect(hasher.cost()).toBe(16);
            expect(hasher.supportedAlgorithm()).toEqual(['sha256', 'sha512']);

            const hash = hasher.make('secretPassword');
            expect(hash).toContain('$5a$16$');

            expect(hasher.check('secretPassword', hash)).toBe(true);
            expect(hasher.check('wrongPassword', hash)).toBe(false);
        });

        test('info returns parsed hashing metadata', () => {
            const hasher = new CryptoHasher();
            const hash = hasher.make('myPassword', { rounds: 12 });
            const info = hasher.info(hash);

            expect(info).toBeDefined();
            expect(info.cost).toBe(12);
            expect(info.algorithm).toBe('sha256');

            expect(hasher.info('invalid-hash-string')).toBe(false);
        });

        test('needsRehash verifies if cost configuration differs', () => {
            const hasher = new CryptoHasher({ rounds: 16 });
            const hash16 = hasher.make('pass', { rounds: 16 });

            expect(hasher.needsRehash(hash16)).toBe(false);
            expect(hasher.needsRehash(hash16, { rounds: 20 })).toBe(true);
            expect(hasher.needsRehash('invalid-hash')).toBe(true);
        });

        test('info parses various algorithm identifiers', () => {
            const hasher = new CryptoHasher();
            expect(hasher.info('$1a$10$').algorithm).toBe('md5');
            expect(hasher.info('$2a$10$').algorithm).toBe('bcrypt');
            expect(hasher.info('$5a$10$').algorithm).toBe('sha256');
            expect(hasher.info('$6a$10$').algorithm).toBe('sha512');
            expect(hasher.info('$9a$10$').algorithm).toBe('9');
        });

        test('throws RuntimeException when verifyAlgorithm is enabled and algorithm mismatches', () => {
            const hasher = new CryptoHasher({ verify: true });
            const md5Hash = '$1a$10$' + Buffer.from('saltandhash').toString('base64');
            expect(() => hasher.check('secret', md5Hash)).toThrow(RuntimeException);
        });

        test('setRounds alters default cost rounds', () => {
            const hasher = new CryptoHasher();
            hasher.setRounds(20);
            expect(hasher.cost()).toBe(20);
        });

        test('check returns false for invalid hash format', () => {
            const hasher = new CryptoHasher();
            expect(hasher.check('plain', 'not-a-valid-hash-format')).toBe(false);
        });

        test('info parses sha1 algorithm identifier', () => {
            const hasher = new CryptoHasher();
            expect(hasher.info('$sha1$10$').algorithm).toBe('sha1');
        });

        test('make throws RuntimeException when crypto hashing returns false', () => {
            const hasher = new CryptoHasher();
            const origHmac = crypto.createHmac;
            crypto.createHmac = (() => ({
                update: () => ({
                    digest: () => false
                })
            })) as any;
            try {
                expect(() => hasher.make('secret')).toThrow('Crypto hashing not supported.');
            } finally {
                crypto.createHmac = origHmac;
            }
        });
    });

    describe('BcryptHasher', () => {
        test('make and check passwords with bcrypt', () => {
            const hasher = new BcryptHasher({ rounds: 10 });
            const hash = hasher.make('plainPassword');

            expect(hasher.check('plainPassword', hash)).toBe(true);
            expect(hasher.check('invalidPassword', hash)).toBe(false);
        });

        test('make throws RuntimeException when bcrypt.hashSync returns false', () => {
            const hasher = new BcryptHasher({ rounds: 10 });
            const origHashSync = bcrypt.hashSync;
            bcrypt.hashSync = (() => false) as any;
            try {
                expect(() => hasher.make('secret')).toThrow('Bcrypt hashing not supported.');
            } finally {
                bcrypt.hashSync = origHashSync;
            }
        });

        test('info and needsRehash methods', () => {
            const hasher = new BcryptHasher({ rounds: 10 });
            const hash = hasher.make('plainPassword');

            const info = hasher.info(hash);
            expect(info.algoName).toBe('bcrypt');
            expect(info.options.cost).toBe(10);

            expect(hasher.needsRehash(hash)).toBe(false);
            expect(hasher.needsRehash(hash, { rounds: 12 })).toBe(true);
        });

        test('setRounds modifies rounds', () => {
            const hasher = new BcryptHasher();
            hasher.setRounds(12);
            expect(hasher.cost()).toBe(12);
        });
    });

    describe('HashManager', () => {
        test('resolves default driver and performs hashing operations', () => {
            const app = new Container();
            app.bind('config', () => ({
                hashing: {
                    driver: 'bcrypt',
                    bcrypt: { rounds: 10 },
                    crypto: { rounds: 16 }
                }
            }));

            const hashManager = new HashManager(app);
            expect(hashManager.getDefaultDriver()).toBe('bcrypt');

            const hash = hashManager.make('userPass');
            expect(hashManager.check('userPass', hash)).toBe(true);
            expect(hashManager.check('wrongPass', hash)).toBe(false);
            expect(hashManager.check('userPass', '')).toBe(false);
            expect(hashManager.needsRehash(hash)).toBe(false);
            expect(hashManager.info(hash)).toBeDefined();
        });

        test('resolves crypto driver and handles custom creators', () => {
            const app = new Container();
            app.bind('config', () => ({
                hashing: {
                    driver: 'crypto',
                    crypto: { rounds: 16 }
                }
            }));

            const hashManager = new HashManager(app);
            const cryptoDriver = hashManager.driver('crypto');
            expect(cryptoDriver).toBeInstanceOf(CryptoHasher);

            // Custom creator
            hashManager.extend('custom_hash', () => {
                return {
                    make: (val) => `custom_${val}`,
                    check: (val, hash) => hash === `custom_${val}`,
                    info: () => ({ algo: 'custom' }),
                    needsRehash: () => false
                };
            });

            const customDriver = hashManager.driver('custom_hash');
            expect(customDriver.make('hello')).toBe('custom_hello');
            expect(customDriver.check('hello', 'custom_hello')).toBe(true);
            expect(hashManager.check(undefined as any, 'custom_hello')).toBe(false);
            expect((hashManager as any).callCustomCreator({}, 'custom_hash')).toBeDefined();

            const defaultEnc = new Encrypter('1234567890123456');
            expect(defaultEnc.getKeyLength()).toBe(16);

            expect(() => hashManager.driver('unsupported_driver')).toThrow('not supported');
        });
    });

    describe('EncryptionServiceProvider & Exceptions', () => {
        test('registers encrypter and hash services in container', () => {
            const app = new Container();
            const configObj = {
                app: {
                    key: '1234567890123456',
                    cipher: 'AES-128-CBC'
                },
                hashing: {
                    driver: 'bcrypt'
                }
            };
            app.bind('config', () => ({
                get: (key) => configObj[key]
            }));

            const provider = new EncryptionServiceProvider(app);
            provider.register();

            expect(app.bound('encrypter')).toBe(true);
            expect(app.bound('hash')).toBe(true);
            expect(app.bound('hash.driver')).toBe(true);

            const enc = app.make('encrypter');
            expect(enc).toBeInstanceOf(Encrypter);
            expect(enc.getKey()).toBe('1234567890123456');

            const hash = app.make('hash');
            expect(hash).toBeInstanceOf(HashManager);

            const hashDriver = app.make('hash.driver');
            expect(hashDriver).toBeInstanceOf(BcryptHasher);
        });

        test('HashManager creates bcrypt and crypto drivers with missing/empty configs', () => {
            const app = new Container();
            app.bind('config', () => ({
                hashing: {}
            }));
            const hashManager = new HashManager(app);
            const bcryptD = hashManager.createBcryptDriver();
            expect(bcryptD).toBeInstanceOf(BcryptHasher);

            const cryptoD = hashManager.createCryptoDriver();
            expect(cryptoD).toBeInstanceOf(CryptoHasher);
        });

        test('parses base64: prefixed application keys', () => {
            const app = new Container();
            const rawKey = '1234567890123456';
            const base64Key = 'base64:' + Buffer.from(rawKey).toString('base64');
            const configObj = {
                app: {
                    key: base64Key,
                    cipher: 'AES-128-CBC'
                }
            };
            app.bind('config', () => ({
                get: (key) => configObj[key]
            }));

            const provider = new EncryptionServiceProvider(app);
            provider.register();

            const enc = app.make('encrypter');
            expect(enc.getKey()).toBe(rawKey);
        });

        test('throws MissingAppKeyException when app key is empty', () => {
            const app = new Container();
            const configObj = {
                app: {
                    key: '',
                    cipher: 'AES-128-CBC'
                }
            };
            app.bind('config', () => ({
                get: (key) => configObj[key]
            }));

            const provider = new EncryptionServiceProvider(app);
            provider.register();

            expect(() => app.make('encrypter')).toThrow(MissingAppKeyException);
        });

        test('MissingAppKeyException and DecryptException properties', () => {
            const missingKeyErr = new MissingAppKeyException();
            expect(missingKeyErr.statusCode).toBe(500);
            expect(missingKeyErr.code).toBe('ERR_MISS_KEY');

            const decryptErr = new DecryptException();
            expect(decryptErr.statusCode).toBe(500);
            expect(decryptErr.code).toBe('ERR_DECRYPT_PAYLOAD');
        });
    });

});
