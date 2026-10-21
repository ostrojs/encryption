import HasherContract from '@ostro/contracts/encryption/hasher';
import RuntimeException from '@ostro/support/exceptions/runtimeException';
import crypto from 'crypto';

interface CryptoHasherOptions {
    rounds?: number;
    verify?: boolean;
    [key: string]: unknown;
}

interface CryptoHashInfo {
    identifier: string;
    algorithm: string;
    cost: number;
    costFactor: number;
}

class CryptoHasher extends HasherContract {

    /**
     * The default cost factor.
     */
    protected $rounds: number = 16;

    /**
     * Whether to verify the algorithm.
     */
    protected $verifyAlgorithm: boolean = false;

    /**
     * Create a new CryptoHasher instance.
     *
     * @param options - Configuration options
     */
    constructor($options: CryptoHasherOptions = {}) {
        super();
        this.$rounds = ($options['rounds'] as number) || this.$rounds;
        this.$verifyAlgorithm = ($options['verify'] as boolean) || this.$verifyAlgorithm;
    }

    /**
     * Get the supported algorithms.
     *
     * @returns Array of supported algorithm names
     */
    public supportedAlgorithm(): string[] {
        return ['sha256', 'sha512'];
    }

    /**
     * Hash the given value.
     *
     * @param value - Value to hash
     * @param options - Additional hashing options
     * @returns Hashed string
     */
    public make($value: crypto.BinaryLike, $options: CryptoHasherOptions = {}): string {
        const $salt: string = crypto.randomBytes(this.cost($options)).toString('ascii');
        const $hash: any = crypto.createHmac('sha256', $salt).update($value as any).digest('ascii' as any);
        if ($hash === false) {
            throw new RuntimeException('Crypto hashing not supported.');
        }
        return '$5a$' + this.cost($options) + '$' + Buffer.from($salt + $hash).toString('base64');
    }

    /**
     * Check the given plain value against a hash.
     *
     * @param value - Plain value
     * @param hashedValue - Hashed string
     * @param options - Additional options
     * @returns True if value matches hash
     */
    public check($value: unknown, $hashedValue: string, $options: CryptoHasherOptions = {}): boolean {
        const passwordInfo = this.info($hashedValue);
        if (!passwordInfo) {
            return false;
        }
        if (this.$verifyAlgorithm && passwordInfo['algorithm'] !== 'sha256') {
            throw new RuntimeException('This password does not use the sha256 algorithm.');
        }
        const decoded = Buffer.from($hashedValue.replace(passwordInfo.identifier, ''), 'base64').toString('utf-8');
        const $rounds = (passwordInfo.cost * passwordInfo.costFactor);
        const $salt = decoded.substring(0, $rounds);
        const hashPart = decoded.substring($rounds);
        return crypto.createHmac('sha256', $salt).update(String($value)).digest('ascii' as any) === hashPart;
    }

    /**
     * Set the default rounds.
     *
     * @param rounds - Number of rounds
     * @returns this
     */
    public setRounds($rounds: number): this {
        this.$rounds = $rounds;

        return this;
    }

    /**
     * Get information about the given hashed value.
     *
     * @param hashedValue - Hashed string
     * @returns Hash information object or false if invalid
     */
    public info($hashedValue: string): CryptoHashInfo | false {
        const match = $hashedValue.match(/\$([0-9]+|sha1)([a-zA-Z]?)\$([0-9]+)\$/);
        if (!match) {
            return false;
        }
        let [identifier, algorithm, unicode, cost] = match;
        if (algorithm === '1') {
            algorithm = 'md5';
        } else if (algorithm === '2') {
            algorithm = 'bcrypt';
        } else if (algorithm === 'sha1') {
            algorithm = 'sha1';
        } else if (algorithm === '5') {
            algorithm = 'sha256';
        } else if (algorithm === '6') {
            algorithm = 'sha512';
        }
        return { identifier, algorithm, cost: parseInt(cost, 10), costFactor: 1 };
    }

    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param hashedValue - Hashed string
     * @param options - Additional options
     * @returns True if rehashing is needed
     */
    public needsRehash($hashedValue: string, $options: CryptoHasherOptions = {}): boolean {
        const info = this.info($hashedValue);
        if (!info) {
            return true;
        }
        return info.cost !== this.cost($options);
    }

    /**
     * Extract the cost value from the options.
     *
     * @param options - Options object
     * @returns Cost (number of rounds)
     */
    public cost($options: CryptoHasherOptions = {}): number {
        return ($options['rounds'] as number) || this.$rounds;
    }
}

export default CryptoHasher;

