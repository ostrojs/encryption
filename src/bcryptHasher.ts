import HasherContract from '@ostro/contracts/encryption/hasher';
import RuntimeException from '@ostro/support/exceptions/runtimeException';
import bcrypt from 'bcrypt';

interface BcryptHasherOptions {
    rounds?: number;
    [key: string]: unknown;
}

interface BcryptHashInfo {
    algo: string;
    algoName: string;
    options: {
        cost: number;
    };
}

class BcryptHasher extends HasherContract {

    /**
     * The default cost factor.
     */
    protected $rounds: number = 10;

    /**
     * Create a new BcryptHasher instance.
     *
     * @param options - Configuration options for Bcrypt hasher
     */
    constructor($options: BcryptHasherOptions = {}) {
        super();
        this.$rounds = ($options['rounds'] as number) || this.$rounds;
    }

    /**
     * Hash the given value.
     *
     * @param value - Value to hash
     * @param options - Additional hashing options
     * @returns Hashed string
     */
    public make($value: string | Buffer, $options: BcryptHasherOptions = {}): string {
        const salt: string = bcrypt.genSaltSync(this.cost($options));

        const $hash: string | false = bcrypt.hashSync($value, salt);
        if ($hash === false) {
            throw new RuntimeException('Bcrypt hashing not supported.');
        }

        return $hash;
    }

    /**
     * Check the given plain value against a hash.
     *
     * @param value - Plain text value
     * @param hashedValue - Hashed string to compare against
     * @param options - Comparison options
     * @returns True if value matches hash
     */
    public check($value: string | Buffer, $hashedValue: string, $options: BcryptHasherOptions = {}): boolean {
        return bcrypt.compareSync($value, $hashedValue);
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
     * @returns Hash information object
     */
    public info($hashedValue?: string): BcryptHashInfo {
        return {
            algo: '2y',
            algoName: 'bcrypt',
            options: { cost: this.cost() }
        };
    }

    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param hashedValue - Hashed string
     * @param options - Options to check against
     * @returns True if rehashing is needed
     */
    public needsRehash($hashedValue?: string, $options: BcryptHasherOptions = {}): boolean {
        return this.cost($options) !== this.cost();
    }

    /**
     * Extract the cost value from the options.
     *
     * @param options - Options object
     * @returns Cost (number of rounds)
     */
    public cost($options: BcryptHasherOptions = {}): number {
        return ($options['rounds'] as number) || this.$rounds;
    }
}

export default BcryptHasher;