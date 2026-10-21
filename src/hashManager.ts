import '@ostro/support/helpers';
import Manager from '@ostro/support/manager';
import InvalidArgumentException from '@ostro/support/exceptions/invalidArgumentException';
import { pascal } from '@ostro/support/string';
import { isset, method_exists } from '@ostro/support/function';
import BcryptHasher from './bcryptHasher';
import CryptoHasher from './cryptoHasher';

class HashManager extends Manager {

    /**
     * The type of the manager.
     */
    protected $type: string = 'hashing';

    /**
     * Resolve the given driver instance.
     *
     * @param driver - Driver name
     * @returns Hasher driver instance
     */
    public resolve($driver: string): any {
        if (isset(this.$customCreators[$driver])) {
            return this.callCustomCreator($driver);
        } else {
            const $method = 'create' + pascal($driver) + 'Driver';

            if (method_exists(this, $method)) {
                return (this as any)[$method]();
            }
        }

        throw new InvalidArgumentException("Driver [" + $driver + "] not supported.");
    }

    /**
     * Call a custom driver creator.
     *
     * @param driver - Driver name
     * @returns Driver instance returned by custom creator
     */
    public callCustomCreator($config: any, $name?: string): any {
        const driverName = typeof $config === 'string' ? $config : $name;
        return (this as any).$customCreators[driverName].call(this, this.$container, driverName, this.$config);
    }

    /**
     * Create an instance of the Bcrypt hash Driver.
     *
     * @returns Bcrypt hasher instance
     */
    public createBcryptDriver(): BcryptHasher {
        return new BcryptHasher(this.getConfig('bcrypt') || {});
    }

    /**
     * Create an instance of the Crypto hash Driver.
     *
     * @returns Crypto hasher instance
     */
    public createCryptoDriver(): CryptoHasher {
        return new CryptoHasher(this.getConfig('crypto') || {});
    }

    /**
     * Get information about the given hashed value.
     *
     * @param hashedValue - Hashed string
     * @returns Hash information object
     */
    public info($hashedValue: string): any {
        return this.driver().info($hashedValue);
    }

    /**
     * Hash the given value.
     *
     * @param value - Value to hash
     * @param options - Additional hashing options
     * @returns Hashed string
     */
    public make($value: any, $options: Record<string, any> = {}): string {
        return this.driver().make($value, $options);
    }

    /**
     * Check the given plain value against a hash.
     *
     * @param value - Plain text value
     * @param hashedValue - Hashed string to compare against
     * @param options - Comparison options
     * @returns True if value matches hash
     */
    public check($value: string = '', $hashedValue: string, $options: Record<string, any> = {}): boolean {
        if ($hashedValue.length === 0) {
            return false;
        }
        return this.driver().check($value, $hashedValue, $options);
    }

    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param hashedValue - Hashed string
     * @param options - Options to check against
     * @returns True if rehashing is needed
     */
    public needsRehash($hashedValue: string, $options: Record<string, any> = {}): boolean {
        return this.driver().needsRehash($hashedValue, $options);
    }

    /**
     * Get the default driver name.
     *
     * @returns Default driver name
     */
    public getDefaultDriver(): string {
        return this.getConfig('driver', 'bcrypt');
    }
}

export default HashManager;