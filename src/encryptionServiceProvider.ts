import ServiceProvider from '@ostro/support/serviceProvider';
import { tap } from '@ostro/support/function';
import { startsWith, after } from '@ostro/support/string';
import Encrypter from './encrypter';
import HashManager from './hashManager';
import MissingAppKeyException from './missingAppKeyException';
import type { IConfig } from '@ostro/contracts/config/repository';

class EncryptionServiceProvider extends ServiceProvider {

    /**
     * Register the service provider.
     */
    public register(): void {
        this.registerEncrypter();
        this.registerHash();
    }

    /**
     * Register the hash manager service.
     */
    public registerHash(): void {
        this.$app.singleton('hash', function($app: any) {
            return new HashManager($app);
        });

        this.$app.singleton('hash.driver', function($app: any) {
            return $app['hash'].driver();
        });
    }

    /**
     * Register the encrypter service.
     */
    public registerEncrypter(): void {
        this.$app.singleton('encrypter', ($app: any) => {
            const configRepo = $app.make('config') as IConfig;
            const $config = (configRepo.get('app') as Record<string, any>) || {};

            return new Encrypter(this.parseKey($config), $config['cipher']);
        });
    }

    /**
     * Parse the encryption key from configuration.
     *
     * @param config - Application configuration object
     * @returns Parsed encryption key
     */
    public parseKey($config: Record<string, any>): string {
        let $key: any = this.key($config);
        const $prefix = 'base64:';
        if (startsWith($key, $prefix)) {
            const buffer = Buffer.from(after($key, $prefix), 'base64');
            $key = buffer.toString('ascii');
        }

        return $key;
    }

    /**
     * Extract the key from configuration and ensure it is not empty.
     *
     * @param config - Application configuration object
     * @returns The raw key string
     */
    public key($config: Record<string, any>): string {
        return tap($config['key'], function($key: any) {
            if (!$key) {
                throw new MissingAppKeyException();
            }
        });
    }
}

export default EncryptionServiceProvider;