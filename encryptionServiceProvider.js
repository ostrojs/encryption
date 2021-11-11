const ServiceProvider = require('@ostro/support/serviceProvider');
const Encrypter = require('./encrypter')
const HashManager = require('./hashManager')
const MissingAppKeyException = require('./missingAppKeyException')
class EncryptionServiceProvider extends ServiceProvider {

    register() {
        this.registerEncrypter();
        this.registerHash()
    }

    registerHash() {
        this.$app.singleton('hash', function($app) {
            return new HashManager($app);
        });

        this.$app.singleton('hash.driver', function($app) {
            return $app['hash'].driver();
        });
    }

    registerEncrypter() {
        this.$app.singleton('encrypter', ($app) => {
            let $config = $app.make('config').get('app');

            return new Encrypter(this.parseKey($config), $config['cipher']);
        });
    }

    parseKey($config) {
        let $key = this.key($config)
        let $prefix = 'base64:'
        if (String.startsWith($key, $prefix)) {
            $key = new Buffer(String.after($key, $prefix), 'base64');
            $key = $key.toString('ascii')
        }

        return $key;
    }

    key($config) {
        return tap($config['key'], function($key) {
            if (!$key) {
                throw new MissingAppKeyException;
            }
        });
    }

}
module.exports = EncryptionServiceProvider