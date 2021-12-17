require('@ostro/support/helpers')
const Manager = require('@ostro/support/manager');
class HashManager extends Manager {

    $type = 'hashing';

    resolve($driver) {
        if (isset(this.$customCreators[$driver])) {
            return this.callCustomCreator($driver);
        } else {
            let $method = 'create' + String.pascal($driver) + 'Driver';

            if (method_exists(this, $method)) {
                return this[$method]();
            }
        }

        throw new InvalidArgumentException("Driver [" + $driver + "] not supported.");
    }

    callCustomCreator($driver) {
        return this.$customCreators[$driver].call(this, this.$container, $driver, this.$config);
    }

    createBcryptDriver() {
        return new(require('./bcryptHasher'))(this.getConfig('bcrypt') || {});
    }

    createCryptoDriver() {
        return new(require('./cryptoHasher'))(this.getConfig('crypto') || {});
    }

    info($hashedValue) {
        return this.driver().info($hashedValue);
    }

    make($value, $options = []) {
        return this.driver().make($value, $options);
    }

    check($value='', $hashedValue, $options = []) {
        if ($hashedValue.length === 0) {
            return false;
        }
        return this.driver().check($value, $hashedValue, $options);
    }

    needsRehash($hashedValue, $options = []) {
        return this.driver().needsRehash($hashedValue, $options);
    }

    getDefaultDriver() {
        return this.getConfig('driver', 'bcrypt');
    }
}

module.exports = HashManager