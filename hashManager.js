require('@ostro/support/helpers')
const Manager = require('@ostro/support/manager');
class HashManager extends Manager {

    createBcryptDriver() {
        return new(require('./bcryptHasher'))(this.$config.get('hashing.bcrypt') || {});
    }

    createCryptoDriver() {
        return new(require('./cryptoHasher'))(this.$config.get('hashing.crypto') || {});
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
        return this.$config.get('hashing.driver', 'bcrypt');
    }
}

module.exports = HashManager