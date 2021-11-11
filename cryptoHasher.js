const HasherContract = require('@ostro/contracts/encryption/hasher');
const RuntimeException = require('@ostro/support/exceptions/runtimeException');
const crypto = require('crypto');

class CryptoHasher extends HasherContract {

    $rounds = 0;

    constructor($options = {}) {
        super()
        this.$rounds = $options['rounds'] || this.$rounds;
        this.$verifyAlgorithm = $options['verify'] || this.$verifyAlgorithm;
    }
    supportedAlgorithm() {
        return ['sha256', 'sha512']
    }

    make($value, $options = {}) {

        let $salt = crypto.randomBytes(this.cost()).toString('ascii')
        let $hash = crypto.createHmac('sha256', $salt).update($value).digest('ascii');
        if ($hash === false) {
            throw new RuntimeException('Crypto hashing not supported.');
        }
        return '$5a$' + this.$rounds + '$' + Buffer.from($salt + $hash).toString('base64');
    }

    check($value, $hashedValue, $options = {}) {
        let passwordInfo = this.info($hashedValue)
        if (this.$verifyAlgorithm && passwordInfo['algorithm'] !== 'sha256') {
            throw new RuntimeException('This password does not use the sha256 algorithm.');
        }
        $hashedValue = Buffer.from($hashedValue.replace(passwordInfo.identifier, ''), 'base64').toString('utf-8')
        let $rounds = (passwordInfo.cost * passwordInfo.costFactor)
        let $salt = $hashedValue.substring(0, $rounds)
        $hashedValue = $hashedValue.substr($rounds, $hashedValue.length)

        return crypto.createHmac('sha256', $salt).update($value).digest('ascii') == $hashedValue
    }

    setRounds($rounds) {
        this.$rounds = $rounds;

        return this;
    }

    info($hashedValue) {
        let [identifier, algorithm, unicode, cost] = $hashedValue.match(/\$([0-9]+)([a-zA-Z])\$([0-9]+)\$/)
        if (algorithm == 1) {
            algorithm = 'md5'
        } else if (algorithm == 2) {
            algorithm = 'bcrypt'
        } else if (algorithm == 'sha1') {
            algorithm = 'sha1'
        } else if (algorithm == 5) {
            algorithm = 'sha256'
        } else if (algorithm == 6) {
            algorithm = 'sha512'
        }
        return { identifier, algorithm, cost: parseInt(cost), costFactor: 1 }
    }

    cost($options = {}) {
        return $options['rounds'] || this.$rounds;
    }
}

module.exports = CryptoHasher