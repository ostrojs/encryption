require('@ostro/support/helpers')
const EncrypterContract = require('@ostro/contracts/encryption/encrypter');
const RuntimeException = require('@ostro/support/exceptions/runtimeException')
var crypto = require('crypto');
class Encrypter extends EncrypterContract {

    constructor($key, $cipher = 'AES-128-CBC') {
        super()
        if (this.supported($key, $cipher)) {
            this.$key = $key;
            this.$cipher = $cipher;
        } else {
            throw new RuntimeException('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');
        }
    }

    supported($key, $cipher) {
        let $length = $key.length;
        return ($cipher === 'AES-128-CBC' && $length === 16) ||
            ($cipher === 'AES-192-CBC' && $length === 24) ||
            ($cipher === 'AES-256-CBC' && $length === 32);
    }

    getKeyLength() {
        return this.$key.length
    }

    generateKey() {
        return crypto.randomBytes(this.getKeyLength() / 2);
    }

    encrypt($value, $serialize = true) {

        const iv = this.generateKey()

        const cipher = crypto.createCipheriv(this.$cipher, this.$key, iv)

        $value = ($serialize ? JSON.stringify($value) : $value)

        const encrypted = Buffer.concat([cipher.update($value, 'utf-8'), cipher.final()]).toString('base64')

        return Buffer.from(JSON.stringify({
            iv: iv.toString('base64'),
            value: encrypted,
            mac: this.$cipher
        })).toString('base64')
    }

    encryptString($value) {
        return this.encrypt($value, false);
    }

    decrypt($payload, $unserialize = true) {

        $payload = this.getJsonPayload($payload);
        let $iv = Buffer.from($payload['iv'], 'base64');
        const decipher = crypto.createDecipheriv(this.$cipher, this.$key, $iv);
        let $decrypted = Buffer.concat([decipher.update(Buffer.from($payload['value'], 'base64'), 'utf-8'), decipher.final()]).toString()
        return $unserialize ? JSON.parse($decrypted) : $decrypted;
    }

    getJsonPayload($payload) {
        $payload = JSON.parse(Buffer.from($payload, 'base64').toString());

        if (!this.validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }

        return $payload;
    }

    validPayload($payload) {

        return is_json($payload) && isset($payload['iv'], $payload['value'], $payload['mac']) &&
            Buffer.from($payload['iv'], 'base64').length === this.generateKey(this.$cipher).length;
    }

    getKey() {
        return this.$key;
    }
}

module.exports = Encrypter