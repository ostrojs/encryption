class MissingAppKeyException extends Error {
    constructor(message) {
        super();
        this.name = this.constructor.name;
        this.code = 'ERR_MISS_KEY';
        this.statusCode = 500;
        this.message = message || 'Key is missing on config';
        Error.captureStackTrace(this, this.constructor);
    }
}
module.exports = MissingAppKeyException