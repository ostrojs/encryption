class MissingAppKeyException extends Error {
    public code: string;
    public statusCode: number;

    /**
     * Create a new MissingAppKeyException instance.
     *
     * @param message - The error message
     */
    constructor(message?: string) {
        super(message || 'Key is missing on config');
        this.name = this.constructor.name;
        this.code = 'ERR_MISS_KEY';
        this.statusCode = 500;
        this.message = message || 'Key is missing on config';
        Error.captureStackTrace(this, this.constructor);
    }
}

export default MissingAppKeyException;