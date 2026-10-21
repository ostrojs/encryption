class DecryptException extends Error {
    public code: string;
    public statusCode: number;

    /**
     * Create a new DecryptException instance.
     *
     * @param message - The error message
     */
    constructor(message: string = 'The payload is invalid.') {
        super(message);
        this.name = this.constructor.name;
        this.code = 'ERR_DECRYPT_PAYLOAD';
        this.statusCode = 500;
        Error.captureStackTrace(this, this.constructor);
    }
}

export default DecryptException;

