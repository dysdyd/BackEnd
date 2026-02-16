export const ValidationConstants = {
    // Simple Email Regex: ^[^\s@]+@[^\s@]+\.[^\s@]+$
    EMAIL_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    PASSWORD_MIN_LENGTH: 8,
    // At least one letter and one number
    PASSWORD_PATTERN: /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/,
};
