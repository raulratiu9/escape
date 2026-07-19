package dev.raul.escape.auth.exception;

public class EmailAlreadyRegisteredWithLocalLoginException extends RuntimeException {

    public EmailAlreadyRegisteredWithLocalLoginException(String email) {
        super("Email already registered with local login: " + email);
    }
}