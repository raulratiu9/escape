package dev.raul.escape.auth.exception;

public class OAuth2EmailMissingException extends RuntimeException {

    public OAuth2EmailMissingException() {
        super("OAuth2 provider did not return an email");
    }
}