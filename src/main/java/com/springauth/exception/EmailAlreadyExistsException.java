package com.springauth.exception;

// Create a custom exception
public class EmailAlreadyExistsException extends RuntimeException {
    public EmailAlreadyExistsException(String email) {
        // RuntimeException(String message) take a string as an error message
        // so when we call super like that java will know that what inside
        // super is an error message
        super("An account with email '" + email + "' already exists");
    }
}
