package com.wise.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.REQUEST_TIMEOUT, reason="Service processing timed out.")
public class ServiceTimeoutException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ServiceTimeoutException() {
        super();
    }

    public ServiceTimeoutException(String msg) {
        super(msg);
    }

    public ServiceTimeoutException(Throwable cause) {
        super(cause);
    }

    public ServiceTimeoutException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
