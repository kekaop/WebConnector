package com.eldryn.webconnector.api;

/** Expected rejection; message is safe to return to clients. */
public final class ActionException extends RuntimeException {
    private final int httpStatus;
    private final String code;
    public ActionException(int httpStatus, String code, String message) { super(message); this.httpStatus = httpStatus; this.code = code; }
    public int httpStatus() { return httpStatus; }
    public String code() { return code; }
}
