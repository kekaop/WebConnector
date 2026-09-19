package com.eldryn.webconnector.api;

/** A safe, public result. Do not put secrets or exception messages in results. */
public record ActionResult(boolean successful, String code, String message) {
    public static ActionResult success() { return new ActionResult(true, "success", "Completed"); }
    public static ActionResult failure(String code, String message) { return new ActionResult(false, code, message); }
}
