package dspm.lib;

import javacard.framework.CardRuntimeException;

/** An exception class of a library package, thrown here and caught in another package. */
public class LibException extends CardRuntimeException {
    public LibException(short reason) {
        super(reason);
    }
}
