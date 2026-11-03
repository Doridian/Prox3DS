package dspm.lib;

/** Implemented in another package, called from this one (Counter.apply). */
public interface Visitor {
    short visit(Counter c, short x);
}
