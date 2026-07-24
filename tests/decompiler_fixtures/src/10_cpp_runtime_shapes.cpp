/* 10_cpp_runtime_shapes.cpp
 *
 * C++ runtime-shape fixture (compile with g++). Exercises the compiler-generated
 * runtime shapes a decompiler must recover — virtual dispatch (vtables),
 * constructor/destructor sequencing, RAII cleanup, exception unwinding
 * (throw / try-catch), a capturing lambda, and a move — WITHOUT any STL
 * (<vector>/<string> etc.). The target is the generated runtime machinery, not
 * library functions.
 *
 * Each shape is wrapped in an `extern "C"` function that takes/returns plain
 * ints (and, for observable side effects, an int* out-parameter receiving an
 * 8-int buffer), so an execution-differential harness can drive every shape by C
 * symbol name and diff the return value plus any buffer writes.
 *
 * Differential vs. structural:
 *   - The extern "C" wrappers (cpp_virtual_dispatch, cpp_ctor_dtor,
 *     cpp_raii_guard, cpp_exception, cpp_lambda_capture, cpp_move): DIFFERENTIAL.
 *     Deterministic; return unique ints per path; ctor/dtor/RAII side effects are
 *     made observable through the int* out-parameter.
 *   - The underlying shapes themselves — the vtable layout / virtual-call
 *     dispatch, and the exception-handling (landing pad / unwind) tables — are
 *     STRUCTURAL assertions: the harness checks that a virtual call stays an
 *     indirect vtable dispatch and that throw/catch keeps its EH structure, which
 *     the differential return values corroborate but do not fully pin down.
 *
 * No floats. No STL. Deterministic throughout.
 */

/* --- virtual dispatch: base / derived with a virtual method ------------- */

struct Base {
    virtual int op(int x) { return x + 1000; }
    virtual ~Base() {}
};

struct Derived : Base {
    int op(int x) override { return x + 2000; }
};

/* sel picks the dynamic type; the call through the Base* is a virtual dispatch
 * whose result differs by type, so a mis-recovered vtable index diverges. */
extern "C" int cpp_virtual_dispatch(int sel, int x) {
    Base b;
    Derived d;
    Base *p = (sel & 1) ? static_cast<Base *>(&d) : &b;
    return p->op(x);               /* 2000+x for odd sel, 1000+x for even */
}

/* --- constructor / destructor with an observable side effect ------------ */

/* Writes a marker on construction and another on destruction into a caller
 * buffer, so ctor/dtor sequencing becomes observable and differential. */
struct Tracer {
    int *log;
    int idx;
    int tag;
    Tracer(int *l, int i, int t) : log(l), idx(i), tag(t) {
        log[idx] = tag + 1;        /* construction marker */
    }
    ~Tracer() {
        log[idx + 1] = tag + 2;    /* destruction marker */
    }
};

/* out must point to an 8-int buffer. Records ctor then dtor markers and returns
 * a deterministic code. */
extern "C" int cpp_ctor_dtor(int *out, int tag) {
    {
        Tracer t(out, 0, tag);     /* out[0] = tag+1 at ctor */
        out[2] = tag + 10;         /* body marker, before dtor */
    }                              /* out[1] = tag+2 at dtor (scope exit) */
    return out[0] + out[1] + out[2];
}

/* --- RAII cleanup: a guard whose destructor writes to a given int* ------ */

struct Guard {
    int *slot;
    int value;
    Guard(int *s, int v) : slot(s), value(v) {}
    ~Guard() { *slot = value; }    /* cleanup effect on scope exit */
};

/* out is an 8-int buffer. The guard's destructor writes `value` into out[0]
 * when the scope ends; observing that write is the differential signal. */
extern "C" int cpp_raii_guard(int *out, int value) {
    out[0] = 0;                    /* pre-cleanup sentinel */
    {
        Guard g(out, value + 700);
        out[1] = 42;               /* proves body ran before cleanup */
    }                              /* g.~Guard() writes out[0] = value+700 */
    return out[0];
}

/* --- exception: throw and a try/catch returning a distinct code --------- */

static int may_throw(int x) {
    if (x < 0)
        throw x;                   /* triggers unwind */
    return x + 5;
}

/* Distinct return on the caught vs. normal path exercises the EH tables. */
extern "C" int cpp_exception(int x) {
    try {
        return may_throw(x) + 3000;   /* normal path: x+5+3000 */
    } catch (int e) {
        return 9000 - e;              /* caught path: unique, depends on thrown value */
    }
}

/* --- capturing lambda invoked immediately ------------------------------- */

/* The lambda captures `x` by value and a local by reference; invoking it builds
 * and calls the compiler-generated closure type. */
extern "C" int cpp_lambda_capture(int x, int y) {
    int acc = 0;
    auto f = [x, &acc](int z) {
        acc += x * z;              /* uses by-value capture, mutates by-ref capture */
        return x + z;
    };
    int r = f(y);
    return r + acc;                /* (x+y) + (x*y): unique per (x,y) */
}

/* --- move operation ----------------------------------------------------- */

/* A type with distinct copy vs. move behavior: moving zeroes the source and
 * flags the destination, so whether a move (not a copy) occurred is observable. */
struct Movable {
    int v;
    int moved_in;
    Movable(int val) : v(val), moved_in(0) {}
    Movable(const Movable &o) : v(o.v), moved_in(0) {}          /* copy: flag stays 0 */
    Movable(Movable &&o) : v(o.v), moved_in(1) { o.v = 0; }     /* move: flag=1, source zeroed */
};

static int consume(Movable m) {
    return m.v + (m.moved_in ? 50 : 0);
}

/* Constructs a Movable and passes it via std::move-equivalent cast, so the move
 * constructor runs; the moved_in flag makes that observable in the return. */
extern "C" int cpp_move(int val) {
    Movable src(val);
    int r = consume(static_cast<Movable &&>(src));  /* forces move ctor */
    return r + src.v;              /* src.v zeroed by move => r only; r == val+50 */
}
