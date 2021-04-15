// arrays are made [1, 2, 3]

// tuples are made with parenthseis (1, true)

fn main() {
    // variables can be type annotated.
    let logical: bool = true;

    let a_float: f64 = 1.0; //Regular Annotation
    let an_integer = 5i32; //Suffix annotation.

    // Defaults used if not assigned
    let default_float =  3.0; // 'f64'
    let default_integer = 7; // 'i32'

    // A type can also be inferred from context
    let mut inferred_type = 12; // Type i64 is inferred from another line
    inferred_type = 4294967296i64;

    // A mutable variable's value can be changed
    let mut mutable = 12; //mutable 'i32'
    mutable = 21;

    //Error! The type of a variable can't be changed
    mutable = true;

    // Variables can be overwritten with shadowing.
    let mutable = true;

    
}