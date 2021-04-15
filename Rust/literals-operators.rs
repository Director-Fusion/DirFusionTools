fn main() {
    // Interger addition
    println!("1 + 2 = {}", 1u32 + 2);

    // Integer Subtraction
    println!("1 - 2 = {}", 1i32 - 2);
    // TODO Try changing 1i32 to 1u32 to see why the type is important.

    // Short-circuiting boolean logic
    println!("True AND False is {}", true && false);
    println!("true OR false is {}", true || false);
    println!("NOT true is {}", !true);

    //Bitwise operations
    println!("0011 AND 010 is {:04b}", 0b0011u32 & 0b0101);

    // Use underscores to improve readability
    println!("One million is written as {}", 1_000_000u32);
}