macro_rules! shake256 {
    ( $output:expr ; $( $input:expr ),* ) => {
        let mut hasher = ::sha3::Shake256::default();
        $(
            ::digest::Input::input(&mut hasher, &$input[..]);
        )*
        let mut reader = ::digest::ExtendableOutput::xof_result(hasher);
        ::digest::XofReader::read(&mut reader, $output);
    }
}

macro_rules! sha3_256 {
    ( $output:expr ; $( $input:expr ),* ) => {
        let mut hasher = ::sha3::Sha3_256::default();
        $(
            ::digest::Input::input(&mut hasher, &$input[..]);
        )*
        $output.copy_from_slice(::digest::FixedOutput::fixed_result(hasher).as_slice());
    }
}

macro_rules! sha3_512 {
    ( $output:expr ; $( $input:expr ),* ) => {
        let mut hasher = ::sha3::Sha3_512::default();
        $(
            ::digest::Input::input(&mut hasher, &$input[..]);
        )*
        $output.copy_from_slice(::digest::FixedOutput::fixed_result(hasher).as_slice());
    }
}
