#[cfg(test)]
mod fs_abstraction_tests {
    use fs_abstraction::FsError;

    #[test]
    fn test_fs_error_types() {
        let err = FsError::BufferTooSmall;
        assert!(matches!(err, FsError::BufferTooSmall));

        let err = FsError::InvalidMagic;
        assert!(matches!(err, FsError::InvalidMagic));

        let err = FsError::Corrupted;
        assert!(matches!(err, FsError::Corrupted));
    }
}
