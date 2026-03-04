use super::*;

/// Show filesystem usage.
pub fn cmd_df(args: &[String]) -> Result<(), ShellError> {
    super::cmd_df_impl(args)
}
