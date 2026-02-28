use log::{Level, LevelFilter, Metadata, Record};

/// Simple serial port logger
struct SerialLogger;

static LOGGER: SerialLogger = SerialLogger;

impl log::Log for SerialLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let (level_str, msg_color) = match record.level() {
                Level::Error => ("\x1b[31mERROR\x1b[0m", "\x1b[31m"),
                Level::Warn => ("\x1b[33mWARN\x1b[0m", "\x1b[33m"),
                Level::Info => ("\x1b[32mINFO\x1b[0m", "\x1b[37m"),
                Level::Debug => ("\x1b[90mDEBUG\x1b[0m", "\x1b[90m"),
                Level::Trace => ("\x1b[90mTRACE\x1b[0m", "\x1b[90m"),
            };

            crate::arch::x86_64::serial::_print(format_args!(
                "[{}] {}{}\x1b[0m\n",
                level_str,
                msg_color,
                record.args()
            ));
        }
    }

    fn flush(&self) {}
}

/// Initialize the logger
pub fn init() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Trace))
        .expect("Failed to set logger");
}
