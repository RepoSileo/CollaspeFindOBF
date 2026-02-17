// This file defines macros for colored text output.
// It handles the conditional compilation based on the "cli" feature.

#[cfg(feature = "cli")]
#[macro_export]
macro_rules! yellow_text {
    ($text:expr) => {
        {
            use colored::Colorize;
            $text.yellow()
        }
    };
}

#[cfg(not(feature = "cli"))]
#[macro_export]
macro_rules! yellow_text {
    ($text:expr) => {
        $text
    };
}

#[cfg(feature = "cli")]
#[macro_export]
macro_rules! blue_text {
    ($text:expr) => {
        {
            use colored::Colorize;
            $text.blue()
        }
    };
}

#[cfg(not(feature = "cli"))]
#[macro_export]
macro_rules! blue_text {
    ($text:expr) => {
        $text
    };
}

#[cfg(feature = "cli")]
#[macro_export]
macro_rules! green_text {
    ($text:expr) => {
        {
            use colored::Colorize;
            $text.green()
        }
    };
}

#[cfg(not(feature = "cli"))]
#[macro_export]
macro_rules! green_text {
    ($text:expr) => {
        $text
    };
}

#[cfg(feature = "cli")]
#[macro_export]
macro_rules! dimmed_text {
    ($text:expr) => {
        {
            use colored::Colorize;
            $text.dimmed()
        }
    };
}

#[cfg(not(feature = "cli"))]
#[macro_export]
macro_rules! dimmed_text {
    ($text:expr) => {
        $text
    };
}
