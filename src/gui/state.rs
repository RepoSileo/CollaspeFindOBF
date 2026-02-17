use crate::types::{DetectionMode, Progress};
use crate::gui::lang::Language;
use iced::Color;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum AppState {
    Idle,
    Scanning,
    Completed,
    Cancelled,
    Error(String),
}

pub type ScanProgress = Arc<Mutex<Progress>>;

#[derive(Debug, Clone)]
pub struct ScanSettings {
    pub path: String,
    pub mode: DetectionMode,
    pub threads: String,
    pub exclude_patterns: Vec<String>,
    pub find_patterns: Vec<String>,
    pub exclude_pattern_input: String,
    pub find_pattern_input: String,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            path: String::new(),
            mode: DetectionMode::Obfuscation,
            threads: String::from("0"),
            exclude_patterns: Vec::new(),
            find_patterns: Vec::new(),
            exclude_pattern_input: String::new(),
            find_pattern_input: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeMode {
    Dark,
    Light,
}

impl Default for ThemeMode {
    fn default() -> Self {
        Self::Dark
    }
}

impl std::fmt::Display for ThemeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         write!(
            f,
            "{}",
            match self {
                ThemeMode::Dark => "Dark",
                ThemeMode::Light => "Light",
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AppearanceSettings {
    pub theme: ThemeMode,
    pub language: Language,
    pub accent_color: Color,
}

impl Default for AppearanceSettings {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Dark,
            language: Language::English,
            accent_color: Color::from_rgb(0.0, 0.48, 1.0), // Default Blue
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResultsUi {
    pub search: String,
    pub severity: &'static str,
    pub sort_field: &'static str,
    pub sort_asc: bool,
}

impl Default for ResultsUi {
    fn default() -> Self {
        Self {
            search: String::new(),
            severity: "All",
            sort_field: "Danger",
            sort_asc: false,
        }
    }
}
