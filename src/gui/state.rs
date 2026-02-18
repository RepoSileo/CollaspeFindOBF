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

use serde::{Serialize, Deserialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AppearanceSettings {
    pub theme: ThemeMode,
    pub language: Language,
    #[serde(with = "color_serde")]
    pub accent_color: Color,
}

mod color_serde {
    use iced::Color;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(color: &Color, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (color.r, color.g, color.b, color.a).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Color, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (r, g, b, a) = <(f32, f32, f32, f32)>::deserialize(deserializer)?;
        Ok(Color { r, g, b, a })
    }
}

impl Default for AppearanceSettings {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Dark,
            language: Language::English,
            accent_color: Color::from_rgb(0.0, 0.48, 1.0),
        }
    }
}

impl AppearanceSettings {
    pub fn config_path() -> PathBuf {
        let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
        path.set_file_name("gui_settings.json");
        path
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(settings) = serde_json::from_str::<Self>(&content) {
                    return settings;
                }
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        let path = Self::config_path();
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, content);
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
