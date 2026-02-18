use std::path::PathBuf;

use crate::types::{DetectionMode, ScanResult};
use crate::gui::lang::Language;
use crate::gui::state::ThemeMode;
use iced::Color;

#[derive(Debug, Clone)]
pub enum Message {
    SelectPath,
    PathSelected(Option<PathBuf>),
    PathInputChanged(String),

    ModeChanged(DetectionMode),
    ThreadsChanged(String),

    ExcludePatternChanged(String),
    AddExcludePattern,
    RemoveExcludePattern(usize),
    FindPatternChanged(String),
    AddFindPattern,
    RemoveFindPattern(usize),

    StartScan,
    CancelScan,
    ScanCompleted(Result<Vec<ScanResult>, String>),
    Tick,

    TabSelected(usize),
    ClearResults,
    ExpandFinding(usize),
    ResultsSearchChanged(String),
    ResultsSeverityChanged(&'static str),
    ResultsSortChanged(&'static str),
    ResultsSortDirectionToggled,
    ExportFilteredResults,
    ExportResultsCompleted(Result<(), String>),

    
    LanguageChanged(Language),
    ThemeChanged(ThemeMode),
    AccentColorChanged(Color),
}
