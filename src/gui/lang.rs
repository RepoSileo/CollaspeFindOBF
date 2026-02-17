use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    #[default]
    English,
    Russian,
}

impl Language {
    pub const ALL: [Language; 2] = [Language::English, Language::Russian];
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Language::English => "English",
                Language::Russian => "Русский",
            }
        )
    }
}

pub struct Translator {
    en: HashMap<&'static str, &'static str>,
    ru: HashMap<&'static str, &'static str>,
}

impl Translator {
    pub fn new() -> Self {
        let mut en = HashMap::new();
        let mut ru = HashMap::new();

        // General
        en.insert("app_title", "CollapseFindOBF");
        ru.insert("app_title", "CollapseFindOBF");
        
        en.insert("sidebar_scanner", "Scanner");
        ru.insert("sidebar_scanner", "Сканер");
        
        en.insert("sidebar_results", "Results");
        ru.insert("sidebar_results", "Результаты");
        
        en.insert("sidebar_settings", "Settings");
        ru.insert("sidebar_settings", "Настройки");

        // Scanner Tab
        en.insert("scan_title", "CollapseFindOBF");
        ru.insert("scan_title", "CollapseFindOBF");

        en.insert("scan_subtitle", "Advanced JAR/Class File Analysis Tool");
        ru.insert("scan_subtitle", "Продвинутый анализ JAR/Class файлов");
        
        en.insert("select_path_placeholder", "Select path to scan...");
        ru.insert("select_path_placeholder", "Выберите путь для сканирования...");
        
        en.insert("browse_button", "Browse...");
        ru.insert("browse_button", "Обзор...");
        
        en.insert("detection_mode_label", "Detection Mode:");
        ru.insert("detection_mode_label", "Режим обнаружения:");

        en.insert("start_scan_button", "Start Scan");
        ru.insert("start_scan_button", "Начать сканирование");

        en.insert("cancel_scan_button", "Cancel Scan");
        ru.insert("cancel_scan_button", "Отменить сканирование");
        
        en.insert("ready_to_scan", "Ready to scan");
        ru.insert("ready_to_scan", "Готов к сканированию");
        
        en.insert("scanning_progress", "Scanning in progress...");
        ru.insert("scanning_progress", "Идет сканирование...");
        
        en.insert("scan_completed_findings", "Scan completed: {} findings");
        ru.insert("scan_completed_findings", "Сканирование завершено: {} находок");
        
        en.insert("go_to_results", "Go to Results");
        ru.insert("go_to_results", "Перейти к результатам");
        
        en.insert("scan_cancelled", "Scan cancelled");
        ru.insert("scan_cancelled", "Сканирование отменено");
        
        en.insert("scan_error", "Error: {}");
        ru.insert("scan_error", "Ошибка: {}");

        // Results Tab
        en.insert("results_title", "Scan Results");
        ru.insert("results_title", "Результаты сканирования");
        
        en.insert("search_placeholder", "Search results...");
        ru.insert("search_placeholder", "Поиск результатов...");
        
        en.insert("export_button", "Export");
        ru.insert("export_button", "Экспорт");
        
        en.insert("clear_button", "Clear");
        ru.insert("clear_button", "Очистить");
        
        en.insert("no_results", "No results yet. Run a scan to see results here.");
        ru.insert("no_results", "Результатов пока нет. Запустите сканирование.");
        
        en.insert("scan_summary", "Scan Summary");
        ru.insert("scan_summary", "Сводка сканирования");
        
        en.insert("total_files_scanned", "Total files scanned: {}");
        ru.insert("total_files_scanned", "Всего файлов проверено: {}");
        
        en.insert("files_with_findings", "Files with findings (after filter): {}");
        ru.insert("files_with_findings", "Файлов с находками (после фильтра): {}");
        
        en.insert("total_findings", "Total findings: {}");
        ru.insert("total_findings", "Всего находок: {}");
        
        en.insert("risk_label", "Risk: {}/10");
        ru.insert("risk_label", "Риск: {}/10");
        
        en.insert("findings_count_label", "Findings: {}");
        ru.insert("findings_count_label", "Находок: {}");
        
        en.insert("detailed_findings_label", "Findings:");
        ru.insert("detailed_findings_label", "Детали:");

        // Settings Tab
        en.insert("settings_title", "Advanced Settings");
        ru.insert("settings_title", "Расширенные настройки");
        
        en.insert("thread_count_label", "Thread count (0 = auto):");
        ru.insert("thread_count_label", "Количество потоков (0 = авто):");
        
        en.insert("exclude_patterns_label", "Exclude Patterns:");
        ru.insert("exclude_patterns_label", "Исключить шаблоны:");
        
        en.insert("add_button", "Add");
        ru.insert("add_button", "Добавить");
        
        en.insert("remove_button", "Remove");
        ru.insert("remove_button", "Удалить");
        
        en.insert("find_patterns_label", "Find Patterns (only scan matching):");
        ru.insert("find_patterns_label", "Искать шаблоны (сканировать только совпадения):");

        en.insert("appearance_label", "Appearance");
        ru.insert("appearance_label", "Внешний вид");
        
        en.insert("language_label", "Language:");
        ru.insert("language_label", "Язык:");
        
        en.insert("theme_label", "Theme:");
        ru.insert("theme_label", "Тема:");
        
        en.insert("accent_color_label", "Accent Color:");
        ru.insert("accent_color_label", "Цвет акцента:");

        Self { en, ru }
    }

    pub fn get(&self, lang: Language, key: &str) -> String {
        let map = match lang {
            Language::English => &self.en,
            Language::Russian => &self.ru,
        };
        map.get(key).unwrap_or(&key).to_string()
    }
    
    // Helper for formatted strings
    pub fn get_fmt(&self, lang: Language, key: &str, arg: &str) -> String {
        let text = self.get(lang, key);
        text.replace("{}", arg)
    }
}

lazy_static::lazy_static! {
    pub static ref TRANSLATOR: Translator = Translator::new();
}
