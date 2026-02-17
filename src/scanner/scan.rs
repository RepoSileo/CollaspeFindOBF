use moka::sync::Cache;

use std::sync::{Arc, Mutex};
use wildmatch::WildMatch;

#[cfg(feature = "cli")]
use colored::Colorize;

use crate::config::SYSTEM_CONFIG;
use crate::errors::ScanError;
use crate::types::ScannerOptions;

type ResultCache = Arc<Cache<u64, Arc<Vec<(crate::types::FindingType, String)>>>>;

pub struct CollapseFindOBFScanner {
    pub options: ScannerOptions,
    pub found_custom_jvm_indicator: Arc<Mutex<bool>>,
    pub exclude_patterns: Vec<WildMatch>,
    pub find_patterns: Vec<WildMatch>,
    pub result_cache: ResultCache,
}

impl CollapseFindOBFScanner {
    pub fn new(options: ScannerOptions) -> Result<Self, ScanError> {
        if let Some(ref path) = options.ignore_keywords_file {
            if options.verbose {
                println!(
                    "{} Loading keywords ignore list from: {}",
                    yellow_text!("📄"),
                    path.display()
                );
            }

            match Self::load_ignore_list_from_file(path) {
                Ok(ignored) => {
                    if options.verbose {
                        println!(
                            "{} Loaded {} keywords to ignore",
                            yellow_text!("✅"),
                            ignored.len()
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} Warning: Could not load keywords ignore list from {}: {}",
                        yellow_text!("⚠️"),
                        path.display(),
                        e
                    );
                }
            }
        }

        let exclude_patterns = options
            .exclude_patterns
            .iter()
            .map(|p| WildMatch::new(p))
            .collect();
        let find_patterns = options
            .find_patterns
            .iter()
            .map(|p| WildMatch::new(p))
            .collect();

        if options.verbose {
            SYSTEM_CONFIG.log_config();
        }

        Ok(CollapseFindOBFScanner {
            options,
            found_custom_jvm_indicator: Arc::new(Mutex::new(false)),
            exclude_patterns,
            find_patterns,
            result_cache: Arc::new(
                Cache::builder()
                    .max_capacity(SYSTEM_CONFIG.result_cache_size as u64)
                    .build(),
            ),
        })
    }
}
