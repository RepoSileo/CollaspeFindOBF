use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

use crate::detection::{cache_safe_string, calculate_detection_hash, is_cached_safe_string};
use crate::errors::ScanError;
// use crate::filters::URL_REGEX; // Unused

use crate::parser::parse_class_structure;
use crate::scanner::scan::CollapseFindOBFScanner;
use crate::types::{ClassDetails, FindingType, ResourceInfo, ScanResult};
use crate::utils::truncate_string;

impl CollapseFindOBFScanner {

    pub(crate) fn scan_class_file_data(
        &self,
        original_path_str: &str,
        data: Vec<u8>,
        resource_info: Option<ResourceInfo>,
    ) -> Result<ScanResult, ScanError> {
        let res_info = match resource_info {
            Some(ri) => ri,
            None => self.analyze_resource(original_path_str, &data)?,
        };

        let result = self
            .scan_class_data(&data, &res_info.path, Some(res_info.clone()))?
            .unwrap_or_else(|| ScanResult {
                file_path: res_info.path.clone(),
                matches: Arc::new(Vec::new()),
                class_details: None,
                resource_info: Some(res_info.clone()),
                danger_score: 1,
                danger_explanation: vec!["No suspicious elements detected.".to_string()],
            });

        Ok(result)
    }

    pub fn scan_class_data(
        &self,
        data: &[u8],
        original_path_str: &str,
        resource_info: Option<ResourceInfo>,
    ) -> Result<Option<ScanResult>, ScanError> {
        let data_hash = calculate_detection_hash(data);

        if let Some(cached_findings) = self.get_cached_findings(data_hash) {
            return self.handle_cached_findings(
                cached_findings.clone(),
                original_path_str,
                resource_info,
            );
        }

        let mut findings = Vec::new();

        // Non-standard class file (custom JVM)
        if data.len() >= 2 && data[0] != 0xCA && data[1] != 0xFE {
            return self.handle_non_standard_class(
                data,
                data_hash,
                original_path_str,
                resource_info,
                &mut findings,
            );
        }

        let class_details = parse_class_structure(data, original_path_str, self.options.verbose)?;

        // Detect obfuscation only in Obfuscation or All mode
        // Detect obfuscation
        self.check_name_obfuscation(&class_details, &mut findings);

        // Scan strings for Discord webhooks (always) or obfuscation
        let strings_to_scan = self.prepare_strings_for_scanning(&class_details);
        self.scan_strings_for_webhooks_and_obfuscation(&strings_to_scan, &mut findings);

        let _cached_arc = self
            .result_cache
            .get_with(data_hash, || Arc::new(findings.clone()));

        self.create_scan_result(findings, class_details, original_path_str, resource_info)
    }

    /// Проверка имён на обфускацию
    fn check_name_obfuscation(
        &self,
        details: &ClassDetails,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        let mut check = |name: &str, context: &str| {
            if name.is_empty() || name == "java/lang/Object" {
                return;
            }

            // Проверка на Unicode символы (не ASCII), исключая кириллицу
            // Кирилица: U+0400..U+04FF
            let suspicious_count = name.chars()
                .filter(|&c| !c.is_ascii() && !(c >= '\u{0400}' && c <= '\u{04FF}'))
                .count();
            
            let total_chars = name.chars().count();
            
            // Если больше 90% подозрительных символов и их больше 15 — это обфускация
            if suspicious_count > 15 && suspicious_count * 100 / total_chars > 90 {
                findings.push((
                    FindingType::ObfuscationUnicode,
                    format!(
                        "{} '{}' ({} suspicious non-ASCII chars)",
                        context,
                        truncate_string(name, 30),
                        suspicious_count
                    ),
                ));
            }

            // Проверка на случайные имена (a, b, c, aa, ab, abc и т.д.)
            // ВАЖНО: Проверяем только для классов и суперклассов, чтобы избежать ложных срабатываний на полях/методах
            if (context == "Class Name" || context == "Superclass Name") && self.is_random_name(name) {
                findings.push((
                    FindingType::ObfuscationRandomName,
                    format!("{} '{}' (random naming pattern)", context, truncate_string(name, 30)),
                ));
            }
        };

        check(&details.class_name, "Class Name");
        if !details.superclass_name.is_empty() 
            && details.superclass_name != "java/lang/Object"
        {
            check(&details.superclass_name, "Superclass Name");
        }

        for interface in details.interfaces.iter().take(5) {
            check(interface, "Interface Name");
        }

        // Проверяем выборку полей (не все, чтобы не замедлять)
        let fields_to_check = details.fields.len().min(20);
        for f in details.fields.iter().take(fields_to_check) {
            check(&f.name, "Field Name");
        }

        // Проверяем выборку методов (исключая конструкторы)
        let methods_to_check = details.methods.len().min(30);
        for m in details
            .methods
            .iter()
            .filter(|m| m.name != "<init>" && m.name != "<clinit>")
            .take(methods_to_check)
        {
            check(&m.name, "Method Name");
        }
    }

    /// Проверка имени на случайный паттерн
    fn is_random_name(&self, name: &str) -> bool {
        // Убираем package path
        let simple_name = name.rsplit('/').next().unwrap_or(name);
        
        if simple_name.is_empty() || simple_name.len() > 10 {
            return false;
        }

        // Паттерн: только буквы (a-z, A-Z), возможно с цифрами в конце
        // Короткие имена типа a, b, c, aa, ab, abc, aaaa
        if simple_name.len() <= 2 {
            let all_letters = simple_name.chars().all(|c| c.is_ascii_alphabetic());
            let has_lowercase = simple_name.chars().any(|c| c.is_ascii_lowercase());
            
            // Если всё lowercase и длина 1-2 — подозрительно
            if has_lowercase && all_letters && simple_name.len() <= 2 {
                return true;
            }
        }

        false
    }

    /// Проверка строк на обфусцированные строки (Discord webhook check removed)
    fn scan_strings_for_webhooks_and_obfuscation(
        &self,
        strings_to_scan: &[&String],
        findings: &mut Vec<(FindingType, String)>,
    ) {
        let partials: Vec<Vec<(FindingType, String)>> = strings_to_scan
            .par_iter()
            .map(|s| {
                let mut local = Vec::new();
                let s_ref: &str = s.as_str();

                // REMOVED: check_discord_webhook

                // Проверка на обфусцированные строки
                self.check_obfuscated_string(s_ref, &mut local);

                if local.is_empty() {
                    cache_safe_string(s_ref);
                }

                local
            })
            .collect();

        for mut p in partials {
            findings.append(&mut p);
        }
    }

    // fn check_discord_webhook(&self, string: &str, findings: &mut Vec<(FindingType, String)>) { ... } // Removed

    /// Проверка строки на обфускацию
    fn check_obfuscated_string(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        // Пропускаем короткие строки
        if string.len() < 15 {
            return;
        }

        // Проверка на подозрительные символы (не ASCII, исключая кириллицу)
        let suspicious_count = string.chars()
            .filter(|&c| !c.is_ascii() && !(c >= '\u{0400}' && c <= '\u{04FF}'))
            .count();
        let total_chars = string.chars().count();

        if total_chars > 0 && suspicious_count > 20 
            && (suspicious_count * 100 / total_chars) > 70 
        {
            findings.push((
                FindingType::ObfuscationString,
                format!(
                    "Obfuscated string: {} ({} suspicious non-ASCII chars)",
                    truncate_string(string, 50),
                    suspicious_count
                ),
            ));
        }
    }

    fn prepare_strings_for_scanning<'a>(&self, class_details: &'a ClassDetails) -> Vec<&'a String> {
        class_details
            .strings
            .iter()
            .filter(|s| {
                !s.is_empty() && 
                s.len() >= 15 &&  // Увеличил минимальную длину с 3 до 15
                !is_cached_safe_string(s) &&
                // Добавил дополнительную проверку: пропускаем строки, которые выглядят как обычные имена или слова
                !s.chars().all(|c| c.is_ascii_alphabetic() || c == '_' || c == '.') // Пропускаем простые имена классов/методов
            })
            .take(200)
            .collect()
    }

    fn get_cached_findings(&self, hash: u64) -> Option<Arc<Vec<(FindingType, String)>>> {
        self.result_cache.get(&hash)
    }

    fn calculate_danger_score(
        &self,
        findings: &[(FindingType, String)],
        _resource_info: Option<&ResourceInfo>,
    ) -> u8 {
        if findings.is_empty() {
            return 1;
        }

        let mut type_counts: HashMap<FindingType, usize> = HashMap::new();
        for (finding_type, _) in findings {
            *type_counts.entry(finding_type.clone()).or_insert(0) += 1;
        }

        // Discord Webhook = максимальная опасность
        if *type_counts.get(&FindingType::DiscordWebhook).unwrap_or(&0) > 0 {
            return 10;
        }

        let mut score_acc: usize = 0;
        for (ftype, count) in &type_counts {
            let weight = ftype.base_score() as usize;
            let cap = ftype.max_contribution() as usize;
            let contrib = (count * weight).min(cap);
            score_acc += contrib;
        }

        (score_acc as i32).clamp(1, 10) as u8
    }

    fn generate_danger_explanation(
        &self,
        score: u8,
        findings: &[(FindingType, String)],
        _resource_info: Option<&ResourceInfo>,
    ) -> Vec<String> {
        if findings.is_empty() {
            return vec!["No suspicious elements detected.".to_string()];
        }

        let mut explanations = Vec::new();
        let use_emoji = self.options.progress.is_none();
        let warn_prefix = if use_emoji { "⚠️ " } else { "" };

        if score >= 8 {
            explanations.push(format!(
                "{}HIGH RISK: This file contains multiple high-risk indicators!",
                warn_prefix
            ));
        } else if score >= 5 {
            explanations.push(format!(
                "{}MODERATE RISK: This file contains several suspicious elements.",
                warn_prefix
            ));
        } else if score >= 3 {
            explanations.push(format!(
                "{}LOW RISK: This file contains some potentially concerning elements.",
                warn_prefix
            ));
        } else {
            explanations.push(format!(
                "{}MINIMAL RISK: Few or no concerning elements detected.",
                "✅ "
            ));
        }

        let mut by_type: HashMap<FindingType, Vec<String>> = HashMap::new();
        for (finding_type, value) in findings {
            by_type
                .entry(finding_type.clone())
                .or_default()
                .push(value.clone());
        }

        if let Some(webhooks) = by_type.get(&FindingType::DiscordWebhook) {
            if !webhooks.is_empty() {
                explanations.push(format!(
                    "CRITICAL: Found {} Discord webhook(s)! These are extremely dangerous and commonly used for data exfiltration.",
                    webhooks.len()
                ));
            }
        }

        if let Some(unicode) = by_type.get(&FindingType::ObfuscationUnicode) {
            if !unicode.is_empty() {
                explanations.push(format!(
                    "Found {} obfuscated name(s) with Unicode characters.",
                    unicode.len()
                ));
            }
        }

        if let Some(random) = by_type.get(&FindingType::ObfuscationRandomName) {
            if !random.is_empty() {
                explanations.push(format!(
                    "Found {} obfuscated name(s) with random naming pattern (a, b, c, ...).",
                    random.len()
                ));
            }
        }

        if let Some(obf_strings) = by_type.get(&FindingType::ObfuscationString) {
            if !obf_strings.is_empty() {
                explanations.push(format!(
                    "Found {} obfuscated string(s) with non-ASCII characters.",
                    obf_strings.len()
                ));
            }
        }

        explanations
    }

    fn handle_cached_findings(
        &self,
        cached_findings_arc: Arc<Vec<(FindingType, String)>>,
        original_path_str: &str,
        resource_info: Option<ResourceInfo>,
    ) -> Result<Option<ScanResult>, ScanError> {
        let cached_findings: &[(FindingType, String)] = cached_findings_arc.as_ref();

        if !cached_findings.is_empty() || self.options.verbose {
            let danger_score = self.calculate_danger_score(cached_findings, resource_info.as_ref());
            let danger_explanation = self.generate_danger_explanation(
                danger_score,
                cached_findings,
                resource_info.as_ref(),
            );

            Ok(Some(ScanResult {
                file_path: original_path_str.to_string(),
                matches: cached_findings_arc.clone(),
                class_details: None,
                resource_info,
                danger_score,
                danger_explanation,
            }))
        } else {
            Ok(None)
        }
    }

    fn handle_non_standard_class(
        &self,
        _data: &[u8],
        data_hash: u64,
        original_path_str: &str,
        resource_info: Option<ResourceInfo>,
        findings: &mut Vec<(FindingType, String)>,
    ) -> Result<Option<ScanResult>, ScanError> {
        {
            let mut found_flag = self.found_custom_jvm_indicator.lock().unwrap();
            *found_flag = true;
        }

        self.cache_findings_new(data_hash, findings);

        if !findings.is_empty() || self.options.verbose {
            let danger_score = self.calculate_danger_score(findings, resource_info.as_ref());
            let danger_explanation =
                self.generate_danger_explanation(danger_score, findings, resource_info.as_ref());

            Ok(Some(ScanResult {
                file_path: original_path_str.to_string(),
                matches: Arc::new(findings.clone()),
                class_details: None,
                resource_info,
                danger_score,
                danger_explanation,
            }))
        } else {
            Ok(None)
        }
    }

    fn cache_findings_new(&self, hash: u64, findings: &[(FindingType, String)]) {
        let vec = findings.to_vec();
        let arc = Arc::new(vec);
        let _ = self.result_cache.get_with(hash, || arc.clone());
    }

    fn create_scan_result(
        &self,
        findings: Vec<(FindingType, String)>,
        class_details: ClassDetails,
        original_path_str: &str,
        resource_info: Option<ResourceInfo>,
    ) -> Result<Option<ScanResult>, ScanError> {
        if !findings.is_empty() || self.options.verbose {
            let danger_score = self.calculate_danger_score(&findings, resource_info.as_ref());
            let danger_explanation =
                self.generate_danger_explanation(danger_score, &findings, resource_info.as_ref());

            Ok(Some(ScanResult {
                file_path: original_path_str.to_string(),
                matches: Arc::new(findings),
                class_details: Some(class_details),
                resource_info,
                danger_score,
                danger_explanation,
            }))
        } else {
            Ok(None)
        }
    }
}
