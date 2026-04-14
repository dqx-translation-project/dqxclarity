/// Validate a DeepL API key by calling /v2/usage.
/// Returns character usage info on success, or an error string.
#[tauri::command]
pub async fn validate_deepl_key(key: String) -> Result<String, String> {
    if key.is_empty() {
        return Err("Enter a key before attempting to validate.".to_string());
    }

    // Free-tier keys end with ":fx"
    let url = if key.ends_with(":fx") {
        "https://api-free.deepl.com/v2/usage"
    } else {
        "https://api.deepl.com/v2/usage"
    };

    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header("Authorization", format!("DeepL-Auth-Key {key}"))
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "Key validation failed (HTTP {}).",
            response.status().as_u16()
        ));
    }

    let body: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
    let used = body["character_count"].as_u64().unwrap_or(0);
    let limit = body["character_limit"].as_u64().unwrap_or(0);

    if limit == 0 {
        return Err("Unexpected response from DeepL API.".to_string());
    }

    let pct = (used as f64 / limit as f64 * 100.0 * 100.0).round() / 100.0;
    Ok(format!("{used}/{limit} characters used ({pct}%)."))
}

/// Validate a Google Translate API key by translating a sample word.
#[tauri::command]
pub async fn validate_google_key(key: String) -> Result<String, String> {
    if key.is_empty() {
        return Err("Enter a key before attempting to validate.".to_string());
    }

    let url = format!(
        "https://translation.googleapis.com/language/translate/v2?q=a&target=es&source=en&key={key}"
    );

    let response = reqwest::get(&url)
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    let body: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;

    if body["data"]["translations"].is_array() {
        Ok("Key successfully validated.".to_string())
    } else if let Some(msg) = body["error"]["message"].as_str() {
        Err(msg.to_string())
    } else {
        Err("Key validation failed.".to_string())
    }
}
