use clap::Args;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Args)]
pub struct LoginCommand {
    /// Dashboard URL
    #[arg(long, default_value = "https://app.krystawing.com")]
    dashboard: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct KrystaConfig {
    pub user_id: String,
    pub dashboard: String,
}

impl LoginCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        println!("{}", "🔐 Krysta Login".bold().cyan());
        println!();

        let client = reqwest::Client::new();

        // Step 1: Get auth code from dashboard
        let res = client
            .post(format!("{}/api/auth/cli", self.dashboard))
            .send()
            .await?;

        let json: serde_json::Value = res.json().await?;
        let code = json["code"].as_str().unwrap_or("").to_string();

        if code.is_empty() {
            anyhow::bail!("Failed to get auth code from dashboard");
        }

        // Step 2: Open browser
        let auth_url = format!("{}/auth/cli?code={}", self.dashboard, code);
        println!("  Opening browser to authorize...");
        println!();
        println!("  {}", auth_url.cyan().underline());
        println!();
        println!("  {}", "If browser didn't open, copy the URL above.".dimmed());
        println!();

        // Try to open browser
        #[cfg(target_os = "windows")]
        std::process::Command::new("cmd")
            .args(["/c", "start", &auth_url])
            .spawn()
            .ok();

        #[cfg(target_os = "macos")]
        std::process::Command::new("open")
            .arg(&auth_url)
            .spawn()
            .ok();

        #[cfg(target_os = "linux")]
        std::process::Command::new("xdg-open")
            .arg(&auth_url)
            .spawn()
            .ok();

        // Step 3: Poll for authorization
        println!("  Waiting for authorization");

        let poll_url = format!("{}/api/auth/cli?code={}", self.dashboard, code);
        let mut attempts = 0;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            attempts += 1;

            if attempts > 90 {
                anyhow::bail!("Authorization timed out. Please try again.");
            }

            let poll_res = client.get(&poll_url).send().await?;
            let poll_json: serde_json::Value = poll_res.json().await?;

            match poll_json["status"].as_str() {
                Some("pending") => {
                    print!(".");
                    std::io::Write::flush(&mut std::io::stdout())?;
                }
                Some("authorized") => {
                    let user_id = poll_json["userId"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();

                    println!();
                    println!();
                    println!("{}", "✅ Authorized!".green().bold());
                    println!();

                    // Step 4: Save config
                    let config = KrystaConfig {
                        user_id,
                        dashboard: self.dashboard.clone(),
                    };

                    let config_path = get_config_path()?;
                    fs::create_dir_all(config_path.parent().unwrap())?;
                    fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

                    println!("  Config saved to: {}", config_path.display().to_string().dimmed());
                    println!("  Run: {}", "krysta probe --deep --upload".cyan());
                    println!();

                    return Ok(());
                }
                Some("expired") => {
                    anyhow::bail!("Auth code expired. Please run krysta login again.");
                }
                _ => {
                    anyhow::bail!("Unexpected response from dashboard.");
                }
            }
        }
    }
}

pub fn get_config_path() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    Ok(home.join(".krysta").join("config.json"))
}

pub fn load_config() -> Option<KrystaConfig> {
    let path = get_config_path().ok()?;
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}