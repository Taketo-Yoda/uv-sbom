mod cli;
mod cyclonedx;
mod error;
mod license;
mod lockfile;
mod markdown;

use anyhow::{Context, Result};
use cli::{Args, OutputFormat};
use error::SbomError;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

fn main() {
    if let Err(e) = run() {
        eprintln!("\n❌ エラーが発生しました:\n");
        eprintln!("{}", e);

        // エラーチェーンの表示
        let mut source = e.source();
        while let Some(err) = source {
            eprintln!("\n原因: {}", err);
            source = err.source();
        }

        eprintln!();
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse_args();

    // プロジェクトディレクトリの検証
    let project_dir = args.path.as_deref().unwrap_or(".");
    let project_path = PathBuf::from(project_dir);

    validate_project_path(&project_path)?;

    // uv.lockファイルのパスを構築
    let lockfile_path = project_path.join("uv.lock");

    // uv.lockファイルの存在確認
    if !lockfile_path.exists() {
        return Err(SbomError::LockfileNotFound {
            path: lockfile_path.clone(),
            suggestion: format!(
                "プロジェクトディレクトリ「{}」にuv.lockファイルが存在しません。\n   \
                 uvプロジェクトのルートディレクトリで実行するか、--pathオプションで正しいパスを指定してください。",
                project_path.display()
            ),
        }
        .into());
    }

    // uv.lockファイルの読み込みとパース
    eprintln!("📖 uv.lockファイルを読み込んでいます: {}", lockfile_path.display());
    let lockfile_content = fs::read_to_string(&lockfile_path).map_err(|e| {
        SbomError::LockfileParseError {
            path: lockfile_path.clone(),
            details: e.to_string(),
        }
    })?;

    let packages = lockfile::parse_lockfile(&lockfile_content).map_err(|e| {
        SbomError::LockfileParseError {
            path: lockfile_path.clone(),
            details: e.to_string(),
        }
    })?;

    eprintln!("✅ {}個のパッケージを検出しました", packages.len());

    // ライセンス情報の取得
    eprintln!("🔍 ライセンス情報を取得しています...");
    let packages_with_licenses = license::fetch_licenses(packages)?;

    // 出力フォーマットに応じて生成
    let format_name = match args.format {
        OutputFormat::Json => "CycloneDX JSON",
        OutputFormat::Markdown => "Markdown",
    };
    eprintln!("📝 {}形式で出力を生成しています...", format_name);

    let output_content = match args.format {
        OutputFormat::Json => {
            let bom = cyclonedx::generate_bom(packages_with_licenses)
                .context("CycloneDX BOMの生成に失敗しました")?;
            serde_json::to_string_pretty(&bom).context("JSONのシリアライズに失敗しました")?
        }
        OutputFormat::Markdown => markdown::generate_table(packages_with_licenses),
    };

    // 出力先の決定
    if let Some(output_path) = args.output {
        let output_pathbuf = PathBuf::from(&output_path);

        // 出力ディレクトリの存在確認
        if let Some(parent) = output_pathbuf.parent() {
            if !parent.exists() && parent != Path::new("") {
                return Err(SbomError::FileWriteError {
                    path: output_pathbuf,
                    details: format!(
                        "親ディレクトリが存在しません: {}",
                        parent.display()
                    ),
                }
                .into());
            }
        }

        fs::write(&output_pathbuf, output_content).map_err(|e| SbomError::FileWriteError {
            path: output_pathbuf.clone(),
            details: e.to_string(),
        })?;
        eprintln!("✅ 出力完了: {}", output_pathbuf.display());
    } else {
        io::stdout()
            .write_all(output_content.as_bytes())
            .context("標準出力への書き込みに失敗しました")?;
    }

    Ok(())
}

fn validate_project_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "ディレクトリが存在しません".to_string(),
        }
        .into());
    }

    if !path.is_dir() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "ディレクトリではありません".to_string(),
        }
        .into());
    }

    Ok(())
}
