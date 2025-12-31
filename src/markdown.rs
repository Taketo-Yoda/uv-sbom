use crate::lockfile::Package;

pub fn generate_table(packages: Vec<Package>) -> String {
    let mut output = String::new();

    // ヘッダー
    output.push_str("# Software Bill of Materials (SBOM)\n\n");
    output.push_str("| Package | Version | License | Description |\n");
    output.push_str("|---------|---------|---------|-------------|\n");

    // 各パッケージの行
    for pkg in packages {
        let license = pkg.license.as_deref().unwrap_or("N/A");
        let description = pkg
            .description
            .as_deref()
            .unwrap_or("")
            .replace('|', "\\|") // パイプ文字をエスケープ
            .replace('\n', " "); // 改行を削除

        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            pkg.name, pkg.version, license, description
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_table() {
        let packages = vec![
            Package {
                name: "requests".to_string(),
                version: "2.31.0".to_string(),
                description: Some("HTTP library for Python".to_string()),
                license: Some("Apache 2.0".to_string()),
            },
            Package {
                name: "numpy".to_string(),
                version: "1.24.0".to_string(),
                description: Some("Fundamental package for array computing".to_string()),
                license: None,
            },
        ];

        let table = generate_table(packages);

        assert!(table.contains("# Software Bill of Materials (SBOM)"));
        assert!(table.contains("| Package | Version | License | Description |"));
        assert!(table.contains("| requests | 2.31.0 | Apache 2.0 | HTTP library for Python |"));
        assert!(table.contains(
            "| numpy | 1.24.0 | N/A | Fundamental package for array computing |"
        ));
    }

    #[test]
    fn test_generate_table_escapes_pipe() {
        let packages = vec![Package {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Description with | pipe".to_string()),
            license: Some("MIT".to_string()),
        }];

        let table = generate_table(packages);

        assert!(table.contains("Description with \\| pipe"));
    }
}
