use crate::lockfile::{DependencyInfo, Package};
use std::collections::HashMap;

#[allow(dead_code)]
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

pub fn generate_detailed_table(dep_info: DependencyInfo, packages: Vec<Package>) -> String {
    let mut output = String::new();

    // Create package lookup map
    let package_map: HashMap<String, &Package> = packages
        .iter()
        .map(|p| (p.name.clone(), p))
        .collect();

    // Header
    output.push_str("# Software Bill of Materials (SBOM)\n\n");

    // Component Inventory Section
    output.push_str("## Component Inventory\n\n");
    output.push_str("A comprehensive list of all software components and libraries included in this project.\n\n");
    output.push_str("| Package | Version | License | Description |\n");
    output.push_str("|---------|---------|---------|-------------|\n");

    for pkg_name in &dep_info.all_packages {
        if let Some(pkg) = package_map.get(&pkg_name.name) {
            let license = pkg.license.as_deref().unwrap_or("N/A");
            let description = pkg
                .description
                .as_deref()
                .unwrap_or("")
                .replace('|', "\\|")
                .replace('\n', " ");

            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                pkg.name, pkg.version, license, description
            ));
        }
    }

    // Direct Dependencies Section
    output.push_str("\n## Direct Dependencies\n\n");
    output.push_str("Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).\n\n");
    output.push_str("| Package | Version | License | Description |\n");
    output.push_str("|---------|---------|---------|-------------|\n");

    for dep_name in &dep_info.direct_dependencies {
        if let Some(pkg) = package_map.get(dep_name) {
            let license = pkg.license.as_deref().unwrap_or("N/A");
            let description = pkg
                .description
                .as_deref()
                .unwrap_or("")
                .replace('|', "\\|")
                .replace('\n', " ");

            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                pkg.name, pkg.version, license, description
            ));
        }
    }

    // Transitive Dependencies Section
    if !dep_info.transitive_dependencies.is_empty() {
        output.push_str("\n## Transitive Dependencies\n\n");
        output.push_str("Secondary dependencies introduced by the primary packages.\n\n");

        for (direct_dep, trans_deps) in &dep_info.transitive_dependencies {
            if trans_deps.is_empty() {
                continue;
            }

            output.push_str(&format!("### Dependencies for {}\n\n", direct_dep));
            output.push_str("| Package | Version | License | Description |\n");
            output.push_str("|---------|---------|---------|-------------|\n");

            for trans_dep_name in trans_deps {
                if let Some(pkg) = package_map.get(trans_dep_name) {
                    let license = pkg.license.as_deref().unwrap_or("N/A");
                    let description = pkg
                        .description
                        .as_deref()
                        .unwrap_or("")
                        .replace('|', "\\|")
                        .replace('\n', " ");

                    output.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        pkg.name, pkg.version, license, description
                    ));
                }
            }

            output.push('\n');
        }
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

    #[test]
    fn test_generate_table_removes_newlines() {
        let packages = vec![Package {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Description with\nmultiple\nlines".to_string()),
            license: Some("MIT".to_string()),
        }];

        let table = generate_table(packages);

        assert!(table.contains("Description with multiple lines"));
        assert!(!table.contains("Description with\nmultiple"));
    }

    #[test]
    fn test_generate_table_empty_packages() {
        let packages = vec![];
        let table = generate_table(packages);

        assert!(table.contains("# Software Bill of Materials (SBOM)"));
        assert!(table.contains("| Package | Version | License | Description |"));
        // Should only have header rows
        assert_eq!(table.lines().count(), 4); // Title + empty line + header + separator
    }

    #[test]
    fn test_generate_table_no_license_no_description() {
        let packages = vec![Package {
            name: "minimal-package".to_string(),
            version: "0.0.1".to_string(),
            description: None,
            license: None,
        }];

        let table = generate_table(packages);

        assert!(table.contains("| minimal-package | 0.0.1 | N/A |  |"));
    }

    #[test]
    fn test_generate_table_escapes_both_pipe_and_newline() {
        let packages = vec![Package {
            name: "complex".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Description | with pipe\nand newline".to_string()),
            license: Some("Apache 2.0".to_string()),
        }];

        let table = generate_table(packages);

        assert!(table.contains("Description \\| with pipe and newline"));
    }
}
