use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum SbomError {
    LockfileNotFound {
        path: PathBuf,
        suggestion: String,
    },
    LockfileParseError {
        path: PathBuf,
        details: String,
    },
    LicenseFetchError {
        package_name: String,
        details: String,
    },
    OutputGenerationError {
        format: String,
        details: String,
    },
    FileWriteError {
        path: PathBuf,
        details: String,
    },
    InvalidProjectPath {
        path: PathBuf,
        reason: String,
    },
}

impl fmt::Display for SbomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SbomError::LockfileNotFound { path, suggestion } => {
                write!(
                    f,
                    "uv.lockファイルが見つかりません: {}\n\n💡 ヒント: {}",
                    path.display(),
                    suggestion
                )
            }
            SbomError::LockfileParseError { path, details } => {
                write!(
                    f,
                    "uv.lockファイルのパースに失敗しました: {}\n詳細: {}\n\n💡 ヒント: uv.lockファイルが正しい形式か確認してください",
                    path.display(),
                    details
                )
            }
            SbomError::LicenseFetchError {
                package_name,
                details,
            } => {
                write!(
                    f,
                    "パッケージ「{}」のライセンス情報取得に失敗しました\n詳細: {}\n\n💡 ヒント: インターネット接続を確認してください",
                    package_name, details
                )
            }
            SbomError::OutputGenerationError { format, details } => {
                write!(
                    f,
                    "{}形式の出力生成に失敗しました\n詳細: {}",
                    format, details
                )
            }
            SbomError::FileWriteError { path, details } => {
                write!(
                    f,
                    "ファイルへの書き込みに失敗しました: {}\n詳細: {}\n\n💡 ヒント: ディレクトリが存在するか、書き込み権限があるか確認してください",
                    path.display(),
                    details
                )
            }
            SbomError::InvalidProjectPath { path, reason } => {
                write!(
                    f,
                    "無効なプロジェクトパスです: {}\n理由: {}\n\n💡 ヒント: 正しいプロジェクトディレクトリを指定してください",
                    path.display(),
                    reason
                )
            }
        }
    }
}

impl std::error::Error for SbomError {}

// anyhow::Errorからの変換
impl From<SbomError> for anyhow::Error {
    fn from(err: SbomError) -> Self {
        anyhow::anyhow!(err)
    }
}
