use std::path::{Path, PathBuf};
use std::io::Cursor;
use image::{ImageOutputFormat, GenericImageView, DynamicImage, ImageFormat};
use actix_web::web::Bytes;
use log::error;
use tokio::try_join;

use crate::errors::AppError;
use crate::models::user::{Dispatcher, Session, User};
use crate::utils::{generate_session_token, hash_password, verify_password};

use super::dto::auth::LoginResponseDto;

pub trait AuthRepository {
    async fn create_user(&self, username: &str, password: &str, role: &str) -> Result<(), AppError>;
    async fn find_user_by_id(&self, id: i32) -> Result<Option<User>, AppError>;
    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, AppError>;
    async fn create_dispatcher(&self, user_id: i32, area_id: i32) -> Result<(), AppError>;
    async fn find_dispatcher_by_id(&self, id: i32) -> Result<Option<Dispatcher>, AppError>;
    async fn find_dispatcher_by_user_id(&self, user_id: i32) -> Result<Option<Dispatcher>, AppError>;
    async fn find_profile_image_name_by_user_id(&self, user_id: i32) -> Result<Option<String>, AppError>;
    async fn create_session(&self, user_id: i32, session_token: &str) -> Result<(), AppError>;
    async fn delete_session(&self, session_token: &str) -> Result<(), AppError>;
    async fn find_session_by_session_token(&self, session_token: &str) -> Result<Session, AppError>;
}

#[derive(Debug)]
pub struct AuthService<T: AuthRepository + std::fmt::Debug> {
    repository: T,
}

impl<T: AuthRepository + std::fmt::Debug> AuthService<T> {
    pub fn new(repository: T) -> Self {
        AuthService { repository }
    }

    // ユーザ登録メソッドの改善
    pub async fn register_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
        area: Option<i32>,
    ) -> Result<LoginResponseDto, AppError> {
        if role == "dispatcher" && area.is_none() {
            return Err(AppError::BadRequest);
        }

        // データベースのクエリを並列化してパフォーマンスを向上させる
        let find_user_future = self.repository.find_user_by_username(username);
        let hash_password_future = tokio::task::spawn_blocking(|| hash_password(password).unwrap());

        let (user_result, hashed_password) = try_join!(find_user_future, hash_password_future)?;

        if user_result.is_some() {
            return Err(AppError::Conflict);
        }

        self.repository.create_user(username, &hashed_password, role).await?;
        let session_token = generate_session_token();

        match self.repository.find_user_by_username(username).await? {
            Some(user) => {
                self.repository.create_session(user.id, &session_token).await?;
                match user.role.as_str() {
                    "dispatcher" => {
                        self.repository.create_dispatcher(user.id, area.unwrap()).await?;
                        let dispatcher = self.repository.find_dispatcher_by_user_id(user.id).await?.unwrap();
                        Ok(LoginResponseDto {
                            user_id: user.id,
                            username: user.username,
                            session_token,
                            role: user.role,
                            dispatcher_id: Some(dispatcher.id),
                            area_id: Some(dispatcher.area_id),
                        })
                    }
                    _ => Ok(LoginResponseDto {
                        user_id: user.id,
                        username: user.username,
                        session_token,
                        role: user.role,
                        dispatcher_id: None,
                        area_id: None,
                    }),
                }
            }
            None => Err(AppError::InternalServerError),
        }
    }

    // ログインメソッドの改善
    pub async fn login_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LoginResponseDto, AppError> {
        match self.repository.find_user_by_username(username).await? {
            Some(user) => {
                let is_password_valid = tokio::task::spawn_blocking(move || verify_password(&user.password, password).unwrap()).await?;
                if !is_password_valid {
                    return Err(AppError::Unauthorized);
                }

                let session_token = generate_session_token();
                self.repository.create_session(user.id, &session_token).await?;

                match user.role.as_str() {
                    "dispatcher" => match self.repository.find_dispatcher_by_user_id(user.id).await? {
                        Some(dispatcher) => Ok(LoginResponseDto {
                            user_id: user.id,
                            username: user.username,
                            session_token,
                            role: user.role.clone(),
                            dispatcher_id: Some(dispatcher.id),
                            area_id: Some(dispatcher.area_id),
                        }),
                        None => Err(AppError::InternalServerError),
                    },
                    _ => Ok(LoginResponseDto {
                        user_id: user.id,
                        username: user.username,
                        session_token,
                        role: user.role.clone(),
                        dispatcher_id: None,
                        area_id: None,
                    }),
                }
            }
            None => Err(AppError::Unauthorized),
        }
    }

    // ログアウトメソッド
    pub async fn logout_user(&self, session_token: &str) -> Result<(), AppError> {
        self.repository.delete_session(session_token).await?;
        Ok(())
    }

    // プロフィール画像のリサイズと取得メソッドの改善
    pub async fn get_resized_profile_image_byte(
        &self,
        user_id: i32,
        width: i32,
        height: i32,
    ) -> Result<Bytes, AppError> {
        let profile_image_name = match self
            .repository
            .find_profile_image_name_by_user_id(user_id)
            .await
        {
            Ok(Some(name)) => name,
            Ok(None) => return Err(AppError::NotFound),
            Err(_) => return Err(AppError::NotFound),
        };

        let path: PathBuf = Path::new(&format!("images/user_profile/{}", profile_image_name)).to_path_buf();

        // 外部コマンドの代わりに `image` crate を使用して画像をリサイズ
        let img = tokio::task::spawn_blocking(move || {
            image::open(&path).map_err(|e| {
                error!("Failed to open image: {:?}", e);
                AppError::InternalServerError
            }).and_then(|img| {
                let resized_img = img.resize_exact(width as u32, height as u32, image::imageops::FilterType::Lanczos3);
                let mut buffer = Vec::new();
                resized_img.write_to(&mut Cursor::new(&mut buffer), ImageOutputFormat::Png).map_err(|e| {
                    error!("Failed to write resized image: {:?}", e);
                    AppError::InternalServerError
                })?;
                Ok(buffer)
            })
        }).await??;

        Ok(Bytes::from(img))
    }

    // セッションの検証メソッド
    pub async fn validate_session(&self, session_token: &str) -> Result<bool, AppError> {
        let session = self
            .repository
            .find_session_by_session_token(session_token)
            .await?;

        Ok(session.is_valid)
    }
}




/*use std::path::{Path, PathBuf};
use std::process::Command;

use actix_web::web::Bytes;
use log::error;

use crate::errors::AppError;
use crate::models::user::{Dispatcher, Session, User};
use crate::utils::{generate_session_token, hash_password, verify_password};

use super::dto::auth::LoginResponseDto;

pub trait AuthRepository {
    async fn create_user(&self, username: &str, password: &str, role: &str)
        -> Result<(), AppError>;
    async fn find_user_by_id(&self, id: i32) -> Result<Option<User>, AppError>;
    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, AppError>;
    async fn create_dispatcher(&self, user_id: i32, area_id: i32) -> Result<(), AppError>;
    async fn find_dispatcher_by_id(&self, id: i32) -> Result<Option<Dispatcher>, AppError>;
    async fn find_dispatcher_by_user_id(
        &self,
        user_id: i32,
    ) -> Result<Option<Dispatcher>, AppError>;
    async fn find_profile_image_name_by_user_id(
        &self,
        user_id: i32,
    ) -> Result<Option<String>, AppError>;
    async fn create_session(&self, user_id: i32, session_token: &str) -> Result<(), AppError>;
    async fn delete_session(&self, session_token: &str) -> Result<(), AppError>;
    async fn find_session_by_session_token(&self, session_token: &str)
        -> Result<Session, AppError>;
}

#[derive(Debug)]
pub struct AuthService<T: AuthRepository + std::fmt::Debug> {
    repository: T,
}

impl<T: AuthRepository + std::fmt::Debug> AuthService<T> {
    pub fn new(repository: T) -> Self {
        AuthService { repository }
    }

    pub async fn register_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
        area: Option<i32>,
    ) -> Result<LoginResponseDto, AppError> {
        if role == "dispatcher" && area.is_none() {
            return Err(AppError::BadRequest);
        }

        if (self.repository.find_user_by_username(username).await?).is_some() {
            return Err(AppError::Conflict);
        }

        let hashed_password = hash_password(password).unwrap();

        self.repository
            .create_user(username, &hashed_password, role)
            .await?;

        let session_token = generate_session_token();

        match self.repository.find_user_by_username(username).await? {
            Some(user) => {
                self.repository
                    .create_session(user.id, &session_token)
                    .await?;
                match user.role.as_str() {
                    "dispatcher" => {
                        self.repository
                            .create_dispatcher(user.id, area.unwrap())
                            .await?;
                        let dispatcher = self
                            .repository
                            .find_dispatcher_by_user_id(user.id)
                            .await?
                            .unwrap();
                        Ok(LoginResponseDto {
                            user_id: user.id,
                            username: user.username,
                            session_token,
                            role: user.role,
                            dispatcher_id: Some(dispatcher.id),
                            area_id: Some(dispatcher.area_id),
                        })
                    }
                    _ => Ok(LoginResponseDto {
                        user_id: user.id,
                        username: user.username,
                        session_token,
                        role: user.role,
                        dispatcher_id: None,
                        area_id: None,
                    }),
                }
            }
            None => Err(AppError::InternalServerError),
        }
    }

    pub async fn login_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LoginResponseDto, AppError> {
        match self.repository.find_user_by_username(username).await? {
            Some(user) => {
                let is_password_valid = verify_password(&user.password, password).unwrap();
                if !is_password_valid {
                    return Err(AppError::Unauthorized);
                }

                let session_token = generate_session_token();
                self.repository
                    .create_session(user.id, &session_token)
                    .await?;

                match user.role.as_str() {
                    "dispatcher" => {
                        match self.repository.find_dispatcher_by_user_id(user.id).await? {
                            Some(dispatcher) => Ok(LoginResponseDto {
                                user_id: user.id,
                                username: user.username,
                                session_token,
                                role: user.role.clone(),
                                dispatcher_id: Some(dispatcher.id),
                                area_id: Some(dispatcher.area_id),
                            }),
                            None => Err(AppError::InternalServerError),
                        }
                    }
                    _ => Ok(LoginResponseDto {
                        user_id: user.id,
                        username: user.username,
                        session_token,
                        role: user.role.clone(),
                        dispatcher_id: None,
                        area_id: None,
                    }),
                }
            }
            None => Err(AppError::Unauthorized),
        }
    }

    pub async fn logout_user(&self, session_token: &str) -> Result<(), AppError> {
        self.repository.delete_session(session_token).await?;
        Ok(())
    }

    pub async fn get_resized_profile_image_byte(
        &self,
        user_id: i32,
        width: i32,
        height: i32,
    ) -> Result<Bytes, AppError> {
        let profile_image_name = match self
            .repository
            .find_profile_image_name_by_user_id(user_id)
            .await
        {
            Ok(Some(name)) => name,
            Ok(None) => return Err(AppError::NotFound),
            Err(_) => return Err(AppError::NotFound),
        };

        let path: PathBuf =
            Path::new(&format!("images/user_profile/{}", profile_image_name)).to_path_buf();

        let output = Command::new("convert")
            .arg(&path)
            .arg("-resize")
            .arg(format!("{}x{}!", width, height))
            .arg("png:-")
            .output()
            .map_err(|e| {
                error!("画像リサイズのコマンド実行に失敗しました: {:?}", e);
                AppError::InternalServerError
            })?;

        match output.status.success() {
            true => Ok(Bytes::from(output.stdout)),
            false => {
                error!(
                    "画像リサイズのコマンド実行に失敗しました: {:?}",
                    String::from_utf8_lossy(&output.stderr)
                );
                Err(AppError::InternalServerError)
            }
        }
    }

    pub async fn validate_session(&self, session_token: &str) -> Result<bool, AppError> {
        let session = self
            .repository
            .find_session_by_session_token(session_token)
            .await?;

        Ok(session.is_valid)
    }
}
*/
