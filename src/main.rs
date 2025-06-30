use axum::{http::StatusCode, routing::post, Json, Router};
use serde::{Serialize, Deserialize};
use solana_sdk::{
    bs58, 
    pubkey::Pubkey, 
    signature::{Keypair, Signature}, 
    signer::Signer,
    instruction::{AccountMeta, Instruction},
    system_instruction,
};
use spl_token;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use std::str::FromStr;
use base64;
use base64::engine::Engine;
use ed25519_dalek::{VerifyingKey, Verifier};

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeyPairData {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct SolTransferData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct CreateTokenAccount {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct MintTokenAccount {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenCreationData {
    program_id: String,
    accounts: CreateTokenAccount,
    instruction_data: String,
}

#[derive(Serialize)]
struct MintTokenData {
    program_id: String,
    accounts: Vec<MintTokenAccount>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

// helper fn
impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
}

impl ApiResponse<()> {
    fn error(message: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.to_string()),
        }
    }
}

fn parse_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(pubkey_str).map_err(|_| format!("Invalid pubkey: {}", pubkey_str))
}

// Endpoint handlers
async fn generate_keypair() -> Json<ApiResponse<KeyPairData>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    
    Json(ApiResponse::success(KeyPairData { pubkey, secret }))
}

async fn create_token(
    Json(request): Json<CreateTokenRequest>,
) -> Result<Json<ApiResponse<TokenCreationData>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Validate required fields
    if request.mint_authority.is_empty() || request.mint.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("Missing required fields"))));
    }

    let mint_authority = parse_pubkey(&request.mint_authority)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::error(&e))))?;

    let mint = parse_pubkey(&request.mint)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::error(&e))))?;

    let instruction = spl_token::instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        request.decimals,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::error(&e.to_string()))))?;


    let mint_account = instruction.accounts.get(0).ok_or((
        StatusCode::BAD_REQUEST, 
        Json(ApiResponse::error("No accounts found in instruction"))
    ))?;

    let accounts = CreateTokenAccount {
        pubkey: mint_account.pubkey.to_string(),
        is_signer: mint_account.is_signer,
        is_writable: mint_account.is_writable,
    };

    let token_data = TokenCreationData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(Json(ApiResponse::success(token_data)))
}

async fn mint_token(
    Json(request): Json<MintTokenRequest>,
) -> Result<Json<ApiResponse<MintTokenData>>, (StatusCode, Json<ApiResponse<()>>)> {

    if request.mint.is_empty() || request.destination.is_empty() || request.authority.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("missing fields"))));
    }

    let mint = parse_pubkey(&request.mint)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::error(&e))))?;
    
    let destination = parse_pubkey(&request.destination)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::error(&e))))?;
    
    let authority = parse_pubkey(&request.authority)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::error(&e))))?;

    if request.amount == 0 {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("acc > 0"))));
    }

    let instruction = spl_token::instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        request.amount,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::error(&e.to_string()))))?;

    let accounts: Vec<MintTokenAccount> = instruction
        .accounts
        .iter()
        .map(|account_meta| MintTokenAccount {
            pubkey: account_meta.pubkey.to_string(),
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        })
        .collect();

    let mint_data = MintTokenData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(Json(ApiResponse::success(mint_data)))
}

async fn sign_message(
    Json(request): Json<SignMessageRequest>,
) -> Result<Json<ApiResponse<SignMessageData>>, (StatusCode, Json<ApiResponse<()>>)> {
    if request.message.is_empty() || request.secret.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("Missing required fields"))));
    }

    let secret_bytes = bs58::decode(&request.secret)
        .into_vec()
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(ApiResponse::error("Invalid secret key format"))))?;

    if secret_bytes.len() != 64 {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("Invalid secret key length"))));
    }

    let keypair = Keypair::try_from(&secret_bytes[..])
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(ApiResponse::error("Invalid secret key"))))?;

    let message_bytes = request.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let sign_data = SignMessageData {
        signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
        public_key: bs58::encode(keypair.pubkey().as_ref()).into_string(),
        message: request.message,
    };

    Ok(Json(ApiResponse::success(sign_data)))
}

async fn verify_message(
    Json(request): Json<VerifyMessageRequest>,
) -> Result<Json<ApiResponse<VerifyMessageData>>, (StatusCode, Json<ApiResponse<()>>)> {
    if request.message.is_empty() || request.signature.is_empty() || request.pubkey.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("missing fields"))));
    }

    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(ApiResponse::error("invalid format"))))?;

    let pubkey_bytes = bs58::decode(&request.pubkey)
        .into_vec()
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(ApiResponse::error("pubkey err"))))?;

    if signature_bytes.len() != 64 {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("sign length"))));
    }

    if pubkey_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("public key length"))));
    }

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap())
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(ApiResponse::error("invalid"))))?;

    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes.try_into().unwrap());
    let message_bytes = request.message.as_bytes();

    let is_valid = verifying_key.verify(message_bytes, &signature).is_ok();

    let verify_data = VerifyMessageData {
        valid: is_valid,
        message: request.message,
        pubkey: request.pubkey,
    };

    Ok(Json(ApiResponse::success(verify_data)))
}

async fn send_sol(
    Json(request): Json<SendSolRequest>,
) -> Result<Json<ApiResponse<SolTransferData>>, (StatusCode, Json<ApiResponse<()>>)> {

    if request.from.is_empty() || request.to.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("missing fields"))));
    }

    if request.lamports == 0 {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("lmp > 0"))));
    }

    let from_pubkey = parse_pubkey(&request.from)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::error(&e))))?;

    let to_pubkey = parse_pubkey(&request.to)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::error(&e))))?;


    if from_pubkey == to_pubkey {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("from and to pubkeys are the same"))));
    }

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, request.lamports);

    let sol_transfer_data = SolTransferData {
        program_id: instruction.program_id.to_string(),
        accounts: instruction
            .accounts
            .iter()
            .map(|account_meta| account_meta.pubkey.to_string())
            .collect(),
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(Json(ApiResponse::success(sol_transfer_data)))
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("127.0.0.1:{}", port);

    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .layer(CorsLayer::permissive());

    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|_| panic!("Unable to bind to address: {}", addr));
    println!("Server running on {}", addr);

    axum::serve(listener, app)
        .await
        .expect("Error starting server");
}