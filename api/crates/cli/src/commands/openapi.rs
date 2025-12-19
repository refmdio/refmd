use anyhow::Result;
use std::io::Write;

use crate::cli::OpenapiCommand;
use bootstrap::presentation;
use utoipa::OpenApi;

pub(crate) fn handle(command: OpenapiCommand) -> Result<()> {
    match command {
        OpenapiCommand::Export => {
            let json = presentation::openapi::ApiDoc::openapi()
                .to_json()
                .expect("serialize OpenAPI JSON");
            let mut stdout = std::io::stdout().lock();
            match stdout.write_all(json.as_bytes()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                Err(e) => return Err(e.into()),
            }
            let _ = stdout.write_all(b"\n");
            Ok(())
        }
    }
}
