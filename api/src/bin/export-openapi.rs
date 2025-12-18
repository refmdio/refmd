use presentation::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let json = ApiDoc::openapi().to_json().expect("serialize OpenAPI JSON");
    println!("{}", json);
}
