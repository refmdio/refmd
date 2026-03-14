#[rustler::nif(schedule = "DirtyCpu")]
fn hash<'a>(env: rustler::Env<'a>, data: rustler::Binary) -> rustler::Binary<'a> {
    let hash = blake3::hash(data.as_slice());
    let mut out = rustler::OwnedBinary::new(32).unwrap();
    out.as_mut_slice().copy_from_slice(hash.as_bytes());
    out.release(env)
}

rustler::init!("Elixir.RefMD.Crypto.Blake3");
