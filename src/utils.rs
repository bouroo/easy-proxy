use openssl::{
    asn1::{Asn1Time, Asn1TimeRef},
    error::ErrorStack,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn asn1_time_to_unix_time(time: &Asn1TimeRef) -> Result<i128, ErrorStack> {
    // get "now" as an ASN.1 time
    let now_asn1 = Asn1Time::days_from_now(0)?;
    // compute difference (days, secs) between now and the provided time
    let diff = now_asn1.diff(time)?;
    // total diff in seconds
    let delta_secs = diff.days as u64 * 86_400 + diff.secs as u64;
    // current UNIX timestamp
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ErrorStack::get())?
        .as_secs() as i128;
    // return delta + now
    Ok(delta_secs as i128 + now_secs)
}
