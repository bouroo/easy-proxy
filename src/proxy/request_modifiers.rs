use super::context::Context;
use crate::config::proxy::Header;
use crate::errors::Errors;
use http::uri::Uri;
use pingora::proxy::Session;

pub fn headers(
    session: &mut Session,
    ctx: &Context,
    add_headers: &[Header],
    remove_headers: &[String],
) {
    // remove unwanted headers
    if !remove_headers.is_empty() {
        let rh = session.req_header_mut();
        for name in remove_headers {
            let _ = rh.remove_header(name);
        }
    }

    // add or override headers
    for hdr in add_headers {
        // interpolate ctx.variables: "${key}" → value
        let mut val = ctx
            .variables
            .iter()
            .fold(hdr.value.clone(), |acc, (k, v)| acc.replace(&format!("${}", k), v));

        // support "$HK_<header>" → copy existing request header
        if let Some(suffix) = val.strip_prefix("$HK_") {
            let key = suffix.to_ascii_lowercase();
            if let Some(orig) = session.get_header(&key).and_then(|v| v.cloned()) {
                let _ = session.req_header_mut().append_header(hdr.name.clone(), orig);
            }
        } else {
            let _ = session.req_header_mut().append_header(hdr.name.clone(), &val);
        }
    }
}

pub async fn rewrite(
    session: &mut Session,
    path: &str,
    rewrite: &Option<String>,
) -> Result<(), Errors> {
    if let Some(r) = rewrite.as_deref() {
        let req = session.req_header();
        // replace `path` prefix in the request‐path
        let mut pq = req.uri.path().replace(path, r);
        if let Some(q) = req.uri.query() {
            pq.push('?');
            pq.push_str(q);
        }
        let new_uri = Uri::builder()
            .path_and_query(pq)
            .build()
            .map_err(|e| Errors::ProxyError(format!("Unable to build URI: {}", e)))?;
        session.req_header_mut().set_uri(new_uri);
    }
    Ok(())
}
