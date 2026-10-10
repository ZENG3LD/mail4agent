//! Element Web against our server, headless: login through the product's Matrix login, the room
//! list with a space and its rooms, and a message each way. Needs `M4A_ELEMENT_DIR` (an unpacked
//! Element Web release), `M4A_PUPPETEER_DIR` (a directory with `puppeteer-core` in its
//! node_modules) and `M4A_CHROME` (a Chrome/Chromium binary); without them the test says so and
//! passes. The page is served from localhost; no TLS is needed there.

#[path = "support_product.rs"]
mod support_product;
#[path = "support/fed.rs"]
mod support_fed;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use mail4agent_server::federation::enc;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use support_fed::{free_port, start_node};

/// Drives Element: log in, list rooms, open a room, send a message, wait for a message from the API.
const DRIVER: &str = r#"
const puppeteer = require(process.env.M4A_PUPPETEER_DIR + '/node_modules/puppeteer-core');
const [url, user, pw, shots, room, mine, theirs, space] = process.argv.slice(2);
const out = { bad: [], steps: [] };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const b = await puppeteer.launch({ executablePath: process.env.M4A_CHROME, headless: true, args: ['--no-sandbox', '--disable-gpu'] });
  const p = await b.newPage();
  await p.setViewport({ width: 1400, height: 900 });
  p.on('response', async (r) => {
    const u = r.url();
    if (r.status() >= 400 && (u.includes('/client/') || u.includes('/media/') || u.includes('/_matrix/'))) {
      let extra = '';
      if (r.status() != 404) { try { extra = ' :: ' + (r.request().postData() || '').slice(0, 300) + ' => ' + (await r.text()).slice(0, 200); } catch (_) {} }
      out.bad.push(r.status() + ' ' + r.request().method() + ' ' + u.replace(/^https?:\/\/[^/]+/, '').split('?')[0] + extra);
    }
  });
  p.on('pageerror', (e) => out.steps.push('pageerror ' + e.message));
  const shot = (n) => p.screenshot({ path: shots + '/' + n + '.png' });
  const step = (s) => out.steps.push(s);
  try {
    await p.goto(url + '/#/login', { waitUntil: 'networkidle2', timeout: 60000 });
    await p.waitForSelector('#mx_LoginForm_username', { timeout: 60000 });
    await p.type('#mx_LoginForm_username', user);
    await p.type('#mx_LoginForm_password', pw);
    await shot('1-login');
    await p.click('.mx_Login_submit');
    step('submitted login');
    await p.waitForSelector('.mx_LeftPanel, .mx_MatrixChat_wrapper .mx_RoomView, .mx_HomePage', { timeout: 60000 });
    await sleep(8000);
    await shot('2-after-login');
    out.url = p.url();
    out.spaces = await p.evaluate(() => [...document.querySelectorAll('.mx_SpacePanel [aria-label], .mx_SpacePanel [title]')].map((e) => e.getAttribute('aria-label') || e.getAttribute('title')));
    await p.evaluate(() => { const b = [...document.querySelectorAll('button')].find((e) => e.innerText.trim() === 'Later'); if (b) b.click(); });
    const inSpace = await p.evaluate((name) => {
      const el = [...document.querySelectorAll('.mx_SpacePanel [aria-label], .mx_SpacePanel [title]')].find((e) => (e.getAttribute('aria-label') || e.getAttribute('title') || '').includes(name));
      if (el) { el.click(); return true; }
      return false;
    }, space);
    out.spaceClicked = inSpace;
    await sleep(3000);
    await shot('2b-space');
    out.leftPanel = await p.evaluate(() => (document.querySelector('.mx_LeftPanel') || document.body).innerText.slice(0, 1500));
    // open the room by its name
    const opened = await p.evaluate((name) => {
      const els = [...document.querySelectorAll('[role=option], [role=treeitem], .mx_RoomTile, .mx_SpaceButton, .mx_RoomListItemView, [class*=RoomListItem]')];
      const el = els.find((e) => e.innerText && e.innerText.includes(name));
      if (el) { el.click(); return true; }
      return false;
    }, room);
    out.opened = opened;
    await sleep(3000);
    await shot('3-room');
    if (opened) {
      const composer = '[contenteditable=true][role=textbox], .mx_BasicMessageComposer_input';
      await p.waitForSelector(composer, { timeout: 30000 });
      await p.click(composer);
      await p.keyboard.type(mine);
      await p.keyboard.press('Enter');
      await sleep(4000);
      await shot('4-sent');
      out.sentVisible = await p.evaluate((t) => document.body.innerText.includes(t), mine);
      out.theirsVisible = false;
      for (let i = 0; i < 20 && !out.theirsVisible; i++) {
        out.theirsVisible = await p.evaluate((t) => document.body.innerText.includes(t), theirs);
        if (!out.theirsVisible) await sleep(1000);
      }
      await shot('5-received');
    }
  } catch (e) {
    out.error = String(e);
    try { await shot('error'); } catch (_) {}
  }
  out.bad = [...new Set(out.bad)];
  console.log('RESULT ' + JSON.stringify(out));
  await b.close();
})();
"#;

#[test]
fn element_web_logs_in_lists_rooms_and_exchanges_messages() {
    let (Ok(el), Ok(pp), Ok(chrome)) = (std::env::var("M4A_ELEMENT_DIR"), std::env::var("M4A_PUPPETEER_DIR"), std::env::var("M4A_CHROME")) else {
        eprintln!("skipped: M4A_ELEMENT_DIR, M4A_PUPPETEER_DIR and M4A_CHROME are not all set");
        return;
    };
    let work = PathBuf::from(format!("/tmp/m4a-element-{}", std::process::id()));
    std::fs::create_dir_all(work.join("shots")).unwrap();
    let site = work.join("site");
    assert!(Command::new("cp").args(["-rs", &el, site.to_str().unwrap()]).status().unwrap().success());

    let port = free_port();
    let ours = start_node("localhost", "alice", port, &[]);
    let c = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    // The page's config: our product server is the homeserver.
    let _ = std::fs::remove_file(site.join("config.json"));
    std::fs::write(site.join("config.json"), json!({
        "default_server_config": { "m.homeserver": { "base_url": ours.purl, "server_name": "localhost" } },
        "disable_guests": true, "disable_custom_urls": true, "show_labs_settings": false, "brand": "Element",
        "setting_defaults": { "UIFeature.registration": false, "UIFeature.passwordReset": false }
    }).to_string()).unwrap();
    let web_port = free_port();
    let web = Command::new("python3").args(["-m", "http.server", &web_port.to_string(), "--bind", "127.0.0.1", "-d", site.to_str().unwrap()]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    struct Kill(std::process::Child, PathBuf);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            if std::env::var("M4A_KEEP_SHOTS").is_err() {
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
    }
    let _guard = Kill(web, work.clone());

    // Alice has a space with a channel in it and a private group; bob joins them and writes.
    let pr = support_product::Product { url: ours.purl.clone() };
    let bob_tok = support_product::product_user(&pr, "bob");
    let bob = |m: &str, p: &str, b: Option<Value>| -> (u16, Value) {
        let url = format!("{}{}", ours.purl, p);
        let mut r = c.request(m.parse().unwrap(), url).bearer_auth(&bob_tok);
        if let Some(b) = b { r = r.json(&b); }
        let resp = r.send().unwrap();
        (resp.status().as_u16(), resp.json().unwrap_or(Value::Null))
    };
    let (st, v) = ours.call(&c, "POST", "/client/v3/createRoom", Some(json!({"name":"Domain","creation_content":{"type":"m.space"},"visibility":"private"})));
    assert_eq!(st, 200, "space: {v}");
    let space = v["room_id"].as_str().unwrap().to_string();
    let (st, v) = ours.call(&c, "POST", "/client/v3/createRoom", Some(json!({"name":"general","visibility":"public"})));
    assert_eq!(st, 200, "channel: {v}");
    let chan = v["room_id"].as_str().unwrap().to_string();
    let (st, v) = ours.call(&c, "POST", "/client/v3/createRoom", Some(json!({"name":"team","visibility":"private","invite":[bob_user(&bob)]})));
    assert_eq!(st, 200, "group: {v}");
    let group = v["room_id"].as_str().unwrap().to_string();
    for (room, ty, key, content) in [(&space, "m.space.child", chan.as_str(), json!({"via":["localhost"]})), (&space, "m.space.child", group.as_str(), json!({"via":["localhost"]})), (&chan, "m.space.parent", space.as_str(), json!({"via":["localhost"],"canonical":true}))] {
        let (st, v) = ours.call(&c, "PUT", &format!("/client/v3/rooms/{}/state/{}/{}", enc(room), ty, enc(key)), Some(content));
        assert_eq!(st, 200, "{ty}: {v}");
    }
    assert_eq!(bob("POST", &format!("/client/v3/rooms/{}/join", enc(&chan)), Some(json!({}))).0, 200);
    // A channel is written by its owner; bob gets the power to post.
    let (_, mut pl) = ours.call(&c, "GET", &format!("/client/v3/rooms/{}/state/m.room.power_levels", enc(&chan)), None);
    pl["users"][bob_user(&bob)] = json!(50);
    let (st, v) = ours.call(&c, "PUT", &format!("/client/v3/rooms/{}/state/m.room.power_levels", enc(&chan)), Some(pl));
    assert_eq!(st, 200, "power levels: {v}");
    let (st, v) = bob("POST", &format!("/client/v3/rooms/{}/join", enc(&group)), Some(json!({})));
    assert_eq!(st, 200, "bob joins the group: {v}");
    let (st, v) = bob("PUT", &format!("/client/v3/rooms/{}/send/m.room.message/b0", enc(&chan)), Some(json!({"msgtype":"m.text","body":"bob was here"})));
    assert_eq!(st, 200, "{v}");

    let driver = work.join("driver.js");
    std::fs::write(&driver, DRIVER).unwrap();
    let out = Command::new("node").arg(&driver).args([&format!("http://127.0.0.1:{web_port}"), "alice", "correct horse", work.join("shots").to_str().unwrap(), "general", "hello from element", "reply from bob", "Domain"]).env("M4A_PUPPETEER_DIR", &pp).env("M4A_CHROME", &chrome).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
    // Bob answers once Element has sent its message.
    let chan2 = chan.clone();
    for _ in 0..40 {
        let (_, m) = bob("GET", &format!("/client/v3/rooms/{}/messages?dir=b&limit=20", enc(&chan2)), None);
        if m["chunk"].as_array().is_some_and(|c| c.iter().any(|e| e["content"]["body"] == "hello from element")) {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let (st, v) = bob("PUT", &format!("/client/v3/rooms/{}/send/m.room.message/b1", enc(&chan)), Some(json!({"msgtype":"m.text","body":"reply from bob"})));
    assert_eq!(st, 200, "{v}");
    let out = out.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.starts_with("RESULT ")).expect("driver result");
    let r: Value = serde_json::from_str(&line[7..]).unwrap();
    eprintln!("ELEMENT RESULT\n{}", serde_json::to_string_pretty(&r).unwrap());
    eprintln!("screenshots in {}/shots", work.display());
    assert!(r["error"].is_null(), "driver error: {}", r["error"]);
    assert_eq!(r["opened"], true, "the room is in Element's list");
    assert_eq!(r["sentVisible"], true);
    assert_eq!(r["theirsVisible"], true);
}

fn bob_user(bob: &dyn Fn(&str, &str, Option<Value>) -> (u16, Value)) -> String {
    bob("GET", "/client/v3/account/whoami", None).1["user_id"].as_str().unwrap().to_string()
}

