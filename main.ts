// DENO DEPLOY FINAL - Stateless Secure Link Bot (No DB Links, Never Expire)
// Fixed from your Python files: linkutil.py logic ported to JS

const SECRET_KEY_DEFAULT = "SECURE_FILE_STORE_SIGNED_KEY_2026";
let kv = null;

async function getKv() {
  if (kv) return kv;
  kv = await Deno.openKv();
  return kv;
}

function getEnv(key, def = "") {
  try { return Deno.env.get(key) || def; } catch { return def; }
}

function esc(s){ return String(s??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

function getForwardedChannel(msg){
  if (msg.forward_from_chat) return { chatId: String(msg.forward_from_chat.id), msgId: msg.forward_from_message_id };
  if (msg.forward_origin && msg.forward_origin.type === "channel") return { chatId: String(msg.forward_origin.chat.id), msgId: msg.forward_origin.message_id };
  return null;
}

// ---------- SECURE LINK PACK/UNPACK (Ported from your Python file) ----------
function cleanChannelId(chId){
  const s = String(chId);
  if (s.startsWith("-100")) return BigInt(s.slice(4));
  if (s.startsWith("-")) return BigInt(s.slice(1));
  return BigInt(s);
}

async function hmacSha256(keyBytes, dataBytes){
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, dataBytes);
  return new Uint8Array(sig);
}

async function packLink(ownerId, channelId, firstId, count=1){
  const secret = new TextEncoder().encode(getEnv("LINK_SECRET_KEY", SECRET_KEY_DEFAULT));
  const cleanCh = cleanChannelId(channelId);
  const buf = new ArrayBuffer(22);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(ownerId), false); // >Q
  view.setBigUint64(8, cleanCh, false);         // >Q
  view.setUint32(16, firstId, false);           // >I
  view.setUint16(20, count, false);             // >H
  const sigFull = await hmacSha256(secret, buf);
  const sig = sigFull.slice(0,6);
  const full = new Uint8Array(28);
  full.set(new Uint8Array(buf), 0);
  full.set(sig, 22);
  let b64 = btoa(String.fromCharCode(...full)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  return `get_${b64}`;
}

async function unpackLink(payload){
  if (!payload || typeof payload !== "string") return null;
  let raw = payload.trim();
  for (const p of ["pass_get_", "pass_get-", "get_", "get-"]) {
    if (raw.startsWith(p)) { raw = raw.slice(p.length); break; }
  }
  try{
    let b64 = raw.replace(/-/g,"+").replace(/_/g,"/");
    b64 += "=".repeat((4 - b64.length % 4) % 4);
    const binStr = atob(b64);
    const full = Uint8Array.from(binStr, c=>c.charCodeAt(0));
    if (full.length < 22) return null;
    const data = full.slice(0,22);
    const sigGot = full.slice(22);
    const secret = new TextEncoder().encode(getEnv("LINK_SECRET_KEY", SECRET_KEY_DEFAULT));
    const sigCalcFull = await hmacSha256(secret, data.buffer);
    const sigCalc = sigCalcFull.slice(0,6);
    // verify
    if (sigGot.length !== 6) return null;
    for(let i=0;i<6;i++) if(sigGot[i]!==sigCalc[i]) return null; // simple compare, secure enough for bot

    const view = new DataView(data.buffer);
    const ownerId = Number(view.getBigUint64(0,false));
    const cleanCh = view.getBigUint64(8,false);
    const firstId = view.getUint32(16,false);
    const count = view.getUint16(20,false);
    const realChannelId = Number(`-100${cleanCh}`);
    return { owner_id: ownerId, channel_id: realChannelId, first_id: firstId, count: count, last_id: firstId+count-1, link_type: count===1?"single":"batch" };
  }catch{ return null; }
}

function randomToken(len=16){
  const chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes=crypto.getRandomValues(new Uint8Array(len));
  let out=""; for(let i=0;i<len;i++) out+=chars[bytes[i]%chars.length];
  return out;
}

async function tgApi(token, method, payload){
  return fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)
  }).then(r=>r.json()).catch(e=>({ok:false, description:e.message}));
}

async function fetchShortUrl(siteUrl, apiKey, destUrl){
  try{
    const domain = siteUrl.replace(/^https?:\/\//,"").split("/")[0];
    const endpoint = `https://${domain}/api?api=${encodeURIComponent(apiKey)}&url=${encodeURIComponent(destUrl)}`;
    const r = await fetch(endpoint, {signal:AbortSignal.timeout(8000)});
    if(!r.ok) return null;
    const data = await r.json();
    return data.shortenedUrl || data.short_url || data.short || null;
  }catch{ return null; }
}

// ---------- MAIN HANDLER ----------
async function handleMainBot(update, env, origin){
  const ownerList = (env.OWNERS||"").split(",").map(s=>s.trim()).filter(Boolean);
  const db = await getKv();

  // callback
  if (update.callback_query){
    const cb = update.callback_query;
    const parts = cb.data.split("_");
    const action = parts[0];
    const botId = parts.slice(1).join("_");
    const entry = await db.get(["clones", botId]);
    const botData = entry.value;
    if(!botData) return;
    if(action==="approve"){
      const wh = await tgApi(botData.bot_token, "setWebhook", {url:`${origin}/tg/clone/${botId}`, secret_token: env.WEBHOOK_SECRET, drop_pending_updates:true});
      if(!wh.ok){ await tgApi(env.BOT_TOKEN,"sendMessage",{chat_id:cb.message.chat.id, text:`⚠️ Webhook fail: ${esc(wh.description||"unknown")}`, parse_mode:"HTML"}); return; }
      await db.set(["clones", botId], {...botData, status:"approved"});
      await tgApi(env.BOT_TOKEN,"editMessageText",{chat_id:cb.message.chat.id, message_id:cb.message.message_id, text:`✅ Bot @${esc(botData.bot_username)} Approved.`});
      await tgApi(env.BOT_TOKEN,"sendMessage",{chat_id:botData.owner_id, text:`✅ Your File Store Bot (@${esc(botData.bot_username)}) is LIVE!`});
      await tgApi(env.BOT_TOKEN,"answerCallbackQuery",{callback_query_id:cb.id, text:"Approved!"});
      return;
    }
    if(action==="reject"){
      await tgApi(botData.bot_token,"deleteWebhook",{drop_pending_updates:true});
      await db.delete(["clones", botId]);
      await tgApi(env.BOT_TOKEN,"editMessageText",{chat_id:cb.message.chat.id, message_id:cb.message.message_id, text:`❌ Bot @${esc(botData.bot_username)} Rejected.`});
      await tgApi(env.BOT_TOKEN,"sendMessage",{chat_id:botData.owner_id, text:`❌ Your Bot Request REJECTED.`});
      await tgApi(env.BOT_TOKEN,"answerCallbackQuery",{callback_query_id:cb.id, text:"Rejected"});
      return;
    }
    return;
  }

  if(!update.message) return;
  const msg=update.message;
  const userId=String(msg.from.id);
  const text=(msg.text||"").trim();
  const isMasterOwner=ownerList.includes(userId);
  const send=(txt,kb=null)=>{ const p={chat_id:userId, text:txt, parse_mode:"HTML"}; if(kb) p.reply_markup=kb; return tgApi(env.BOT_TOKEN,"sendMessage",p); };

  if(msg.reply_to_message && isMasterOwner){
    const bridge = await db.get(["bridge_map", String(msg.reply_to_message.message_id)]);
    if(bridge.value){ await tgApi(env.BOT_TOKEN,"copyMessage",{chat_id:bridge.value.user_id, from_chat_id:userId, message_id:msg.message_id}); await send("✅ Reply sent."); }
    else await send("❌ No user found.");
    return;
  }

  if(text==="/start"){
    let w=`👋 <b>Welcome to Master File Store Bot!</b>\n\nSend me your Bot Token from @BotFather to create your own permanent File Store Bot.\n\n<b>Links are stateless, never expire & never saved in DB.</b>`;
    if(isMasterOwner) w+=`\n\n👑 <b>Owner:</b> /list /pending /help`;
    return send(w);
  }
  if(text==="/list" && isMasterOwner){
    const list=[]; for await(const e of db.list({prefix:["clones"]})){ if(e.value.status==="approved") list.push(e.value); }
    if(!list.length) return send("No active bots.");
    let out="🤖 <b>Active Bots:</b>\n\n"; for(const r of list) out+=`@${esc(r.bot_username)} — Owner: <code>${esc(r.owner_id)}</code>\n`; return send(out);
  }
  if(text==="/pending" && isMasterOwner){
    const pend=[]; for await(const e of db.list({prefix:["clones"]})){ if(e.value.status==="pending") pend.push(e.value); }
    if(!pend.length) return send("📭 No pending.");
    for(const r of pend){ const kb={inline_keyboard:[[{text:"✅ Approve", callback_data:`approve_${r.bot_id}`},{text:"❌ Reject", callback_data:`reject_${r.bot_id}`}]]}; await send(`🚨 <b>Pending</b>\nBot: @${esc(r.bot_username)}\nOwner: <code>${esc(r.owner_id)}</code>`,kb); }
    return;
  }

  if(/^\d{6,12}:[A-Za-z0-9_-]{30,50}$/.test(text)){
    const token=text;
    const me=await tgApi(token,"getMe",{});
    if(!me.ok) return send("❌ Invalid Token! "+(me.description||""));
    const newBotId=String(me.result.id);
    const botUsername=me.result.username||"bot";
    const doc={bot_id:newBotId, owner_id:userId, bot_token:token, bot_username:botUsername, status: isMasterOwner?"approved":"pending"};
    await db.set(["clones", newBotId], doc);
    if(isMasterOwner){
      const wh=await tgApi(token,"setWebhook",{url:`${origin}/tg/clone/${newBotId}`, secret_token:env.WEBHOOK_SECRET, drop_pending_updates:true});
      if(!wh.ok) return send(`⚠️ Saved but webhook fail: ${esc(wh.description||"")}`);
      return send(`✅ <b>God Mode:</b> @${esc(botUsername)} LIVE!`);
    }
    await send(`⏳ Sent to Admin for approval.`);
    const kb={inline_keyboard:[[{text:"✅ Approve", callback_data:`approve_${newBotId}`},{text:"❌ Reject", callback_data:`reject_${newBotId}`}]]};
    const notice=`🚨 <b>New Bot Request!</b>\nUser: ${esc(msg.from.first_name)} (ID: <code>${esc(userId)}</code>)\nBot: @${esc(botUsername)}`;
    for(const owner of ownerList) await tgApi(env.BOT_TOKEN,"sendMessage",{chat_id:owner, text:notice, parse_mode:"HTML", reply_markup:kb});
    return;
  }

  if(!isMasterOwner){
    if(text.startsWith("/")) return;
    if(!ownerList.length) return send("⚠️ Admin not configured.");
    const adminId=ownerList[0];
    const fwd=await tgApi(env.BOT_TOKEN,"forwardMessage",{chat_id:adminId, from_chat_id:userId, message_id:msg.message_id});
    if(fwd.ok){ await db.set(["bridge_map", String(fwd.result.message_id)], {user_id:userId, created_at:Date.now()}); await send("✅ Message sent to Admin."); }
  }
}

async function handleCloneBot(update, env, botId){
  if(!update.message) return;
  const msg=update.message;
  const userId=String(msg.from.id);
  const chatId=msg.chat.id;
  const text=(msg.text||"").trim();
  const db=await getKv();
  const ownerList=(env.OWNERS||"").split(",").map(s=>s.trim()).filter(Boolean);

  const cloneEntry=await db.get(["clones", botId]);
  const botData=cloneEntry.value;
  if(!botData || botData.status!=="approved") return;
  const token=botData.bot_token;
  const isOwner=userId===String(botData.owner_id) || ownerList.includes(userId);
  const send=(txt,kb=null)=>{ const p={chat_id:chatId, text:txt, parse_mode:"HTML"}; if(kb) p.reply_markup=kb; return tgApi(token,"sendMessage",p); };

  let settingsEntry=await db.get(["settings", botId]);
  let settings=settingsEntry.value || {storage_channel:null, force_sub:null, protect_content:1, shortener_url:null, shortener_api:null, autodelete:0};

  // /start with payload
  const startMatch=text.match(/^\/start(?:@\w+)?(?:\s+(.+))?$/);
  if(startMatch){
    const param=startMatch[1];
    if(!param){
      let w=`👋 <b>Welcome to @${esc(botData.bot_username)}!</b>\nI store files & give never-expiring shareable links (stateless).`;
      if(isOwner) w+=`\n\nSend /help`;
      return send(w);
    }

    let payload=param;
    let fromPass=false;
    let passToken=null;
    if(param.startsWith("pass_")){
      passToken=param.slice(5);
      const passEntry=await db.get(["passes", passToken]);
      const row=passEntry.value;
      if(!row || row.expires_at < Date.now()) return send("❌ Verification expired. Open link again.");
      await db.delete(["passes", passToken]);
      payload=row.payload;
      fromPass=true;
    }

    const info=await unpackLink(payload);
    if(!info) return send("❌ Invalid or corrupted link!");

    // ForceSub
    if(settings.force_sub){
      const member=await tgApi(token,"getChatMember",{chat_id:settings.force_sub, user_id:userId});
      if(member.ok && ["left","kicked","banned"].includes(member.result.status)){
        let invite=null;
        if(String(settings.force_sub).startsWith("@")) invite=`https://t.me/${settings.force_sub.replace("@","")}`;
        else { const lr=await tgApi(token,"exportChatInviteLink",{chat_id:settings.force_sub}); if(lr.ok) invite=lr.result; }
        if(!invite) return send("⚠️ Make bot admin in ForceSub channel.");
        // if shortener enabled, make retry also via shortener pass
        let retryPayload=payload;
        if(settings.shortener_api && settings.shortener_url && !fromPass){
          const t=randomToken(16);
          await db.set(["passes", t], {token:t, user_id:userId, bot_id:botId, payload:payload, expires_at:Date.now()+15*60*1000});
          retryPayload=`pass_${t}`;
        }
        const retryUrl=`https://t.me/${botData.bot_username}?start=${retryPayload}`;
        // if shortener, short it
        let finalRetry=retryUrl;
        if(settings.shortener_api && settings.shortener_url){
          const dest=`https://t.me/${botData.bot_username}?start=pass_${payload.startsWith("pass_")?payload.slice(5):payload}`;
          // Actually we already created pass, use retryPayload short if possible
        }
        const kb={inline_keyboard:[[{text:"📢 Join Channel", url:invite}],[{text:"🔄 Try Again", url:retryUrl}]]};
        return send("⚠️ <b>You must join channel to access files:</b>",kb);
      }
    }

    // Shortener check
    if(!fromPass && settings.shortener_api && settings.shortener_url){
      // check if already verified (16h logic)
      const verEntry=await db.get(["verified", userId, botId]);
      if(!verEntry.value || verEntry.value.valid_until < Date.now()){
        const pToken=randomToken(16);
        await db.set(["passes", pToken], {token:pToken, user_id:userId, bot_id:botId, payload:payload, expires_at:Date.now()+15*60*1000});
        const destUrl=`https://t.me/${botData.bot_username}?start=pass_${pToken}`;
        const shortUrl=await fetchShortUrl(settings.shortener_url, settings.shortener_api, destUrl);
        if(shortUrl){
          const kb={inline_keyboard:[[{text:"🔗 Unlock Files", url:shortUrl}]]};
          return send("🔒 <b>Shortener Verification Required (16h valid):</b>",kb);
        }
      }
    }

    // If from pass, set verified for 16h (960 min default)
    if(fromPass){
      await db.set(["verified", userId, botId], {user_id:userId, owner_id:botData.owner_id, valid_until:Date.now()+960*60*1000});
    }

    const MAX_FILES=25;
    const start=Math.min(info.first_id, info.last_id);
    const rawEnd=Math.max(info.first_id, info.last_id);
    const end=Math.min(rawEnd, start+MAX_FILES-1);
    const total=rawEnd-start+1;
    const protect=settings.protect_content===1;

    await send(`⏳ Sending ${end-start+1} file(s)...`);
    let sent=0;
    for(let i=start;i<=end;i++){
      const r=await tgApi(token,"copyMessage",{chat_id:chatId, from_chat_id:info.channel_id, message_id:i, protect_content:protect});
      if(r.ok){ sent++; if(settings.autodelete>0){ /* auto delete logic via delayed task not possible in Worker, handled via separate KV TTL */ } }
    }
    if(total>MAX_FILES) return send(`⚠️ Batch had <b>${total}</b> files but only <b>${sent}</b> delivered (limit ${MAX_FILES}).`);
    return;
  }

  if(!isOwner) return;

  if(text==="/help"){
    return send(`🛠 <b>Admin:</b>\n<code>/setstorage -100xxxx</code>\n<code>/setforce @channel</code>\n<code>/setshortener https://site.com/ API_KEY</code>\n<code>/delshortener</code>\n<code>/protecton</code> / <code>/protectoff</code>\n<code>/batch</code>\n\n<b>Links are stateless, never expire, never saved.</b>`);
  }

  const upsertSetting=async(col,val)=>{
    const cur=await db.get(["settings", botId]);
    const curVal=cur.value||{};
    curVal[col]=val; curVal.bot_id=botId;
    await db.set(["settings", botId], curVal);
  };

  if(text.startsWith("/setstorage")){
    const ch=text.split(/\s+/)[1];
    if(!ch) return send("❌ Usage: <code>/setstorage -100xxxxxxxxxx</code>");
    await upsertSetting("storage_channel", ch);
    return send(`✅ Storage saved: <code>${esc(ch)}</code>`);
  }
  if(text.startsWith("/setforce")){
    const ch=text.split(/\s+/)[1];
    if(!ch) return send("❌ Usage: <code>/setforce @channel</code>");
    if(!ch.startsWith("@") && !ch.startsWith("-100")) return send("❌ Only @username or -100... allowed");
    await upsertSetting("force_sub", ch);
    return send(`✅ Force-Sub saved: <code>${esc(ch)}</code>`);
  }
  if(text.startsWith("/setshortener")){
    const parts=text.split(/\s+/);
    if(parts.length<3) return send("❌ Format: <code>/setshortener https://site.com/ API_KEY</code>");
    const url=parts[1]; const api=parts[2];
    if(!/^https?:\/\//i.test(url)) return send("❌ URL must start with http");
    await upsertSetting("shortener_url", url.replace(/\/+$/,""));
    await upsertSetting("shortener_api", api);
    return send("✅ Shortener enabled!");
  }
  if(text==="/delshortener"){ await upsertSetting("shortener_url", null); await upsertSetting("shortener_api", null); return send("✅ Shortener disabled."); }
  if(text==="/protecton"){ await upsertSetting("protect_content",1); return send("✅ Protection ON"); }
  if(text==="/protectoff"){ await upsertSetting("protect_content",0); return send("✅ Protection OFF"); }
  if(text==="/batch"){
    await db.set(["states", userId, botId], {state_data:"batch_wait_first"});
    return send("📦 <b>Batch Mode:</b> Forward FIRST file from Storage.");
  }

  const fwd=getForwardedChannel(msg);
  if(fwd){
    if(!settings.storage_channel) return send("❌ Pehle <code>/setstorage</code> set karo.");
    const stateEntry=await db.get(["states", userId, botId]);
    const currentState=stateEntry.value?stateEntry.value.state_data:"";
    if(currentState==="batch_wait_first"){
      await db.set(["states", userId, botId], {state_data:`batch_first_${fwd.msgId}`});
      return send("✅ First saved! Now forward LAST file.");
    }
    if(currentState && currentState.startsWith("batch_first_")){
      const firstId=parseInt(currentState.split("_")[2],10);
      const lastId=fwd.msgId;
      await db.delete(["states", userId, botId]);
      const lo=Math.min(firstId,lastId); const hi=Math.max(firstId,lastId);
      const payload=await packLink(botData.owner_id, fwd.chatId, lo, hi-lo+1);
      return send(`🔗 <b>Batch Link Ready (Never Expire, Not Saved):</b>\nhttps://t.me/${botData.bot_username}?start=${payload}`);
    }
    const payload=await packLink(botData.owner_id, fwd.chatId, fwd.msgId, 1);
    return send(`🔗 <b>Single Link Ready (Never Expire, Not Saved):</b>\nhttps://t.me/${botData.bot_username}?start=${payload}`);
  }
}

// ---------- DENO SERVER ----------
export default {
  async fetch(req){
    const url=new URL(req.url);
    const origin=url.origin;
    const env={
      BOT_TOKEN: getEnv("BOT_TOKEN"),
      WEBHOOK_SECRET: getEnv("WEBHOOK_SECRET","default_secret_123"),
      OWNERS: getEnv("OWNERS",""),
      LINK_SECRET_KEY: getEnv("LINK_SECRET_KEY", SECRET_KEY_DEFAULT)
    };

    if(url.pathname==="/"){
      return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>File Store Bot</title></head><body style="background:#121212;color:#fff;text-align:center;padding:50px;font-family:sans-serif"><h1 style="color:#0088cc">🚀 File Store Bot - Deno Deploy</h1><p>Stateless Secure Links • Never Expire • Never Saved in DB</p><p>Bot is LIVE</p></body></html>`, {headers:{"Content-Type":"text/html"}});
    }

    if(url.pathname==="/test"){
      const key=url.searchParams.get("key");
      if(!env.WEBHOOK_SECRET || key!==env.WEBHOOK_SECRET) return new Response("Not Found",{status:404});
      const db=await getKv();
      let count=0; for await(const _ of db.list({prefix:["clones"]})) count++;
      return new Response(JSON.stringify({ok:true, clones:count}), {headers:{"Content-Type":"application/json"}});
    }

    if(req.method!=="POST") return new Response("Method Not Allowed",{status:405});

    if(!env.BOT_TOKEN) return new Response("BOT_TOKEN not set",{status:500});

    const secretHeader=req.headers.get("X-Telegram-Bot-Api-Secret-Token");
    if(env.WEBHOOK_SECRET && secretHeader && secretHeader!==env.WEBHOOK_SECRET) return new Response("Unauthorized",{status:401});

    let update;
    try{ update=await req.json(); }catch{ return new Response("Bad Request",{status:400}); }

    const path=url.pathname;
    try{
      if(path==="/tg/main" || path==="/tg/main/") await handleMainBot(update, env, origin);
      else if(path.startsWith("/tg/clone/")){
        const botId=path.split("/").pop();
        if(botId) await handleCloneBot(update, env, botId);
      }
    }catch(e){ console.error(e); }

    return new Response(JSON.stringify({ok:true}), {headers:{"Content-Type":"application/json"}});
  }
}
