'use strict';
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { neon } = require('@neondatabase/serverless');
const { z } = require('zod');
const crypto = require('crypto');
const PizZip = require('pizzip');
const Docxtemplater = require('docxtemplater');

const required = ['DATABASE_URL','JWT_SECRET','APP_ORIGIN'];
for (const key of required) if (!process.env[key]) throw new Error(`Variável obrigatória ausente: ${key}`);
if (process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET precisa ter pelo menos 32 caracteres.');
const sql = neon(process.env.DATABASE_URL);
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  fontSrc: ["'self'", 'https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:', 'https:'], connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"]
}}}));
app.use(express.json({ limit: '200kb' }));
app.use(cookieParser());
app.use(express.static('public', { index: 'index.html', etag: true, maxAge: '1h' }));
const loginLimiter = rateLimit({ windowMs: 15*60*1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Muitas tentativas. Aguarde 15 minutos.' } });
const totpLimiter = rateLimit({ windowMs: 5*60*1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Muitas tentativas de 2FA. Aguarde alguns minutos.' } });

const ROLES = ['coordenador','vice_coordenador','contribuinte','escola'];
const COOKIE = 'tce_session';
const isCoord = u => ['coordenador','vice_coordenador'].includes(u.role);
const b32chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(buf){let bits=0,value=0,out='';for(const byte of buf){value=(value<<8)|byte;bits+=8;while(bits>=5){out+=b32chars[(value>>>(bits-5))&31];bits-=5;}}if(bits)out+=b32chars[(value<<(5-bits))&31];return out;}
function unbase32(s){let bits=0,value=0,out=[];for(const ch of s){const n=b32chars.indexOf(ch);if(n<0)continue;value=(value<<5)|n;bits+=5;if(bits>=8){out.push((value>>>(bits-8))&255);bits-=8;}}return Buffer.from(out);}
function totp(secret,at=Date.now()){const counter=Math.floor(at/30000),buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(counter));const h=crypto.createHmac('sha1',unbase32(secret)).update(buf).digest();const off=h[h.length-1]&15;const n=(h.readUInt32BE(off)&0x7fffffff)%1000000;return String(n).padStart(6,'0');}
function verifyTotp(secret,code){if(!secret||!/^\d{6}$/.test(String(code||'')))return false;const now=Date.now();return [-1,0,1].some(w=>crypto.timingSafeEqual(Buffer.from(totp(secret,now+w*30000)),Buffer.from(String(code))));}
function encryptSecret(value){const key=crypto.createHash('sha256').update(process.env.JWT_SECRET).digest();const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);const enc=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);return [iv.toString('base64'),cipher.getAuthTag().toString('base64'),enc.toString('base64')].join('.');}
function decryptSecret(value){const [iv,tag,data]=String(value).split('.');const key=crypto.createHash('sha256').update(process.env.JWT_SECRET).digest();const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(iv,'base64'));decipher.setAuthTag(Buffer.from(tag,'base64'));return Buffer.concat([decipher.update(Buffer.from(data,'base64')),decipher.final()]).toString('utf8');}
async function requireTOTP(req,res,next){try{if(!isCoord(req.user))return next();const rows=await sql`SELECT totp_secret_enc,totp_enabled FROM users WHERE id=${req.user.id}`;if(!rows[0]?.totp_enabled||!rows[0]?.totp_secret_enc)return res.status(428).json({error:'Configure o aplicativo autenticador antes desta operação.',code:'TOTP_SETUP_REQUIRED'});const secret=decryptSecret(rows[0].totp_secret_enc);if(!verifyTotp(secret,req.get('x-tce-2fa-code')))return res.status(401).json({error:'Código do aplicativo autenticador inválido ou expirado.',code:'TOTP_INVALID'});next();}catch(e){next(e);}}

async function auth(req,res,next) {
  const token = req.cookies[COOKIE];
  if (!token) return res.status(401).json({error:'Sessão não autenticada.'});
  let payload;
  try { payload = jwt.verify(token, process.env.JWT_SECRET, { issuer:'tce-portal', audience:'tce-users' }); }
  catch { res.clearCookie(COOKIE); return res.status(401).json({error:'Sessão expirada ou inválida.'}); }
  const rows = await sql`SELECT id,name,email,role,contributor_id,must_change_password,active,cargo_detalhado,session_version,totp_enabled FROM users WHERE id=${payload.id} LIMIT 1`;
  if (!rows[0] || !rows[0].active) { res.clearCookie(COOKIE); return res.status(401).json({error:'Conta inativa ou sessão revogada.'}); }
  if (Number(rows[0].session_version) !== Number(payload.session_version)) { res.clearCookie(COOKIE); return res.status(401).json({error:'Sessão revogada. Entre novamente.'}); }
  req.user = rows[0];
  if (req.user.must_change_password && !['/auth/me','/auth/password','/auth/logout'].includes(req.path.replace('/api',''))) return res.status(403).json({error:'Troque sua senha antes de continuar.'});
  next();
}
function allow(...roles) { return (req,res,next) => roles.includes(req.user.role) ? next() : res.status(403).json({error:'Você não tem permissão para esta operação.'}); }
function originGuard(req,res,next) {
  if (!['GET','HEAD','OPTIONS'].includes(req.method)) {
    const origin = req.get('origin');
    if (!origin || origin !== process.env.APP_ORIGIN) return res.status(403).json({error:'Origem da requisição não autorizada.'});
  }
  next();
}
app.use('/api', originGuard);
const cleanUser = u => ({id:u.id,name:u.name,email:u.email,role:u.role,cargo_detalhado:u.cargo_detalhado,contributor_id:u.contributor_id,must_change_password:u.must_change_password,totp_enabled:Boolean(u.totp_enabled)});
async function audit(req, action, entity, entityId=null, details={}) {
  await sql`INSERT INTO audit_logs (actor_id,action,entity,entity_id,details,ip_address) VALUES (${req.user?.id||null},${action},${entity},${entityId},${JSON.stringify(details)}::jsonb,${req.ip})`;
}

app.get('/api/health', async (_req,res) => {
  try { await sql`SELECT 1`; res.json({status:'ok',database:'connected'}); }
  catch { res.status(503).json({status:'error',database:'unavailable'}); }
});
app.post('/api/auth/login', loginLimiter, async (req,res) => {
  const parsed = z.object({email:z.string().email().max(254),password:z.string().min(1).max(200)}).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:'Informe e-mail e senha válidos.'});
  const email = parsed.data.email.trim().toLowerCase();
  const rows = await sql`SELECT * FROM users WHERE email=${email} AND active=true LIMIT 1`;
  const user = rows[0];
  if (!user || !(await bcrypt.compare(parsed.data.password,user.password_hash))) {
    await sql`INSERT INTO audit_logs(action,entity,details,ip_address) VALUES ('login_failed','auth',${JSON.stringify({email})}::jsonb,${req.ip})`;
    return res.status(401).json({error:'E-mail ou senha incorretos.'});
  }
  const token = jwt.sign({id:user.id,name:user.name,email:user.email,role:user.role,contributor_id:user.contributor_id,must_change_password:user.must_change_password,session_version:user.session_version},process.env.JWT_SECRET,{expiresIn:'8h',issuer:'tce-portal',audience:'tce-users'});
  res.cookie(COOKIE,token,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'strict',maxAge:8*60*60*1000,path:'/'});
  await audit({user,ip:req.ip},'login','auth',user.id);
  res.json({user:cleanUser(user)});
});
app.post('/api/auth/logout', auth, async (req,res) => { await audit(req,'logout','auth',req.user.id); res.clearCookie(COOKIE,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'strict',path:'/'}); res.json({ok:true}); });
app.get('/api/auth/me',auth,(req,res)=>res.json({user:req.user}));
app.post('/api/auth/password',auth,async(req,res)=>{
  const p=z.object({currentPassword:z.string().min(1),newPassword:z.string().min(8).max(200).regex(/[A-Z]/).regex(/[a-z]/).regex(/[0-9]/)}).safeParse(req.body);
  if(!p.success) return res.status(400).json({error:'A senha precisa ter pelo menos 8 caracteres, incluindo letra maiúscula, minúscula e número.'});
  const rows=await sql`SELECT password_hash FROM users WHERE id=${req.user.id} AND active=true`;
  if(!rows[0] || !(await bcrypt.compare(p.data.currentPassword,rows[0].password_hash))) return res.status(400).json({error:'Senha atual incorreta.'});
  const hash=await bcrypt.hash(p.data.newPassword,12);
  const updated=await sql`UPDATE users SET password_hash=${hash},must_change_password=false,session_version=session_version+1,updated_at=now() WHERE id=${req.user.id} RETURNING session_version`;
  await audit(req,'password_changed','users',req.user.id);
  const token=jwt.sign({...req.user,must_change_password:false,session_version:updated[0].session_version},process.env.JWT_SECRET,{expiresIn:'8h',issuer:'tce-portal',audience:'tce-users'});
  res.cookie(COOKIE,token,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'strict',maxAge:8*60*60*1000,path:'/'});
  res.json({ok:true});
});

// Configuração TOTP: segredo criptografado no banco e nunca devolvido após ativação.
app.post('/api/auth/2fa/setup',auth,allow('coordenador','vice_coordenador'),async(req,res)=>{
 const current=await sql`SELECT totp_enabled FROM users WHERE id=${req.user.id}`;if(current[0]?.totp_enabled)return res.status(409).json({error:'O 2FA já está configurado nesta conta.'});
 const secret=base32(crypto.randomBytes(20));
 await sql`UPDATE users SET totp_secret_enc=${encryptSecret(secret)},totp_enabled=false,updated_at=now() WHERE id=${req.user.id}`;
 await audit(req,'totp_setup_started','users',req.user.id);
 const issuer='TCE Portal',label=encodeURIComponent(`${issuer}:${req.user.email}`);
 res.json({secret,otpauth_url:`otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`});
});
app.post('/api/auth/2fa/confirm',auth,allow('coordenador','vice_coordenador'),totpLimiter,async(req,res)=>{
 const p=z.object({code:z.string().regex(/^\d{6}$/)}).safeParse(req.body);
 if(!p.success)return res.status(400).json({error:'Informe o código de seis dígitos.'});
 const rows=await sql`SELECT totp_secret_enc FROM users WHERE id=${req.user.id}`;
 if(!rows[0]?.totp_secret_enc||!verifyTotp(decryptSecret(rows[0].totp_secret_enc),p.data.code))return res.status(400).json({error:'Código inválido. Confira o horário do celular e tente novamente.'});
 await sql`UPDATE users SET totp_enabled=true,updated_at=now() WHERE id=${req.user.id}`;
 await audit(req,'totp_enabled','users',req.user.id);res.json({ok:true});
});

// Users are managed separately; hashes are never returned to the browser.
app.get('/api/users',auth,allow('coordenador','vice_coordenador'),async(_req,res)=>{
 const rows=await sql`SELECT id,name,email,role,cargo_detalhado,contributor_id,active,must_change_password,totp_enabled,created_at FROM users ORDER BY name`;
 res.json(rows);
});
app.post('/api/users',auth,allow('coordenador','vice_coordenador'),totpLimiter,requireTOTP,async(req,res)=>{
 const p=z.object({name:z.string().trim().min(2).max(150),email:z.string().email().max(254),role:z.enum(ROLES),cargo_detalhado:z.string().max(120).optional(),contributor_id:z.string().uuid().optional(),temporaryPassword:z.string().min(8).max(200).regex(/[A-Z]/).regex(/[a-z]/).regex(/[0-9]/)}).safeParse(req.body);
 if(!p.success)return res.status(400).json({error:'Dados de usuário inválidos.'});
 const d=p.data;if(req.user.role==='vice_coordenador'&&['coordenador','vice_coordenador'].includes(d.role))return res.status(403).json({error:'O vice-coordenador pode criar contas de contribuinte e escola, mas não novas contas administrativas.'});if(d.role==='contribuinte'&&!d.contributor_id)return res.status(400).json({error:'Vincule a conta a um cadastro de contribuinte.'});
 const hash=await bcrypt.hash(d.temporaryPassword,12);
 try { const rows=await sql`INSERT INTO users(name,email,password_hash,role,cargo_detalhado,contributor_id,must_change_password) VALUES (${d.name},${d.email.toLowerCase()},${hash},${d.role},${d.cargo_detalhado||null},${d.contributor_id||null},true) RETURNING id,name,email,role,cargo_detalhado,contributor_id,active,must_change_password`;
 await audit(req,'create','users',rows[0].id,{role:d.role});res.status(201).json(rows[0]); }
 catch(e){if(e.code==='23505')return res.status(409).json({error:'Este e-mail já está cadastrado.'});throw e;}
});
app.patch('/api/users/:id',auth,allow('coordenador','vice_coordenador'),totpLimiter,requireTOTP,async(req,res)=>{
 const p=z.object({active:z.boolean().optional(),role:z.enum(ROLES).optional(),name:z.string().trim().min(2).max(150).optional(),cargo_detalhado:z.string().max(120).nullable().optional()}).strict().safeParse(req.body);
 if(!p.success)return res.status(400).json({error:'Alteração inválida.'});
 if(req.user.role==='vice_coordenador'&&['coordenador','vice_coordenador'].includes(p.data.role))return res.status(403).json({error:'O vice-coordenador não pode atribuir perfis administrativos.'});
 if(req.params.id===req.user.id && p.data.active===false)return res.status(400).json({error:'Não é permitido desativar a própria conta.'});
 if(req.user.role==='vice_coordenador'&&p.data.active===false){const target=await sql`SELECT role FROM users WHERE id=${req.params.id}`;if(['coordenador','vice_coordenador'].includes(target[0]?.role))return res.status(403).json({error:'O vice-coordenador não pode desativar contas administrativas.'});}
 const d=p.data, keys=Object.keys(d);if(!keys.length)return res.status(400).json({error:'Nenhuma alteração enviada.'});if(d.role==='contribuinte'){const existing=await sql`SELECT contributor_id FROM users WHERE id=${req.params.id}`;if(!existing.length||!existing[0].contributor_id)return res.status(400).json({error:'Vincule um cadastro de contribuinte antes de atribuir este perfil.'});}
 const sets=[];const vals=[];const allowed={active:'active',role:'role',name:'name',cargo_detalhado:'cargo_detalhado'};
 for(const k of keys){sets.push(`${allowed[k]}=$${vals.length+1}`);vals.push(d[k]);} if(keys.includes('active'))sets.push('session_version=session_version+1'); sets.push('updated_at=now()');
 vals.push(req.params.id);
 const q=`UPDATE users SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING id,name,email,role,cargo_detalhado,contributor_id,active,must_change_password`;
 const rows=await sql.query(q,vals);if(!rows.length)return res.status(404).json({error:'Usuário não encontrado.'});
 await audit(req,'update','users',req.params.id,{fields:keys});res.json(rows[0]);
});

app.delete('/api/users/:id',auth,allow('coordenador','vice_coordenador'),totpLimiter,requireTOTP,async(req,res)=>{
 if(req.params.id===req.user.id)return res.status(400).json({error:'Não é permitido excluir a própria conta.'});
 const target=await sql`SELECT id,role,name FROM users WHERE id=${req.params.id}`;
 if(!target.length)return res.status(404).json({error:'Usuário não encontrado.'});
 if(['coordenador','vice_coordenador'].includes(target[0].role)&&req.user.role==='vice_coordenador')return res.status(403).json({error:'O vice-coordenador não pode desativar contas administrativas.'});
 if(target[0].role==='coordenador')return res.status(403).json({error:'A conta do coordenador principal não pode ser excluída por este fluxo. Desative-a somente após definir sucessão administrativa.'});
 await sql`UPDATE users SET active=false,session_version=session_version+1,updated_at=now() WHERE id=${req.params.id}`;
 await audit(req,'user_deactivated','users',req.params.id,{name:target[0].name,role:target[0].role});
 res.json({ok:true,deleted:false,message:'Conta desativada e sessões revogadas. O histórico foi preservado.'});
});

app.post('/api/users/:id/reset-password',auth,allow('coordenador','vice_coordenador'),totpLimiter,requireTOTP,async(req,res)=>{
 const p=z.object({temporaryPassword:z.string().min(8).max(200).regex(/[A-Z]/).regex(/[a-z]/).regex(/[0-9]/)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'A senha temporária precisa ter pelo menos 8 caracteres, incluindo maiúscula, minúscula e número.'});
 const hash=await bcrypt.hash(p.data.temporaryPassword,12);const rows=await sql`UPDATE users SET password_hash=${hash},must_change_password=true,session_version=session_version+1,updated_at=now() WHERE id=${req.params.id} RETURNING id`;
 if(!rows.length)return res.status(404).json({error:'Usuário não encontrado.'});await audit(req,'password_reset','users',req.params.id);res.json({ok:true});
});

// Whitelisted resources: SQL identifiers come only from this server-side map.
const resources={
 contributors:{table:'contributors',roles:['coordenador','vice_coordenador'],read:['coordenador','vice_coordenador'],fields:['full_name','birth_date','email','address','cpf','photo_url','document_url','status'],required:['full_name','email'],order:'created_at DESC'},
 suppliers:{table:'suppliers',roles:['coordenador','vice_coordenador'],read:['coordenador','vice_coordenador'],fields:['legal_name','trade_name','cnpj','general_contact','seller_name','seller_contact'],required:['legal_name'],order:'legal_name ASC'},
 financial:{table:'financial_entries',roles:['coordenador'],read:['coordenador'],fields:['description','type','amount','due_date','status','counterparty','invoice_number','receipt_url'],required:['description','type','amount','due_date','counterparty'],order:'due_date DESC'},
 purchases:{table:'purchases',roles:['coordenador'],read:['coordenador'],fields:['supplier_id','item','amount','access_key','purchase_date','notes','receipt_url'],required:['item','amount','access_key','purchase_date'],order:'purchase_date DESC'},
 announcements:{table:'announcements',roles:['coordenador','vice_coordenador'],read:ROLES,fields:['title','content','category'],required:['title','content'],order:'created_at DESC'},
 requests:{table:'service_requests',roles:['escola'],read:['coordenador','vice_coordenador','escola'],fields:['sector','activity_name','event_date','support_type','description'],required:['sector','activity_name','event_date','support_type','description'],order:'created_at DESC'},
 tasks:{table:'tasks',roles:['coordenador','vice_coordenador'],read:['coordenador','vice_coordenador','contribuinte'],fields:['title','description','assigned_to','due_date','priority','status'],required:['title','due_date'],order:'due_date ASC'},
 hours:{table:'declared_hours',roles:['contribuinte'],read:['coordenador','vice_coordenador','contribuinte','escola'],fields:['contributor_id','task_id','work_date','start_time','end_time','hours','activity','notes'],required:['work_date','start_time','end_time','hours','activity'],order:'work_date DESC'}
};
function rowFilter(key,user){
 if(key==='tasks'&&user.role==='contribuinte')return {sql:'assigned_to=$1',values:[user.contributor_id]};
 if(key==='hours'&&user.role==='contribuinte')return {sql:'contributor_id=$1',values:[user.contributor_id]};
 if(key==='requests'&&user.role==='escola')return {sql:'requester_id=$1',values:[user.id]};
 return null;
}
function validCpf(value){const s=String(value||'');if(!/^\d{11}$/.test(s)||/^([0-9])\1{10}$/.test(s))return false;let sum=0;for(let i=0;i<9;i++)sum+=Number(s[i])*(10-i);let d=(sum*10)%11;if(d===10)d=0;if(d!==Number(s[9]))return false;sum=0;for(let i=0;i<10;i++)sum+=Number(s[i])*(11-i);d=(sum*10)%11;if(d===10)d=0;return d===Number(s[10]);}
function validCnpj(value){const s=String(value||'');if(!/^\d{14}$/.test(s)||/^([0-9])\1{13}$/.test(s))return false;const calc=(base,weights)=>{const sum=base.split('').reduce((a,n,i)=>a+Number(n)*weights[i],0);const r=sum%11;return r<2?0:11-r};const d1=calc(s.slice(0,12),[5,4,3,2,9,8,7,6,5,4,3,2]);const d2=calc(s.slice(0,12)+d1,[6,5,4,3,2,9,8,7,6,5,4,3,2]);return s.endsWith(String(d1)+String(d2));}
function validateFields(cfg,body,partial=false){
 if(!body||typeof body!=='object'||Array.isArray(body))return {error:'Corpo inválido.'};
 const keys=Object.keys(body);if(keys.some(k=>!cfg.fields.includes(k)))return {error:'Campo não permitido.'};
 if(!partial&&cfg.required.some(k=>body[k]===undefined||body[k]===null||body[k]===''))return {error:'Preencha todos os campos obrigatórios.'};
 const out={};for(const [k,v] of Object.entries(body)){if(v===null||['string','number','boolean'].includes(typeof v))out[k]=typeof v==='string'?v.trim():v;else return {error:`Valor inválido em ${k}.`};}if(typeof out.email==='string')out.email=out.email.toLowerCase();
 for(const k of ['photo_url','document_url','receipt_url'])if(out[k]&& !/^https:\/\//i.test(out[k]))return {error:`${k} precisa usar HTTPS.`};
 if(out.amount!==undefined&&(!Number.isFinite(Number(out.amount))||Number(out.amount)<=0))return {error:'Valor financeiro inválido.'};
 if(out.hours!==undefined&&(!Number.isFinite(Number(out.hours))||Number(out.hours)<=0||Number(out.hours)>16))return {error:'Carga horária inválida (máximo de 16 horas por declaração).'};
 if(out.start_time&&out.end_time){if(out.end_time<=out.start_time)return {error:'A hora final deve ser posterior à inicial.'};if(out.hours!==undefined){const [a,b]=out.start_time.split(':').map(Number),[c,d]=out.end_time.split(':').map(Number);const exact=((c*60+d)-(a*60+b))/60;if(Math.abs(Number(out.hours)-exact)>0.01)return {error:'O total de horas não corresponde ao intervalo informado.'};}}
 if(out.cpf!==undefined&&out.cpf!==''&&!validCpf(out.cpf))return {error:'CPF inválido. Informe os 11 números com dígitos verificadores corretos.'};
 if(out.access_key!==undefined&&out.access_key!==''&&!/^\d{44}$/.test(out.access_key))return {error:'A chave de acesso da NFC-e deve conter exatamente 44 números.'};
 if(out.cnpj!==undefined&&out.cnpj!==''&&!validCnpj(out.cnpj))return {error:'CNPJ inválido. Informe os 14 números com dígitos verificadores corretos.'};
 return {data:out};
}
app.get('/api/data/:resource',auth,async(req,res)=>{
 const key=req.params.resource,cfg=resources[key];if(!cfg)return res.status(404).json({error:'Módulo não encontrado.'});
 if(!cfg.read.includes(req.user.role))return res.status(403).json({error:'Acesso negado.'});
 let q=key==='tasks'?'SELECT t.*,c.full_name AS assigned_to_name FROM tasks t LEFT JOIN contributors c ON c.id=t.assigned_to':key==='hours'?'SELECT h.*,c.full_name AS contributor_name,u.name AS reviewer_name FROM declared_hours h JOIN contributors c ON c.id=h.contributor_id LEFT JOIN users u ON u.id=h.reviewed_by':key==='purchases'?'SELECT p.*,COALESCE(s.trade_name,s.legal_name) AS supplier_name FROM purchases p LEFT JOIN suppliers s ON s.id=p.supplier_id':`SELECT * FROM ${cfg.table}`;
 const f=rowFilter(key,req.user);if(f){q+=` WHERE ${f.sql.replaceAll('assigned_to','t.assigned_to').replaceAll('contributor_id','h.contributor_id').replaceAll('requester_id','requester_id')}`;}
 q+=` ORDER BY ${key==='tasks'?'t.due_date ASC':key==='hours'?'h.work_date DESC':key==='purchases'?'p.purchase_date DESC':cfg.order}`;
 const rows=f?await sql.query(q,f.values):await sql.query(q,[]);
 res.json(rows);
});
app.post('/api/data/:resource',auth,totpLimiter,requireTOTP,async(req,res)=>{
 const key=req.params.resource,cfg=resources[key];if(!cfg)return res.status(404).json({error:'Módulo não encontrado.'});
 if(!cfg.roles.includes(req.user.role))return res.status(403).json({error:'Acesso negado.'});
 const p=validateFields(cfg,req.body);if(p.error)return res.status(400).json({error:p.error});const d=p.data;
 if(key==='hours'&&req.user.role==='contribuinte')d.contributor_id=req.user.contributor_id;
 if(key==='hours'&&d.task_id){const linked=await sql`SELECT assigned_to FROM tasks WHERE id=${d.task_id} AND status <> 'cancelada'`;if(!linked.length||linked[0].assigned_to!==d.contributor_id)return res.status(400).json({error:'A tarefa informada não pertence ao contribuinte selecionado.'});}
 if(key==='requests'&&req.user.role==='escola'){
  d.requester_id=req.user.id;d.requester_name=req.user.name;
 }
 if(key==='announcements')d.author_id=req.user.id;
 if(key==='tasks')d.created_by=req.user.id;
 if(key==='hours')d.status='Pendente Aprovação Escola';
 if(key==='requests')d.status='Pendente';
 if(key==='tasks')d.status='pendente';
 const extra={requests:['requester_id','requester_name','status'],announcements:['author_id'],tasks:['created_by','status'],hours:['status']}[key]||[];
 const fields=[...Object.keys(d),...extra.filter(k=>d[k]!==undefined&&!Object.hasOwn(d,k))];const values=fields.map(k=>d[k]);
 const cols=fields.join(',');const placeholders=fields.map((_,i)=>`$${i+1}`).join(',');
 const rows=await sql.query(`INSERT INTO ${cfg.table} (${cols}) VALUES (${placeholders}) RETURNING *`,values);
 await audit(req,'create',key,rows[0].id);res.status(201).json(rows[0]);
});
app.patch('/api/data/:resource/:id',auth,totpLimiter,requireTOTP,async(req,res)=>{
 const key=req.params.resource,cfg=resources[key];if(!cfg)return res.status(404).json({error:'Módulo não encontrado.'});
 let fields,values;
 if(key==='hours'&&req.user.role==='escola'){
  const p=z.object({status:z.enum(['Aprovado Escola','Rejeitado']),review_note:z.string().max(500).optional()}).strict().safeParse(req.body);
  if(!p.success)return res.status(400).json({error:'Decisão de aprovação inválida.'});if(p.data.status==='Rejeitado'&&(!p.data.review_note||p.data.review_note.trim().length<3))return res.status(400).json({error:'Informe uma justificativa para rejeitar a declaração.'});
  const rows=await sql`UPDATE declared_hours SET status=${p.data.status},reviewed_by=${req.user.id},reviewed_at=now(),review_note=${p.data.review_note||null} WHERE id=${req.params.id} AND status='Pendente Aprovação Escola' RETURNING *`;
  if(!rows.length)return res.status(409).json({error:'Declaração inexistente ou já analisada.'});await audit(req,'review','hours',req.params.id,{status:p.data.status});return res.json(rows[0]);
 }
 if(key==='requests'&&isCoord(req.user)){
  const p=z.object({status:z.enum(['Em análise','Aprovada','Rejeitada','Concluída'])}).strict().safeParse(req.body);if(!p.success)return res.status(400).json({error:'Status inválido.'});
  const rows=await sql`UPDATE service_requests SET status=${p.data.status},updated_at=now() WHERE id=${req.params.id} RETURNING *`;if(!rows.length)return res.status(404).json({error:'Solicitação não encontrada.'});await audit(req,'status_change',key,req.params.id,{status:p.data.status});return res.json(rows[0]);
 }
 if(key==='tasks'&&req.user.role==='contribuinte'){
  const p=z.object({status:z.enum(['em_andamento','concluida'])}).strict().safeParse(req.body);if(!p.success)return res.status(400).json({error:'Atualização inválida.'});
  const rows=await sql`UPDATE tasks SET status=${p.data.status},updated_at=now() WHERE id=${req.params.id} AND assigned_to=${req.user.contributor_id} RETURNING *`;if(!rows.length)return res.status(404).json({error:'Tarefa não encontrada.'});await audit(req,'status_change',key,req.params.id,{status:p.data.status});return res.json(rows[0]);
 }
 if(!cfg.roles.includes(req.user.role))return res.status(403).json({error:'Acesso negado.'});
 const p=validateFields(cfg,req.body,true);if(p.error)return res.status(400).json({error:p.error});fields=Object.keys(p.data);values=fields.map(k=>p.data[k]);if(!fields.length)return res.status(400).json({error:'Nenhuma alteração enviada.'});
 const sets=fields.map((k,i)=>`${k}=$${i+1}`);if(['contributors','suppliers','financial','announcements','tasks'].includes(key))sets.push('updated_at=now()');values.push(req.params.id);
 const rows=await sql.query(`UPDATE ${cfg.table} SET ${sets.join(',')} WHERE id=$${values.length} RETURNING *`,values);if(!rows.length)return res.status(404).json({error:'Registro não encontrado.'});await audit(req,'update',key,req.params.id,{fields});res.json(rows[0]);
});
app.delete('/api/data/:resource/:id',auth,totpLimiter,requireTOTP,async(req,res)=>{
 const key=req.params.resource,cfg=resources[key];if(!cfg)return res.status(404).json({error:'Módulo não encontrado.'});
 if(!['coordenador','vice_coordenador'].includes(req.user.role)||!['contributors','suppliers','financial','purchases','announcements','requests','tasks'].includes(key))return res.status(403).json({error:'Somente a coordenação pode excluir este tipo de registro.'});
 const rows=await sql.query(`DELETE FROM ${cfg.table} WHERE id=$1 RETURNING id`,[req.params.id]);if(!rows.length)return res.status(404).json({error:'Registro não encontrado.'});await audit(req,'delete',key,req.params.id);res.json({ok:true});
});

app.get('/api/dashboard',auth,async(req,res)=>{
 const role=req.user.role;const [contributors,financial,requests,tasks,hours]=await Promise.all([
  ['coordenador','vice_coordenador'].includes(role)?sql`SELECT count(*)::int AS count FROM contributors WHERE status='Ativo'`:Promise.resolve([{count:null}]),
  role==='coordenador'?sql`SELECT type,status,COALESCE(sum(amount),0)::numeric(12,2) AS total FROM financial_entries GROUP BY type,status`:Promise.resolve([]),
  role==='escola'?sql`SELECT status,count(*)::int AS count FROM service_requests WHERE requester_id=${req.user.id} GROUP BY status`:['coordenador','vice_coordenador'].includes(role)?sql`SELECT status,count(*)::int AS count FROM service_requests GROUP BY status`:Promise.resolve([]),
  role==='contribuinte'?sql`SELECT status,count(*)::int AS count FROM tasks WHERE assigned_to=${req.user.contributor_id} GROUP BY status`:['coordenador','vice_coordenador'].includes(role)?sql`SELECT status,count(*)::int AS count FROM tasks GROUP BY status`:Promise.resolve([]),
  role==='contribuinte'?sql`SELECT COALESCE(sum(hours),0)::numeric(8,2) AS total FROM declared_hours WHERE contributor_id=${req.user.contributor_id} AND status='Aprovado Escola'`:sql`SELECT COALESCE(sum(hours),0)::numeric(8,2) AS total FROM declared_hours WHERE status='Aprovado Escola'`
 ]);
 res.json({active_contributors:contributors[0]?.count,financial,requests,tasks,approved_hours:hours[0]?.total||0});
});
app.get('/api/contributor-options',auth,allow('coordenador','vice_coordenador','escola'),async(_req,res)=>{
 const rows=await sql`SELECT id,full_name FROM contributors ORDER BY full_name`;res.json(rows);
});
// Modelos Word cadastráveis: os links precisam permitir download público pelo OneDrive/SharePoint.
const templateRoles=['coordenador','vice_coordenador','escola'];
const allowedModelHost=h=>h==='1drv.ms'||h==='onedrive.live.com'||h==='api.onedrive.com'||h==='1drv.com'||h.endsWith('.1drv.com')||h.endsWith('.sharepoint.com')||h==='sharepoint.com';
function validateModelUrl(value){try{const u=new URL(value);return u.protocol==='https:'&&allowedModelHost(u.hostname.toLowerCase());}catch{return false;}}
async function fetchOneDriveDocx(raw){
 if(!validateModelUrl(raw))throw new Error('Use um link HTTPS compartilhado do OneDrive ou SharePoint.');
 let current=new URL(raw);if(current.hostname!=='1drv.ms'&&!current.searchParams.has('download'))current.searchParams.set('download','1');
 for(let i=0;i<6;i++){
  if(!validateModelUrl(current.toString()))throw new Error('O OneDrive redirecionou para um domínio não permitido.');
  const response=await fetch(current,{redirect:'manual',signal:AbortSignal.timeout(20000),headers:{'User-Agent':'TCE-Document-Generator/1.0'}});
  if([301,302,303,307,308].includes(response.status)){const loc=response.headers.get('location');if(!loc)throw new Error('Redirecionamento inválido do OneDrive.');current=new URL(loc,current);continue;}
  if(!response.ok)throw new Error(`Não foi possível baixar o modelo do OneDrive (HTTP ${response.status}). Confira o compartilhamento.`);
  const type=(response.headers.get('content-type')||'').toLowerCase();const len=Number(response.headers.get('content-length')||0);if(len>12*1024*1024)throw new Error('O modelo ultrapassa o limite de 12 MB.');
  const arr=Buffer.from(await response.arrayBuffer());if(arr.length>12*1024*1024)throw new Error('O modelo ultrapassa o limite de 12 MB.');
  if(arr.length<4||arr[0]!==0x50||arr[1]!==0x4b)throw new Error('O link não retornou um arquivo Word .docx. Use um modelo .docx, não .doc ou PDF.');
  return arr;
 }
 throw new Error('O link do OneDrive realizou redirecionamentos demais.');
}
const systemTagHelp=[
 ['data_emissao','Data de emissão'],['data_emissão','Data de emissão (com acento)'],['hora_emissao','Hora de emissão'],['nome_emissor','Nome de quem emitiu'],['email_emissor','E-mail de quem emitiu'],['nome_completo_contribuinte','Nome completo do contribuinte'],['email_contribuinte','E-mail do contribuinte'],['cpf_contribuinte','CPF do contribuinte'],['data_nascimento_contribuinte','Data de nascimento'],['endereco_contribuinte','Endereço do contribuinte'],['situacao_contribuinte','Situação do cadastro'],['nome_escola','Nome da instituição (preenchimento manual)'],['nome_atividade','Nome da atividade (preenchimento manual)'],['data_inicio','Data inicial do período'],['data_fim','Data final do período'],['total_horas','Total de horas aprovadas no período'],['quantidade_registros','Quantidade de declarações de horas aprovadas'],['lista_horas_aprovadas','Lista textual das horas aprovadas no período']
];
app.get('/api/document-templates',auth,allow(...templateRoles),async(req,res)=>{
 const rows=await sql`SELECT id,name,description,category,model_url,tags,active,created_at,updated_at FROM document_templates WHERE active=true ORDER BY category,name`;if(req.user.role==='escola')for(const row of rows)delete row.model_url;res.json({templates:rows,tag_catalog:systemTagHelp});
});
app.post('/api/document-templates',auth,allow('coordenador','vice_coordenador'),totpLimiter,requireTOTP,async(req,res)=>{
 const p=z.object({name:z.string().trim().min(2).max(180),description:z.string().max(1000).optional().nullable(),category:z.string().trim().min(2).max(80),model_url:z.string().url().max(1500),tags:z.array(z.string().regex(/^[\p{L}\p{N}_]+$/u).min(2).max(80)).max(80)}).safeParse(req.body);
 if(!p.success)return res.status(400).json({error:'Preencha nome, categoria, link e tags válidos.'});if(!validateModelUrl(p.data.model_url))return res.status(400).json({error:'O link precisa ser HTTPS do OneDrive ou SharePoint.'});
 const tags=[...new Set(p.data.tags)];const rows=await sql`INSERT INTO document_templates(name,description,category,model_url,tags,created_by) VALUES(${p.data.name},${p.data.description||null},${p.data.category},${p.data.model_url},${JSON.stringify(tags)}::jsonb,${req.user.id}) RETURNING id,name,description,category,model_url,tags,active,created_at`;
 await audit(req,'document_template_create','document_templates',rows[0].id,{name:rows[0].name,tags});res.status(201).json(rows[0]);
});
app.patch('/api/document-templates/:id',auth,allow('coordenador','vice_coordenador'),totpLimiter,requireTOTP,async(req,res)=>{
 const p=z.object({name:z.string().trim().min(2).max(180).optional(),description:z.string().max(1000).nullable().optional(),category:z.string().trim().min(2).max(80).optional(),model_url:z.string().url().max(1500).optional(),tags:z.array(z.string().regex(/^[\p{L}\p{N}_]+$/u).min(2).max(80)).max(80).optional(),active:z.boolean().optional()}).strict().safeParse(req.body);
 if(!p.success||!Object.keys(p.data||{}).length)return res.status(400).json({error:'Alterações inválidas.'});const d=p.data;if(d.model_url&&!validateModelUrl(d.model_url))return res.status(400).json({error:'O link precisa ser HTTPS do OneDrive ou SharePoint.'});
 const cols={name:'name',description:'description',category:'category',model_url:'model_url',tags:'tags',active:'active'},sets=[],vals=[];for(const [k,v] of Object.entries(d)){sets.push(k==='tags'?`${cols[k]}=$${vals.length+1}::jsonb`:`${cols[k]}=$${vals.length+1}`);vals.push(k==='tags'?JSON.stringify([...new Set(v)]):v);}sets.push('updated_at=now()');vals.push(req.params.id);const rows=await sql.query(`UPDATE document_templates SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING id,name,description,category,model_url,tags,active,updated_at`,vals);if(!rows.length)return res.status(404).json({error:'Modelo não encontrado.'});await audit(req,'document_template_update','document_templates',req.params.id,{fields:Object.keys(d)});res.json(rows[0]);
});
app.delete('/api/document-templates/:id',auth,allow('coordenador','vice_coordenador'),totpLimiter,requireTOTP,async(req,res)=>{
 const rows=await sql`UPDATE document_templates SET active=false,updated_at=now() WHERE id=${req.params.id} AND active=true RETURNING id,name`;if(!rows.length)return res.status(404).json({error:'Modelo não encontrado ou já desativado.'});await audit(req,'document_template_deactivate','document_templates',req.params.id,{name:rows[0].name});res.json({ok:true});
});
app.post('/api/document-templates/:id/generate',auth,allow(...templateRoles),async(req,res)=>{
 const p=z.object({contributor_id:z.string().uuid().optional(),values:z.record(z.string(),z.union([z.string(),z.number(),z.boolean()])).default({}),from:z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),to:z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional()}).safeParse(req.body);
 if(!p.success)return res.status(400).json({error:'Dados de emissão inválidos.'});if(p.data.from&&p.data.to&&p.data.from>p.data.to)return res.status(400).json({error:'O início do período não pode ser posterior ao fim.'});
 const found=await sql`SELECT id,name,model_url,tags FROM document_templates WHERE id=${req.params.id} AND active=true`;if(!found.length)return res.status(404).json({error:'Modelo não encontrado.'});const template=found[0];
 try{
  const model=await fetchOneDriveDocx(template.model_url);const values={...p.data.values};const now=new Date();const fmtDate=d=>{if(typeof d==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(d)){const [y,m,day]=d.split('-');return `${day}/${m}/${y}`;}return new Intl.DateTimeFormat('pt-BR',{timeZone:'America/Sao_Paulo'}).format(d);};
  Object.assign(values,{data_emissao:fmtDate(now),'data_emissão':fmtDate(now),hora_emissao:new Intl.DateTimeFormat('pt-BR',{timeZone:'America/Sao_Paulo',hour:'2-digit',minute:'2-digit'}).format(now),nome_emissor:req.user.name,email_emissor:req.user.email});
  if(p.data.contributor_id){const cs=await sql`SELECT full_name,email,cpf,birth_date,address,status FROM contributors WHERE id=${p.data.contributor_id}`;if(!cs.length)return res.status(404).json({error:'Contribuinte não encontrado.'});const c=cs[0];Object.assign(values,{nome_completo_contribuinte:c.full_name,email_contribuinte:c.email,cpf_contribuinte:c.cpf||'',data_nascimento_contribuinte:c.birth_date?fmtDate(String(c.birth_date).slice(0,10)): '',endereco_contribuinte:c.address||'',situacao_contribuinte:c.status});}
  values.data_inicio=p.data.from||'';values.data_fim=p.data.to||'';
  const needsHours=(Array.isArray(template.tags)?template.tags:[]).some(t=>['total_horas','quantidade_registros','lista_horas_aprovadas'].includes(t));
  if(needsHours){let q="SELECT COALESCE(sum(hours),0)::numeric(10,2) AS total,count(*)::int AS count FROM declared_hours WHERE status='Aprovado Escola'";const vals=[];if(p.data.contributor_id){vals.push(p.data.contributor_id);q+=` AND contributor_id=$${vals.length}`;}if(p.data.from){vals.push(p.data.from);q+=` AND work_date >= $${vals.length}`;}if(p.data.to){vals.push(p.data.to);q+=` AND work_date <= $${vals.length}`;}const h=await sql.query(q,vals);values.total_horas=String(h[0]?.total||0);values.quantidade_registros=String(h[0]?.count||0);}
  if((Array.isArray(template.tags)?template.tags:[]).includes('lista_horas_aprovadas')){let q="SELECT h.work_date,h.start_time,h.end_time,h.hours,h.activity,c.full_name FROM declared_hours h JOIN contributors c ON c.id=h.contributor_id WHERE h.status='Aprovado Escola'";const vals=[];if(p.data.contributor_id){vals.push(p.data.contributor_id);q+=` AND h.contributor_id=$${vals.length}`;}if(p.data.from){vals.push(p.data.from);q+=` AND h.work_date >= $${vals.length}`;}if(p.data.to){vals.push(p.data.to);q+=` AND h.work_date <= $${vals.length}`;}q+=' ORDER BY h.work_date,h.start_time';const records=await sql.query(q,vals);values.lista_horas_aprovadas=records.map(r=>`${fmtDate(String(r.work_date).slice(0,10))} | ${r.full_name} | ${r.activity} | ${r.start_time}–${r.end_time} | ${r.hours} h`).join('\n');}

  for(const tag of (Array.isArray(template.tags)?template.tags:[]))if(values[tag]===undefined)values[tag]='';
  const doc=new Docxtemplater(new PizZip(model),{delimiters:{start:'<<',end:'>>'},paragraphLoop:true,linebreaks:true});doc.render(values);const output=doc.getZip().generate({type:'nodebuffer',compression:'DEFLATE'});const safe=template.name.normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-zA-Z0-9_-]+/g,'_').slice(0,70)||'documento';
  await audit(req,'document_generated','document_templates',template.id,{name:template.name,contributor_id:p.data.contributor_id||null});res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.wordprocessingml.document');res.setHeader('Content-Disposition',`attachment; filename="${safe}.docx"`);res.send(output);
 }catch(e){console.error('Document generation error:',e.message);const msg=/tag|template|render|xml/i.test(e.message)?'Não foi possível preencher o modelo. Confira se todas as tags do Word estão cadastradas e escritas corretamente.':'Falha ao baixar ou processar o modelo. Verifique o compartilhamento do OneDrive e se o arquivo é .docx.';res.status(422).json({error:msg});}
});

app.get('/api/documents/hours',auth,allow('coordenador','vice_coordenador','escola'),async(req,res)=>{
 const p=z.object({contributor_id:z.string().uuid().optional(),from:z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),to:z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),status:z.enum(['Todos','Pendente Aprovação Escola','Aprovado Escola','Rejeitado']).optional(),activity:z.string().trim().max(180).optional()}).safeParse(req.query);
 if(!p.success)return res.status(400).json({error:'Filtros do relatório inválidos.'});
 const d=p.data;if(d.from&&d.to&&d.from>d.to)return res.status(400).json({error:'A data inicial não pode ser posterior à data final.'});let q='SELECT h.*,c.full_name AS contributor_name,u.name AS reviewer_name FROM declared_hours h JOIN contributors c ON c.id=h.contributor_id LEFT JOIN users u ON u.id=h.reviewed_by WHERE 1=1';const vals=[];
 if(d.contributor_id){vals.push(d.contributor_id);q+=` AND h.contributor_id=$${vals.length}`;}
 if(d.from){vals.push(d.from);q+=` AND h.work_date >= $${vals.length}`;}
 if(d.to){vals.push(d.to);q+=` AND h.work_date <= $${vals.length}`;}
 if(d.status&&d.status!=='Todos'){vals.push(d.status);q+=` AND h.status=$${vals.length}`;}
 if(d.activity){vals.push(`%${d.activity}%`);q+=` AND h.activity ILIKE $${vals.length}`;}
 q+=' ORDER BY h.work_date ASC,h.start_time ASC';
 const rows=await sql.query(q,vals);res.json(rows);
});

app.get('/api/audit',auth,allow('coordenador'),async(req,res)=>{const rows=await sql`SELECT l.id,l.action,l.entity,l.entity_id,l.details,l.ip_address,l.created_at,u.name AS actor_name FROM audit_logs l LEFT JOIN users u ON u.id=l.actor_id ORDER BY l.created_at DESC LIMIT 200`;res.json(rows);});

app.use('/api',(err,req,res,_next)=>{console.error('API error',err.code||err.name);if(['23505','23503','23514','23P01','22P02','22007','22008'].includes(err.code))return res.status(409).json({error:'A operação viola uma regra de integridade. Verifique duplicidade, vínculos e valores informados.'});res.status(500).json({error:'Erro interno. A operação não foi concluída.'});});
app.get('/',(_req,res)=>res.sendFile(require('path').join(__dirname,'public','index.html')));
app.use((req,res)=>res.status(404).json({error:'Rota não encontrada.'}));
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`TCE Portal ativo na porta ${port}`));
